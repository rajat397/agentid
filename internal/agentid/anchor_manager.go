package agentid

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

// AnchorCadence controls when the next chain head is stamped.
type AnchorCadence struct {
	MaxReceipts int
	MaxInterval time.Duration
}

// AnchorConfig is the customer's anchoring policy. StrictCA defaults to true;
// production deployments supply their TSA CA bundle rather than disabling it.
type AnchorConfig struct {
	TSAURL   string
	CAPEM    []byte
	StrictCA bool
	Cadence  AnchorCadence
}

// AnchorManager anchors chain heads at a cadence, queues failures and retries
// them. It never blocks a receipt write: Observe is called after the write.
type AnchorManager struct {
	config  AnchorConfig
	client  *http.Client
	mu      sync.Mutex
	anchors []map[string]any
	queue   []string
	lastSeq int
	lastAt  time.Time
}

// NewAnchorManager builds a manager with safe defaults.
func NewAnchorManager(config AnchorConfig) (*AnchorManager, error) {
	if config.Cadence.MaxReceipts <= 0 {
		config.Cadence.MaxReceipts = 1
	}
	if config.Cadence.MaxInterval <= 0 {
		config.Cadence.MaxInterval = 24 * time.Hour
	}
	if config.TSAURL == "" {
		config.TSAURL = DefaultTSA
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if len(config.CAPEM) > 0 && !roots.AppendCertsFromPEM(config.CAPEM) {
		return nil, errors.New("TSA CA bundle contains no valid certificates")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}
	parsed, err := url.Parse(config.TSAURL)
	if err != nil {
		return nil, err
	}
	host, port := parsed.Hostname(), parsed.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(host, port))
	}
	return &AnchorManager{
		config: config, client: &http.Client{Transport: transport, Timeout: 15 * time.Second},
	}, nil
}

// Observe anchors the current head if the cadence is reached, retries any
// queued heads, and returns the current anchor set. Failures are retained in
// the queue and never propagated as write errors.
func (m *AnchorManager) Observe(ledger *Ledger, tsaURL string) ([]map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(ledger.Receipts) == 0 {
		return m.snapshot(), nil
	}
	head, err := ChainHead(ledger)
	if err != nil {
		return m.snapshot(), nil
	}
	seq := len(ledger.Receipts) - 1
	due := seq >= m.lastSeq+m.config.Cadence.MaxReceipts ||
		(m.lastAt.IsZero() || time.Since(m.lastAt) >= m.config.Cadence.MaxInterval)
	if due {
		if err := m.anchor(head, seq, tsaURL); err != nil {
			m.enqueue(head)
		} else {
			m.queue = nil
		}
	}
	for _, pending := range append([]string{}, m.queue...) {
		if err := m.anchor(pending, seq, tsaURL); err == nil {
			m.removeQueued(pending)
		}
	}
	return m.snapshot(), nil
}

func (m *AnchorManager) anchor(head string, seq int, tsaURL string) error {
	endpoint := tsaURL
	if endpoint == "" {
		endpoint = m.config.TSAURL
	}
	request, err := BuildTimestampReq(head)
	if err != nil {
		return err
	}
	response, err := m.client.Post(endpoint, "application/timestamp-query", bytes.NewReader(request))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("TSA returned HTTP %d", response.StatusCode)
	}
	info, err := ParseTimestampResp(body)
	if err != nil || info.MessageImprint != head {
		return errors.New("TSA response does not bind the requested head")
	}
	record := map[string]any{
		"head_hash": head, "head_seq": seq, "tsa_url": endpoint,
		"request_der_b64":  b64StdEncode(request),
		"response_der_b64": b64StdEncode(body),
		"gen_time":         info.GenTime, "serial": info.Serial,
		"anchored_at": dateTimeNow().Format(timeLayout),
	}
	m.anchors = append(m.anchors, record)
	m.lastSeq = seq
	m.lastAt = time.Now()
	return nil
}

func (m *AnchorManager) enqueue(head string) {
	for _, pending := range m.queue {
		if pending == head {
			return
		}
	}
	m.queue = append(m.queue, head)
}

func (m *AnchorManager) removeQueued(head string) {
	out := m.queue[:0]
	for _, pending := range m.queue {
		if pending != head {
			out = append(out, pending)
		}
	}
	m.queue = out
}

func (m *AnchorManager) snapshot() []map[string]any {
	return append([]map[string]any{}, m.anchors...)
}

// Pending returns the head hashes still awaiting a successful TSA response.
func (m *AnchorManager) Pending() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.queue...)
}

// DetectAnchorGaps reports anchors that do not bind receipts in this ledger,
// or a ledger head with no anchor at all.
func DetectAnchorGaps(anchors []map[string]any, ledger *Ledger) []string {
	problems := []string{}
	if len(ledger.Receipts) == 0 {
		return problems
	}
	known := map[string]bool{}
	for _, receipt := range ledger.Receipts {
		hash, err := receipt.Hash()
		if err == nil {
			known[hash] = true
		}
	}
	head, err := ChainHead(ledger)
	if err != nil {
		return append(problems, err.Error())
	}
	anchoredHead := false
	for _, anchor := range anchors {
		hash := stringField(anchor, "head_hash")
		if !known[hash] {
			problems = append(problems, "anchor names a head absent from the ledger: "+shortHash(hash))
		}
		if bound := VerifyAnchorBinding(anchor); len(bound) > 0 {
			problems = append(problems, bound...)
		}
		if hash == head {
			anchoredHead = true
		}
	}
	if !anchoredHead {
		problems = append(problems, "no anchor for current chain head "+shortHash(head))
	}
	sort.Strings(problems)
	return problems
}

func b64StdEncode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
