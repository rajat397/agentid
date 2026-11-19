package agentid

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// SCIMUser and SCIMGroup are the minimal SCIM 2.0 resource shapes we need.
type SCIMUser struct {
	ID       string    `json:"id"`
	UserName string    `json:"userName"`
	Active   *bool     `json:"active"`
	Groups   []SCIMRef `json:"groups"`
}

type SCIMGroup struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"displayName"`
	Members     []SCIMRef `json:"members"`
}

type SCIMRef struct {
	Value   string `json:"value"`
	Display string `json:"display"`
}

// SCIMClient reads Users and Groups from a SCIM 2.0 service. The bearer token
// comes from the deployment; no credentials are persisted by this library.
type SCIMClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

func (c SCIMClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{}
}

func (c SCIMClient) fetch(ctx context.Context, resource string) ([]json.RawMessage, error) {
	all := []json.RawMessage{}
	start := 1
	for {
		endpoint := strings.TrimRight(c.BaseURL, "/") + "/" + resource
		query := url.Values{"startIndex": {strconv.Itoa(start)}, "count": {"100"}}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet,
			endpoint+"?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/scim+json")
		if c.Token != "" {
			request.Header.Set("Authorization", "Bearer "+c.Token)
		}
		response, err := c.client().Do(request)
		if err != nil {
			return nil, fmt.Errorf("SCIM %s: %w", resource, err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		response.Body.Close()
		if err != nil {
			return nil, err
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, fmt.Errorf("SCIM %s returned HTTP %d", resource, response.StatusCode)
		}
		var page struct {
			TotalResults int               `json:"totalResults"`
			Resources    []json.RawMessage `json:"Resources"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("SCIM %s: %w", resource, err)
		}
		all = append(all, page.Resources...)
		start += len(page.Resources)
		if len(page.Resources) == 0 || (page.TotalResults > 0 && start > page.TotalResults) {
			return all, nil
		}
	}
}

// FetchUsers reads all users with paging.
func (c SCIMClient) FetchUsers(ctx context.Context) ([]SCIMUser, error) {
	raw, err := c.fetch(ctx, "Users")
	if err != nil {
		return nil, err
	}
	users := make([]SCIMUser, 0, len(raw))
	for _, item := range raw {
		var user SCIMUser
		if err := json.Unmarshal(item, &user); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// FetchGroups reads all groups with paging.
func (c SCIMClient) FetchGroups(ctx context.Context) ([]SCIMGroup, error) {
	raw, err := c.fetch(ctx, "Groups")
	if err != nil {
		return nil, err
	}
	groups := make([]SCIMGroup, 0, len(raw))
	for _, item := range raw {
		var group SCIMGroup
		if err := json.Unmarshal(item, &group); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

// PseudonymousID hashes a directory identifier before it enters our artifacts.
func PseudonymousID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "subj_" + hex.EncodeToString(sum[:])[:16]
}

// SCIMRevocations returns raw directory IDs whose authority changed since the
// previous sync. A user is active only when `active` is true and, when a
// required group is configured, is a member of it.
func SCIMRevocations(users []SCIMUser, requiredGroup string,
	previous map[string]bool) (revoked, reactivated []string) {
	current := map[string]bool{}
	for _, user := range users {
		active := user.Active == nil || *user.Active
		if requiredGroup != "" {
			member := false
			for _, group := range user.Groups {
				if group.Display == requiredGroup || group.Value == requiredGroup {
					member = true
					break
				}
			}
			active = active && member
		}
		current[user.ID] = active
	}
	for id, active := range current {
		old, known := previous[id]
		if known && old != active {
			if active {
				reactivated = append(reactivated, id)
			} else {
				revoked = append(revoked, id)
			}
		}
	}
	return revoked, reactivated
}

// SCIMSyncResult contains only pseudonymous identifiers — never raw PII.
type SCIMSyncResult struct {
	SyncedAt         string   `json:"synced_at"`
	RevokedCount     int      `json:"revoked_count"`
	ReactivatedCount int      `json:"reactivated_count"`
	PseudonymousIDs  []string `json:"pseudonymous_ids"`
	SkippedCount     int      `json:"skipped_count"`
}

// ApplySCIMSync maps directory revocations to status-list indices and returns
// the updated statuses plus a PII-free result.
func ApplySCIMSync(statuses []int, subjectIndex map[string]int,
	revoked, reactivated []string) ([]int, SCIMSyncResult) {
	updated := append([]int{}, statuses...)
	result := SCIMSyncResult{
		SyncedAt:        dateTimeNow().Format(timeLayout),
		PseudonymousIDs: []string{},
		RevokedCount:    len(revoked), ReactivatedCount: len(reactivated),
	}
	for _, raw := range revoked {
		result.PseudonymousIDs = append(result.PseudonymousIDs, PseudonymousID(raw))
		idx, ok := subjectIndex[raw]
		if !ok || idx < 0 || idx >= len(updated) {
			result.SkippedCount++
			continue
		}
		updated[idx] = 0x01
	}
	for _, raw := range reactivated {
		result.PseudonymousIDs = append(result.PseudonymousIDs, PseudonymousID(raw))
		idx, ok := subjectIndex[raw]
		if !ok || idx < 0 || idx >= len(updated) {
			result.SkippedCount++
			continue
		}
		updated[idx] = 0x00
	}
	return updated, result
}

// NewSCIMWebhookHandler accepts SCIM push events. The shared secret is
// compared in constant time and raw directory IDs never leave the response.
func NewSCIMWebhookHandler(secret string, onEvent func(event, pseudonym string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		authorization := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(authorization), []byte("Bearer "+secret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Event string `json:"event"`
			ID    string `json:"id"`
		}
		decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		if err := decoder.Decode(&body); err != nil || body.ID == "" || body.Event == "" {
			http.Error(w, "invalid event", http.StatusBadRequest)
			return
		}
		if onEvent != nil {
			onEvent(body.Event, PseudonymousID(body.ID))
		}
		w.WriteHeader(http.StatusAccepted)
	})
}
