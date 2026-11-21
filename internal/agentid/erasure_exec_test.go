package agentid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPConnectorOutcomesAndIdempotency(t *testing.T) {
	records := map[string]bool{"cust_1": true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method == http.MethodDelete {
			if !records["cust_1"] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(records, "cust_1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if records["cust_1"] {
			w.Write([]byte(`{"found":true}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	connector := HTTPConnector{SystemName: "crm", BaseURL: server.URL, Credential: "secret"}

	record, err := connector.DeleteSubject(context.Background(), "cust_1")
	if err != nil || record.Outcome != OutcomeDeleted {
		t.Fatalf("delete failed: %+v %v", record, err)
	}
	record, err = connector.DeleteSubject(context.Background(), "cust_1")
	if err != nil || record.Outcome != OutcomeNotFound {
		t.Fatalf("idempotent replay failed: %+v %v", record, err)
	}
	absent, err := connector.VerifyAbsent(context.Background(), "cust_1")
	if err != nil || !absent {
		t.Fatalf("absence check failed: %v %v", absent, err)
	}
	bad := HTTPConnector{SystemName: "crm", BaseURL: server.URL, Credential: "wrong"}
	if _, err := bad.DeleteSubject(context.Background(), "cust_1"); err == nil {
		t.Fatal("forbidden connector did not fail")
	}
	if problems := VerifyErasure([]DownstreamConnector{connector}, "cust_1"); len(problems) > 0 {
		t.Fatalf("verify failed on clean subject: %v", problems)
	}
}

func TestExecuteErasureReceiptsCarryDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	ledger := &Ledger{}
	receipts, err := ExecuteErasure(ledger, "ers_9", "cust_1",
		[]DownstreamConnector{HTTPConnector{SystemName: "zendesk", BaseURL: server.URL}},
		dateTimeNow())
	if err != nil || len(receipts) != 1 {
		t.Fatalf("erasure failed: %v %d", err, len(receipts))
	}
	attributes := AsMap(AsMap(receipts[0].Resource)["attributes"])
	if stringField(attributes, "erasure_request_id") != "ers_9" ||
		len(stringField(attributes, "deadline")) != len(timeLayout) {
		t.Fatalf("deletion receipt lacks request binding/deadline: %+v", attributes)
	}
	if problems := ledger.VerifyChain(nil); len(problems) > 0 {
		t.Fatalf("deletion receipt broke chain: %v", problems)
	}
}
