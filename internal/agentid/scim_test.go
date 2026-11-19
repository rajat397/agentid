package agentid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSCIMClientPagingAndAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing bearer token")
		}
		if r.Header.Get("Accept") != "application/scim+json" {
			t.Errorf("missing SCIM accept header")
		}
		w.Header().Set("Content-Type", "application/scim+json")
		if strings.HasPrefix(r.URL.Path, "/Users") {
			if r.URL.Query().Get("startIndex") == "1" {
				w.Write([]byte(`{"totalResults":2,"Resources":[{"id":"u1","userName":"alice@example.com","active":true}]}`))
			} else {
				w.Write([]byte(`{"totalResults":2,"Resources":[{"id":"u2","userName":"bob@example.com","active":false}]}`))
			}
			return
		}
		w.Write([]byte(`{"totalResults":0,"Resources":[]}`))
	}))
	defer server.Close()

	client := SCIMClient{BaseURL: server.URL, Token: "test-token"}
	users, err := client.FetchUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[1].ID != "u2" {
		t.Fatalf("paging failed: %+v", users)
	}
}

func TestSCIMSyncRevokesAndPseudonymizes(t *testing.T) {
	yes := true
	no := false
	users := []SCIMUser{
		{ID: "usr_alice", UserName: "alice@example.com", Active: &no,
			Groups: []SCIMRef{{Value: "g1", Display: "agents"}}},
		{ID: "usr_bob", UserName: "bob@example.com", Active: &yes,
			Groups: []SCIMRef{{Value: "g1", Display: "agents"}}},
		{ID: "usr_cara", UserName: "cara@example.com", Active: &yes,
			Groups: []SCIMRef{{Value: "g1", Display: "agents"}}},
	}
	previous := map[string]bool{
		"usr_alice": true, "usr_bob": true, "usr_cara": false,
	}
	revoked, reactivated := SCIMRevocations(users, "agents", previous)
	if len(revoked) != 1 || revoked[0] != "usr_alice" {
		t.Fatalf("unexpected revocations: %v", revoked)
	}
	if len(reactivated) != 1 || reactivated[0] != "usr_cara" {
		t.Fatalf("unexpected reactivations: %v", reactivated)
	}
	subjectIndex := map[string]int{"usr_alice": 1, "usr_cara": 2}
	statuses, result := ApplySCIMSync([]int{0x00, 0x00, 0x01}, subjectIndex,
		revoked, reactivated)
	if statuses[1] != 0x01 || statuses[2] != 0x00 {
		t.Fatalf("statuses not updated: %v", statuses)
	}
	if result.RevokedCount != 1 || result.ReactivatedCount != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"alice", "bob", "cara", "@example.com", "usr_"} {
		if strings.Contains(string(serialized), leak) {
			t.Fatalf("raw directory data leaked: %s", leak)
		}
	}
}

func TestSCIMWebhookHandler(t *testing.T) {
	received := []string{}
	handler := NewSCIMWebhookHandler("secret", func(event, pseudonym string) {
		received = append(received, event+":"+pseudonym)
	})
	body := `{"event":"UserDeleted","id":"usr_alice"}`

	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodPost, "/scim/events",
		strings.NewReader(body)))
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized event accepted: %d", bad.Code)
	}

	request := httptest.NewRequest(http.MethodPost, "/scim/events", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer secret")
	good := httptest.NewRecorder()
	handler.ServeHTTP(good, request)
	if good.Code != http.StatusAccepted || len(received) != 1 {
		t.Fatalf("webhook rejected: %d %v", good.Code, received)
	}
	if strings.Contains(good.Body.String(), "usr_alice") {
		t.Fatal("raw directory ID returned by webhook")
	}
}

func TestSCIMClientFailsOnHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	client := SCIMClient{BaseURL: server.URL}
	if _, err := client.FetchUsers(context.Background()); err == nil {
		t.Fatal("SCIM HTTP 500 treated as success")
	}
}
