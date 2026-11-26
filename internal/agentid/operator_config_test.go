package agentid

import (
	"os"
	"path/filepath"
	"testing"
)

func writeOperatorConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agentid.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOperatorConfigValid(t *testing.T) {
	path := writeOperatorConfig(t, `{
  "version": "v1",
  "mode": "enforce",
  "tools": [{"name":"purchase","action":"ad.credit.purchase","system":"meta-ads","resource_type":"ad_credit_account","allowed_args":["amount","currency"]}]
}`)
	config, err := LoadOperatorConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != OperatorModeEnforce {
		t.Fatalf("mode = %q", config.Mode)
	}
}

func TestOperatorConfigRejectsBadModeAndAuthorityArgs(t *testing.T) {
	cases := map[string]string{
		"bad mode": `{"mode":"maybe","tools":[{"name":"purchase","action":"a","system":"s","resource_type":"r"}]}`,
		"bad arg":  `{"mode":"enforce","tools":[{"name":"purchase","action":"a","system":"s","resource_type":"r","allowed_args":["stage"]}]}`,
		"no tools": `{"mode":"enforce","tools":[]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadOperatorConfig(writeOperatorConfig(t, body)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
