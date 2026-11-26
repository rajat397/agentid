//go:build !enterprise

package agentid

import (
	"strings"
	"testing"
)

func TestEnterpriseCommandsAbsentInDefaultBuild(t *testing.T) {
	for _, command := range []string{"config", "health", "key"} {
		_, errOut, code := runCLI(t, command)
		if code != 2 || !strings.Contains(errOut, "unknown command") {
			t.Fatalf("%q was available in the open build: code=%d stderr=%s", command, code, errOut)
		}
	}
}
