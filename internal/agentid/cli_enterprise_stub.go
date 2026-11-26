//go:build !enterprise

package agentid

import "io"

func enterpriseCommand(name string) func([]string, io.Writer, io.Writer) int {
	return nil
}
