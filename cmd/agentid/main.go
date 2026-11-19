package main

import (
	"os"

	"github.com/rajat397/agentid/internal/agentid"
)

func main() {
	os.Exit(agentid.Run(os.Args[1:], os.Stdout, os.Stderr))
}
