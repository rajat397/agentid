//go:build enterprise
// SPDX-License-Identifier: LicenseRef-agentid-commercial

package agentid

import (
	"fmt"
	"io"
)

func enterpriseCommand(name string) func([]string, io.Writer, io.Writer) int {
	switch name {
	case "config":
		return cmdConfig
	case "health":
		return cmdHealth
	case "key":
		return cmdKey
	default:
		return nil
	}
}

func cmdKey(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: agentid key <generate|rotate|publish>")
		return 2
	}
	dir, kid, out := "", "", ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			if i+1 < len(args) {
				i++
				dir = args[i]
			}
		case "--kid":
			if i+1 < len(args) {
				i++
				kid = args[i]
			}
		case "--out":
			if i+1 < len(args) {
				i++
				out = args[i]
			}
		}
	}
	if dir == "" {
		fmt.Fprintln(stderr, "key requires --dir <directory>")
		return 2
	}
	switch args[0] {
	case "generate":
		keyDir, err := GenerateLocalKey(dir, kid)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "generated %s\n", keyDir)
		return 0
	case "rotate":
		keyDir, err := RotateLocalKey(dir, kid)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "rotated to %s\n", keyDir)
		return 0
	case "publish":
		if out == "" {
			fmt.Fprintln(stderr, "key publish requires --out <file>")
			return 2
		}
		if err := PublishLocalKeys(dir, out); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote %s\n", out)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown key command %q\n", args[0])
		return 2
	}
}

func configPathArg(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func cmdConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(stderr, "usage: agentid config check --config <file>")
		return 2
	}
	path := configPathArg(args[1:])
	if path == "" {
		fmt.Fprintln(stderr, "config check requires --config <file>")
		return 2
	}
	config, err := LoadOperatorConfig(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "VALID mode=%s tools=%d\n", config.Mode, len(config.Tools))
	return 0
}

func cmdHealth(args []string, stdout, stderr io.Writer) int {
	path := configPathArg(args)
	if path == "" {
		fmt.Fprintln(stderr, "health requires --config <file>")
		return 2
	}
	config, err := LoadOperatorConfig(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	payload, err := CanonicalJSON(map[string]any{
		"status":  "ok",
		"mode":    config.Mode,
		"tools":   len(config.Tools),
		"version": BuildVersion,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, string(payload))
	return 0
}
