package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Vulnerabilities with no upstream fix — remove entries once fixed.
var ignore = map[string]string{
	"GO-2026-4518": "pgproto3/v2 DoS, no fix available (EOL). Transitive via pgconn v1 + pop/v6.",
}

type finding struct {
	OSV string `json:"osv"`
}

func main() {
	dec := json.NewDecoder(os.Stdin)

	var unignored []string
	seen := make(map[string]bool)

	for {
		var f finding
		if err := dec.Decode(&f); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		if f.OSV == "" {
			continue
		}
		id := f.OSV
		if seen[id] {
			continue
		}
		seen[id] = true

		if reason, ok := ignore[id]; ok {
			fmt.Fprintf(os.Stderr, "ignoring %s: %s\n", id, reason)
		} else {
			fmt.Fprintf(os.Stderr, "ERROR: %s (not in ignore list)\n", id)
			unignored = append(unignored, id)
		}
	}

	if len(unignored) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d unignored vulnerability(ies) found\n", len(unignored))
		os.Exit(1)
	}
}
