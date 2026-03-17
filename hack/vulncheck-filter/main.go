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

type message struct {
	Finding *struct {
		OSV *struct {
			ID string `json:"id"`
		} `json:"osv"`
	} `json:"finding"`
}

func main() {
	dec := json.NewDecoder(os.Stdin)

	var unignored []string
	seen := make(map[string]bool)
	for {
		var m message
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			// govulncheck JSON stream may contain objects we don't care about; skip decode errors
			continue
		}
		if m.Finding == nil {
			continue
		}
		if m.Finding.OSV == nil {
			continue
		}
		id := m.Finding.OSV.ID
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
