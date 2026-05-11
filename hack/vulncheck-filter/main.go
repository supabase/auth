package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

// Vulnerabilities with no upstream fix — remove entries once fixed.
var ignore = map[string]string{
	"GO-2026-4518": "pgproto3/v2 DoS, no fix available (EOL). Transitive via pgconn v1 + pop/v6.",
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vulncheck-filter: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	const (
		stInit = iota
		stVulnOpen
	)

	type vuln struct {
		ID   string `json:"id"`
		Text string
	}

	var (
		cur   vuln
		vulns []*vuln
	)
	st := stInit
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		v := sc.Text()
		switch st {
		case stInit:
			if strings.HasPrefix(v, "Vulnerability ") {
				st = stVulnOpen
				_, id, ok := strings.Cut(v, ": ")
				if !ok {
					return errors.New("no longer able to parse format")
				}
				cur = vuln{
					ID: id,
				}
			}
		case stVulnOpen:
			cur.Text += v + "\n"
			if v == "" {
				st = stInit
				cpy := cur
				vulns = append(vulns, &cpy)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	vulns = slices.DeleteFunc(vulns, func(v *vuln) bool {
		reason, ok := ignore[v.ID]
		if ok {
			fmt.Fprintf(os.Stderr, "ignoring %s: %s\n", v.ID, reason)
		}
		return ok
	})
	if len(vulns) == 0 {
		return nil
	}

	fmt.Fprintf(os.Stderr, "\n")
	for idx, vuln := range vulns {
		msg := "Vulnerability #%d: %v\n%v"
		fmt.Fprintf(os.Stderr, msg, idx+1, vuln.ID, vuln.Text)
	}
	return fmt.Errorf("%d unignored vulnerability(ies) found", len(vulns))
}
