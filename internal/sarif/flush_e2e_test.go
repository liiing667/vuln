// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sarif

import (
	"bytes"
	"encoding/json"
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
)

// TestFlushRuleResultLocationClosure simulates a realistic stream (config,
// OSVs, and
// multiple findings per OSV) in both source and binary mode and checks
// rule/result/location closure on the flushed document.
func TestFlushRuleResultLocationClosure(t *testing.T) {
	for _, mode := range []govulncheck.ScanMode{govulncheck.ScanModeSource, govulncheck.ScanModeBinary} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			var buf bytes.Buffer
			h := NewHandler(&buf)
			if err := h.Config(&govulncheck.Config{
				ProtocolVersion: govulncheck.ProtocolVersion,
				ScannerName:     "govulncheck",
				ScanLevel:       govulncheck.ScanLevelSymbol,
				ScanMode:        mode,
			}); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"GO-1", "GO-2"} {
				if err := h.OSV(testEntry(id)); err != nil {
					t.Fatal(err)
				}
			}
			// Module + package + symbol findings for GO-1, emitted out of
			// precision order. Two distinct symbol findings for GO-2.
			if err := h.Finding(moduleFinding("GO-1", "example.com/m")); err != nil {
				t.Fatal(err)
			}
			if err := h.Finding(&govulncheck.Finding{OSV: "GO-1", Trace: []*govulncheck.Frame{
				{Module: "example.com/m", Package: "example.com/m/p"},
			}}); err != nil {
				t.Fatal(err)
			}
			if err := h.Finding(&govulncheck.Finding{OSV: "GO-1", Trace: []*govulncheck.Frame{
				{Module: "example.com/m", Package: "example.com/m/p", Function: "V"},
				{Module: "example.com/app", Package: "example.com/app", Function: "main"},
			}}); err != nil {
				t.Fatal(err)
			}
			if err := h.Finding(&govulncheck.Finding{OSV: "GO-2", Trace: []*govulncheck.Frame{
				{Module: "example.com/m2", Package: "example.com/m2/p", Function: "W"},
				{Module: "example.com/app", Package: "example.com/app", Function: "main"},
			}}); err != nil {
				t.Fatal(err)
			}
			if err := h.Finding(&govulncheck.Finding{OSV: "GO-2", Trace: []*govulncheck.Frame{
				{Module: "example.com/m2", Package: "example.com/m2/p", Function: "Z"},
				{Module: "example.com/app", Package: "example.com/app", Function: "main"},
			}}); err != nil {
				t.Fatal(err)
			}

			if err := h.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}

			var log Log
			if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
				t.Fatalf("invalid json: %v", err)
			}
			run := log.Runs[0]
			rules := map[string]bool{}
			for _, r := range run.Tool.Driver.Rules {
				rules[r.ID] = true
			}
			results := map[string]Result{}
			for _, res := range run.Results {
				results[res.RuleID] = res
				if !rules[res.RuleID] {
					t.Errorf("result %q has no matching rule", res.RuleID)
				}
			}
			if len(rules) != len(results) {
				t.Errorf("rule/result counts differ: %d rules vs %d results", len(rules), len(results))
			}
			for id := range rules {
				if _, ok := results[id]; !ok {
					t.Errorf("rule %q has no matching result", id)
				}
			}
			// GO-1 must have collapsed to its single symbol-level finding.
			if got := len(results["GO-1"].Stacks); got != 1 {
				t.Errorf("GO-1 stacks = %d, want 1", got)
			}
			if got := len(results["GO-2"].Stacks); got != 2 {
				t.Errorf("GO-2 stacks = %d, want 2", got)
			}
			for _, res := range results {
				switch mode {
				case govulncheck.ScanModeBinary:
					if len(res.Locations) != 0 {
						t.Errorf("binary result %q must have no locations", res.RuleID)
					}
				default:
					if len(res.Locations) != 1 || res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "go.mod" {
						t.Errorf("source result %q must attach to go.mod", res.RuleID)
					}
				}
			}
		})
	}
}
