// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openvex

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

func TestSubcomponentSet(t *testing.T) {
	id1 := "GO-2021-0265"
	id2 := "GO-2022-1234"
	tests := []struct {
		name     string
		findings []*govulncheck.Finding
		want     []string
	}{
		{
			name: "multiple findings at same level different mod",
			findings: []*govulncheck.Finding{
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod1",
							Package: "mod1/pkg",
						},
					},
				},
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod2",
							Package: "mod2/pkg2",
						},
					},
				},
			},
			want: []string{
				"pkg:golang/mod1",
				"pkg:golang/mod2",
			},
		},
		{
			name: "multiple Findings at same level same mod",
			findings: []*govulncheck.Finding{
				{
					OSV:          id1,
					FixedVersion: "v1.9.3",
					Trace: []*govulncheck.Frame{
						{
							Module:   "github.com/tidwall/gjson",
							Version:  "v1.6.5",
							Package:  "github.com/tidwall/gjson",
							Function: "Get",
						},
					},
				},
				{
					OSV:          id1,
					FixedVersion: "v1.9.3",
					Trace: []*govulncheck.Frame{
						{
							Module:   "github.com/tidwall/gjson",
							Version:  "v1.6.5",
							Package:  "github.com/tidwall/gjson",
							Function: "Get",
							Receiver: "Result",
						},
					},
				},
			},
			want: []string{
				"pkg:golang/github.com%2Ftidwall%2Fgjson@v1.6.5",
			},
		},
		{
			name: "mix of findings for different osvs",
			findings: []*govulncheck.Finding{
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod1",
							Version: "v1.0.0",
						},
					},
				},
				{
					OSV: id2,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod2",
							Version: "v1.0.0",
							Package: "mod2/pkg2",
						},
					},
				},
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod2",
							Version: "v1.2.1",
						},
					},
				},
			},
			want: []string{
				"pkg:golang/mod1@v1.0.0",
				"pkg:golang/mod2@v1.0.0",
				"pkg:golang/mod2@v1.2.1",
			},
		},
		{
			name: "subcomponents are sorted regardless of finding order",
			findings: []*govulncheck.Finding{
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{Module: "zebra.example/mod", Version: "v1.0.0"},
					},
				},
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{Module: "alpha.example/mod", Version: "v1.0.0"},
					},
				},
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{Module: "mid.example/mod", Version: "v1.0.0"},
					},
				},
			},
			want: []string{
				"pkg:golang/alpha.example%2Fmod@v1.0.0",
				"pkg:golang/mid.example%2Fmod@v1.0.0",
				"pkg:golang/zebra.example%2Fmod@v1.0.0",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := subcomponentSet(tt.findings)
			var gotIDs []string
			for _, sc := range got {
				gotIDs = append(gotIDs, sc.ID)
			}
			if !slices.Equal(gotIDs, tt.want) {
				t.Errorf("want %v subcomponents, got %v instead", tt.want, gotIDs)
			}
		})
	}
}

func moduleFinding(osv, mod, version string) *govulncheck.Finding {
	return &govulncheck.Finding{
		OSV: osv,
		Trace: []*govulncheck.Frame{
			{Module: mod, Version: version},
		},
	}
}

func packageFinding(osv, mod, version, pkg string) *govulncheck.Finding {
	return &govulncheck.Finding{
		OSV: osv,
		Trace: []*govulncheck.Frame{
			{Module: mod, Version: version, Package: pkg},
		},
	}
}

func callFinding(osv, mod, version, pkg, fn string) *govulncheck.Finding {
	return &govulncheck.Finding{
		OSV: osv,
		Trace: []*govulncheck.Frame{
			{Module: mod, Version: version, Package: pkg, Function: fn},
			{Module: "example.com/main", Version: "v0.1.0", Package: "example.com/main", Function: "main"},
		},
	}
}

// flushDocument feeds the given config, OSV entries and findings to a fresh
// openvex handler and returns the VEX document it produces.
func flushDocument(t *testing.T, scanLevel govulncheck.ScanLevel,
	osvs []*osv.Entry, findings ...*govulncheck.Finding) Document {
	t.Helper()

	h := NewHandler(&bytes.Buffer{})
	if err := h.Config(&govulncheck.Config{ScanLevel: scanLevel}); err != nil {
		t.Fatalf("Config: %v", err)
	}
	for _, e := range osvs {
		if err := h.OSV(e); err != nil {
			t.Fatalf("OSV: %v", err)
		}
	}
	for _, f := range findings {
		if err := h.Finding(f); err != nil {
			t.Fatalf("Finding: %v", err)
		}
	}

	var buf bytes.Buffer
	h.w = &buf
	if err := h.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal vex document: %v", err)
	}
	return doc
}

func subcomponentIDs(s Statement) []string {
	var ids []string
	for _, p := range s.Products {
		for _, sc := range p.Subcomponents {
			ids = append(ids, sc.ID)
		}
	}
	return ids
}

// TestFindingKeepsEverySubcomponent makes sure that a more precise finding for
// one subcomponent does not erase the findings for the other subcomponents of
// the same vulnerability.
func TestFindingKeepsEverySubcomponent(t *testing.T) {
	const osvID = "GO-2024-0001"
	osvs := []*osv.Entry{{ID: osvID, Summary: "test vuln"}}

	// mod1 is called, while mod2 is only imported. The module-level
	// findings govulncheck emits first must not be dropped for mod2 once
	// the call finding for mod1 arrives.
	doc := flushDocument(t, govulncheck.ScanLevelSymbol, osvs,
		moduleFinding(osvID, "example.com/mod1", "v1.0.0"),
		moduleFinding(osvID, "example.com/mod2", "v2.0.0"),
		packageFinding(osvID, "example.com/mod1", "v1.0.0", "example.com/mod1/p"),
		packageFinding(osvID, "example.com/mod2", "v2.0.0", "example.com/mod2/p"),
		callFinding(osvID, "example.com/mod1", "v1.0.0", "example.com/mod1/p", "Vuln"),
	)

	gotStatuses := make(map[string]string)
	var allSubcomponents []string
	for _, s := range doc.Statements {
		if s.Vulnerability.Name != osvID {
			t.Fatalf("unexpected vulnerability %q", s.Vulnerability.Name)
		}
		ids := subcomponentIDs(s)
		if !slices.IsSorted(ids) {
			t.Errorf("subcomponents not sorted: %v", ids)
		}
		allSubcomponents = append(allSubcomponents, ids...)
		for _, id := range ids {
			gotStatuses[id] = s.Status
		}
	}
	slices.Sort(allSubcomponents)

	wantSubcomponents := []string{
		"pkg:golang/example.com%2Fmod1@v1.0.0",
		"pkg:golang/example.com%2Fmod2@v2.0.0",
	}
	if !slices.Equal(allSubcomponents, wantSubcomponents) {
		t.Fatalf("affected scope shrunk: want subcomponents %v, got %v",
			wantSubcomponents, allSubcomponents)
	}

	// The two subcomponents are at different levels, so they need
	// separate statements with statuses matching the scan level.
	wantStatuses := map[string]string{
		"pkg:golang/example.com%2Fmod1@v1.0.0": StatusAffected,
		"pkg:golang/example.com%2Fmod2@v2.0.0": StatusNotAffected,
	}
	if len(gotStatuses) != len(wantStatuses) {
		t.Fatalf("want %d status-grouped statements, got %d",
			len(wantStatuses), len(gotStatuses))
	}
	for purl, want := range wantStatuses {
		if got := gotStatuses[purl]; got != want {
			t.Errorf("subcomponent %q: want status %q, got %q", purl, want, got)
		}
	}

	// The imported-but-not-called subcomponent carries the not executed
	// justification rather than the not present one.
	for _, s := range doc.Statements {
		if s.Status == StatusNotAffected {
			if s.Justification != JustificationNotExecuted {
				t.Errorf("want justification %q, got %q",
					JustificationNotExecuted, s.Justification)
			}
		}
	}
}

// TestSingleModuleVEXUnchanged verifies that the common case of a single
// subcomponent per vulnerability keeps producing a single statement per OSV.
func TestSingleModuleVEXUnchanged(t *testing.T) {
	const osvID = "GO-2024-0002"
	osvs := []*osv.Entry{{ID: osvID, Summary: "test vuln"}}

	doc := flushDocument(t, govulncheck.ScanLevelSymbol, osvs,
		moduleFinding(osvID, "example.com/mod1", "v1.0.0"),
		packageFinding(osvID, "example.com/mod1", "v1.0.0", "example.com/mod1/p"),
		callFinding(osvID, "example.com/mod1", "v1.0.0", "example.com/mod1/p", "Vuln"),
	)

	if len(doc.Statements) != 1 {
		t.Fatalf("want 1 statement for a single module, got %d: %+v",
			len(doc.Statements), doc.Statements)
	}
	s := doc.Statements[0]
	want := []string{"pkg:golang/example.com%2Fmod1@v1.0.0"}
	if got := subcomponentIDs(s); !slices.Equal(got, want) {
		t.Errorf("want subcomponents %v, got %v", want, got)
	}
	if s.Status != StatusAffected {
		t.Errorf("want status %q, got %q", StatusAffected, s.Status)
	}
}

// TestMultiSubcomponentSameStatus groups multiple subcomponents at the same
// level into one statement and checks deterministic statement ordering across
// vulnerabilities.
func TestMultiSubcomponentSameStatus(t *testing.T) {
	osvs := []*osv.Entry{
		{ID: "GO-2024-0002", Summary: "second"},
		{ID: "GO-2024-0001", Summary: "first"},
	}

	doc := flushDocument(t, govulncheck.ScanLevelModule, osvs,
		moduleFinding("GO-2024-0002", "z.example/mod", "v1.0.0"),
		moduleFinding("GO-2024-0002", "a.example/mod", "v1.0.0"),
		moduleFinding("GO-2024-0001", "m.example/mod", "v1.0.0"),
	)

	if len(doc.Statements) != 2 {
		t.Fatalf("want 2 statements, got %d", len(doc.Statements))
	}
	if doc.Statements[0].Vulnerability.Name != "GO-2024-0001" ||
		doc.Statements[1].Vulnerability.Name != "GO-2024-0002" {
		t.Errorf("statements not sorted by vulnerability: %+v", doc.Statements)
	}

	got := subcomponentIDs(doc.Statements[1])
	want := []string{
		"pkg:golang/a.example%2Fmod@v1.0.0",
		"pkg:golang/z.example%2Fmod@v1.0.0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("want sorted subcomponents %v, got %v", want, got)
	}
	for _, s := range doc.Statements {
		if s.Status != StatusAffected {
			t.Errorf("module-level findings must be affected, got %q", s.Status)
		}
	}
}

// Copied from internal/sarif
func TestMoreSpecific(t *testing.T) {
	frame := func(m, p, f string) *govulncheck.Frame {
		return &govulncheck.Frame{
			Module:   m,
			Package:  p,
			Function: f,
		}
	}

	for _, tc := range []struct {
		name   string
		want   int
		trace1 []*govulncheck.Frame
		trace2 []*govulncheck.Frame
	}{
		{"sym-vs-sym", 0,
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m1", "p1", "f2")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v2"), frame("m1", "p1", "f1"), frame("m2", "p2", "f2")},
		},
		{"sym-vs-pkg", -1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m1", "p1", "f2")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
		},
		{"pkg-vs-sym", 1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m2", "p2", "v2")},
		},
		{"pkg-vs-mod", -1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
			[]*govulncheck.Frame{
				frame("m1", "", "")},
		},
		{"mod-vs-pkg", 1,
			[]*govulncheck.Frame{
				frame("m1", "", "")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
		},
		{"mod-vs-sym", 1,
			[]*govulncheck.Frame{
				frame("m1", "", "")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v2"), frame("m1", "p1", "f1")},
		},
		{"mod-vs-mod", 0,
			[]*govulncheck.Frame{
				frame("m1", "", "")},
			[]*govulncheck.Frame{
				frame("m2", "", "")},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f1 := &govulncheck.Finding{Trace: tc.trace1}
			f2 := &govulncheck.Finding{Trace: tc.trace2}
			if got := moreSpecific(f1, f2); got != tc.want {
				t.Errorf("want %d; got %d", tc.want, got)
			}
		})
	}
}
