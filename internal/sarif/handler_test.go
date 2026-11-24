// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

func scanLevel(f *govulncheck.Finding) string {
	fr := f.Trace[0]
	if fr.Function != "" {
		return "symbol"
	}
	if fr.Package != "" {
		return "package"
	}
	return "module"
}

func newTestHandler() *handler {
	h := NewHandler(nil)
	h.cfg = &govulncheck.Config{}
	return h
}

func TestHandlerSymbol(t *testing.T) {
	fs := `
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2020-0015",
    "trace": [
      {
        "module": "golang.org/x/text"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson",
        "function": "Get",
        "receiver": "Result"
      },
      {
        "module": "golang.org/vuln",
        "package": "golang.org/vuln",
        "function": "main"
      }
    ]
  }
}`

	h := newTestHandler()
	if err := govulncheck.HandleJSON(strings.NewReader(fs), h); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"GO-2021-0265": "symbol",
		"GO-2021-0054": "package",
		"GO-2020-0015": "module",
	}
	got := make(map[string]string)
	for osv, fs := range h.findings {
		got[osv] = scanLevel(fs[0])
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want;got+): %s", diff)
	}
}

func TestHandlerPackage(t *testing.T) {
	fs := `
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2020-0015",
    "trace": [
      {
        "module": "golang.org/x/text"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}`

	h := newTestHandler()
	if err := govulncheck.HandleJSON(strings.NewReader(fs), h); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"GO-2021-0265": "package",
		"GO-2021-0054": "package",
		"GO-2020-0015": "module",
	}
	got := make(map[string]string)
	for osv, fs := range h.findings {
		got[osv] = scanLevel(fs[0])
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want;got+): %s", diff)
	}
}

func TestHandlerModule(t *testing.T) {
	fs := `
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2020-0015",
    "trace": [
      {
        "module": "golang.org/x/text"
      }
    ]
  }
}`

	h := newTestHandler()
	if err := govulncheck.HandleJSON(strings.NewReader(fs), h); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"GO-2021-0265": "module",
		"GO-2021-0054": "module",
		"GO-2020-0015": "module",
	}
	got := make(map[string]string)
	for osv, fs := range h.findings {
		got[osv] = scanLevel(fs[0])
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want;got+): %s", diff)
	}
}

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

func TestResultMessage(t *testing.T) {
	config := func(l govulncheck.ScanLevel) *govulncheck.Config {
		return &govulncheck.Config{ScanLevel: l}
	}

	finding := func(m, p, f string) *govulncheck.Finding {
		return &govulncheck.Finding{
			Trace: []*govulncheck.Frame{
				{Module: m, Package: p, Function: f},
			},
		}
	}

	for _, tc := range []struct {
		findings []*govulncheck.Finding
		level    govulncheck.ScanLevel
		want     string
	}{
		{[]*govulncheck.Finding{finding("m", "p", "f1"), finding("m", "p", "f2")}, govulncheck.ScanLevelSymbol,
			"Your code calls vulnerable functions in 1 package (p)."},
		{[]*govulncheck.Finding{finding("m", "p", "")}, govulncheck.ScanLevelPackage,
			"Your code imports 1 vulnerable package (p). Run the call-level analysis to understand whether your code actually calls the vulnerabilities."},
		{[]*govulncheck.Finding{finding("m", "p1", ""), finding("m", "p2", ""), finding("m", "p3", "")}, govulncheck.ScanLevelSymbol,
			"Your code imports 3 vulnerable packages (p1, p2, and p3), but doesn’t appear to call any of the vulnerable symbols."},
		{[]*govulncheck.Finding{finding("m1", "", ""), finding("m2", "", "")}, govulncheck.ScanLevelModule,
			"Your code depends on 2 vulnerable modules (m1 and m2). Run the call-level analysis to understand whether your code actually calls the vulnerabilities."},
		{[]*govulncheck.Finding{finding("m1", "", ""), finding("m2", "", "")}, govulncheck.ScanLevelPackage,
			"Your code depends on 2 vulnerable modules (m1 and m2), but doesn't appear to import any of the vulnerable symbols."},
		{[]*govulncheck.Finding{finding("m1", "", ""), finding("m2", "", "")}, govulncheck.ScanLevelSymbol,
			"Your code depends on 2 vulnerable modules (m1 and m2), but doesn't appear to call any of the vulnerable symbols."},
	} {
		got := resultMessage(tc.findings, config(tc.level))
		if tc.want != got {
			t.Errorf("want %s; got %s", tc.want, got)
		}
	}
}

func testEntry(id string) *osv.Entry {
	return &osv.Entry{
		ID:      id,
		Summary: "summary of " + id,
		Details: "details of " + id,
	}
}

func moduleFinding(id, module string) *govulncheck.Finding {
	return &govulncheck.Finding{
		OSV: id,
		Trace: []*govulncheck.Frame{
			{Module: module},
		},
	}
}

// TestFlushMissingOSV ensures that a finding whose OSV entry was never
// emitted prevents Flush from producing a document: without the entry there
// is no rule backing the result, and the old code panicked on a nil entry.
func TestFlushMissingOSV(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf)
	if err := h.Config(&govulncheck.Config{ScanMode: govulncheck.ScanModeSource}); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(moduleFinding("GO-2021-0054", "example.com/m")); err != nil {
		t.Fatal(err)
	}

	if err := h.Flush(); err == nil {
		t.Fatal("Flush succeeded without an OSV entry for the finding")
	}
	if buf.Len() != 0 {
		t.Fatalf("Flush wrote a partial document (%d bytes) after failing", buf.Len())
	}
}

// TestFlushClosedIdentities verifies the happy path: one rule and one result
// per OSV, with a go.mod location in source mode, yields a complete document.
func TestFlushClosedIdentities(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf)
	if err := h.Config(&govulncheck.Config{ScanMode: govulncheck.ScanModeSource}); err != nil {
		t.Fatal(err)
	}
	const id = "GO-2021-0054"
	if err := h.OSV(testEntry(id)); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(moduleFinding(id, "example.com/m")); err != nil {
		t.Fatal(err)
	}

	if err := h.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	var log Log
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF json: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != id {
		t.Fatalf("rules do not match the single OSV: %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 1 || run.Results[0].RuleID != id {
		t.Fatalf("results do not match the single OSV: %+v", run.Results)
	}
	locs := run.Results[0].Locations
	if len(locs) != 1 || locs[0].PhysicalLocation.ArtifactLocation.URI != "go.mod" {
		t.Fatalf("source result must be attached to go.mod: %+v", locs)
	}
}

// TestFlushBinaryMode ensures binary findings, which carry no positions,
// flush successfully and produce results without physical locations.
func TestFlushBinaryMode(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf)
	if err := h.Config(&govulncheck.Config{ScanMode: govulncheck.ScanModeBinary}); err != nil {
		t.Fatal(err)
	}
	const id = "GO-2021-0054"
	if err := h.OSV(testEntry(id)); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(&govulncheck.Finding{
		OSV: id,
		Trace: []*govulncheck.Frame{
			{Module: "example.com/m", Version: "v1.0.0", Package: "example.com/m/p", Function: "Vuln"},
			{Module: "example.com/main", Package: "example.com/main", Function: "main"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := h.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	var log Log
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF json: %v", err)
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 || len(run.Results) != 1 {
		t.Fatalf("want 1 rule and 1 result, got %d rules, %d results",
			len(run.Tool.Driver.Rules), len(run.Results))
	}
	if got := run.Results[0].RuleID; got != id {
		t.Fatalf("result ruleId = %q, want %q", got, id)
	}
	if len(run.Results[0].Locations) != 0 {
		t.Fatalf("binary result must not carry locations, got %+v", run.Results[0].Locations)
	}
	for _, st := range run.Results[0].Stacks {
		for _, fr := range st.Frames {
			if fr.Location.PhysicalLocation.ArtifactLocation.URI != "" {
				t.Fatalf("binary stack frame must not reference a source file: %+v", fr)
			}
		}
	}
}

// TestFlushBinaryFindingWithPosition rejects a binary finding that
// unexpectedly carries source position information.
func TestFlushBinaryFindingWithPosition(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf)
	if err := h.Config(&govulncheck.Config{ScanMode: govulncheck.ScanModeBinary}); err != nil {
		t.Fatal(err)
	}
	const id = "GO-2021-0054"
	if err := h.OSV(testEntry(id)); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(&govulncheck.Finding{
		OSV: id,
		Trace: []*govulncheck.Frame{{
			Module:   "example.com/m",
			Position: &govulncheck.Position{Filename: "vuln.go", Line: 10},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	if err := h.Flush(); err == nil {
		t.Fatal("Flush succeeded for a binary finding with a source position")
	}
	if buf.Len() != 0 {
		t.Fatalf("Flush wrote a partial document (%d bytes) after failing", buf.Len())
	}
}

// TestFlushMissingConfig ensures Flush without a Config message fails
// instead of dereferencing a nil config while building the document.
func TestFlushMissingConfig(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf)
	if err := h.OSV(testEntry("GO-2021-0054")); err != nil {
		t.Fatal(err)
	}
	if err := h.Flush(); err == nil {
		t.Fatal("Flush succeeded without a config message")
	}
	if buf.Len() != 0 {
		t.Fatalf("Flush wrote a partial document (%d bytes) after failing", buf.Len())
	}
}

// TestFindingSpecificityOrdering exercises the moreSpecific comparison when
// the less specific module finding arrives after a package finding. The
// package-level finding must be retained rather than replaced.
func TestFindingSpecificityOrdering(t *testing.T) {
	const id = "GO-2021-0054"
	h := newTestHandler()
	h.cfg.ScanMode = govulncheck.ScanModeSource

	pkg := &govulncheck.Finding{OSV: id, Trace: []*govulncheck.Frame{
		{Module: "example.com/m", Package: "example.com/m/p"},
	}}
	mod := moduleFinding(id, "example.com/m")

	if err := h.Finding(pkg); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(mod); err != nil {
		t.Fatal(err)
	}

	got := h.findings[id]
	if len(got) != 1 || got[0].Trace[0].Package == "" {
		t.Fatalf("package-level finding was replaced by the module-level finding: %+v", got)
	}
}
