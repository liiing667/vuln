// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openvex

import (
	"bytes"
	"encoding/json"
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

// TestGoldenHashReplicatesCMDTest reproduces the single-module scenarios
// captured in cmd/govulncheck/testdata/.../*_vex.ct and asserts that the
// content-based document hash is unchanged.
func TestGoldenHashReplicatesCMDTest(t *testing.T) {
	entries := []*osv.Entry{
		{
			ID:      "GO-2020-0015",
			Summary: "Infinite loop when decoding some inputs in golang.org/x/text",
			Aliases: []string{"CVE-2020-14040", "GHSA-5rcv-m4m3-hfh7"},
		},
		{
			ID:      "GO-2021-0054",
			Summary: "Due to improper bounds checking, maliciously crafted JSON objects can cause an out-of-bounds panic. If parsing user input, this may be used as a denial of service vector.",
			Aliases: []string{"CVE-2020-36067", "GHSA-p64j-r5f4-pwwx"},
		},
		{
			ID:      "GO-2021-0113",
			Summary: "Due to improper index calculation, an incorrectly formatted language tag can cause Parse to panic via an out of bounds read. If Parse is used to process untrusted user inputs, this may be used as a vector for a denial of service attack.",
			Aliases: []string{"CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"},
		},
		{
			ID:      "GO-2021-0265",
			Summary: "A maliciously crafted path can cause Get and other query functions to consume excessive amounts of CPU and time.",
			Aliases: []string{
				"CVE-2021-42248", "CVE-2021-42836",
				"GHSA-c9gm-7rfj-8w5h", "GHSA-ppj4-34rq-v8j9",
			},
		},
	}

	textPurl := "pkg:golang/golang.org%2Fx%2Ftext@v0.3.0"
	gjsonPurl := "pkg:golang/github.com%2Ftidwall%2Fgjson@v1.6.5"

	findings := []*govulncheck.Finding{
		// GO-2020-0015: required only (module level finding).
		moduleFinding("GO-2020-0015", "golang.org/x/text", "v0.3.0"),
		// GO-2021-0113: imported but not called.
		packageFinding("GO-2021-0113", "golang.org/x/text", "v0.3.0", "golang.org/x/text/language"),
		// GO-2021-0054: called.
		callFinding("GO-2021-0054", "github.com/tidwall/gjson", "v1.6.5",
			"github.com/tidwall/gjson", "Get"),
		// GO-2021-0265: called.
		callFinding("GO-2021-0265", "github.com/tidwall/gjson", "v1.6.5",
			"github.com/tidwall/gjson", "Get"),
	}

	doc := flushDocument(t, govulncheck.ScanLevelSymbol, entries, findings...)

	const wantHash = "261b597336f7aa5eb53a4a196c354c5afed43fe55658ae3816194192b5268881"
	if doc.ID != "govulncheck/vex:"+wantHash {
		out, _ := json.MarshalIndent(doc, "", "  ")
		t.Fatalf("golden hash changed:\nwant: govulncheck/vex:%s\n got: %s\n%s",
			wantHash, doc.ID, out)
	}

	want := map[string]struct {
		status        string
		justification string
		purl          string
	}{
		"GO-2020-0015": {StatusNotAffected, JustificationNotPresent, textPurl},
		"GO-2021-0054": {StatusAffected, "", gjsonPurl},
		"GO-2021-0113": {StatusNotAffected, JustificationNotExecuted, textPurl},
		"GO-2021-0265": {StatusAffected, "", gjsonPurl},
	}
	if len(doc.Statements) != len(want) {
		t.Fatalf("want %d statements, got %d", len(want), len(doc.Statements))
	}
	for _, s := range doc.Statements {
		w, ok := want[s.Vulnerability.Name]
		if !ok {
			t.Fatalf("unexpected statement %q", s.Vulnerability.Name)
		}
		if s.Status != w.status || s.Justification != w.justification {
			t.Errorf("%s: want (%s,%s), got (%s,%s)", s.Vulnerability.Name,
				w.status, w.justification, s.Status, s.Justification)
		}
		ids := subcomponentIDs(s)
		if len(ids) != 1 || ids[0] != w.purl {
			t.Errorf("%s: want subcomponent %s, got %v", s.Vulnerability.Name, w.purl, ids)
		}
	}

	// Sanity check: Flush output is valid JSON with the same hash.
	var buf bytes.Buffer
	h := NewHandler(&buf)
	_ = h.Config(&govulncheck.Config{ScanLevel: govulncheck.ScanLevelSymbol})
	for _, e := range entries {
		_ = h.OSV(e)
	}
	for _, f := range findings {
		_ = h.Finding(f)
	}
	if err := h.Flush(); err != nil {
		t.Fatal(err)
	}
	var roundTrip Document
	if err := json.Unmarshal(buf.Bytes(), &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.ID != doc.ID {
		t.Fatalf("nondeterministic ID: %s vs %s", roundTrip.ID, doc.ID)
	}
}
