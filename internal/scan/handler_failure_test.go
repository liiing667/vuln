// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
)

// partialStream is a valid prefix followed by malformed JSON, mirroring a
// govulncheck stream that breaks halfway through a scan.
const partialStream = `
{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scan_level":"module"}}
{"finding":{"osv":"GO-0000-0001","trace":[{"module":"golang.org/vmod","version":"v0.0.1"}]}}
{broken json
`

const cleanStream = `
{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scan_level":"module"}}
{"finding":{"osv":"GO-0000-0002","trace":[{"module":"golang.org/other","version":"v0.2.0"}]}}
`

// TestHandleJSONFailureIsFatalAndResetsText drives the text handler through
// the same HandleJSON + Flush sequence used by convert mode:
//   - a broken stream must return an error rather than look like a finished
//     zero-exit scan, and must reset the handler;
//   - the following scan must start from an empty state.
func TestHandleJSONFailureIsFatalAndResetsText(t *testing.T) {
	var out bytes.Buffer
	h := NewTextHandler(&out)

	if err := govulncheck.HandleJSON(strings.NewReader(partialStream), h); err == nil {
		t.Fatal("HandleJSON returned nil for a broken stream")
	}
	// HandleJSON must have reset the partial state.
	if len(h.findings) != 0 || h.err != nil {
		t.Errorf("handler was not reset after the failed stream: %+v", h)
	}

	// The next scan starts from an empty state: it must only contain its own
	// finding and none from the failed stream.
	if err := govulncheck.HandleJSON(strings.NewReader(cleanStream), h); err != nil {
		t.Fatalf("second HandleJSON failed: %v", err)
	}
	if err := Flush(h); err == nil {
		// module-level findings produce the vulnerabilities-found exit code
		t.Fatal("Flush returned nil for a scan containing a finding")
	}
	got := out.String()
	if strings.Contains(got, "GO-0000-0001") {
		t.Errorf("partial finding from the failed scan survived:\n%s", got)
	}
	if strings.Count(got, "GO-0000-0002") != 1 {
		t.Errorf("rescan output does not contain exactly the new finding:\n%s", got)
	}
}

// TestHandleJSONFailureIsFatalAndResetsJSON exercises the same flow for the
// JSON handler, whose writes are streamed straight to the output.
func TestHandleJSONFailureIsFatalAndResetsJSON(t *testing.T) {
	var out bytes.Buffer
	h := govulncheck.NewJSONHandler(&out)

	if err := govulncheck.HandleJSON(strings.NewReader(partialStream), h); err == nil {
		t.Fatal("HandleJSON returned nil for a broken stream")
	}

	// A following clean scan must produce only its own messages, with no
	// duplicated finding from the partial stream.
	out.Reset()
	if err := govulncheck.HandleJSON(strings.NewReader(cleanStream), h); err != nil {
		t.Fatalf("second HandleJSON failed: %v", err)
	}
	if err := Flush(h); err != nil {
		t.Fatalf("Flush after a clean rescan = %v", err)
	}
	got := out.String()
	if strings.Contains(got, "GO-0000-0001") {
		t.Errorf("partial finding from the failed scan survived:\n%s", got)
	}
	if strings.Count(got, "GO-0000-0002") != 1 {
		t.Errorf("rescan output does not contain exactly the new finding:\n%s", got)
	}
}
