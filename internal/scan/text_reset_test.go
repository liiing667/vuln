// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
)

// errWriter fails every write.
type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

func textTestFinding() *govulncheck.Finding {
	return &govulncheck.Finding{
		OSV: "GO-0000-0001",
		Trace: []*govulncheck.Frame{
			{Module: "golang.org/vmod", Version: "v0.0.1"},
		},
	}
}

// TestTextFlushSuccess verifies a complete successful scan still renders the
// text summary and reports vulnerabilities via the exit code error.
func TestTextFlushSuccess(t *testing.T) {
	var out bytes.Buffer
	h := NewTextHandler(&out)
	if err := h.Config(&govulncheck.Config{ScanLevel: govulncheck.ScanLevelModule}); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(textTestFinding()); err != nil {
		t.Fatal(err)
	}
	if err := h.Flush(); !errors.Is(err, errVulnerabilitiesFound) {
		t.Fatalf("Flush = %v, want %v", err, errVulnerabilitiesFound)
	}
	if !strings.Contains(out.String(), "GO-0000-0001") {
		t.Errorf("successful text output is missing the finding:\n%s", out.String())
	}
}

// TestTextBindErrorFlushReset verifies a stream failure is bound to the
// partial output, surfaced by Flush (so CI cannot see a zero exit), and
// cleared by Reset so the next scan starts from an empty state.
func TestTextBindErrorFlushReset(t *testing.T) {
	var out bytes.Buffer
	h := NewTextHandler(&out)
	if err := h.Config(&govulncheck.Config{ScanLevel: govulncheck.ScanLevelModule}); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(textTestFinding()); err != nil {
		t.Fatal(err)
	}

	streamErr := errors.New("stream interrupted")
	h.BindError(streamErr)
	if err := h.Flush(); !errors.Is(err, streamErr) {
		t.Fatalf("Flush = %v, want bound error %v", err, streamErr)
	}
	// The bound error must be sticky until Reset.
	if err := h.Flush(); !errors.Is(err, streamErr) {
		t.Fatalf("second Flush = %v, want %v", err, streamErr)
	}

	h.Reset()
	if h.err != nil || len(h.findings) != 0 || len(h.osvs) != 0 || h.sbom != nil ||
		h.scanLevel != "" || h.scanMode != "" {
		t.Errorf("Reset did not clear handler state: %+v", h)
	}
	// After reset, an empty scan flushes cleanly and prints the no-vulns
	// message rather than the previous finding.
	out.Reset()
	if err := h.Flush(); err != nil {
		t.Fatalf("Flush after Reset = %v, want nil", err)
	}
	if strings.Contains(out.String(), "GO-0000-0001") {
		t.Errorf("partial finding survived Reset:\n%s", out.String())
	}
	if !strings.Contains(out.String(), noVulnsMessage) {
		t.Errorf("empty rescan did not print %q:\n%s", noVulnsMessage, out.String())
	}

	// A new scan after Reset accumulates exactly its own finding.
	if err := h.Config(&govulncheck.Config{ScanLevel: govulncheck.ScanLevelModule}); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(textTestFinding()); err != nil {
		t.Fatal(err)
	}
	if len(h.findings) != 1 {
		t.Fatalf("rescan findings = %d, want 1", len(h.findings))
	}
}

// TestTextWriteErrorBound verifies a failing writer binds its write error so
// Flush reports failure instead of silently succeeding.
func TestTextWriteErrorBound(t *testing.T) {
	h := NewTextHandler(errWriter{err: io.ErrClosedPipe})
	h.showVerbose = true
	if err := h.Config(&govulncheck.Config{
		ScanLevel:   govulncheck.ScanLevelModule,
		ScannerName: "govulncheck",
	}); err != nil {
		t.Fatal(err)
	}
	// Config may not write anything unless version is shown, so force a write.
	if err := h.Progress(&govulncheck.Progress{Message: "scanning"}); err == nil {
		t.Fatal("Progress on a broken writer returned nil")
	}
	if err := h.Flush(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Flush = %v, want %v", err, io.ErrClosedPipe)
	}
}
