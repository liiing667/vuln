// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openvex

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

func testFinding() *govulncheck.Finding {
	return &govulncheck.Finding{
		OSV: "GO-2021-0001",
		Trace: []*govulncheck.Frame{
			{Module: "golang.org/vmod", Version: "v0.0.1"},
		},
	}
}

// TestFlushSuccessWritesOutput ensures a complete, successful scan still
// produces the VEX document and a nil error.
func TestFlushSuccessWritesOutput(t *testing.T) {
	var out bytes.Buffer
	h := NewHandler(&out)
	if err := h.Config(&govulncheck.Config{ScannerName: "govulncheck"}); err != nil {
		t.Fatal(err)
	}
	if err := h.OSV(&osv.Entry{ID: "GO-2021-0001"}); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(testFinding()); err != nil {
		t.Fatal(err)
	}
	if err := h.Flush(); err != nil {
		t.Fatalf("Flush returned unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "GO-2021-0001") {
		t.Errorf("Flush output is missing the finding:\n%s", out.String())
	}
}

// TestBindErrorFlushReset verifies a stream failure is bound to the partial
// output, reported by Flush, and cleared by Reset so the next scan is empty.
func TestBindErrorFlushReset(t *testing.T) {
	var out bytes.Buffer
	h := NewHandler(&out)
	if err := h.Config(&govulncheck.Config{ScannerName: "govulncheck"}); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(testFinding()); err != nil {
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
	// After reset, the buffered state from the failed scan is empty.
	if len(h.findings) != 0 || len(h.osvs) != 0 || h.cfg != nil || h.err != nil {
		t.Errorf("Reset did not clear handler state: %+v", h)
	}

	// A new scan after Reset accumulates only its own findings.
	if err := h.Config(&govulncheck.Config{ScannerName: "govulncheck"}); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(testFinding()); err != nil {
		t.Fatal(err)
	}
	if len(h.findings) != 1 || len(h.findings["GO-2021-0001"]) != 1 {
		t.Errorf("rescan did not start from an empty findings state: %+v", h.findings)
	}
}

// TestFlushWriteErrorBound verifies a failing writer binds the write error
// instead of Flush silently succeeding.
func TestFlushWriteErrorBound(t *testing.T) {
	h := NewHandler(errWriter{err: io.ErrClosedPipe})
	if err := h.Config(&govulncheck.Config{ScannerName: "govulncheck"}); err != nil {
		t.Fatal(err)
	}
	if err := h.Finding(testFinding()); err != nil {
		t.Fatal(err)
	}
	if err := h.Flush(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Flush = %v, want %v", err, io.ErrClosedPipe)
	}
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }
