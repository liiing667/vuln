// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/vuln/internal/osv"
)

// errWriter fails every write after the first failAfter successful writes.
type errWriter struct {
	buf       bytes.Buffer
	failAfter int
	err       error
}

func (w *errWriter) Write(p []byte) (int, error) {
	if w.failAfter <= 0 {
		return 0, w.err
	}
	w.failAfter--
	return w.buf.Write(p)
}

// failingHandler returns an error from every handler method.
type failingHandler struct {
	calls int
}

var errHandlerFailed = errors.New("handler failed")

func (h *failingHandler) Config(*Config) error     { h.calls++; return errHandlerFailed }
func (h *failingHandler) SBOM(*SBOM) error         { h.calls++; return errHandlerFailed }
func (h *failingHandler) Progress(*Progress) error { h.calls++; return errHandlerFailed }
func (h *failingHandler) OSV(*osv.Entry) error     { h.calls++; return errHandlerFailed }
func (h *failingHandler) Finding(*Finding) error   { h.calls++; return errHandlerFailed }

const validStream = `
{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scan_level":"symbol"}}
{"finding":{"osv":"GO-0000-0001","trace":[{"module":"golang.org/vmod","version":"v0.0.1","package":"vmod","function":"Vuln"}]}}
`

// TestHandleJSONSuccessKeepsOutput ensures a fully consumed, valid stream
// produces the complete output and a nil error.
func TestHandleJSONSuccessKeepsOutput(t *testing.T) {
	var out bytes.Buffer
	h := NewJSONHandler(&out)
	if err := HandleJSON(strings.NewReader(validStream), h); err != nil {
		t.Fatalf("HandleJSON returned unexpected error: %v", err)
	}
	if err := h.(*jsonHandler).Flush(); err != nil {
		t.Fatalf("Flush returned unexpected error: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "GO-0000-0001") || !strings.Contains(got, "v1.0.0") {
		t.Errorf("successful output is missing messages:\n%s", got)
	}
}

// TestHandleJSONDecodeErrorResets verifies that a malformed stream does not
// look like a successful scan: HandleJSON returns the decode error, the
// handler is reset so a following scan starts empty, and the second scan's
// output contains no findings from the failed first stream.
func TestHandleJSONDecodeErrorResets(t *testing.T) {
	var out bytes.Buffer
	h := NewJSONHandler(&out).(*jsonHandler)

	bad := `
{"config":{"protocol_version":"v1.0.0"}}
{"finding":{"osv":"GO-0000-0001","trace":[{"module":"golang.org/vmod"}]}}
{not valid json
`
	err := HandleJSON(strings.NewReader(bad), h)
	if err == nil {
		t.Fatal("HandleJSON returned nil for a malformed stream")
	}
	// The returned error is what run.go's Flush path reports to CI, so a
	// malformed stream cannot look like a successful zero-exit scan.
	if !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("returned error %v does not look like the decode failure", err)
	}

	// The handler must have been reset to an empty state.
	if h.err != nil {
		t.Errorf("handler still holds bound failure after reset: %v", h.err)
	}
	if got := h.Flush(); got != nil {
		t.Errorf("Flush after reset = %v, want nil", got)
	}

	// The next scan starts from an empty state: its output must not contain
	// findings accumulated during the failed scan.
	out.Reset()
	if err := HandleJSON(strings.NewReader(validStream), h); err != nil {
		t.Fatalf("second HandleJSON failed: %v", err)
	}
	if err := h.Flush(); err != nil {
		t.Fatalf("Flush after successful rescan failed: %v", err)
	}
	got := out.String()
	if strings.Count(got, "GO-0000-0001") != 1 {
		t.Errorf("rescan output mixes partial findings from the failed stream:\n%s", got)
	}
}

// TestHandleJSONHandlerErrorResets verifies that a handler method failure is
// reported and the buffered partial state is discarded.
func TestHandleJSONHandlerErrorResets(t *testing.T) {
	failing := &failingHandler{}

	// Drive messages through the failing handler; it errors on the first
	// message, before any finding can be considered complete.
	err := HandleJSON(strings.NewReader(validStream), failing)
	if !errors.Is(err, errHandlerFailed) {
		t.Fatalf("HandleJSON error = %v, want %v", err, errHandlerFailed)
	}
	if failing.calls == 0 {
		t.Error("failing handler was never invoked")
	}

	// Sanity check the same failure path for the JSON handler: once a write
	// fails, Flush surfaces the bound error and Reset clears it.
	failWriter := &errWriter{failAfter: 0, err: io.ErrClosedPipe}
	jh := NewJSONHandler(failWriter).(*jsonHandler)
	if err := jh.Config(&Config{ProtocolVersion: ProtocolVersion}); err == nil {
		t.Error("Config on a broken writer returned nil")
	}
	if err := jh.Flush(); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("Flush = %v, want %v", err, io.ErrClosedPipe)
	}
	jh.Reset()
	if err := jh.Flush(); err != nil {
		t.Errorf("Flush after Reset = %v, want nil", err)
	}
}

// TestJSONHandlerWriteFailureBound verifies the JSON handler keeps returning
// the same bound write error instead of silently succeeding later.
func TestJSONHandlerWriteFailureBound(t *testing.T) {
	failWriter := &errWriter{failAfter: 1, err: io.ErrShortWrite}
	h := NewJSONHandler(failWriter).(*jsonHandler)

	// The first message writes successfully, the second fails.
	if err := h.Config(&Config{ProtocolVersion: ProtocolVersion}); err != nil {
		t.Fatalf("first write failed unexpectedly: %v", err)
	}
	if err := h.Finding(&Finding{OSV: "GO-0000-0001"}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Finding error = %v, want %v", err, io.ErrShortWrite)
	}
	// The bound error is sticky and must be reported by Flush.
	if err := h.Flush(); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Flush = %v, want %v", err, io.ErrShortWrite)
	}
	// A later successful-looking call must not overwrite or clear the error.
	if err := h.Finding(&Finding{OSV: "GO-0000-0002"}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("second Finding error = %v, want %v", err, io.ErrShortWrite)
	}
	h.Reset()
	if err := h.Flush(); err != nil {
		t.Fatalf("Flush after Reset = %v, want nil", err)
	}
}

// TestBindErrorFlushAndReset verifies a stream-level failure is bound to the
// handler's partial output, surfaced by Flush, and then cleared by Reset so
// the following scan starts empty.
func TestBindErrorFlushAndReset(t *testing.T) {
	h := NewJSONHandler(io.Discard).(*jsonHandler)
	streamErr := errors.New("boom")

	h.BindError(streamErr)
	if got := h.Flush(); !errors.Is(got, streamErr) {
		t.Fatalf("Flush after BindError = %v, want %v", got, streamErr)
	}
	// A later BindError must not overwrite the first bound failure.
	h.BindError(errors.New("second"))
	if got := h.Flush(); !errors.Is(got, streamErr) {
		t.Fatalf("Flush = %v, want first bound error %v", got, streamErr)
	}
	h.Reset()
	if got := h.Flush(); got != nil {
		t.Fatalf("Flush after Reset = %v, want nil", got)
	}

	// After reset, a fresh successful scan works and produces valid output.
	var out bytes.Buffer
	h2 := NewJSONHandler(&out).(*jsonHandler)
	h2.BindError(streamErr)
	h2.Reset()
	if err := HandleJSON(strings.NewReader(validStream), h2); err != nil {
		t.Fatalf("scan after reset failed: %v", err)
	}
	if err := h2.Flush(); err != nil {
		t.Fatalf("Flush after successful rescan = %v", err)
	}
	if strings.Count(out.String(), "GO-0000-0001") != 1 {
		t.Errorf("rescan output is not a single clean scan:\n%s", out.String())
	}
}
