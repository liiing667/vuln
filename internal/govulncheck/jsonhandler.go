// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"encoding/json"

	"io"

	"golang.org/x/vuln/internal/osv"
)

type jsonHandler struct {
	enc *json.Encoder
	// err records the first write error observed while streaming
	// messages. Once a write fails, the output stream is partial and
	// every subsequent write is a no-op so the same failure is
	// reported exactly once, by Flush.
	err error
}

// NewJSONHandler returns a handler that writes govulncheck output as json.
func NewJSONHandler(w io.Writer) Handler {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return &jsonHandler{enc: enc}
}

// jsonHandler participates in HandleJSON's failure binding: a stream
// failure is bound to the partial JSON output via BindError, reported by
// Flush, and discarded by Reset so the next scan starts empty.
var _ resettableHandler = (*jsonHandler)(nil)

// write encodes msg to the underlying writer. The first write failure
// is bound to the handler state and retained until Flush; later writes
// are skipped so the recorded failure is not overwritten.
func (h *jsonHandler) write(msg Message) error {
	if h.err != nil {
		return h.err
	}
	if err := h.enc.Encode(msg); err != nil {
		h.err = err
		return err
	}
	return nil
}

// Config writes config block in JSON to the underlying writer.
func (h *jsonHandler) Config(config *Config) error {
	return h.write(Message{Config: config})
}

// Progress writes a progress message in JSON to the underlying writer.
func (h *jsonHandler) Progress(progress *Progress) error {
	return h.write(Message{Progress: progress})
}

// SBOM writes the SBOM block in JSON to the underlying writer.
func (h *jsonHandler) SBOM(sbom *SBOM) error {
	return h.write(Message{SBOM: sbom})
}

// OSV writes an osv entry in JSON to the underlying writer.
func (h *jsonHandler) OSV(entry *osv.Entry) error {
	return h.write(Message{OSV: entry})
}

// Finding writes a finding in JSON to the underlying writer.
func (h *jsonHandler) Finding(finding *Finding) error {
	return h.write(Message{Finding: finding})
}

// Flush reports any failure that occurred while streaming messages.
// A non-nil error means the emitted JSON is partial, i.e. the scan did
// not complete successfully. On success it returns nil and leaves the
// complete, valid output untouched.
func (h *jsonHandler) Flush() error {
	return h.err
}

// BindError attaches a stream-level failure (for instance a JSON decode
// error or a handler method failure) to the partial output emitted so far,
// so the failure is reported by Flush instead of a misleading success.
// The first bound failure is retained.
func (h *jsonHandler) BindError(err error) {
	if h.err == nil && err != nil {
		h.err = err
	}
}

// Reset clears every message accumulated for the current scan,
// including a bound failure, so the next scan starts from an empty
// state and cannot mix findings with a previous partial output.
func (h *jsonHandler) Reset() {
	h.err = nil
}
