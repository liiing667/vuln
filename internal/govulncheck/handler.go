// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/vuln/internal/osv"
)

// Handler handles messages to be presented in a vulnerability scan output
// stream.
type Handler interface {
	// Config communicates introductory message to the user.
	Config(config *Config) error

	// SBOM shows information about what govulncheck is scanning.
	SBOM(sbom *SBOM) error

	// Progress is called to display a progress message.
	Progress(progress *Progress) error

	// OSV is invoked for each osv Entry in the stream.
	OSV(entry *osv.Entry) error

	// Finding is called for each vulnerability finding in the stream.
	Finding(finding *Finding) error
}

// resettableHandler is implemented by handlers that buffer scan output.
// Flush reports a failure bound to partial output, BindError attaches a
// stream-level failure to that partial output, and Reset discards the
// buffered state (including any bound failure) so a new scan starts empty.
type resettableHandler interface {
	Flush() error
	BindError(error)
	Reset()
}

// HandleJSON reads the json from the supplied stream and hands the decoded
// output to the handler.
//
// If the stream cannot be decoded, or a handler method fails, the partial
// output produced so far and the failure are bound to the same handler
// state and the joined error is returned. The handler is then reset so a
// subsequent scan starts from an empty state.
// A fully consumed, successful stream leaves the handler's accumulated
// output untouched.
func HandleJSON(from io.Reader, to Handler) error {
	var err error
	defer func() {
		if err == nil {
			return
		}
		// Bind the failure to the partial output already emitted by the
		// handler, then start the next scan from an empty state.
		if rh, ok := to.(resettableHandler); ok {
			rh.BindError(err)
			err = errors.Join(err, rh.Flush())
			rh.Reset()
		}
	}()
	dec := json.NewDecoder(from)
	for dec.More() {
		msg := Message{}
		// decode the next message in the stream
		if err = dec.Decode(&msg); err != nil {
			return err
		}
		// dispatch the message
		if msg.Config != nil {
			err = to.Config(msg.Config)
		}
		if msg.Progress != nil {
			err = to.Progress(msg.Progress)
		}
		if msg.SBOM != nil {
			err = to.SBOM(msg.SBOM)
		}
		if msg.OSV != nil {
			err = to.OSV(msg.OSV)
		}
		if msg.Finding != nil {
			err = to.Finding(msg.Finding)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
