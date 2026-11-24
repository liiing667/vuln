// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openvex

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

type findingLevel int

const (
	invalid findingLevel = iota
	required
	imported
	called
)

type handler struct {
	w    io.Writer
	cfg  *govulncheck.Config
	sbom *govulncheck.SBOM
	osvs map[string]*osv.Entry
	// findings contains, per OSV, the most precise finding
	// available for each affected subcomponent (identified by
	// its PURL). A more precise finding for one subcomponent
	// therefore never erases findings for the other
	// subcomponents of the same OSV. For instance, if an osv
	// is called in one module but only required through
	// another, both modules are retained.
	findings map[string][]*govulncheck.Finding
}

func NewHandler(w io.Writer) *handler {
	return &handler{
		w:        w,
		osvs:     make(map[string]*osv.Entry),
		findings: make(map[string][]*govulncheck.Finding),
	}
}

func (h *handler) Config(cfg *govulncheck.Config) error {
	h.cfg = cfg
	return nil
}

func (h *handler) Progress(progress *govulncheck.Progress) error {
	return nil
}

func (h *handler) SBOM(s *govulncheck.SBOM) error {
	h.sbom = s
	return nil
}

func (h *handler) OSV(e *osv.Entry) error {
	h.osvs[e.ID] = e
	return nil
}

// foundAtLevel returns the level at which a specific finding is present in the
// scanned product.
func foundAtLevel(f *govulncheck.Finding) findingLevel {
	frame := f.Trace[0]
	if frame.Function != "" {
		return called
	}
	if frame.Package != "" {
		return imported
	}
	return required
}

// moreSpecific favors a call finding over a non-call
// finding and a package finding over a module finding.
func moreSpecific(f1, f2 *govulncheck.Finding) int {
	if len(f1.Trace) > 1 && len(f2.Trace) > 1 {
		// Both are call stack findings.
		return 0
	}
	if len(f1.Trace) > 1 {
		return -1
	}
	if len(f2.Trace) > 1 {
		return 1
	}

	fr1, fr2 := f1.Trace[0], f2.Trace[0]
	if fr1.Function != "" && fr2.Function == "" {
		return -1
	}
	if fr1.Function == "" && fr2.Function != "" {
		return 1
	}
	if fr1.Package != "" && fr2.Package == "" {
		return -1
	}
	if fr1.Package == "" && fr2.Package != "" {
		return 1
	}
	return 0 // findings always have module info
}

func (h *handler) Finding(f *govulncheck.Finding) error {
	purl := purlFromFinding(f)
	fs := h.findings[f.OSV]
	for i, existing := range fs {
		if purlFromFinding(existing) != purl {
			continue
		}

		// The finding belongs to a subcomponent we already know
		// about, so only the most precise finding for that
		// subcomponent is kept. Findings for other subcomponents
		// are left untouched.
		switch moreSpecific(f, existing) {
		case -1:
			// The new finding is more specific, so it replaces
			// the less precise finding for this subcomponent.
			fs[i] = f
		case 0:
			// The new finding is at the same level of precision.
			fs = append(fs, f)
		}
		h.findings[f.OSV] = fs
		return nil
	}

	// This is the first finding for the subcomponent.
	fs = append(fs, f)
	h.findings[f.OSV] = fs
	return nil
}

// Flush is used to print the vex json to w.
// This is needed as vex is not streamed.
func (h *handler) Flush() error {
	doc := toVex(h)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	_, err = h.w.Write(out)
	return err
}

func toVex(h *handler) Document {
	doc := Document{
		Context:    ContextURI,
		Author:     DefaultAuthor,
		Timestamp:  time.Now().UTC(),
		Version:    1,
		Tooling:    Tooling,
		Statements: statements(h),
	}

	id := hashVex(doc)
	doc.ID = "govulncheck/vex:" + id
	return doc
}

// Given a slice of findings, returns those findings as a set of subcomponents
// that are unique per the vulnerable artifact's PURL. The subcomponents are
// sorted by PURL so that the generated VEX document is deterministic and
// independent of the order in which findings were emitted.
func subcomponentSet(findings []*govulncheck.Finding) []Component {
	var scs []Component
	seen := make(map[string]bool)
	for _, f := range findings {
		purl := purlFromFinding(f)
		if !seen[purl] {
			scs = append(scs, Component{ID: purl})
			seen[purl] = true
		}
	}
	slices.SortFunc(scs, func(a, b Component) int {
		return strings.Compare(a.ID, b.ID)
	})
	return scs
}

// statements combines all OSVs found by govulncheck and generates the list of
// vex statements with the proper affected level and justification to match the
// openVEX specification.
func statements(h *handler) []Statement {
	var scanLevel findingLevel
	switch h.cfg.ScanLevel {
	case govulncheck.ScanLevelModule:
		scanLevel = required
	case govulncheck.ScanLevelPackage:
		scanLevel = imported
	case govulncheck.ScanLevelSymbol:
		scanLevel = called
	}

	var statements []Statement
	for id, osv := range h.osvs {
		// if there are no findings emitted for a given OSV that means that
		// the vulnerable module is not required at a vulnerable version.
		if len(h.findings[id]) == 0 {
			continue
		}

		// Group findings by the level at which they are present in the
		// scanned product. Findings for the same OSV can come from
		// different subcomponents at different levels (e.g. the vulnerable
		// code is called in one module but only imported through another),
		// and each level maps to a different VEX status. Every statement
		// therefore covers subcomponents sharing the same status.
		findingsByLevel := make(map[findingLevel][]*govulncheck.Finding)
		for _, f := range h.findings[id] {
			level := foundAtLevel(f)
			findingsByLevel[level] = append(findingsByLevel[level], f)
		}
		var levels []findingLevel
		for level := range findingsByLevel {
			levels = append(levels, level)
		}
		slices.Sort(levels)

		for _, level := range levels {
			statements = append(statements,
				h.statement(id, osv, findingsByLevel[level], level, scanLevel))
		}
	}

	slices.SortFunc(statements, func(a, b Statement) int {
		if c := strings.Compare(a.Vulnerability.ID, b.Vulnerability.ID); c != 0 {
			return c
		}
		// Statements for the same OSV are ordered by the status
		// of their subcomponents.
		return strings.Compare(a.Status, b.Status)
	})
	return statements
}

// statement builds a single VEX statement for the given OSV from the findings
// of subcomponents that are all present at the same finding level. The status
// is derived from that level relative to the scan level, so every
// subcomponent listed in the statement shares an identical status.
func (h *handler) statement(id string, osv *osv.Entry, levelFindings []*govulncheck.Finding,
	level, scanLevel findingLevel) Statement {
	description := osv.Summary
	if description == "" {
		description = osv.Details
	}

	s := Statement{
		Vulnerability: Vulnerability{
			ID:          fmt.Sprintf("https://pkg.go.dev/vuln/%s", id),
			Name:        id,
			Description: description,
			Aliases:     osv.Aliases,
		},
		Products: []Product{
			{
				Component:     Component{ID: DefaultPID},
				Subcomponents: subcomponentSet(levelFindings),
			},
		},
	}

	if level >= scanLevel {
		s.Status = StatusAffected
	} else {
		s.Status = StatusNotAffected
		s.ImpactStatement = Impact
		s.Justification = JustificationNotPresent
		// We only reach this case if running in symbol mode
		if level == imported {
			s.Justification = JustificationNotExecuted
		}
	}
	return s
}

func hashVex(doc Document) string {
	// json.Marshal should never error here (because of the structure of Document).
	// If an error does occur, it won't be a jsonerror, but instead a panic
	d := Document{
		Context:    doc.Context,
		ID:         doc.ID,
		Author:     doc.Author,
		Version:    doc.Version,
		Tooling:    doc.Tooling,
		Statements: doc.Statements,
	}
	out, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(out))
}
