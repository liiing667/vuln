// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/test"
)

func TestConsistentCallFinding(t *testing.T) {
	pkg := &packages.Package{
		PkgPath: "golang.org/bmod/bvuln",
		Module:  &packages.Module{Path: "golang.org/bmod", Version: "v0.5.0"},
	}
	sink := &FuncNode{
		Name:     "M",
		Package:  pkg,
		RecvType: "*golang.org/bmod/bvuln.Wrap[int]",
	}
	baseVuln := func() *Vuln {
		return &Vuln{
			OSV:      &osv.Entry{ID: "VM"},
			Symbol:   "Wrap.M",
			Package:  pkg,
			CallSink: sink,
		}
	}
	goodFrame := func() *govulncheck.Frame {
		return &govulncheck.Frame{
			Module:   "golang.org/bmod",
			Package:  "golang.org/bmod/bvuln",
			Receiver: sink.Receiver(),
			Function: "M",
		}
	}

	for _, tc := range []struct {
		name  string
		vuln  *Vuln
		trace []*govulncheck.Frame
		want  bool
	}{
		{
			name:  "consistent method",
			vuln:  baseVuln(),
			trace: []*govulncheck.Frame{goodFrame()},
			want:  true,
		},
		{
			name: "consistent function",
			vuln: func() *Vuln {
				v := baseVuln()
				v.Symbol = "Vuln"
				v.CallSink = &FuncNode{Name: "Vuln", Package: pkg}
				return v
			}(),
			trace: []*govulncheck.Frame{{
				Module:   "golang.org/bmod",
				Package:  "golang.org/bmod/bvuln",
				Function: "Vuln",
			}},
			want: true,
		},
		{
			name:  "nil package",
			vuln:  func() *Vuln { v := baseVuln(); v.Package = nil; return v }(),
			trace: []*govulncheck.Frame{goodFrame()},
			want:  false,
		},
		{
			name:  "nil call sink",
			vuln:  func() *Vuln { v := baseVuln(); v.CallSink = nil; return v }(),
			trace: []*govulncheck.Frame{goodFrame()},
			want:  false,
		},
		{
			name:  "empty trace",
			vuln:  baseVuln(),
			trace: nil,
			want:  false,
		},
		{
			name: "wrong module in sink frame",
			vuln: baseVuln(),
			trace: []*govulncheck.Frame{func() *govulncheck.Frame {
				fr := goodFrame()
				fr.Module = "golang.org/other"
				return fr
			}()},
			want: false,
		},
		{
			name: "wrong package in sink frame",
			vuln: baseVuln(),
			trace: []*govulncheck.Frame{func() *govulncheck.Frame {
				fr := goodFrame()
				fr.Package = "golang.org/entry/x"
				return fr
			}()},
			want: false,
		},
		{
			name: "wrong function in sink frame",
			vuln: baseVuln(),
			trace: []*govulncheck.Frame{func() *govulncheck.Frame {
				fr := goodFrame()
				fr.Function = "Other"
				return fr
			}()},
			want: false,
		},
		{
			name: "wrong receiver in sink frame",
			vuln: baseVuln(),
			trace: []*govulncheck.Frame{func() *govulncheck.Frame {
				fr := goodFrame()
				fr.Receiver = "Other"
				return fr
			}()},
			want: false,
		},
		{
			name: "receiver missing in sink frame",
			vuln: baseVuln(),
			trace: []*govulncheck.Frame{func() *govulncheck.Frame {
				fr := goodFrame()
				fr.Receiver = ""
				return fr
			}()},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := consistentCallFinding(tc.vuln, tc.trace); got != tc.want {
				t.Errorf("consistentCallFinding() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestEmitCallFindingsDropsInconsistent checks that an inconsistent call
// finding is not published while a consistent one still is.
func TestEmitCallFindingsDropsInconsistent(t *testing.T) {
	pkg := &packages.Package{
		PkgPath: "golang.org/bmod/bvuln",
		Module:  &packages.Module{Path: "golang.org/bmod", Version: "v0.5.0"},
	}
	sink := &FuncNode{Name: "Vuln", Package: pkg}

	goodVuln := &Vuln{
		OSV:      &osv.Entry{ID: "GOOD"},
		Symbol:   "Vuln",
		Package:  pkg,
		CallSink: sink,
	}
	badVuln := &Vuln{
		OSV:      &osv.Entry{ID: "BAD"},
		Symbol:   "Vuln",
		Package:  pkg,
		CallSink: sink,
	}

	goodStack := CallStack{StackEntry{Function: sink}}

	// A stack whose frame points at a different package than the
	// finding, modeling an attribution mismatch.
	wrongPkg := &packages.Package{
		PkgPath: "golang.org/entry/x",
		Module:  &packages.Module{Path: "golang.org/entry", Version: "v0.0.1"},
	}
	wrongSink := &FuncNode{Name: "Vuln", Package: wrongPkg}
	badStack := CallStack{StackEntry{Function: wrongSink}}

	handler := test.NewMockHandler()
	err := emitCallFindings(handler, map[*Vuln]CallStack{
		goodVuln: goodStack,
		badVuln:  badStack,
	})
	if err != nil {
		t.Fatal(err)
	}

	var emitted []string
	for _, f := range handler.FindingMessages {
		emitted = append(emitted, f.OSV)
	}
	if len(emitted) != 1 || emitted[0] != "GOOD" {
		t.Fatalf("emitted findings = %v, want only GOOD", emitted)
	}
}
