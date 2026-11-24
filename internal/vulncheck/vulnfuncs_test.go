// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/osv"
)

// TestVulnFuncsSkipsUnknownPackage verifies that a call graph node whose
// package cannot be resolved is never matched against the database.
// Database symbol names are only unique within their enclosing package,
// so prefix-based resolution against an unknown package could attribute a
// symbol to the wrong module/package.
func TestVulnFuncsSkipsUnknownPackage(t *testing.T) {
	prog := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)

	// A synthetic function with no package: pkgPath resolves it as
	// unknown-package.
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	unknown := prog.NewFunction("M", sig, "bound method wrapper for fake.M")

	cg := &callgraph.Graph{Nodes: map[*ssa.Function]*callgraph.Node{}}
	cg.CreateNode(unknown)

	aff := affectingVulns{
		{
			Module: &packages.Module{Path: "golang.org/bmod", Version: "v0.5.0"},
			Vulns: []*osv.Entry{
				{
					ID: "VM",
					Affected: []osv.Affected{{
						Module: osv.Module{Path: "golang.org/bmod"},
						Ranges: []osv.Range{{Type: osv.RangeTypeSemver}},
						EcosystemSpecific: osv.EcosystemSpecific{
							Packages: []osv.Package{{
								Path:    "golang.org/bmod/bvuln",
								Symbols: []string{"M", "Vuln"},
							}},
						},
					}},
				},
			},
		},
	}

	graph := NewPackageGraph("go1.18")
	// Register the vulnerable module/package in the graph so that an
	// unknown-package node would otherwise be resolved through the
	// most-specific module prefix heuristic in ForSymbol.
	graph.GetPackage("golang.org/bmod/bvuln").Module = &packages.Module{Path: "golang.org/bmod", Version: "v0.5.0"}
	matches := vulnFuncs(cg, aff, graph)

	if len(matches) != 0 {
		t.Fatalf("unknown-package node must not match, got %d matches", len(matches))
	}

	// Sanity check that the test's premise holds: the node really is
	// attributed to the unknown-package sentinel.
	if got := pkgPath(unknown); got != internal.UnknownPackagePath {
		t.Fatalf("test premise: pkgPath = %q, want %q", got, internal.UnknownPackagePath)
	}
}
