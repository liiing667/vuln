// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"errors"
	"path"
	"testing"

	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/test"
)

// genericModules builds a module graph where a generic method is
// instantiated and called from the entry package.
func genericModules(t *testing.T) *packagestest.Exported {
	return packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import "golang.org/bmod/bvuln"

			func X() {
				v := bvuln.Wrap[int]{}
				v.M()
			}
			`,
			},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"bvuln/bvuln.go": `
			package bvuln

			type Wrap[T any] struct{}
			func (w Wrap[T]) M() {}
			`},
		},
	})
}

func genericVulnClient(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.NewInMemoryClient(
		[]*osv.Entry{
			{
				ID: "VM",
				Affected: []osv.Affected{{
					Module: osv.Module{Path: "golang.org/bmod"},
					Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							Path:    "golang.org/bmod/bvuln",
							Symbols: []string{"Wrap.M"},
						}},
					},
				}},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestSourceGenericSymbolAttribution checks that a vulnerable generic
// method, reached through a monomorphized instantiation, is attributed to
// the package that defines the generic source function and that its
// finding is emitted with consistent module/package/function frames.
func TestSourceGenericSymbolAttribution(t *testing.T) {
	e := genericModules(t)
	defer e.Cleanup()

	graph := NewPackageGraph("go1.18")
	if err := graph.LoadPackagesAndMods(e.Config, nil, []string{path.Join(e.Temp(), "entry/x")}, true); err != nil {
		t.Fatal(err)
	}

	c := genericVulnClient(t)
	cfg := &govulncheck.Config{ScanLevel: "symbol"}
	result, err := source(context.Background(), test.NewMockHandler(), cfg, c, graph)
	if err != nil {
		t.Fatal(err)
	}

	var vuln *Vuln
	for _, v := range result.Vulns {
		if v.Symbol == "Wrap.M" {
			vuln = v
		}
	}
	if vuln == nil {
		t.Fatal("expected Wrap.M vulnerability to be detected")
	}
	if vuln.Package == nil || vuln.Package.PkgPath != "golang.org/bmod/bvuln" {
		t.Fatalf("Wrap.M attributed to %v, want golang.org/bmod/bvuln", vuln.Package)
	}
	if vuln.CallSink == nil {
		t.Fatal("expected a call sink for Wrap.M")
	}

	stack := sourceCallstacks(result)[vuln]
	trace := traceFromEntries(stack)
	if !consistentCallFinding(vuln, trace) {
		t.Fatalf("inconsistent call finding: %+v", trace)
	}
	sink := trace[0]
	if sink.Module != "golang.org/bmod" || sink.Package != "golang.org/bmod/bvuln" || sink.Function != "M" {
		t.Fatalf("unexpected sink frame: %+v", sink)
	}

	// The same consistency must hold for the finding emitted to the handler.
	handler := test.NewMockHandler()
	if err := Source(context.Background(), handler, cfg, c, graph); err != nil {
		t.Fatal(err)
	}
	var symbolFinding *govulncheck.Finding
	for _, f := range handler.FindingMessages {
		if f.OSV == "VM" && len(f.Trace) > 1 {
			symbolFinding = f
		}
	}
	if symbolFinding == nil {
		t.Fatal("expected a symbol-level finding to be emitted")
	}
	frame := symbolFinding.Trace[0]
	if frame.Module != "golang.org/bmod" || frame.Package != "golang.org/bmod/bvuln" || frame.Function != "M" {
		t.Fatalf("unexpected emitted sink frame: %+v", frame)
	}
}

// TestSourceSameNameReceiverNotMisattributed checks that a method whose
// receiver base name collides with a vulnerable receiver in another
// package is not reported as vulnerable. The database symbol names are
// only unique within their enclosing package, so the package resolution
// must drive the matching.
func TestSourceSameNameReceiverNotMisattributed(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import "golang.org/bmod/bvuln"

			// Wrap has the same base name and method as
			// bvuln.Wrap, but it is a benign local type.
			type Wrap[T any] struct{}
			func (w Wrap[T]) M() {}

			func X() {
				v := Wrap[int]{}
				v.M()
				// keep bvuln in the import graph
				_ = bvuln.Wrap[int]{}
			}
			`,
			},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"bvuln/bvuln.go": `
			package bvuln

			type Wrap[T any] struct{}
			func (w Wrap[T]) M() {}
			`},
		},
	})
	defer e.Cleanup()

	graph := NewPackageGraph("go1.18")
	if err := graph.LoadPackagesAndMods(e.Config, nil, []string{path.Join(e.Temp(), "entry/x")}, true); err != nil {
		t.Fatal(err)
	}

	c := genericVulnClient(t)
	cfg := &govulncheck.Config{ScanLevel: "symbol"}
	result, err := source(context.Background(), test.NewMockHandler(), cfg, c, graph)
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range result.Vulns {
		if v.Symbol == "Wrap.M" {
			t.Fatalf("benign local Wrap.M misattributed as vulnerable: %+v", v.Package.PkgPath)
		}
	}

	handler := test.NewMockHandler()
	if err := Source(context.Background(), handler, cfg, c, graph); err != nil {
		t.Fatal(err)
	}
	for _, f := range handler.FindingMessages {
		for _, fr := range f.Trace {
			if fr.Package == "golang.org/entry/x" && fr.Function == "M" {
				t.Fatalf("misattributed symbol finding emitted: %+v", f)
			}
		}
	}
}

// TestSourceCallGraphBuildErrorNotPublished checks that a failure to build
// the call graph results in an error and no symbol-level finding is
// published instead of a partial or incorrect call result.
func TestSourceCallGraphBuildErrorNotPublished(t *testing.T) {
	e := genericModules(t)
	defer e.Cleanup()

	graph := NewPackageGraph("go1.18")
	if err := graph.LoadPackagesAndMods(e.Config, nil, []string{path.Join(e.Temp(), "entry/x")}, true); err != nil {
		t.Fatal(err)
	}

	c := genericVulnClient(t)
	cfg := &govulncheck.Config{ScanLevel: "symbol"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call graph build runs

	handler := test.NewMockHandler()
	err := Source(ctx, handler, cfg, c, graph)
	if err == nil {
		t.Fatal("expected an error when the call graph build is cancelled")
	}
	if ctx.Err() == nil {
		t.Fatal("test setup: context was not cancelled")
	}
	// Sanity: the returned error must be the context cancellation.
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	for _, f := range handler.FindingMessages {
		// Module/package findings may be emitted before the build
		// finishes; symbol (call) findings carry function frames and
		// must not be published after a build failure.
		for _, fr := range f.Trace {
			if fr.Function != "" {
				t.Fatalf("call finding published despite build failure: %+v", f)
			}
		}
	}
}
