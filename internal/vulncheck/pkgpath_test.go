// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"path"
	"testing"

	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// TestPkgPathResolvesThroughOriginChain verifies that package attribution
// works for ssa.Function values that have no package of their own:
// monomorphized generic instantiations and synthetic thunk/bound
// wrappers. Such functions must be attributed to the package defining
// the underlying source symbol rather than unknown-package.
func TestPkgPathResolvesThroughOriginChain(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import "golang.org/bmod/bvuln"

			func X() {
				// monomorphized instance of the generic method
				v := bvuln.Wrap[int]{}
				v.M()
				// bound method wrapper, which has no ssa package
				f := v.M
				f()
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

	prog, _ := buildSSA(graph.TopPkgs(), graph.TopPkgs()[0].Fset)

	var sawInstance, sawWrapper bool
	for f := range ssautil.AllFunctions(prog) {
		switch {
		case f.Name() == "M" && f.Synthetic == "instance of M":
			sawInstance = true
			// The instantiation itself has no package, but its origin
			// generic function belongs to bvuln.
			if f.Package() != nil {
				t.Fatalf("test premise changed: generic instance has a package")
			}
			if got := pkgPath(f); got != "golang.org/bmod/bvuln" {
				t.Errorf("generic instance pkgPath = %q, want golang.org/bmod/bvuln", got)
			}
		case f.Name() == "M$bound":
			sawWrapper = true
			if got := pkgPath(f); got != "golang.org/bmod/bvuln" {
				t.Errorf("bound wrapper pkgPath = %q, want golang.org/bmod/bvuln", got)
			}
		}
	}
	if !sawInstance {
		t.Fatal("did not encounter a generic method instantiation")
	}
	if !sawWrapper {
		t.Fatal("did not encounter a bound method wrapper")
	}
}

// TestPkgPathRegularFunctions ensures ordinary functions and package
// initializers keep their direct package attribution.
func TestPkgPathRegularFunctions(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			func X() {}
			`,
			},
		},
	})
	defer e.Cleanup()

	graph := NewPackageGraph("go1.18")
	if err := graph.LoadPackagesAndMods(e.Config, nil, []string{path.Join(e.Temp(), "entry/x")}, true); err != nil {
		t.Fatal(err)
	}

	prog, _ := buildSSA(graph.TopPkgs(), graph.TopPkgs()[0].Fset)
	for f := range ssautil.AllFunctions(prog) {
		if pkgPath(f) != "golang.org/entry/x" {
			var origin *ssa.Function
			if f.Origin() != nil {
				origin = f.Origin()
			}
			t.Errorf("pkgPath(%q, origin=%v) = %q, want golang.org/entry/x", f.Name(), origin != nil, pkgPath(f))
		}
	}
}
