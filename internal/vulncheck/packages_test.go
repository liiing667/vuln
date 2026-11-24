// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/govulncheck"
)

// TestModuleIdentity checks that the module identity used in public
// reports is consistent with the package graph: a versioned module
// replacement takes over the module identity, while a local directory
// replacement keeps the original module path and, importantly, its
// version.
func TestModuleIdentity(t *testing.T) {
	local := &packages.Module{
		Path:    "golang.org/local",
		Version: "v1.0.0",
		Replace: &packages.Module{Path: "../local"},
	}
	forked := &packages.Module{
		Path:    "golang.org/forked",
		Version: "v2.0.0",
		Replace: &packages.Module{Path: "golang.org/fork", Version: "v2.0.1"},
	}
	plain := &packages.Module{Path: "golang.org/plain", Version: "v1.1.0"}
	main := &packages.Module{Path: "golang.org/main"}

	for _, test := range []struct {
		mod         *packages.Module
		wantPath    string
		wantVersion string
	}{
		{local, "golang.org/local", "v1.0.0"},
		{forked, "golang.org/fork", "v2.0.1"},
		{plain, "golang.org/plain", "v1.1.0"},
		{main, "golang.org/main", ""},
	} {
		if got := modPath(test.mod); got != test.wantPath {
			t.Errorf("modPath(%+v) = %q, want %q", test.mod, got, test.wantPath)
		}
		if got := modVersion(test.mod); got != test.wantVersion {
			t.Errorf("modVersion(%+v) = %q, want %q", test.mod, got, test.wantVersion)
		}
	}
}

// TestAddModulesReplace checks that replacement modules are not added
// to the package graph as separate modules. Otherwise, distinct
// artifacts sharing a path would be merged and module identities
// would be reported more than once.
func TestAddModulesReplace(t *testing.T) {
	graph := NewPackageGraph("go1.18")
	graph.AddModules(&packages.Module{
		Path:    "golang.org/forked",
		Version: "v2.0.0",
		Replace: &packages.Module{Path: "golang.org/fork", Version: "v2.0.1"},
	})

	for _, m := range graph.Modules() {
		if m.Path == "golang.org/fork" {
			t.Errorf("replacement module golang.org/fork should not be in the package graph")
		}
	}
	if got := graph.GetModule("golang.org/forked"); got.Version != "v2.0.0" {
		t.Errorf("graph module golang.org/forked has version %q, want v2.0.0", got.Version)
	}
}

// TestSBOM checks that the SBOM module identities are consistent with
// the package graph: real versions are not lost for local replacements
// and empty versions, distinct artifacts are not merged, and identical
// module identities are reported only once, also with multiple roots.
func TestSBOM(t *testing.T) {
	main := &packages.Module{Path: "golang.org/main"}
	local := &packages.Module{
		Path:    "golang.org/local",
		Version: "v1.0.0",
		Replace: &packages.Module{Path: "../local"},
	}
	forked := &packages.Module{
		Path:    "golang.org/forked",
		Version: "v2.0.0",
		Replace: &packages.Module{Path: "golang.org/fork", Version: "v2.0.1"},
	}
	// golang.org/fork is also required directly at the same version
	// as the replacement, so its identity must be reported only once.
	fork := &packages.Module{Path: "golang.org/fork", Version: "v2.0.1"}
	dep := &packages.Module{Path: "golang.org/dep", Version: "v1.1.0"}

	graph := NewPackageGraph("go1.18")
	graph.AddModules(main, local, forked, fork, dep)

	// Multiple top-level packages, two of which share the main module.
	graph.topPkgs = []*packages.Package{
		{PkgPath: "golang.org/main", Module: main},
		{PkgPath: "golang.org/main/sub", Module: main},
		{PkgPath: "golang.org/dep", Module: dep},
	}

	got := graph.SBOM()
	want := &govulncheck.SBOM{
		GoVersion: "go1.18",
		Roots:     []string{"golang.org/main", "golang.org/main/sub", "golang.org/dep"},
		Modules: []*govulncheck.Module{
			// root modules first
			{Path: "golang.org/dep", Version: "v1.1.0"},
			{Path: "golang.org/main"},
			// then the remaining modules
			{Path: "golang.org/fork", Version: "v2.0.1"},
			{Path: "golang.org/local", Version: "v1.0.0"},
			{Path: "stdlib", Version: "v1.18.0"},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SBOM mismatch (-want +got):\n%s", diff)
	}
}

// TestBinSBOM checks that binary SBOM module identities follow the
// same rules as source SBOM identities.
func TestBinSBOM(t *testing.T) {
	bin := &Bin{
		Main: &packages.Module{Path: "golang.org/main", Version: "v0.1.0"},
		Modules: []*packages.Module{
			{
				Path:    "golang.org/local",
				Version: "v1.0.0",
				Replace: &packages.Module{Path: "../local"},
			},
			{
				Path:    "golang.org/forked",
				Version: "v2.0.0",
				Replace: &packages.Module{Path: "golang.org/fork", Version: "v2.0.1"},
			},
			{Path: "golang.org/dep", Version: "v1.1.0"},
			// duplicate of the main module should not be repeated
			{Path: "golang.org/main", Version: "v0.1.0"},
		},
		GoVersion: "go1.18",
	}

	got := bin.SBOM()
	want := &govulncheck.SBOM{
		GoVersion: "go1.18",
		Roots:     []string{"golang.org/main"},
		Modules: []*govulncheck.Module{
			{Path: "golang.org/main", Version: "v0.1.0"},
			{Path: "golang.org/local", Version: "v1.0.0"},
			{Path: "golang.org/fork", Version: "v2.0.1"},
			{Path: "golang.org/dep", Version: "v1.1.0"},
			{Path: "stdlib", Version: "go1.18"},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Bin.SBOM mismatch (-want +got):\n%s", diff)
	}
}

// TestFramesModuleIdentity checks that finding frames use the same
// module identity as the package graph and do not panic on
// incomplete input.
func TestFramesModuleIdentity(t *testing.T) {
	local := &packages.Module{
		Path:    "golang.org/local",
		Version: "v1.0.0",
		Replace: &packages.Module{Path: "../local"},
	}
	forked := &packages.Module{
		Path:    "golang.org/forked",
		Version: "v2.0.0",
		Replace: &packages.Module{Path: "golang.org/fork", Version: "v2.0.1"},
	}

	for _, test := range []struct {
		name string
		mod  *packages.Module
		want *govulncheck.Frame
	}{
		{"nil", nil, &govulncheck.Frame{}},
		{"local replace", local, &govulncheck.Frame{Module: "golang.org/local", Version: "v1.0.0"}},
		{"versioned replace", forked, &govulncheck.Frame{Module: "golang.org/fork", Version: "v2.0.1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := frameFromModule(test.mod); *got != *test.want {
				t.Errorf("frameFromModule = %+v, want %+v", got, test.want)
			}
		})
	}

	// frameFromPackage should not panic on nil packages or packages
	// without module information.
	if got := frameFromPackage(nil); *got != (govulncheck.Frame{}) {
		t.Errorf("frameFromPackage(nil) = %+v, want empty frame", got)
	}
	pkg := &packages.Package{PkgPath: "golang.org/local/p", Module: local}
	want := &govulncheck.Frame{Module: "golang.org/local", Version: "v1.0.0", Package: "golang.org/local/p"}
	if got := frameFromPackage(pkg); *got != *want {
		t.Errorf("frameFromPackage = %+v, want %+v", got, want)
	}
	noMod := &packages.Package{PkgPath: "golang.org/nomod/p"}
	want = &govulncheck.Frame{Package: "golang.org/nomod/p"}
	if got := frameFromPackage(noMod); *got != *want {
		t.Errorf("frameFromPackage = %+v, want %+v", got, want)
	}
}
