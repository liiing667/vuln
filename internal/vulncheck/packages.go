// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/semver"
)

// PackageGraph holds a complete module and package graph.
// Its primary purpose is to allow fast access to the nodes
// by path and make sure all(stdlib)  packages have a module.
type PackageGraph struct {
	// topPkgs are top-level packages specified by the user.
	// Empty in binary mode.
	topPkgs  []*packages.Package
	modules  map[string]*packages.Module  // all modules in the build list
	packages map[string]*packages.Package // all packages (even dependencies)
}

func NewPackageGraph(goVersion string) *PackageGraph {
	graph := &PackageGraph{
		modules:  map[string]*packages.Module{},
		packages: map[string]*packages.Package{},
	}

	goRoot := ""
	if out, err := exec.Command("go", "env", "GOROOT").Output(); err == nil {
		goRoot = strings.TrimSpace(string(out))
	}
	stdlibModule := &packages.Module{
		Path:    internal.GoStdModulePath,
		Version: semver.GoTagToSemver(goVersion),
		Dir:     goRoot,
	}
	graph.AddModules(stdlibModule)
	return graph
}

func (g *PackageGraph) TopPkgs() []*packages.Package {
	return g.topPkgs
}

// DepPkgs returns the number of packages that graph.TopPkgs()
// strictly depend on. This does not include topPkgs even if
// they are dependency of each other.
func (g *PackageGraph) DepPkgs() []*packages.Package {
	topPkgs := g.TopPkgs()
	tops := make(map[string]bool)
	depPkgs := make(map[string]*packages.Package)

	for _, t := range topPkgs {
		tops[t.PkgPath] = true
	}

	var visit func(*packages.Package, bool)
	visit = func(p *packages.Package, top bool) {
		path := p.PkgPath
		if _, ok := depPkgs[path]; ok {
			return
		}
		if tops[path] && !top {
			// A top package that is a dependency
			// will not be in depPkgs, so we skip
			// reiterating on it here.
			return
		}

		// We don't count a top-level package as
		// a dependency even when they are used
		// as a dependent package.
		if !tops[path] {
			depPkgs[path] = p
		}

		for _, d := range p.Imports {
			visit(d, false)
		}
	}

	for _, t := range topPkgs {
		visit(t, true)
	}

	var deps []*packages.Package
	for _, d := range depPkgs {
		deps = append(deps, g.GetPackage(d.PkgPath))
	}
	return deps
}

func (g *PackageGraph) Modules() []*packages.Module {
	var mods []*packages.Module
	for _, m := range g.modules {
		mods = append(mods, m)
	}
	return mods
}

// AddModules adds the modules to the graph. It will ignore modules
// that have duplicate paths to ones the graph already holds.
//
// Modules that are targets of a replace directive are not added:
// a replace directive substitutes the source of a module, not its
// identity in the build list. Adding them would merge distinct
// artifacts sharing a path and produce duplicate module identities
// in the graph.
func (g *PackageGraph) AddModules(mods ...*packages.Module) {
	for _, mod := range mods {
		if _, found := g.modules[mod.Path]; found {
			//TODO: check duplicates are okay?
			continue
		}
		g.modules[mod.Path] = mod
	}
}

// GetModule gets module at path if one exists. Otherwise,
// it creates a module and returns it.
func (g *PackageGraph) GetModule(path string) *packages.Module {
	if mod, ok := g.modules[path]; ok {
		return mod
	}
	mod := &packages.Module{
		Path:    path,
		Version: "",
	}
	g.AddModules(mod)
	return mod
}

// AddPackages adds the packages and their full graph of imported packages.
// It also adds the modules of the added packages. It will ignore packages
// that have duplicate paths to ones the graph already holds.
func (g *PackageGraph) AddPackages(pkgs ...*packages.Package) {
	for _, pkg := range pkgs {
		if _, found := g.packages[pkg.PkgPath]; found {
			//TODO: check duplicates are okay?
			continue
		}
		g.packages[pkg.PkgPath] = pkg
		g.fixupPackage(pkg)
		for _, child := range pkg.Imports {
			g.AddPackages(child)
		}
	}
}

// fixupPackage adds the module of pkg, if any, to the set
// of all modules in g. If packages is not assigned a module
// (likely stdlib package), a module set for pkg.
func (g *PackageGraph) fixupPackage(pkg *packages.Package) {
	if pkg.Module != nil {
		g.AddModules(pkg.Module)
		return
	}
	pkg.Module = g.findModule(pkg.PkgPath)
}

// findModule finds a module for package.
// It does a longest prefix search amongst the existing modules, if that does
// not find anything, it returns the "unknown" module.
func (g *PackageGraph) findModule(pkgPath string) *packages.Module {
	//TODO: better stdlib test
	if IsStdPackage(pkgPath) {
		return g.GetModule(internal.GoStdModulePath)
	}
	for _, m := range g.modules {
		//TODO: not first match, best match...
		if pkgPath == m.Path || strings.HasPrefix(pkgPath, m.Path+"/") {
			return m
		}
	}
	return g.GetModule(internal.UnknownModulePath)
}

// GetPackage returns the package matching the path.
// If the graph does not already know about the package, a new one is added.
func (g *PackageGraph) GetPackage(path string) *packages.Package {
	if pkg, ok := g.packages[path]; ok {
		return pkg
	}
	pkg := &packages.Package{
		PkgPath: path,
	}
	g.AddPackages(pkg)
	return pkg
}

// LoadPackages loads the packages specified by the patterns into the graph.
// See golang.org/x/tools/go/packages.Load for details of how it works.
func (g *PackageGraph) LoadPackagesAndMods(cfg *packages.Config, tags []string, patterns []string, wantSymbols bool) error {
	if len(tags) > 0 {
		cfg.BuildFlags = []string{fmt.Sprintf("-tags=%s", strings.Join(tags, ","))}
	}

	addLoadMode(cfg, wantSymbols)

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return err
	}
	var perrs []packages.Error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		perrs = append(perrs, p.Errors...)
	})
	if len(perrs) > 0 {
		err = &packageError{perrs}
	}

	// Add all packages, top-level ones and their imports.
	// This will also add their respective modules.
	g.AddPackages(pkgs...)

	// save top-level packages
	for _, p := range pkgs {
		g.topPkgs = append(g.topPkgs, g.GetPackage(p.PkgPath))
	}
	return err
}

func addLoadMode(cfg *packages.Config, wantSymbols bool) {
	cfg.Mode |=
		packages.NeedModule |
			packages.NeedName |
			packages.NeedDeps |
			packages.NeedImports
	if wantSymbols {
		cfg.Mode |= packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo
	}
}

// packageError contains errors from loading a set of packages.
type packageError struct {
	Errors []packages.Error
}

func (e *packageError) Error() string {
	var b strings.Builder
	fmt.Fprintln(&b, "\nThere are errors with the provided package patterns:")
	fmt.Fprintln(&b, "")
	for _, e := range e.Errors {
		fmt.Fprintln(&b, e)
	}
	fmt.Fprintln(&b, "\nFor details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.")
	return b.String()
}

func (g *PackageGraph) SBOM() *govulncheck.SBOM {
	getMod := func(mod *packages.Module) *govulncheck.Module {
		return &govulncheck.Module{
			Path:    modPath(mod),
			Version: modVersion(mod),
		}
	}
	// modID identifies a module identity. Modules with distinct
	// identities are distinct artifacts and must not be merged,
	// whereas the same identity can be reached through different
	// graph nodes, say a module and the target of its replace
	// directive, and should be reported only once.
	modID := func(mod *govulncheck.Module) string {
		return mod.Path + "\x00" + mod.Version
	}

	var roots []string
	seenRoots := make(map[string]bool)
	rootMods := make(map[string]*govulncheck.Module)
	for _, pkg := range g.TopPkgs() {
		if !seenRoots[pkg.PkgPath] {
			seenRoots[pkg.PkgPath] = true
			roots = append(roots, pkg.PkgPath)
		}
		mod := getMod(pkg.Module)
		rootMods[modID(mod)] = mod
	}

	// Govulncheck attempts to put the modules that correspond to the matched package patterns (i.e. the root modules)
	// at the beginning of the SBOM.Modules message.
	// Note: This does not guarantee that the first element is the root module.
	var topMods, depMods []*govulncheck.Module
	var goVersion string
	seenMods := make(map[string]bool)
	for _, mod := range g.Modules() {
		gmod := getMod(mod)
		id := modID(gmod)
		if seenMods[id] {
			continue
		}
		seenMods[id] = true

		if gmod.Path == internal.GoStdModulePath {
			goVersion = semver.SemverToGoTag(gmod.Version)
		}

		// if the mod is not associated with a root package, add it to depMods
		if rootMods[id] == nil {
			depMods = append(depMods, gmod)
		}
	}

	for _, mod := range rootMods {
		topMods = append(topMods, mod)
	}
	// Sort for deterministic output
	sortMods(topMods)
	sortMods(depMods)

	mods := append(topMods, depMods...)

	return &govulncheck.SBOM{
		GoVersion: goVersion,
		Modules:   mods,
		Roots:     roots,
	}
}

// Sorts modules alphabetically by path and version.
func sortMods(mods []*govulncheck.Module) {
	slices.SortFunc(mods, func(a, b *govulncheck.Module) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
}
