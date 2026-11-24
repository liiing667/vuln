// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/buildinfo"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/semver"
)

// Bin is an abstraction of Go binary containing
// minimal information needed by govulncheck.
type Bin struct {
	// Path of the main package.
	Path string `json:"path,omitempty"`
	// Main module. When present, it never has empty information.
	Main       *packages.Module   `json:"main,omitempty"`
	Modules    []*packages.Module `json:"modules,omitempty"`
	PkgSymbols []buildinfo.Symbol `json:"pkgSymbols,omitempty"`
	GoVersion  string             `json:"goVersion,omitempty"`
	GOOS       string             `json:"goos,omitempty"`
	GOARCH     string             `json:"goarch,omitempty"`
}

// Binary detects presence of vulnerable symbols in bin and
// emits findings to handler.
func Binary(ctx context.Context, handler govulncheck.Handler, bin *Bin, cfg *govulncheck.Config, client *client.Client) error {
	vr, err := binary(ctx, handler, bin, cfg, client)
	if err != nil {
		return err
	}
	if cfg.ScanLevel.WantSymbols() {
		return emitCallFindings(handler, binaryCallstacks(vr))
	}
	return nil
}

// binary detects presence of vulnerable symbols in bin.
// It does not compute call graphs so the corresponding
// info in Result will be empty.
func binary(ctx context.Context, handler govulncheck.Handler, bin *Bin, cfg *govulncheck.Config, client *client.Client) (*Result, error) {
	graph := NewPackageGraph(bin.GoVersion)
	mods := append(bin.Modules, graph.GetModule(internal.GoStdModulePath))

	if bin.Main != nil {
		mods = append(mods, bin.Main)
	}

	graph.AddModules(mods...)

	if err := handler.SBOM(bin.SBOM()); err != nil {
		return nil, err
	}

	if err := handler.Progress(&govulncheck.Progress{Message: fetchingVulnsMessage}); err != nil {
		return nil, err
	}

	mv, err := FetchVulnerabilities(ctx, client, mods)
	if err != nil {
		return nil, err
	}

	// Emit OSV entries immediately in their raw unfiltered form.
	if err := emitOSVs(handler, mv); err != nil {
		return nil, err
	}

	if err := handler.Progress(&govulncheck.Progress{Message: checkingBinVulnsMessage}); err != nil {
		return nil, err
	}

	// Emit warning message for ancient Go binaries, defined as binaries
	// built with Go version without support for debug.BuildInfo (< go1.18).
	if semver.Valid(bin.GoVersion) && semver.Less(bin.GoVersion, "go1.18") {
		p := &govulncheck.Progress{Message: fmt.Sprintf("warning: binary built with Go version %s, only standard library vulnerabilities will be checked", bin.GoVersion)}
		if err := handler.Progress(p); err != nil {
			return nil, err
		}
	}

	if bin.GOOS == "" || bin.GOARCH == "" {
		p := &govulncheck.Progress{Message: fmt.Sprintf("warning: failed to extract build system specification GOOS: %s GOARCH: %s\n", bin.GOOS, bin.GOARCH)}
		if err := handler.Progress(p); err != nil {
			return nil, err
		}
	}
	affVulns := affectingVulnerabilities(mv, bin.GOOS, bin.GOARCH)
	if err := emitModuleFindings(handler, affVulns); err != nil {
		return nil, err
	}

	if !cfg.ScanLevel.WantPackages() || len(affVulns) == 0 {
		return &Result{}, nil
	}

	// Group symbols per package to avoid querying affVulns all over again.
	var pkgSymbols map[string]binPackageInfo
	if len(bin.PkgSymbols) == 0 {
		// The binary exe is stripped. We currently cannot detect inlined
		// symbols for stripped binaries (see #57764), so we report
		// vulnerabilities at the go.mod-level precision.
		pkgSymbols = allKnownVulnerableSymbols(affVulns)
	} else {
		pkgSymbols = packagesAndSymbols(bin)
	}

	impVulns := binImportedVulnPackages(graph, pkgSymbols, affVulns)
	// Emit information on imported vulnerable packages now to
	// mimic behavior of source.
	if err := emitPackageFindings(handler, impVulns); err != nil {
		return nil, err
	}

	// Return result immediately if not in symbol mode to mimic the
	// behavior of source.
	if !cfg.ScanLevel.WantSymbols() || len(impVulns) == 0 {
		return &Result{Vulns: impVulns}, nil
	}

	symVulns := binVulnSymbols(graph, pkgSymbols, affVulns)
	return &Result{Vulns: symVulns}, nil
}

// binPackageInfo groups the symbols found in a binary package. The module is
// set when symbol information is unavailable and the owning module is known
// from the vulnerability database instead.
type binPackageInfo struct {
	module  *packages.Module
	symbols []string
}

func packagesAndSymbols(bin *Bin) map[string]binPackageInfo {
	pkgSymbols := make(map[string]binPackageInfo)
	for _, sym := range bin.PkgSymbols {
		// If the name of the package is main, we need to expand
		// it to its full path as that is what vuln db uses.
		pkg := sym.Pkg
		if sym.Pkg == "main" && bin.Path != "" {
			pkg = bin.Path
		}
		info := pkgSymbols[pkg]
		info.symbols = append(info.symbols, sym.Name)
		pkgSymbols[pkg] = info
	}
	return pkgSymbols
}

// binaryPackage returns the package for pkg, using info.module as its
// module when that module was determined from the vulnerability data.
func binaryPackage(graph *PackageGraph, pkg string, info binPackageInfo) *packages.Package {
	p := graph.GetPackage(pkg)
	if info.module != nil {
		p.Module = info.module
	}
	return p
}

func binImportedVulnPackages(graph *PackageGraph, pkgSymbols map[string]binPackageInfo, affVulns affectingVulns) []*Vuln {
	var vulns []*Vuln
	for pkg, info := range pkgSymbols {
		p := binaryPackage(graph, pkg, info)
		for _, osv := range affVulns.ForPackage(pkgModPath(p), pkg) {
			vuln := &Vuln{
				OSV:     osv,
				Package: p,
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns
}

func binVulnSymbols(graph *PackageGraph, pkgSymbols map[string]binPackageInfo, affVulns affectingVulns) []*Vuln {
	var vulns []*Vuln
	for pkg, info := range pkgSymbols {
		p := binaryPackage(graph, pkg, info)
		mod := pkgModPath(p)
		for _, symbol := range info.symbols {
			for _, osv := range affVulns.ForSymbol(mod, pkg, symbol) {
				vuln := &Vuln{
					OSV:     osv,
					Symbol:  symbol,
					Package: p,
				}
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns
}

// allKnownVulnerableSymbols returns all known vulnerable symbols for packages in graph.
// If all symbols of a package are vulnerable, that is modeled as a wildcard symbol "<pkg-path>/*".
func allKnownVulnerableSymbols(affVulns affectingVulns) map[string]binPackageInfo {
	pkgSymbols := make(map[string]binPackageInfo)
	for _, mv := range affVulns {
		for _, osv := range mv.Vulns {
			for _, affected := range osv.Affected {
				for _, p := range affected.EcosystemSpecific.Packages {
					// Vulnerability data describes packages of a replaced
					// module using the replacement module path. Map them
					// back to the import path that the binary uses so that
					// stripped and non-stripped binaries report the same
					// package identity.
					pkg := p.Path
					if r := mv.Module.Replace; r != nil && r.Path != "" && r.Path != mv.Module.Path && modulePathMatches(pkg, r.Path) {
						pkg = mv.Module.Path + strings.TrimPrefix(pkg, r.Path)
					}

					syms := p.Symbols
					if len(syms) == 0 {
						// If every symbol of pkg is vulnerable, we would ideally
						// compute every symbol mentioned in the pkg and then add
						// Vuln entry for it, just as we do in Source. However,
						// we don't have code of pkg here and we don't even have
						// pkg symbols used in stripped binary, so we add a placeholder
						// symbol.
						syms = []string{fmt.Sprintf("%s/*", pkg)}
					}

					info := pkgSymbols[pkg]
					if info.module == nil {
						info.module = mv.Module
					}
					info.symbols = append(info.symbols, syms...)
					pkgSymbols[pkg] = info
				}
			}
		}
	}
	return pkgSymbols
}

func (bin *Bin) SBOM() (sbom *govulncheck.SBOM) {
	sbom = &govulncheck.SBOM{}
	if bin.Main != nil {
		sbom.Roots = []string{bin.Main.Path}
		sbom.Modules = append(sbom.Modules, &govulncheck.Module{
			Path:    bin.Main.Path,
			Version: bin.Main.Version,
		})
	}

	sbom.GoVersion = bin.GoVersion
	for _, mod := range bin.Modules {
		if mod.Replace != nil && mod.Replace.Path != "" {
			mod = mod.Replace
		}
		sbom.Modules = append(sbom.Modules, &govulncheck.Module{
			Path:    mod.Path,
			Version: mod.Version,
		})
	}

	// add stdlib to mirror source mode output
	sbom.Modules = append(sbom.Modules, &govulncheck.Module{
		Path:    internal.GoStdModulePath,
		Version: bin.GoVersion,
	})

	return sbom
}
