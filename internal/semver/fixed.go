// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package semver

import "golang.org/x/vuln/internal/osv"

// NonSupersededFix returns a fixed version from ranges
// that is not superseded by any other fix or any other
// introduction of a vulnerability. Returns "" in case
// there is no such fixed version.
//
// When a version is returned, Affects reports that version
// and every later semver as unaffected by the SEMVER ranges.
func NonSupersededFix(ranges []osv.Range) string {
	var latestFixed string
	for _, r := range ranges {
		if r.Type != osv.RangeTypeSemver {
			continue
		}
		for _, e := range r.Events {
			fixed := e.Fixed
			if fixed != "" && Less(latestFixed, fixed) {
				latestFixed = fixed
			}
		}
	}
	if latestFixed == "" {
		return ""
	}

	// The returned version must mean the same thing to Affects and to
	// client indexing: it is not itself affected. This also catches an
	// unclosed introduction that overlaps the fix from another range.
	if Affects(ranges, latestFixed) {
		return ""
	}

	// Affects at latestFixed alone is not enough: a vulnerability can be
	// re-introduced at or after latestFixed without a later fix. Such an
	// introduction affects future versions even though latestFixed itself
	// is unaffected, so there is no non-superseded terminal fix.
	for _, r := range ranges {
		if r.Type != osv.RangeTypeSemver {
			continue
		}
		for _, e := range r.Events {
			introduced := e.Introduced
			if introduced != "" && introduced != "0" && !Less(introduced, latestFixed) {
				return ""
			}
		}
	}
	return latestFixed
}
