// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package semver

import (
	"sort"

	"golang.org/x/vuln/internal/osv"
)

func Affects(a []osv.Range, v string) bool {
	if len(a) == 0 {
		// No ranges implies all versions are affected
		return true
	}
	var semverRangePresent bool
	for _, r := range a {
		if r.Type != osv.RangeTypeSemver {
			continue
		}
		semverRangePresent = true
		if ContainsSemver(r, v) {
			return true
		}
	}
	// If there were no semver ranges present we
	// assume that all semvers are affected, similarly
	// to how to we assume all semvers are affected
	// if there are no ranges at all.
	return !semverRangePresent
}

// ContainsSemver checks if semver version v is in the
// range encoded by ar. If ar is not a semver range,
// returns false. A range is interpreted as a left-closed
// and right-open interval. Events are normalized on a copy,
// so reordered events produce the same result without changing
// the caller's OSV value.
//
// Assumes that
//   - exactly one of Introduced or Fixed fields is set
//   - valid ranges in ar do not overlap
//   - beginning of time is encoded with .Introduced="0"
//   - no-fix is not an event, as opposed to being an
//     event where Introduced="" and Fixed=""
func ContainsSemver(ar osv.Range, v string) bool {
	if ar.Type != osv.RangeTypeSemver {
		return false
	}
	if len(ar.Events) == 0 {
		return true
	}

	// Strip and then add the semver prefix so we can support bare versions,
	// versions prefixed with 'v', and versions prefixed with 'go'.
	v = canonicalizeSemverPrefix(v)

	// Work on a copy. Sorting ar.Events in place would make a query
	// observable through the caller's OSV value and could change later
	// calls made by NonSupersededFix or client indexing.
	events := sortedEvents(ar.Events)

	var affected bool
	for _, e := range events {
		if !affected && e.Introduced != "" {
			affected = e.Introduced == "0" || !Less(v, e.Introduced)
		} else if affected && e.Fixed != "" {
			affected = Less(v, e.Fixed)
		}
	}

	return affected
}

// sortedEvents returns a sorted copy of events. "0" is the beginning of
// time. At equal versions, fixed events come before introduced events so
// that adjacent intervals such as [a, b) and [b, c) include b in the
// latter interval.
func sortedEvents(events []osv.RangeEvent) []osv.RangeEvent {
	sorted := append([]osv.RangeEvent(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		e1, e2 := sorted[i], sorted[j]
		if c := compareEventVersions(eventVersion(e1), eventVersion(e2)); c != 0 {
			return c < 0
		}
		return isFixedOnlyEvent(e1) && isIntroducedOnlyEvent(e2)
	})
	return sorted
}

// eventVersion returns the version carried by e.
func eventVersion(e osv.RangeEvent) string {
	if e.Introduced != "" {
		return e.Introduced
	}
	return e.Fixed
}

func isFixedOnlyEvent(e osv.RangeEvent) bool {
	return e.Fixed != "" && e.Introduced == ""
}

func isIntroducedOnlyEvent(e osv.RangeEvent) bool {
	return e.Introduced != "" && e.Fixed == ""
}

// compareEventVersions orders event versions. The special introduced
// version "0" represents the beginning of time and sorts before all
// ordinary semver versions.
func compareEventVersions(v1, v2 string) int {
	switch {
	case v1 == "0" && v2 == "0":
		return 0
	case v1 == "0":
		return -1
	case v2 == "0":
		return 1
	case Less(v1, v2):
		return -1
	case Less(v2, v1):
		return 1
	default:
		return 0
	}
}
