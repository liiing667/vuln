// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package semver

import (
	"fmt"
	"sort"

	"golang.org/x/vuln/internal/osv"
)

// Affects reports whether the semver version v is affected
// by any of the ranges in a.
//
// Ranges with malformed events cannot be interpreted, so
// they are treated as not containing v.
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
		if contains, err := ContainsSemver(r, v); err == nil && contains {
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
// returns false. A range is interpreted as a collection of
// left-closed and right-open intervals.
//
// ContainsSemver does not modify ar. The events of ar are
// validated and normalized before evaluation:
//   - each event must set exactly one of Introduced or Fixed
//   - versions must be valid semver, where "0" is allowed
//     only for Introduced and denotes the beginning of time
//   - unsorted and overlapping events are merged into a
//     deterministic sequence of disjoint intervals
//
// An error is returned if the events are malformed.
func ContainsSemver(ar osv.Range, v string) (bool, error) {
	if ar.Type != osv.RangeTypeSemver {
		return false, nil
	}
	if len(ar.Events) == 0 {
		return true, nil
	}

	// Strip and then add the semver prefix so we can support bare versions,
	// versions prefixed with 'v', and versions prefixed with 'go'.
	v = canonicalizeSemverPrefix(v)

	events, err := normalizeEvents(ar.Events)
	if err != nil {
		return false, err
	}

	var affected bool
	for _, e := range events {
		if !affected && e.Introduced != "" {
			affected = e.Introduced == "0" || !Less(v, e.Introduced)
		} else if affected && e.Fixed != "" {
			affected = Less(v, e.Fixed)
		}
	}

	return affected, nil
}

// normalizeEvents validates events and returns a sorted copy
// in which introduced and fixed events strictly alternate,
// starting with an introduced event. Overlapping introduced
// events are merged into a single interval. The input slice
// is not modified.
//
// An error is returned if an event is malformed or if a
// fixed event cannot be matched to a preceding introduced
// event.
func normalizeEvents(events []osv.RangeEvent) ([]osv.RangeEvent, error) {
	// Copy the events so the caller's slice is never modified.
	sorted := make([]osv.RangeEvent, len(events))
	copy(sorted, events)

	for _, e := range sorted {
		switch {
		case e.Introduced != "" && e.Fixed != "":
			return nil, fmt.Errorf("semver range event has both introduced %q and fixed %q", e.Introduced, e.Fixed)
		case e.Introduced == "" && e.Fixed == "":
			return nil, fmt.Errorf("semver range event has neither introduced nor fixed")
		case e.Introduced != "" && e.Introduced != "0" && !Valid(e.Introduced):
			return nil, fmt.Errorf("invalid introduced version %q", e.Introduced)
		case e.Fixed != "" && (e.Fixed == "0" || !Valid(e.Fixed)):
			return nil, fmt.Errorf("invalid fixed version %q", e.Fixed)
		}
	}

	// Sort events by version using a strict weak ordering:
	// "0" (beginning of time) sorts before any other version,
	// and at the same version a fixed event sorts before an
	// introduced event so that adjacent intervals such as
	// [a, b), [b, c) are preserved.
	sort.SliceStable(sorted, func(i, j int) bool {
		if c := compareEventVersions(eventVersion(sorted[i]), eventVersion(sorted[j])); c != 0 {
			return c < 0
		}
		return sorted[i].Fixed != "" && sorted[j].Introduced != ""
	})

	// Merge events into an alternating sequence of introduced
	// and fixed events describing disjoint intervals.
	var merged []osv.RangeEvent
	affected := false
	var introduced string
	for _, e := range sorted {
		if e.Introduced != "" {
			if affected {
				// Overlapping introduction: the interval
				// started earlier, so this event is redundant.
				continue
			}
			affected = true
			introduced = e.Introduced
			merged = append(merged, e)
			continue
		}
		if !affected {
			return nil, fmt.Errorf("fixed version %q has no preceding introduced version", e.Fixed)
		}
		if introduced != "0" && !Less(introduced, e.Fixed) {
			return nil, fmt.Errorf("fixed version %q does not come after introduced version %q", e.Fixed, introduced)
		}
		affected = false
		merged = append(merged, e)
	}

	return merged, nil
}

// eventVersion returns the version of e, which is either
// its introduced or its fixed version.
func eventVersion(e osv.RangeEvent) string {
	if e.Introduced != "" {
		return e.Introduced
	}
	return e.Fixed
}

// compareEventVersions compares two event versions, where
// "0" represents the beginning of time and sorts before
// any other version.
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
