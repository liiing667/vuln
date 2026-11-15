// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package semver

import (
	"reflect"
	"testing"

	"golang.org/x/vuln/internal/osv"
)

func TestAffectsSemver(t *testing.T) {
	cases := []struct {
		affects []osv.Range
		version string
		want    bool
	}{
		{
			// empty []Range indicates everything is affected
			affects: []osv.Range{},
			version: "v0.0.0",
			want:    true,
		},
		{
			// []Range containing an empty SEMVER range also indicates
			// everything is affected
			affects: []osv.Range{{Type: osv.RangeTypeSemver}},
			version: "v0.0.0",
			want:    true,
		},
		{
			// []Range containing a SEMVER range with only an "introduced":"0"
			// also indicates everything is affected
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}}}},
			version: "v0.0.0",
			want:    true,
		},
		{
			// v1.0.0 < v2.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.1"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0 < v2.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0 < v2.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.1"}, {Fixed: "2.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v2.0.0 < v3.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}},
			version: "v3.0.0",
			want:    false,
		},
		{
			// Multiple ranges
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}, {Introduced: "3.0.0"}}}},
			version: "v3.0.0",
			want:    true,
		},
		{
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "1.18.6"}, {Introduced: "1.19.0"}, {Fixed: "1.19.1"}}}},
			version: "v1.18.6",
			want:    false,
		},
		{
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}, {Introduced: "1.19.0"}, {Fixed: "1.19.1"}}}},
			version: "v1.18.6",
			want:    true,
		},
		{
			// Multiple non-sorted ranges.
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.19.0"}, {Fixed: "1.19.1"}, {Introduced: "0"}, {Fixed: "1.18.6"}}}},
			version: "v1.18.1",
			want:    true,
		},
		{
			// Wrong type range
			affects: []osv.Range{{Type: osv.RangeType("unspecified"), Events: []osv.RangeEvent{{Introduced: "3.0.0"}}}},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Semver ranges don't match
			affects: []osv.Range{
				{Type: osv.RangeType("unspecified"), Events: []osv.RangeEvent{{Introduced: "3.0.0"}}},
				{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "4.0.0"}}},
			},
			version: "v3.0.0",
			want:    false,
		},
		{
			// Semver ranges do match
			affects: []osv.Range{
				{Type: osv.RangeType("unspecified"), Events: []osv.RangeEvent{{Introduced: "3.0.0"}}},
				{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "3.0.0"}}},
			},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Semver ranges match (go prefix)
			affects: []osv.Range{
				{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "3.0.0"}}},
			},
			version: "go3.0.1",
			want:    true,
		},
	}

	for _, c := range cases {
		got := Affects(c.affects, c.version)
		if c.want != got {
			t.Errorf("%#v.AffectsSemver(%s): want %t, got %t", c.affects, c.version, c.want, got)
		}
	}
}

func TestContainsSemverDoesNotModifyEvents(t *testing.T) {
	events := []osv.RangeEvent{
		{Introduced: "1.19.0"},
		{Fixed: "1.19.1"},
		{Introduced: "0"},
		{Fixed: "1.18.6"},
	}
	want := make([]osv.RangeEvent, len(events))
	copy(want, events)

	r := osv.Range{Type: osv.RangeTypeSemver, Events: events}
	got, err := ContainsSemver(r, "v1.18.1")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Errorf("ContainsSemver(v1.18.1) = false; want true")
	}
	if !reflect.DeepEqual(events, want) {
		t.Errorf("ContainsSemver modified events: got %v; want %v", events, want)
	}
}

func TestContainsSemverOrderIndependent(t *testing.T) {
	sorted := []osv.RangeEvent{
		{Introduced: "0"},
		{Fixed: "1.18.6"},
		{Introduced: "1.19.0"},
		{Fixed: "1.19.1"},
	}
	shuffled := []osv.RangeEvent{
		{Fixed: "1.19.1"},
		{Introduced: "1.19.0"},
		{Fixed: "1.18.6"},
		{Introduced: "0"},
	}
	for _, v := range []string{"v1.18.5", "v1.18.6", "v1.19.0", "v1.19.1", "v1.20.0"} {
		want, err := ContainsSemver(osv.Range{Type: osv.RangeTypeSemver, Events: sorted}, v)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ContainsSemver(osv.Range{Type: osv.RangeTypeSemver, Events: shuffled}, v)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("ContainsSemver(%s) = %t for shuffled events; want %t", v, got, want)
		}
	}
}

func TestContainsSemverNormalization(t *testing.T) {
	cases := []struct {
		name    string
		events  []osv.RangeEvent
		version string
		want    bool
	}{
		{
			// Overlapping introductions are merged into a
			// single interval starting at the earliest
			// introduced version.
			name:    "overlapping introduced",
			events:  []osv.RangeEvent{{Introduced: "0"}, {Introduced: "1.19.0"}, {Fixed: "1.19.1"}},
			version: "v1.18.6",
			want:    true,
		},
		{
			// Adjacent intervals [0, 1.0.0) and [1.0.0, 2.0.0):
			// the shared version belongs to the second interval.
			name:    "adjacent intervals shared version",
			events:  []osv.RangeEvent{{Introduced: "0"}, {Fixed: "1.0.0"}, {Introduced: "1.0.0"}, {Fixed: "2.0.0"}},
			version: "v1.0.0",
			want:    true,
		},
		{
			name:    "adjacent intervals first interval",
			events:  []osv.RangeEvent{{Introduced: "0"}, {Fixed: "1.0.0"}, {Introduced: "1.0.0"}, {Fixed: "2.0.0"}},
			version: "v0.9.0",
			want:    true,
		},
		{
			name:    "adjacent intervals after end",
			events:  []osv.RangeEvent{{Introduced: "0"}, {Fixed: "1.0.0"}, {Introduced: "1.0.0"}, {Fixed: "2.0.0"}},
			version: "v2.0.0",
			want:    false,
		},
		{
			// Shuffled adjacent intervals normalize to the
			// same disjoint intervals.
			name:    "adjacent intervals shuffled",
			events:  []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "1.0.0"}, {Introduced: "0"}, {Fixed: "2.0.0"}},
			version: "v1.0.0",
			want:    true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := osv.Range{Type: osv.RangeTypeSemver, Events: c.events}
			got, err := ContainsSemver(r, c.version)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("ContainsSemver(%s) = %t; want %t", c.version, got, c.want)
			}
		})
	}
}

func TestContainsSemverMalformed(t *testing.T) {
	cases := []struct {
		name   string
		events []osv.RangeEvent
	}{
		{"both introduced and fixed", []osv.RangeEvent{{Introduced: "1.0.0", Fixed: "2.0.0"}}},
		{"empty event", []osv.RangeEvent{{Introduced: "0"}, {}}},
		{"invalid introduced version", []osv.RangeEvent{{Introduced: "1.0.x"}}},
		{"invalid fixed version", []osv.RangeEvent{{Introduced: "0"}, {Fixed: "not-a-version"}}},
		{"fixed version zero", []osv.RangeEvent{{Introduced: "0"}, {Fixed: "0"}}},
		{"fixed without introduced", []osv.RangeEvent{{Fixed: "1.0.0"}}},
		{"fixed before introduced", []osv.RangeEvent{{Introduced: "2.0.0"}, {Fixed: "1.0.0"}}},
		{"fixed equal to introduced", []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "1.0.0"}}},
		{"overlapping fixed", []osv.RangeEvent{{Introduced: "0"}, {Fixed: "1.0.0"}, {Fixed: "2.0.0"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := osv.Range{Type: osv.RangeTypeSemver, Events: c.events}
			if got, err := ContainsSemver(r, "v1.0.0"); err == nil {
				t.Errorf("ContainsSemver = %t, nil; want error", got)
			}
		})
	}
}
