package flow

import (
	"net/netip"
	"testing"
	"time"
)

// outRow builds a translated direction="out" state row: a LAN host behind the
// firewall's WAN address, talking to a remote endpoint.
func outRow(proto, wanAddr, wanPort, remote, remotePort, lanAddr, lanPort string) StateRow {
	return StateRow{
		Proto:     proto,
		Direction: "out",
		SrcAddr:   wanAddr,
		SrcPort:   wanPort,
		DstAddr:   remote,
		DstPort:   remotePort,
		NatAddr:   lanAddr,
		NatPort:   lanPort,
	}
}

func tuple(proto uint8, src string, sport uint16, dst string, dport uint16) routeKey {
	return routeKey{
		proto: proto,
		src:   netip.MustParseAddr(src),
		dst:   netip.MustParseAddr(dst),
		sport: sport,
		dport: dport,
	}
}

func TestBuildNATTableCanonicalisesBothDirections(t *testing.T) {
	tbl := BuildNATTable(NATTableInput{
		Rows:  []StateRow{outRow("tcp", "198.51.100.6", "42031", "203.0.113.9", "8007", "10.0.0.6", "36180")},
		Built: time.Unix(1700000000, 0),
	})

	// Each translated state contributes both directional forms.
	if got := tbl.Stats().Entries; got != 2 {
		t.Fatalf("Entries = %d, want 2 (the outbound form and its inbound reverse)", got)
	}

	t.Run("outbound post-NAT copy canonicalises to the LAN host", func(t *testing.T) {
		got, ok := tbl.Canonical(tuple(6, "198.51.100.6", 42031, "203.0.113.9", 8007))
		if !ok {
			t.Fatal("outbound post-NAT tuple was not recognised")
		}
		if want := tuple(6, "10.0.0.6", 36180, "203.0.113.9", 8007); got != want {
			t.Errorf("Canonical = %+v, want %+v", got, want)
		}
	})

	t.Run("inbound post-NAT copy canonicalises to the LAN host", func(t *testing.T) {
		// The reverse half is a separate unidirectional NetFlow record. Without it
		// the download of every conversation would stay doubled while the upload was
		// de-duplicated, which reads as an asymmetry in the traffic rather than a bug.
		got, ok := tbl.Canonical(tuple(6, "203.0.113.9", 8007, "198.51.100.6", 42031))
		if !ok {
			t.Fatal("inbound post-NAT tuple was not recognised")
		}
		if want := tuple(6, "203.0.113.9", 8007, "10.0.0.6", 36180); got != want {
			t.Errorf("Canonical = %+v, want %+v", got, want)
		}
	})

	t.Run("the PRE-NAT tuple is not itself a key", func(t *testing.T) {
		// This is what keeps the pre-NAT copy safe from suppression: only a genuine
		// post-NAT tuple ever resolves.
		if _, ok := tbl.Canonical(tuple(6, "10.0.0.6", 36180, "203.0.113.9", 8007)); ok {
			t.Error("the pre-NAT tuple resolved as a post-NAT copy; the pre-NAT record would be suppressed")
		}
	})
}

func TestBuildNATTableIgnoresRowsWithNoTranslation(t *testing.T) {
	// 1,009 of the 1,434 WAN-addressed records in the reference capture were
	// firewall-originated traffic with no twin at all. A table that answered for
	// those would suppress real records.
	rows := []StateRow{
		{Proto: "tcp", Direction: "in", SrcAddr: "10.0.0.6", SrcPort: "36180", DstAddr: "203.0.113.9", DstPort: "8007"},
		{Proto: "tcp", Direction: "out", SrcAddr: "198.51.100.6", SrcPort: "53", DstAddr: "203.0.113.9", DstPort: "53"},
	}
	tbl := BuildNATTable(NATTableInput{Rows: rows, Built: time.Unix(1700000000, 0)})
	if got := tbl.Stats().Entries; got != 0 {
		t.Errorf("Entries = %d, want 0: neither an in row nor an untranslated out row is a translation", got)
	}
	if got := tbl.Stats().Skipped; got != 0 {
		t.Errorf("Skipped = %d, want 0: those rows are normal, not unkeyable", got)
	}
}

func TestBuildNATTableCountsUnkeyableRows(t *testing.T) {
	rows := []StateRow{
		outRow("carp", "198.51.100.6", "1", "203.0.113.9", "2", "10.0.0.6", "3"),         // unmodelled proto
		outRow("tcp", "not-an-address", "1", "203.0.113.9", "2", "10.0.0.6", "3"),        // bad addr
		outRow("tcp", "198.51.100.6", "not-a-port", "203.0.113.9", "2", "10.0.0.6", "3"), // bad port
	}
	tbl := BuildNATTable(NATTableInput{Rows: rows, Built: time.Unix(1700000000, 0)})
	if got := tbl.Stats().Skipped; got != 3 {
		t.Errorf("Skipped = %d, want 3 — an unkeyable row must be counted, not silently dropped", got)
	}
	if got := tbl.Stats().Entries; got != 0 {
		t.Errorf("Entries = %d, want 0", got)
	}
}

func TestBuildNATTableSkipsPassThroughTranslation(t *testing.T) {
	// The endpoint did not change, so there is no second copy to tell apart.
	tbl := BuildNATTable(NATTableInput{
		Rows:  []StateRow{outRow("udp", "10.0.0.6", "500", "203.0.113.9", "500", "10.0.0.6", "500")},
		Built: time.Unix(1700000000, 0),
	})
	if got := tbl.Stats().Entries; got != 0 {
		t.Errorf("Entries = %d, want 0 for a pass-through translation", got)
	}
}

func TestBuildNATTableFirstWriterWinsAndConflictsAreCounted(t *testing.T) {
	same := outRow("tcp", "198.51.100.6", "42031", "203.0.113.9", "8007", "10.0.0.6", "36180")
	clash := outRow("tcp", "198.51.100.6", "42031", "203.0.113.9", "8007", "10.0.0.7", "40000")
	tbl := BuildNATTable(NATTableInput{Rows: []StateRow{same, clash}, Built: time.Unix(1700000000, 0)})

	if got := tbl.Stats().Conflicts; got != 2 {
		t.Errorf("Conflicts = %d, want 2 (both directional forms clashed)", got)
	}
	got, _ := tbl.Canonical(tuple(6, "198.51.100.6", 42031, "203.0.113.9", 8007))
	if want := tuple(6, "10.0.0.6", 36180, "203.0.113.9", 8007); got != want {
		t.Errorf("Canonical = %+v, want the FIRST writer %+v", got, want)
	}
}

func TestBuildNATTableIdenticalRowIsNotAConflict(t *testing.T) {
	row := outRow("tcp", "198.51.100.6", "42031", "203.0.113.9", "8007", "10.0.0.6", "36180")
	tbl := BuildNATTable(NATTableInput{Rows: []StateRow{row, row}, Built: time.Unix(1700000000, 0)})
	if got := tbl.Stats().Conflicts; got != 0 {
		t.Errorf("Conflicts = %d, want 0: the same mapping twice is not an ambiguity", got)
	}
}

func TestBuildNATTableCarriesForwardWithinRetention(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	row := outRow("tcp", "198.51.100.6", "42031", "203.0.113.9", "8007", "10.0.0.6", "36180")
	first := BuildNATTable(NATTableInput{Rows: []StateRow{row}, Built: t0})

	t.Run("an expired translation stays answerable inside the window", func(t *testing.T) {
		// This is the whole reason the union exists: the post-NAT copy arrives a
		// median of 20s after its twin, by which time the state may be gone.
		next := BuildNATTable(NATTableInput{
			Rows: nil, Built: t0.Add(time.Minute), Previous: first, Retain: 3 * time.Minute,
		})
		if _, ok := next.Canonical(tuple(6, "198.51.100.6", 42031, "203.0.113.9", 8007)); !ok {
			t.Fatal("carried mapping was not answerable")
		}
		if got := next.Stats().Carried; got != 2 {
			t.Errorf("Carried = %d, want 2", got)
		}
	})

	t.Run("it ages out past the window", func(t *testing.T) {
		next := BuildNATTable(NATTableInput{
			Rows: nil, Built: t0.Add(4 * time.Minute), Previous: first, Retain: 3 * time.Minute,
		})
		if _, ok := next.Canonical(tuple(6, "198.51.100.6", 42031, "203.0.113.9", 8007)); ok {
			t.Error("a mapping older than Retain is still answerable")
		}
	})

	t.Run("zero Retain disables carrying entirely", func(t *testing.T) {
		next := BuildNATTable(NATTableInput{Rows: nil, Built: t0.Add(time.Second), Previous: first})
		if got := next.Stats().Entries; got != 0 {
			t.Errorf("Entries = %d, want 0 with Retain unset", got)
		}
	})

	t.Run("a fresh row wins over a carried one", func(t *testing.T) {
		moved := outRow("tcp", "198.51.100.6", "42031", "203.0.113.9", "8007", "10.0.0.9", "36180")
		next := BuildNATTable(NATTableInput{
			Rows: []StateRow{moved}, Built: t0.Add(time.Minute), Previous: first, Retain: 3 * time.Minute,
		})
		got, _ := next.Canonical(tuple(6, "198.51.100.6", 42031, "203.0.113.9", 8007))
		if want := tuple(6, "10.0.0.9", 36180, "203.0.113.9", 8007); got != want {
			t.Errorf("Canonical = %+v, want the FRESH mapping %+v", got, want)
		}
		if got := next.Stats().Conflicts; got != 0 {
			t.Errorf("Conflicts = %d, want 0: a tuple in both snapshots is a live state, not an ambiguity", got)
		}
	})
}

func TestNilNATTableIsInert(t *testing.T) {
	var tbl *NATTable
	if _, ok := tbl.Canonical(tuple(6, "198.51.100.6", 1, "203.0.113.9", 2)); ok {
		t.Error("a nil table answered")
	}
	if got := tbl.Stats(); got != (NATTableStats{}) {
		t.Errorf("Stats = %+v, want zero", got)
	}
	if got := tbl.Age(time.Unix(1700000000, 0)); got != 0 {
		t.Errorf("Age = %v, want 0", got)
	}
}
