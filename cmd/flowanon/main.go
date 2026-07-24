// Command flowanon builds the committed NetFlow v9 replay fixture from a production
// capture.
//
// It reads a capture in either supported form, selects the minimal set of real
// datagrams that retains every case the replay test needs, anonymises them (see
// anon.go for the contract), and writes the anonymised subset to the fixture path.
//
// Two input forms, both auto-detected (see capture.go):
//
//   - The exporter's own debug capture — NDJSON under <capture-dir>/netflow/, written
//     by --flow.netflow.debug-capture=all with --logs.debug-capture.dir set (#360).
//     This is how a NEW capture is taken. Point -in at the file or the directory; a
//     rotated set is read whole, in file order.
//   - The raw frame dump [unix-nanos u64][addr-len u8][addr][payload-len u32][payload]
//     per datagram. The committed fixture was produced from one of these, by a
//     throwaway tool that predates the exporter's own capture path and was never
//     committed — which is exactly why that path exists now.
//
// The capture itself is NEVER committed and is not available in CI. This tool is
// committed and its address/byte-rewriting core is unit-tested (anon_test.go); the
// fixture it produced is committed and replayed by internal/flow/netflow and
// internal/flow tests. Re-running it against the same capture reproduces the fixture
// byte for byte.
//
// The frame indices in fixtureFrames below are into the ORIGINAL 2026-07-21 capture.
// A fresh capture is a different stream, so regenerating the fixture from one means
// re-selecting the cases as well — see the comment on fixtureFrames.
//
// Usage:
//
//	go run ./cmd/flowanon -in /var/opnsense-capture/netflow \
//	    -out internal/flow/netflow/testdata/replay-v9.bin
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"
)

// selection names each datagram the fixture retains and the case it carries. The
// frame indices are into the raw 2026-07-21 capture (38,884 datagrams); each was
// located by decoding the whole capture with the real decoder + ifmap. See the brief
// / issue #346 for how each was found.
type selection struct {
	frame int
	why   string
}

// fixtureFrames is the ordered output list. Order is load-bearing: the data-only
// datagram is emitted FIRST, before the template datagram, so a fresh decoder
// replaying the fixture sees data before its template and counts it (the real
// cold-start path). Every later datagram decodes because frame 0 taught the
// templates.
var fixtureFrames = []selection{
	{1, "data-before-template: data-only datagram, emitted first so a fresh decoder counts NoTemplate"},
	{0, "templates 256 (IPv4) + 259 (IPv6), plus IPv6 data flows (the IPv6 case)"},
	{82, "VLAN-duplicate pair copy: 5-tuple also seen on the parent/child interface in frame 88"},
	{88, "VLAN-duplicate pair copy: same 5-tuple+FIRST+LAST across ixl0 and ixl0_vlan50"},
	{182, "policy-routed WAN mislabel: src is WAN2 (igb0) NAT addr but OUTPUT_SNMP names pppoe0 (WAN1)"},
	{19681, "multi-fragment connection: 3+ records of one 5-tuple share a community-id"},
	{19691, "multi-fragment connection (continued)"},
}

// timeAnchor is where the earliest selected datagram's export time is shifted to.
// The shift is one constant applied to every datagram, so relative spacing and the
// cross-datagram VLAN-duplicate key are preserved while the real capture date is not
// revealed. 2020-01-01 is deliberately not the capture's real date (2026-07-21).
var timeAnchor = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

type frame struct {
	idx      int
	recvUnix int64 // nanoseconds
	exporter netip.Addr
	payload  []byte
}

func main() {
	in := flag.String("in", "", "capture path: a debug-capture file or directory, or a raw frame dump (required)")
	out := flag.String("out", "internal/flow/netflow/testdata/replay-v9.bin", "fixture output path")
	flag.Parse()
	if *in == "" {
		fmt.Fprintln(os.Stderr, "flowanon: -in is required")
		os.Exit(2)
	}
	if err := run(*in, *out); err != nil {
		fmt.Fprintf(os.Stderr, "flowanon: %v\n", err)
		os.Exit(1)
	}
}

func run(inPath, outPath string) error {
	frames, err := readInput(inPath)
	if err != nil {
		return err
	}

	byIdx := make(map[int]frame, len(frames))
	for _, f := range frames {
		byIdx[f.idx] = f
	}

	// Learn + rewrite in ASCENDING index order, so the template datagram (frame 0) is
	// processed before the data-only datagram (frame 1) whose addresses can only be
	// located once its template is known. The output order is independent (below).
	ascending := make([]selection, len(fixtureFrames))
	copy(ascending, fixtureFrames)
	sort.Slice(ascending, func(i, j int) bool { return ascending[i].frame < ascending[j].frame })

	anon := newAnonymizer()

	// The shift maps the earliest selected export time to timeAnchor.
	minSecs := int64(1<<62 - 1)
	for _, s := range ascending {
		f, ok := byIdx[s.frame]
		if !ok {
			return fmt.Errorf("frame %d not present in capture (%d datagrams)", s.frame, len(frames))
		}
		if len(f.payload) < 12 {
			return fmt.Errorf("frame %d shorter than a v9 header", s.frame)
		}
		if secs := int64(binary.BigEndian.Uint32(f.payload[8:12])); secs != 0 && secs < minSecs {
			minSecs = secs
		}
	}
	secShift := timeAnchor.Unix() - minSecs
	nsShift := secShift * int64(time.Second)

	rewritten := make(map[int]frame, len(ascending))
	for _, s := range ascending {
		f := byIdx[s.frame]
		if err := rewriteDatagram(anon, f.payload, secShift); err != nil {
			return fmt.Errorf("frame %d: %w", s.frame, err)
		}
		f.exporter = anon.mapAddr(f.exporter)
		f.recvUnix += nsShift
		rewritten[s.frame] = f
	}

	// Emit in the declared fixture order.
	var buf []byte
	for _, s := range fixtureFrames {
		buf = appendFrame(buf, rewritten[s.frame])
	}
	if err := os.WriteFile(outPath, buf, 0o644); err != nil {
		return err
	}

	printManifest(anon, outPath, len(buf))
	return nil
}

// readFrames parses the capture's frame wrapper. It tolerates a truncated trailing
// frame (a capture killed mid-write) by stopping at the first short frame.
func readFrames(raw []byte) ([]frame, error) {
	var frames []frame
	off, idx := 0, 0
	for off+13 <= len(raw) {
		nanos := int64(binary.BigEndian.Uint64(raw[off : off+8]))
		alen := int(raw[off+8])
		if off+9+alen+4 > len(raw) {
			break
		}
		addr, ok := netip.AddrFromSlice(raw[off+9 : off+9+alen])
		if !ok {
			return nil, fmt.Errorf("frame %d: bad %d-byte address", idx, alen)
		}
		plen := int(binary.BigEndian.Uint32(raw[off+9+alen : off+9+alen+4]))
		start := off + 9 + alen + 4
		if start+plen > len(raw) {
			break
		}
		p := make([]byte, plen)
		copy(p, raw[start:start+plen])
		frames = append(frames, frame{idx: idx, recvUnix: nanos, exporter: addr.Unmap(), payload: p})
		off = start + plen
		idx++
	}
	if len(frames) == 0 {
		return nil, fmt.Errorf("no frames read")
	}
	return frames, nil
}

// appendFrame writes one datagram in the capture's frame format.
func appendFrame(dst []byte, f frame) []byte {
	var hdr [8]byte
	binary.BigEndian.PutUint64(hdr[:], uint64(f.recvUnix))
	dst = append(dst, hdr[:]...)
	ip := f.exporter.AsSlice()
	dst = append(dst, byte(len(ip)))
	dst = append(dst, ip...)
	var plen [4]byte
	binary.BigEndian.PutUint32(plen[:], uint32(len(f.payload)))
	dst = append(dst, plen[:]...)
	dst = append(dst, f.payload...)
	return dst
}

func printManifest(a *anonymizer, outPath string, size int) {
	fmt.Printf("wrote %s (%d datagrams, %d bytes)\n", outPath, len(fixtureFrames), size)
	fmt.Println("retained cases:")
	for _, s := range fixtureFrames {
		fmt.Printf("  raw-frame %-6d %s\n", s.frame, s.why)
	}
	fmt.Println("key anonymised addresses (raw -> fixture):")
	for raw, anonAddr := range pinnedMap() {
		fmt.Printf("  %-20s -> %s\n", raw, anonAddr)
	}
}
