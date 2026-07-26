package netflow

import (
	"encoding/binary"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"
)

// fuzzReplayPayloads reads the committed anonymised replay fixture without
// depending on testing.T helpers. The fixture's wrapper is
// [unix-nanos u64][addr-len u8][addr][payload-len u32][payload].
func fuzzReplayPayloads(f *testing.F) []struct {
	payload  []byte
	exporter netip.Addr
	received time.Time
} {
	f.Helper()
	raw, err := os.ReadFile(replayFixture)
	if err != nil {
		f.Fatalf("read %s: %v", replayFixture, err)
	}

	var frames []struct {
		payload  []byte
		exporter netip.Addr
		received time.Time
	}
	for off := 0; off+13 <= len(raw); {
		nanos := int64(binary.BigEndian.Uint64(raw[off : off+8]))
		addrLen := int(raw[off+8])
		if off+9+addrLen+4 > len(raw) {
			f.Fatalf("fixture frame header at %d is truncated", off)
		}
		exporter, ok := netip.AddrFromSlice(raw[off+9 : off+9+addrLen])
		if !ok {
			f.Fatalf("fixture frame at %d has an invalid exporter", off)
		}
		payloadLen := int(binary.BigEndian.Uint32(raw[off+9+addrLen : off+9+addrLen+4]))
		start := off + 9 + addrLen + 4
		if payloadLen > maxDatagram || start+payloadLen > len(raw) {
			f.Fatalf("fixture payload at %d is invalid", off)
		}
		frames = append(frames, struct {
			payload  []byte
			exporter netip.Addr
			received time.Time
		}{
			payload:  append([]byte(nil), raw[start:start+payloadLen]...),
			exporter: exporter.Unmap(),
			received: time.Unix(0, nanos),
		})
		off = start + payloadLen
	}
	if len(frames) == 0 {
		f.Fatal("replay fixture has no frames")
	}
	return frames
}

// FuzzDecodePacketAndTemplate exercises the stateful v9 template cache with a
// template packet followed by a data packet. A fresh decoder per input makes the
// state deterministic; the two packet caps bound template-cache allocation.
func FuzzDecodePacketAndTemplate(f *testing.F) {
	frames := fuzzReplayPayloads(f)
	for i := range frames {
		f.Add(frames[i].payload, frames[(i+1)%len(frames)].payload)
	}

	// Existing byte-level regression builders provide a known template-then-data
	// transaction in addition to the anonymised real replay seeds.
	template := v9Datagram(testHead(1000), templateFlowset(ipv4Template()))
	data := v9Datagram(testHead(1000), dataFlowset(256, make([]byte, 57)))
	f.Add(template, data)

	f.Fuzz(func(t *testing.T, template, data []byte) {
		if len(template) > maxDatagram || len(data) > maxDatagram {
			t.Skip()
		}

		decode := func() ([]*Datagram, []error, Stats, int) {
			decoder := New()
			outputs := make([]*Datagram, 0, 2)
			errs := make([]error, 0, 2)
			for _, packet := range [][]byte{template, data} {
				output, err := decoder.Decode(packet, testExporter, testNow)
				outputs = append(outputs, output)
				errs = append(errs, err)
			}
			return outputs, errs, decoder.Stats(), len(decoder.templates)
		}

		outputs, errs, stats, templates := decode()
		againOutputs, againErrs, againStats, againTemplates := decode()
		if !reflect.DeepEqual(outputs, againOutputs) || !reflect.DeepEqual(errs, againErrs) || stats != againStats || templates != againTemplates {
			t.Fatal("template transaction is not deterministic")
		}
		for _, output := range outputs {
			if output == nil {
				continue
			}
			if len(output.Records) > maxDatagram {
				t.Fatalf("decoded %d records from a %d-byte-bounded transaction", len(output.Records), maxDatagram)
			}
			if len(output.Unidentified) > maxUnidentifiedPerDatagram {
				t.Fatalf("unidentified report has %d entries, limit is %d", len(output.Unidentified), maxUnidentifiedPerDatagram)
			}
		}
		// A stored template consumes at least its 4-byte definition and one 4-byte
		// field descriptor. Two bounded packets therefore cannot retain more than
		// this many cache entries.
		if templates > (len(template)+len(data))/8 {
			t.Fatalf("template cache has %d entries from %d input bytes", templates, len(template)+len(data))
		}
	})
}
