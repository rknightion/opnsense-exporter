package opnsense

import (
	"net/http"
	"testing"
)

// trafficShaperFixture is the self-consistent test fixture from the plan:
//   - One pipe (id "00001") — flows are always empty on the pipe item itself.
//   - One template:true queue (id "00001.65", pipe "00001") carrying 1 flow and
//     1 rule (attached_to "00001"). This row is the pipe's flow source.
//   - One non-template queue (id "00001.66") with no flows and no rules.
//
// After processing:
//   - Pipe "00001" gets flow stats from the template-queue row.
//   - Queue list contains ONLY "00001.66" (template row excluded).
//   - 1 rule with TargetType "pipe", AttachedTo "00001".
const trafficShaperFixture = `{
  "status": "ok",
  "items": [
    {
      "type": "pipe",
      "id": "00001",
      "pipe": "00001",
      "bw": "10.000 Mbit/s",
      "delay": "0",
      "burst": "0",
      "description": "WAN down",
      "uuid": "u-1",
      "flows": [],
      "rules": []
    },
    {
      "type": "queue",
      "template": true,
      "pipe": "00001",
      "id": "00001.65",
      "flow_set_nr": "65",
      "weight": "1",
      "description": "",
      "flows": [
        {"BKT": "0", "Prot": "ip", "Source": "0.0.0.0/0", "Destination": "0.0.0.0/0",
         "pkt": 1234, "bytes": 567890, "drop_pkt": 3, "drop_bytes": 1500}
      ],
      "rules": [
        {"rule": "60001", "pkts": 999, "bytes": 88888,
         "accessed": "2026-06-09T08:00:00", "accessed_epoch": 1780000000,
         "attached_to": "00001", "rule_uuid": "u-2", "description": "Shape WAN"}
      ]
    },
    {
      "type": "queue",
      "id": "00001.66",
      "flow_set_nr": "66",
      "sched_nr": "00001",
      "pipe": null,
      "description": "VoIP",
      "flows": [],
      "rules": []
    }
  ]
}`

func TestFetchTrafficShaperStatistics_Normal(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(trafficShaperFixture))
	})
	defer server.Close()

	data, err := client.FetchTrafficShaperStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}

	// 1 pipe
	if len(data.Pipes) != 1 {
		t.Fatalf("expected 1 pipe, got %d", len(data.Pipes))
	}
	pipe := data.Pipes[0]
	if pipe.ID != "00001" {
		t.Errorf("pipe.ID = %q, want %q", pipe.ID, "00001")
	}
	if pipe.Description != "WAN down" {
		t.Errorf("pipe.Description = %q, want %q", pipe.Description, "WAN down")
	}
	if pipe.Packets != 1234 {
		t.Errorf("pipe.Packets = %v, want 1234 (from template-queue flow)", pipe.Packets)
	}
	if pipe.Bytes != 567890 {
		t.Errorf("pipe.Bytes = %v, want 567890", pipe.Bytes)
	}
	if pipe.DropPackets != 3 {
		t.Errorf("pipe.DropPackets = %v, want 3", pipe.DropPackets)
	}
	if pipe.DropBytes != 1500 {
		t.Errorf("pipe.DropBytes = %v, want 1500", pipe.DropBytes)
	}
	if pipe.ActiveFlows != 1 {
		t.Errorf("pipe.ActiveFlows = %v, want 1", pipe.ActiveFlows)
	}
	// #584: configured-capacity fields, from the pipe item's own bw/delay/burst
	// (dummynet.c's DN_LINK print: "%7.3f Mbit/s", "%4d ms", humanized burst)
	// and (for weight) folded from the template-queue row per the same
	// attribution the flow stats above already use.
	if !pipe.ConfiguredBandwidthOK {
		t.Error("expected ConfiguredBandwidthOK=true for bw \"10.000 Mbit/s\"")
	}
	if pipe.ConfiguredBandwidthBps != 10_000_000 {
		t.Errorf("pipe.ConfiguredBandwidthBps = %v, want 1e7 (10 Mbit/s)", pipe.ConfiguredBandwidthBps)
	}
	if !pipe.ConfiguredDelayOK {
		t.Error("expected ConfiguredDelayOK=true for delay \"0\"")
	}
	if pipe.ConfiguredDelayMs != 0 {
		t.Errorf("pipe.ConfiguredDelayMs = %v, want 0", pipe.ConfiguredDelayMs)
	}
	if !pipe.ConfiguredBurstOK {
		t.Error("expected ConfiguredBurstOK=true for burst \"0\"")
	}
	if pipe.ConfiguredBurstBytes != 0 {
		t.Errorf("pipe.ConfiguredBurstBytes = %v, want 0", pipe.ConfiguredBurstBytes)
	}
	if !pipe.ConfiguredWeightOK {
		t.Error("expected ConfiguredWeightOK=true, folded from the template-queue row's weight")
	}
	if pipe.ConfiguredWeight != 1 {
		t.Errorf("pipe.ConfiguredWeight = %v, want 1", pipe.ConfiguredWeight)
	}
	// This fixture's template queue carries no queue_size key at all.
	if pipe.ConfiguredQueueSizeOK {
		t.Error("expected ConfiguredQueueSizeOK=false: this fixture's template queue has no queue_size key")
	}

	// 1 queue (template row excluded)
	if len(data.Queues) != 1 {
		t.Fatalf("expected 1 queue (template excluded), got %d", len(data.Queues))
	}
	q := data.Queues[0]
	if q.ID != "00001.66" {
		t.Errorf("queue.ID = %q, want %q", q.ID, "00001.66")
	}
	if q.Description != "VoIP" {
		t.Errorf("queue.Description = %q, want %q", q.Description, "VoIP")
	}
	if q.Packets != 0 || q.Bytes != 0 || q.ActiveFlows != 0 {
		t.Errorf("non-template queue expected all zeros, got: %+v", q)
	}
	// Pipe label should be derived from id prefix (pipe field was null).
	if q.Pipe != "00001" {
		t.Errorf("queue.Pipe = %q, want %q (derived from id prefix)", q.Pipe, "00001")
	}

	// 1 rule with TargetType "pipe"
	if len(data.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(data.Rules))
	}
	rule := data.Rules[0]
	if rule.Rule != "60001" {
		t.Errorf("rule.Rule = %q, want %q", rule.Rule, "60001")
	}
	if rule.AttachedTo != "00001" {
		t.Errorf("rule.AttachedTo = %q, want %q", rule.AttachedTo, "00001")
	}
	if rule.TargetType != "pipe" {
		t.Errorf("rule.TargetType = %q, want %q (template-queue rule)", rule.TargetType, "pipe")
	}
	if rule.Description != "Shape WAN" {
		t.Errorf("rule.Description = %q, want %q", rule.Description, "Shape WAN")
	}
	if rule.Packets != 999 {
		t.Errorf("rule.Packets = %v, want 999", rule.Packets)
	}
	if rule.Bytes != 88888 {
		t.Errorf("rule.Bytes = %v, want 88888", rule.Bytes)
	}
	// accessed_epoch (rider, #224): the fixture's rule carries 1780000000.
	if rule.LastMatchEpoch != 1780000000 {
		t.Errorf("rule.LastMatchEpoch = %v, want 1780000000", rule.LastMatchEpoch)
	}
}

// TestFetchTrafficShaperStatistics_ConfiguredCapacity guards #584's unit
// normalization across the full range of wire shapes FreeBSD's dnctl(8)/
// dummynet.c can produce for bw/burst/queue_size, which OPNsense's
// scripts/shaper/lib/__init__.py passes through as pre-formatted strings with
// no separate unit field:
//   - bw: "unlimited" (bandwidth==0, dummynet.c:634 -- a real "no cap
//     configured", must yield ok=false, never a fabricated 0 bps)
//   - burst: a humanize_number()-scaled byte count with a bare K/M/G/T suffix
//     (dummynet.c:645, third humanize_number arg "" -- no "B" suffix)
//   - queue_size: EITHER "NNN sl." (packet-slot limit) or "NNN B"/"NNN KB"
//     (byte limit) depending on the queue's DN_QSIZE_BYTES flag
//     (dummynet.c:477-484, print_flowset_parms) -- two different physical
//     quantities behind the same field, disambiguated here with a unit label
//     rather than silently picking one.
func TestFetchTrafficShaperStatistics_ConfiguredCapacity(t *testing.T) {
	const fixture = `{
	  "status": "ok",
	  "items": [
	    {
	      "type": "pipe",
	      "id": "00002",
	      "pipe": "00002",
	      "bw": "unlimited",
	      "delay": "20",
	      "burst": "10K",
	      "description": "Unlimited pipe",
	      "flows": [],
	      "rules": []
	    },
	    {
	      "type": "queue",
	      "id": "00002.67",
	      "flow_set_nr": "67",
	      "sched_nr": "00002",
	      "queue_size": "50 sl.",
	      "weight": "5",
	      "description": "Slots queue",
	      "flows": [],
	      "rules": []
	    },
	    {
	      "type": "queue",
	      "id": "00002.68",
	      "flow_set_nr": "68",
	      "sched_nr": "00002",
	      "queue_size": "16 KB",
	      "weight": "10",
	      "description": "Bytes queue",
	      "flows": [],
	      "rules": []
	    }
	  ]
	}`

	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixture))
	})
	defer server.Close()

	data, err := client.FetchTrafficShaperStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Pipes) != 1 {
		t.Fatalf("expected 1 pipe, got %d", len(data.Pipes))
	}
	pipe := data.Pipes[0]
	if pipe.ConfiguredBandwidthOK {
		t.Error("expected ConfiguredBandwidthOK=false for bw \"unlimited\" (no cap configured, not 0 bps)")
	}
	if !pipe.ConfiguredDelayOK || pipe.ConfiguredDelayMs != 20 {
		t.Errorf("expected ConfiguredDelayMs=20 (ok=true), got %v (ok=%v)", pipe.ConfiguredDelayMs, pipe.ConfiguredDelayOK)
	}
	if !pipe.ConfiguredBurstOK {
		t.Error("expected ConfiguredBurstOK=true for humanized burst \"10K\"")
	}
	if pipe.ConfiguredBurstBytes != 10*1024 {
		t.Errorf("pipe.ConfiguredBurstBytes = %v, want %v (10K = 10*1024 bytes)", pipe.ConfiguredBurstBytes, 10*1024)
	}

	if len(data.Queues) != 2 {
		t.Fatalf("expected 2 queues, got %d", len(data.Queues))
	}
	var slots, bytesQ TrafficShaperEntity
	for _, q := range data.Queues {
		switch q.Description {
		case "Slots queue":
			slots = q
		case "Bytes queue":
			bytesQ = q
		}
	}

	if !slots.ConfiguredQueueSizeOK || slots.ConfiguredQueueSizeUnit != "packets" {
		t.Errorf("expected Slots queue ConfiguredQueueSizeUnit=packets (ok=true), got unit=%q ok=%v",
			slots.ConfiguredQueueSizeUnit, slots.ConfiguredQueueSizeOK)
	}
	if slots.ConfiguredQueueSize != 50 {
		t.Errorf("expected Slots queue ConfiguredQueueSize=50, got %v", slots.ConfiguredQueueSize)
	}
	if !slots.ConfiguredWeightOK || slots.ConfiguredWeight != 5 {
		t.Errorf("expected Slots queue ConfiguredWeight=5 (ok=true), got %v (ok=%v)", slots.ConfiguredWeight, slots.ConfiguredWeightOK)
	}

	if !bytesQ.ConfiguredQueueSizeOK || bytesQ.ConfiguredQueueSizeUnit != "bytes" {
		t.Errorf("expected Bytes queue ConfiguredQueueSizeUnit=bytes (ok=true), got unit=%q ok=%v",
			bytesQ.ConfiguredQueueSizeUnit, bytesQ.ConfiguredQueueSizeOK)
	}
	// "16 KB" -> dummynet.c divides by 1024 to print KB, so the real byte
	// count must be multiplied back: 16 * 1024 = 16384.
	if bytesQ.ConfiguredQueueSize != 16*1024 {
		t.Errorf("expected Bytes queue ConfiguredQueueSize=16384 (16 KB), got %v", bytesQ.ConfiguredQueueSize)
	}
	if !bytesQ.ConfiguredWeightOK || bytesQ.ConfiguredWeight != 10 {
		t.Errorf("expected Bytes queue ConfiguredWeight=10 (ok=true), got %v (ok=%v)", bytesQ.ConfiguredWeight, bytesQ.ConfiguredWeightOK)
	}
}

// TestFetchTrafficShaperStatistics_RuleNeverMatched guards the shaper
// scripts/shaper/lib/__init__.py sentinel: a rule that has never matched
// traffic reports accessed_epoch=0 (not a real Unix timestamp), which must be
// distinguishable from "matched at the Unix epoch" so the collector can skip
// emitting the gauge rather than reporting a bogus 1970 last-match (#224).
func TestFetchTrafficShaperStatistics_RuleNeverMatched(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
		  "status": "ok",
		  "items": [
		    {
		      "type": "pipe", "id": "00001", "pipe": "00001", "description": "WAN down",
		      "flows": [],
		      "rules": [
		        {"rule": "60002", "pkts": 0, "bytes": 0,
		         "accessed": "", "accessed_epoch": 0,
		         "attached_to": "00001", "description": "Never matched"}
		      ]
		    }
		  ]
		}`))
	})
	defer server.Close()

	data, err := client.FetchTrafficShaperStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(data.Rules))
	}
	if data.Rules[0].LastMatchEpoch != 0 {
		t.Errorf("expected LastMatchEpoch=0 for a rule that never matched, got %v", data.Rules[0].LastMatchEpoch)
	}
}

func TestFetchTrafficShaperStatistics_Unconfigured(t *testing.T) {
	// Shaper unconfigured: status ok, empty items array.
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok", "items": []}`))
	})
	defer server.Close()

	data, err := client.FetchTrafficShaperStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true when status=ok (even with empty items)")
	}
	if len(data.Pipes) != 0 || len(data.Queues) != 0 || len(data.Rules) != 0 {
		t.Errorf("expected empty pipes/queues/rules for unconfigured shaper, got: %+v", data)
	}
}

func TestFetchTrafficShaperStatistics_Failed(t *testing.T) {
	// Stats unavailable: status "failed", no items key.
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "failed"}`))
	})
	defer server.Close()

	data, err := client.FetchTrafficShaperStatistics()
	if err != nil {
		t.Fatalf("unexpected error on status=failed: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false when status=failed")
	}
}

func TestFetchTrafficShaperStatistics_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchTrafficShaperStatistics()
	if err != nil {
		t.Fatalf("expected nil error on 404 (feature absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}
