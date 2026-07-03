package opnsense

import (
	"encoding/json"
	"math"
	"testing"
)

// bigCounter is larger than math.MaxInt32 (2147483647). On a 32-bit source build
// (GOARCH=386/arm) Go's int is 32-bit, so before #103 these values either failed
// json unmarshal (UnmarshalTypeError) or silently wrapped to negative garbage.
// These tests are architecture-independent: they fail conceptually on a 32-bit
// int and pass with the int64 fields regardless of build GOARCH.
const bigCounter = int64(8442646036)

func TestInt64Widening_FirewallPFStat(t *testing.T) {
	if bigCounter <= math.MaxInt32 {
		t.Fatal("test value must exceed MaxInt32 to be meaningful")
	}
	var s FirewallPFStat
	if err := json.Unmarshal([]byte(`{"in4_pass_bytes": 8442646036, "out6_pass_packets": 8442646036}`), &s); err != nil {
		t.Fatalf("unmarshal of a >2^31 byte counter must not error: %v", err)
	}
	if s.In4PassBytes != bigCounter {
		t.Errorf("In4PassBytes: got %d, want %d", s.In4PassBytes, bigCounter)
	}
	if s.Out6PassPackets != bigCounter {
		t.Errorf("Out6PassPackets: got %d, want %d", s.Out6PassPackets, bigCounter)
	}
}

func TestInt64Widening_FirewallRuleStat(t *testing.T) {
	var s firewallRuleStat
	if err := json.Unmarshal([]byte(`{"bytes": 43215459045, "packets": 8442646036}`), &s); err != nil {
		t.Fatalf("unmarshal of a >2^31 rule byte counter must not error: %v", err)
	}
	if s.Bytes != 43215459045 {
		t.Errorf("Bytes: got %d, want 43215459045", s.Bytes)
	}
}

func TestInt64Widening_IPsecPhase1(t *testing.T) {
	var r ipsecSearchResponse
	if err := json.Unmarshal([]byte(`{"rows":[{"bytes-in": 8442646036, "packets-out": 8442646036}]}`), &r); err != nil {
		t.Fatalf("unmarshal of a >2^31 ipsec byte counter must not error: %v", err)
	}
	if len(r.Rows) != 1 || r.Rows[0].BytesIn != bigCounter {
		t.Errorf("BytesIn not preserved: %+v", r.Rows)
	}
}

func TestInt64Widening_NumToInt(t *testing.T) {
	got := numToInt(json.Number("8442646036"))
	if got != bigCounter {
		t.Errorf("numToInt(8442646036) = %d, want %d (must not narrow/wrap)", got, bigCounter)
	}
}

func TestInt64Widening_Mbuf(t *testing.T) {
	var d mbufStatisticsData
	if err := json.Unmarshal([]byte(`{"bytes-in-use": 8442646036}`), &d); err != nil {
		t.Fatalf("unmarshal of a >2^31 mbuf byte counter must not error: %v", err)
	}
	if d.BytesInUse != bigCounter {
		t.Errorf("BytesInUse: got %d, want %d", d.BytesInUse, bigCounter)
	}
}
