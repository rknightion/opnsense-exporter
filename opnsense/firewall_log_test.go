package opnsense

import (
	"net/http"
	"testing"
)

const firewallLogTCPPass = `[
  {
    "rulenr":"16","subrulenr":"115","anchorname":"","rid":"0","interface":"vtnet2",
    "reason":"match","action":"pass","dir":"out","ipversion":"4","protonum":"6",
    "protoname":"tcp","length":"60","src":"172.16.9.1","dst":"172.16.9.99",
    "srcport":"54046","dstport":"8082","tcpflags":"S","label":"allow web",
    "__timestamp__":"2026-07-13T20:21:57","__host__":"opnsense.internal",
    "__digest__":"aaa111","__spec__":["rulenr"]
  },
  {
    "rulenr":"1","subrulenr":"0","anchorname":"","rid":"deadbeef","interface":"vtnet0",
    "reason":"match","action":"block","dir":"in","ipversion":"6","protonum":"58",
    "protoname":"ipv6-icmp","length":"64","src":"fe80::1","dst":"fe80::2",
    "label":"default deny","__timestamp__":"2026-07-13T20:21:55","__host__":"opnsense.internal",
    "__digest__":"bbb222","__spec__":["rulenr"]
  }
]`

func TestFetchFirewallLog_ParsesAndPassesQuery(t *testing.T) {
	var gotLimit, gotDigest string
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/firewall/log" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		gotLimit = r.URL.Query().Get("limit")
		gotDigest = r.URL.Query().Get("digest")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(firewallLogTCPPass))
	})
	defer server.Close()

	rows, err := client.FetchFirewallLog(500, "cursor123")
	if err != nil {
		t.Fatalf("FetchFirewallLog: %v", err)
	}
	if gotLimit != "500" {
		t.Errorf("limit query = %q, want 500", gotLimit)
	}
	if gotDigest != "cursor123" {
		t.Errorf("digest query = %q, want cursor123", gotDigest)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	r0 := rows[0]
	if r0.Digest != "aaa111" || r0.Action != "pass" || r0.ProtoName != "tcp" ||
		r0.Src != "172.16.9.1" || r0.SrcPort != "54046" || r0.Label != "allow web" ||
		r0.Timestamp != "2026-07-13T20:21:57" || r0.RID != "0" || r0.TCPFlags != "S" {
		t.Errorf("row0 fields not parsed as expected: %+v", r0)
	}
	// The icmp row omits srcport/dstport/tcpflags entirely — they must decode empty.
	r1 := rows[1]
	if r1.SrcPort != "" || r1.DstPort != "" || r1.TCPFlags != "" {
		t.Errorf("icmp row should have empty port/tcpflags, got %+v", r1)
	}
	if r1.Action != "block" || r1.Label != "default deny" || r1.IPVersion != "6" {
		t.Errorf("row1 fields not parsed as expected: %+v", r1)
	}
}

func TestFetchFirewallLog_NoDigestOmitsParam(t *testing.T) {
	var hadDigest bool
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, hadDigest = r.URL.Query()["digest"]
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})
	defer server.Close()

	rows, err := client.FetchFirewallLog(1000, "")
	if err != nil {
		t.Fatalf("FetchFirewallLog: %v", err)
	}
	if hadDigest {
		t.Error("digest query param must be absent when cursor is empty")
	}
	if len(rows) != 0 {
		t.Errorf("got %d rows, want 0", len(rows))
	}
}

func TestFetchFirewallLog_ErrorSurfaced(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errorMessage":"boom"}`))
	})
	defer server.Close()

	_, err := client.FetchFirewallLog(10, "")
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", err.StatusCode)
	}
}
