package syslog

import (
	"testing"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
)

func TestSampleKeep(t *testing.T) {
	tests := []struct {
		name    string
		program string
		rec     logship.Record
		counted bool
		want    bool
	}{
		{
			name:    "uncounted line is always kept, regardless of program",
			program: "filterlog",
			rec:     logship.Record{Attributes: map[string]string{"action": "pass"}},
			counted: false,
			want:    true,
		},
		{
			name:    "uncounted non-derived program is kept",
			program: "unbound",
			rec:     logship.Record{},
			counted: false,
			want:    true,
		},
		{
			name:    "counted firewall pass is dropped",
			program: "filterlog",
			rec:     logship.Record{Attributes: map[string]string{"action": "pass"}},
			counted: true,
			want:    false,
		},
		{
			name:    "counted firewall block is kept",
			program: "filterlog",
			rec:     logship.Record{Attributes: map[string]string{"action": "block"}},
			counted: true,
			want:    true,
		},
		{
			name:    "counted haproxy at info severity is dropped",
			program: "haproxy",
			rec:     logship.Record{Severity: logship.SeverityInfo},
			counted: true,
			want:    false,
		},
		{
			name:    "counted haproxy at warn severity is kept",
			program: "haproxy",
			rec:     logship.Record{Severity: logship.SeverityWarn},
			counted: true,
			want:    true,
		},
		{
			name:    "counted haproxy at error severity is kept",
			program: "haproxy",
			rec:     logship.Record{Severity: logship.SeverityError},
			counted: true,
			want:    true,
		},
		{
			name:    "counted sshd is always kept",
			program: "sshd",
			rec:     logship.Record{Severity: logship.SeverityInfo},
			counted: true,
			want:    true,
		},
		{
			name:    "counted dhcp is always kept",
			program: "dhcpd",
			rec:     logship.Record{},
			counted: true,
			want:    true,
		},
		{
			name:    "counted audit is always kept",
			program: "audit",
			rec:     logship.Record{},
			counted: true,
			want:    true,
		},
		{
			name:    "counted ids is always kept",
			program: "suricata",
			rec:     logship.Record{},
			counted: true,
			want:    true,
		},
		{
			name:    "counted radius access event is retained by default",
			program: "radiusd",
			rec: logship.Record{Attributes: map[string]string{
				"radius.event":        "access",
				"radius.result":       "accepted",
				"radius.client_scope": "configured",
			}},
			counted: true,
			want:    true,
		},
		{
			name:    "counted ipsec lifecycle event is retained by default",
			program: "charon",
			rec: logship.Record{Attributes: map[string]string{
				"vpn.backend": "ipsec",
				"vpn.event":   "authentication_failed",
				"vpn.result":  "failure",
			}},
			counted: true,
			want:    true,
		},
		{
			name:    "counted openvpn lifecycle event is retained by default",
			program: "openvpn_server40",
			rec: logship.Record{Attributes: map[string]string{
				"vpn.backend": "openvpn",
				"vpn.event":   "certificate_failed",
				"vpn.result":  "failure",
			}},
			counted: true,
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sampleKeep(tt.program, tt.rec, tt.counted); got != tt.want {
				t.Errorf("sampleKeep(%q, %+v, %v) = %v, want %v", tt.program, tt.rec, tt.counted, got, tt.want)
			}
		})
	}
}
