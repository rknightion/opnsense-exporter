package opnsense

import (
	"log/slog"
	"testing"
)

func TestPoolSpecSize(t *testing.T) {
	c := &Client{log: slog.Default()} // poolSpecSize is a Client method so it can warn-log

	cases := []struct {
		name string
		in   string
		want float64
	}{
		{"ipv4 range with spaces", "10.0.0.110 - 10.0.0.240", 131},
		{"ipv4 range no spaces", "10.0.0.110-10.0.0.240", 131},
		{"ipv6 range", "2001:db8:100::1000 - 2001:db8:100::1fff", 4096},
		{"cidr v4", "192.0.2.0/26", 64},
		{"cidr v6", "2001:db8::/120", 256},
		{"multiple pools newline separated", "10.0.0.10 - 10.0.0.19\n10.0.0.30 - 10.0.0.39", 20},
		{"multiple pools comma separated", "10.0.0.10 - 10.0.0.19, 10.0.0.30 - 10.0.0.39", 20},
		{"inverted range skipped with warning", "10.0.0.240 - 10.0.0.110", 0},
		{"garbage skipped with warning", "not-an-ip - also-not", 0},
		{"empty", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.poolSpecSize(tc.in); got != tc.want {
				t.Errorf("poolSpecSize(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIPRangeSize(t *testing.T) {
	if got, ok := ipRangeSize("10.0.50.110", "10.0.50.240"); !ok || got != 131 {
		t.Errorf("ipRangeSize v4 = %v,%v; want 131,true", got, ok)
	}
	if _, ok := ipRangeSize("", "10.0.0.1"); ok {
		t.Error("expected ok=false for empty start")
	}
}
