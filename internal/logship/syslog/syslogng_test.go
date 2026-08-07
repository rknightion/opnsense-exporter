package syslog

import (
	"strings"
	"testing"
	"time"
)

func syslogngEnv(t *testing.T, message string) Envelope {
	t.Helper()

	// Envelope header shape mirrors dpingerEnv (dpinger_test.go); only the
	// program name and message differ. syslog-ng's own lines carry no
	// structured [meta] block on the wire, but ParseEnvelope tolerates one.
	env, err := ParseEnvelope([]byte("<134>1 2026-08-07T16:33:00Z test-firewall syslog-ng 314 - [meta sequenceId=\"sanitized-sequence\"] "+message), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

func TestSyslogNGRegistered(t *testing.T) {
	if _, ok := parserFor("syslog-ng"); !ok {
		t.Fatal("no parser registered for program syslog-ng")
	}
}

// TestSyslogNGGroup1ConnectionLifecycle pins the exporter's-own-listener
// connection lifecycle. Every line is verbatim from camden,
// /opt/opnsense2otel/capture/syslog/*.ndjson (captured for #665, read
// 2026-08-07), across fd 7/23/24/25/27/29/31.
func TestSyslogNGGroup1ConnectionLifecycle(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "established",
			msg:  "Syslog connection established; fd='7', server='AF_INET(10.0.0.5:5847)', local='AF_INET(0.0.0.0:0)'",
			want: map[string]string{
				"syslogng.event": "connection_established",
				"syslogng.fd":    "7",
				"dst.ip":         "10.0.0.5",
				"dst.port":       "5847",
			},
		},
		{
			name: "closed",
			msg:  "Syslog connection closed; fd='29', server='AF_INET(10.0.0.5:5847)', time_reopen='60'",
			want: map[string]string{
				"syslogng.event":               "connection_closed",
				"syslogng.fd":                  "29",
				"dst.ip":                       "10.0.0.5",
				"dst.port":                     "5847",
				"syslogng.time_reopen_seconds": "60",
			},
		},
		{
			name: "broken",
			msg:  "Syslog connection broken; fd='27', server='AF_INET(10.0.0.5:5847)', time_reopen='60'",
			want: map[string]string{
				"syslogng.event":               "connection_broken",
				"syslogng.fd":                  "27",
				"dst.ip":                       "10.0.0.5",
				"dst.port":                     "5847",
				"syslogng.time_reopen_seconds": "60",
			},
		},
		{
			name: "eof",
			msg:  "EOF occurred; fd='23'",
			want: map[string]string{
				"syslogng.event": "eof",
				"syslogng.fd":    "23",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseSyslogNG(syslogngEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseSyslogNG(%q) returned ok=false", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message %q", rec.Body, tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}

	// eof and established never carry time_reopen; closed/broken always do.
	rec, _ := parseSyslogNG(syslogngEnv(t, "EOF occurred; fd='23'"), nil, func(string) {})
	assertNoAttrs(t, rec, "syslogng.time_reopen_seconds", "dst.ip", "dst.port")
}

// TestSyslogNGGroup4Errors pins the two error shapes. Both lines are verbatim
// from the same camden capture as Group 1.
func TestSyslogNGGroup4Errors(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "child exited",
			msg:  "Child program exited, restarting; cmdline='/usr/local/sbin/configctl -e -t 0.5 system event config_changed', status='256'",
			want: map[string]string{
				"syslogng.event":       "child_exited",
				"syslogng.cmdline":     "/usr/local/sbin/configctl -e -t 0.5 system event config_changed",
				"syslogng.exit_status": "256",
			},
		},
		{
			name: "read error",
			msg:  "Error reading data; fd='27', error='Operation timed out (60)'",
			want: map[string]string{
				"syslogng.event": "read_error",
				"syslogng.fd":    "27",
				"syslogng.error": "Operation timed out (60)",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseSyslogNG(syslogngEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseSyslogNG(%q) returned ok=false", tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// realSyslogngStatsLine is the FULL ~5.5 KB "Log statistics;" line captured on
// camden, /opt/opnsense2otel/capture/syslog/*.ndjson (2026-08-07, for #665) --
// not a trimmed excerpt, so the no-fan-out assertion below is meaningful. Every
// dropped='...'/truncated_count='...' pair on this real line happens to be 0
// (a healthy box), which is why TestSyslogNGGroup2StatisticsSummation adds a
// second, explicitly synthetic case to prove non-zero values are actually
// summed and not just defaulted.
const realSyslogngStatsLine = `Log statistics; queued='global(scratch_buffers_count)=3', eps_since_start='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=0', processed='destination(d_local_ntpd)=295', processed='destination(d_local_portalauth)=0', processed='destination(d_config_changed_event)=33', processed='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=4825753', processed='destination(d_local_audit)=1308248', dropped='global(internal_source)=0', processed='global(internal_source)=453', queued='global(internal_source)=0', processed='destination(d_local_firewall)=1552', processed='destination(d_local_dnsmasq)=6386', processed='destination(d_a11ce000000040008000000000000001)=4825753', processed='global(sdata_updates)=0', truncated_count='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=0', processed='center(received)=4825753', processed='center(queued)=10911909', eps_since_start='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=20', eps_last_24h='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=15', processed='destination(d_local_wireguard)=0', processed='destination(d_local_lockout_auth)=1308246', processed='destination(d_local_ddclient)=0', truncated_bytes='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=0', eps_last_1h='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=0', msg_size_avg='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=106', processed='source(s_all)=4825753', processed='destination(d_local_resolver)=313299', dropped='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=0', queued='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=0', written='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=1308246', memory_usage='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=0', msg_size_avg='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=119', processed='destination(d_local_gateways)=27', processed='destination(d_local_kea)=73611', eps_last_1h='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=6', processed='global(msg_clones)=4825753', processed='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=1308246', processed='destination(d_local_suricata)=0', processed='destination(d_local_dhcrelay)=0', processed='destination(d_local_routing)=0', dropped='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=0', queued='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=0', written='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=33', processed='destination(d_local_vpn)=0', processed='destination(d_local_hostwatch)=0', eps_since_start='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=5', truncated_count='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=0', eps_last_1h='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=21', msg_size_max='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=5686', msg_size_avg='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=193', processed='destination(d_local_acmeclient)=0', processed='destination(d_local_filter)=1757713', processed='destination(d_local_miniupnpd)=887', processed='destination(d_local_configd)=1313341', memory_usage='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=0', truncated_bytes='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=0', processed='destination(d_local_monit)=0', truncated_count='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=0', eps_last_24h='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=0', truncated_bytes='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=0', memory_usage='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=0', processed='destination(d_local_ipsec)=84', processed='global(payload_reallocs)=1540', dropped='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=0', queued='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=0', written='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=4825753', processed='dst.program(d_config_changed_event#0,/usr/local/sbin/configctl -e -t 0.5 system event config_changed)=33', msg_size_max='dst.program(d_local_lockout_auth#0,/usr/local/opnsense/scripts/syslog/lockout_handler)=311', processed='destination(d_local_openvpn)=0', processed='destination(d_local_lighttpd)=24', queued='global(scratch_buffers_bytes)=768', stamp='src.internal(s_all#0)=1785833167', processed='src.internal(s_all#0)=453', processed='destination(d_local_pkg)=2', processed='destination(d_local_system)=2408', eps_last_24h='dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)=55'`

func TestSyslogNGGroup2StatisticsNoFanOut(t *testing.T) {
	rec, ok := parseSyslogNG(syslogngEnv(t, realSyslogngStatsLine), nil, func(string) {})
	if !ok {
		t.Fatal("parseSyslogNG(realSyslogngStatsLine) returned ok=false")
	}
	if rec.Body != realSyslogngStatsLine {
		t.Error("Body does not carry the full captured statistics line verbatim")
	}
	// The full captured line above has ~80 key='scope=value' pairs across
	// dozens of destinations. The acceptance criteria are explicit: exactly
	// syslogng.event, syslogng.dropped_total, syslogng.truncated_total --
	// nothing per-destination. Counted separately from the envelope metadata
	// attrs (program/host/pid/facility/severity, from newRecord/genericRecord)
	// so this assertion stays meaningful regardless of how many of those exist.
	const maxSyslogngAttrs = 3
	syslogngAttrs := 0
	for k := range rec.Attributes {
		if strings.HasPrefix(k, "syslogng.") {
			syslogngAttrs++
		}
	}
	if syslogngAttrs > maxSyslogngAttrs {
		t.Errorf("statistics record has %d syslogng.* attributes (%v), want at most %d -- looks like per-destination fan-out",
			syslogngAttrs, rec.Attributes, maxSyslogngAttrs)
	}
	assertAttrs(t, rec, map[string]string{
		"syslogng.event":           "statistics",
		"syslogng.dropped_total":   "0",
		"syslogng.truncated_total": "0",
	})
	assertNoAttrs(t, rec,
		"dst.network(d_a11ce000000040008000000000000001#0,tcp,10.0.0.5:5847)",
		"destination(d_local_ntpd)")
}

// TestSyslogNGGroup2StatisticsSummation is SYNTHETIC (not a capture): the real
// captured line above happens to carry only dropped=0/truncated_count=0
// pairs, which cannot distinguish "correctly summed to zero" from "the field
// was never read". This line is hand-built in the same key='scope=value'
// shape syslog-ng emits (confirmed against the real line's grammar above) with
// non-zero values on two destinations each, to pin that the parser actually
// sums rather than reporting the first match or a hardcoded zero.
func TestSyslogNGGroup2StatisticsSummation(t *testing.T) {
	msg := "Log statistics; " +
		"dropped='destination(d_local_audit)=3', " +
		"dropped='destination(d_local_filter)=4', " +
		"truncated_count='destination(d_local_audit)=1', " +
		"truncated_count='destination(d_local_filter)=2', " +
		"processed='destination(d_local_audit)=999'"

	rec, ok := parseSyslogNG(syslogngEnv(t, msg), nil, func(string) {})
	if !ok {
		t.Fatal("parseSyslogNG(synthetic stats line) returned ok=false")
	}
	assertAttrs(t, rec, map[string]string{
		"syslogng.event":           "statistics",
		"syslogng.dropped_total":   "7",
		"syslogng.truncated_total": "3",
	})
}

// TestSyslogNGGroup3ReloadFallsThroughToGeneric pins the deliberate
// non-structuring decision: all three reload lines are verbatim from the
// camden capture and must degrade to a generic record.
func TestSyslogNGGroup3ReloadFallsThroughToGeneric(t *testing.T) {
	msgs := []string{
		"Configuration reload requested over control channel;",
		"Loading the new configuration;",
		"Configuration reload finished;",
	}

	for _, msg := range msgs {
		t.Run(msg, func(t *testing.T) {
			env := syslogngEnv(t, msg)
			rec, parsed := buildRecord(env, nil, func(string) {})
			if parsed {
				t.Fatalf("buildRecord(%q) parsed a syslog-ng line the issue verdict left generic", msg)
			}
			if rec.Body != msg {
				t.Errorf("Body = %q, want generic body %q", rec.Body, msg)
			}
			assertAttrs(t, rec, map[string]string{"program": "syslog-ng"})
			assertNoAttrs(t, rec, "syslogng.event")
		})
	}
}

// TestSyslogNGUnrecognizedLinesDegradeToGeneric covers lines that are neither
// one of the four recognized shapes nor one of the Group 3 reload strings --
// proving an unmatched syslog-ng line still ships (never dropped) and never
// picks up syslogng.* attributes.
func TestSyslogNGUnrecognizedLinesDegradeToGeneric(t *testing.T) {
	msgs := []string{
		"start of service (syslog-ng 4.10.2)",
		"Syslog connection established; fd='7', server='AF_UNIX(/var/run/log)'",
		"Syslog connection closed; fd='29', server='AF_INET(10.0.0.5:5847)'",
	}

	for _, msg := range msgs {
		t.Run(msg, func(t *testing.T) {
			env := syslogngEnv(t, msg)
			rec, parsed := buildRecord(env, nil, func(string) {})
			if parsed {
				t.Fatalf("buildRecord(%q) unexpectedly parsed", msg)
			}
			if rec.Body != msg {
				t.Errorf("Body = %q, want generic body %q", rec.Body, msg)
			}
			assertNoAttrs(t, rec, "syslogng.event", "syslogng.fd", "dst.ip", "dst.port")
		})
	}
}
