package syslog

import (
	"testing"
	"time"
)

func TestParseEnvelope(t *testing.T) {
	now := time.Date(2026, 7, 14, 20, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		line     string
		wantProg string
		wantHost string
		wantPID  string
		wantFac  int
		wantSev  int
		wantMsg  string
		wantTS   time.Time
	}{
		{
			name:     "rfc5424 filterlog with structured data",
			line:     `<134>1 2026-07-14T19:50:01+01:00 opnsense.localdomain filterlog 19325 - [meta sequenceId="590250"] 16,115,,0,vtnet2,match,pass,out,4`,
			wantProg: "filterlog",
			wantHost: "opnsense.localdomain",
			wantPID:  "19325",
			wantFac:  16,
			wantSev:  6,
			wantMsg:  "16,115,,0,vtnet2,match,pass,out,4",
			wantTS:   time.Date(2026, 7, 14, 19, 50, 1, 0, time.FixedZone("", 3600)),
		},
		{
			name:     "rfc3164 filterlog with pid",
			line:     `<134>Jul 14 19:50:01 opnsense filterlog[19325]: 16,115,,0,vtnet2,match,pass,out,4`,
			wantProg: "filterlog",
			wantHost: "opnsense",
			wantPID:  "19325",
			wantFac:  16,
			wantSev:  6,
			wantMsg:  "16,115,,0,vtnet2,match,pass,out,4",
			wantTS:   time.Date(2026, 7, 14, 19, 50, 1, 0, time.UTC),
		},
		{
			name:     "rfc5424 nil structured data",
			line:     `<165>1 2026-07-14T18:21:00+01:00 opnsense unbound 67143 - - cache cleanup done`,
			wantProg: "unbound",
			wantHost: "opnsense",
			wantPID:  "67143",
			wantFac:  20,
			wantSev:  5,
			wantMsg:  "cache cleanup done",
			wantTS:   time.Date(2026, 7, 14, 18, 21, 0, 0, time.FixedZone("", 3600)),
		},
		{
			name:     "rfc3164 without pid",
			line:     `<38>Jul 14 19:50:38 opnsense sshd-session: Accepted publickey for root`,
			wantProg: "sshd-session",
			wantHost: "opnsense",
			wantPID:  "",
			wantFac:  4,
			wantSev:  6,
			wantMsg:  "Accepted publickey for root",
			wantTS:   time.Date(2026, 7, 14, 19, 50, 38, 0, time.UTC),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, err := ParseEnvelope([]byte(tc.line), now)
			if err != nil {
				t.Fatalf("ParseEnvelope: %v", err)
			}
			if env.Program != tc.wantProg {
				t.Errorf("Program = %q, want %q", env.Program, tc.wantProg)
			}
			if env.Hostname != tc.wantHost {
				t.Errorf("Hostname = %q, want %q", env.Hostname, tc.wantHost)
			}
			if env.PID != tc.wantPID {
				t.Errorf("PID = %q, want %q", env.PID, tc.wantPID)
			}
			if env.Facility != tc.wantFac {
				t.Errorf("Facility = %d, want %d", env.Facility, tc.wantFac)
			}
			if env.Severity != tc.wantSev {
				t.Errorf("Severity = %d, want %d", env.Severity, tc.wantSev)
			}
			if env.Message != tc.wantMsg {
				t.Errorf("Message = %q, want %q", env.Message, tc.wantMsg)
			}
			if !env.Timestamp.Equal(tc.wantTS) {
				t.Errorf("Timestamp = %s, want %s", env.Timestamp, tc.wantTS)
			}
		})
	}
}

// The BSD timestamp carries no year. A December log line parsed in January must
// roll BACK a year, not land 11 months in the future.
func TestParseEnvelopeRFC3164NewYearRollback(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC)
	env, err := ParseEnvelope([]byte(`<38>Dec 31 23:59:58 opnsense sshd: bye`), now)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	want := time.Date(2025, 12, 31, 23, 59, 58, 0, time.UTC)
	if !env.Timestamp.Equal(want) {
		t.Fatalf("Timestamp = %s, want %s (must roll back a year)", env.Timestamp, want)
	}
}

// A same-year line must keep the current year.
func TestParseEnvelopeRFC3164SameYear(t *testing.T) {
	now := time.Date(2026, 7, 14, 20, 0, 0, 0, time.UTC)
	env, err := ParseEnvelope([]byte(`<38>Jul 14 19:50:38 opnsense sshd: hi`), now)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if env.Timestamp.Year() != 2026 {
		t.Fatalf("year = %d, want 2026", env.Timestamp.Year())
	}
}

func TestParseEnvelopeMalformed(t *testing.T) {
	now := time.Date(2026, 7, 14, 20, 0, 0, 0, time.UTC)
	for _, line := range []string{
		"",
		"<",
		"<>",
		"<999>",
		"not syslog",
		"<134>1 ",
		"<134>",
		"<abc>hello",
		"<134>1 2026-07-14T19:50:01+01:00 host app",
		"<134>Jul 14 19:50:01",
		"<134>Jul 14 25:99:99 host app: x",
	} {
		t.Run(line, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", line, r)
				}
			}()
			if _, err := ParseEnvelope([]byte(line), now); err == nil {
				t.Fatalf("ParseEnvelope(%q) = nil error, want error", line)
			}
		})
	}
}

// Escaped ']' inside structured data must not end the SD element early.
func TestParseEnvelopeStructuredDataEscapes(t *testing.T) {
	now := time.Now()
	line := `<134>1 2026-07-14T19:50:01Z host app 1 - [ex a="b\]c"][two x="y"] the message`
	env, err := ParseEnvelope([]byte(line), now)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if env.Message != "the message" {
		t.Fatalf("Message = %q, want %q", env.Message, "the message")
	}
}

// RFC5424 nil values ("-") for hostname/procid must degrade to empty strings.
func TestParseEnvelopeNilFields(t *testing.T) {
	now := time.Now()
	env, err := ParseEnvelope([]byte(`<13>1 2026-07-14T19:50:01Z - - - - - hello`), now)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if env.Hostname != "" || env.Program != "" || env.PID != "" {
		t.Fatalf("nil fields not blanked: %+v", env)
	}
	if env.Message != "hello" {
		t.Fatalf("Message = %q", env.Message)
	}
}
