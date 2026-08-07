package options

import (
	"testing"
	"time"
)

func TestLogsUnboundEnabled_DefaultFalse(t *testing.T) {
	if LogsUnboundEnabled() {
		t.Fatal("expected --logs.unbound.enabled to default to false")
	}
}

func TestLogsUnboundMinInterval_Is15Seconds(t *testing.T) {
	if LogsUnboundMinInterval() != 15*time.Second {
		t.Fatalf("unbound log poll floor drifted: %s", LogsUnboundMinInterval())
	}
}

// The two per-query DNS routes carry the same queries by different transports, so
// both-on ships two Loki records per query and silently doubles every per-query
// panel (#659). That is refused at startup rather than warned about, because both
// inputs are the operator's own flags and the fix is to drop one.
func TestValidateUnboundPerQueryRoutes(t *testing.T) {
	tests := []struct {
		name       string
		poll       bool
		syslogLane bool
		wantErr    bool
	}{
		{name: "neither", poll: false, syslogLane: false},
		{name: "poll lane only", poll: true, syslogLane: false},
		{name: "syslog lane only", poll: false, syslogLane: true},
		{name: "both is refused", poll: true, syslogLane: true, wantErr: true},
	}
	prevPoll, prevSyslog := *logsUnboundEnabled, *logsSyslogUnboundPerQuery
	t.Cleanup(func() {
		*logsUnboundEnabled, *logsSyslogUnboundPerQuery = prevPoll, prevSyslog
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			*logsUnboundEnabled, *logsSyslogUnboundPerQuery = tc.poll, tc.syslogLane
			err := ValidateUnboundPerQueryRoutes()
			if tc.wantErr && err == nil {
				t.Fatal("expected both-lanes-enabled to be refused, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestLogsSyslogUnboundPerQueryEnabled_DefaultFalse(t *testing.T) {
	if LogsSyslogUnboundPerQueryEnabled() {
		t.Fatal("expected --logs.syslog.unbound-per-query.enabled to default to false")
	}
}
