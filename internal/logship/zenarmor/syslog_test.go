package zenarmor

import (
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
	"github.com/rknightion/opnsense-exporter/internal/logship/syslog"
)

func TestParseSyslogPayload(t *testing.T) {
	// Real dns line body (envelope already stripped by the syslog receiver).
	msg := `daemon=zenarmor, index=dns, data={"start_time":1784368102000,"query":"gsp-ssl.ls.apple.com","is_blocked":0}`
	fam, data, ok := parseSyslogPayload(msg)
	if !ok || fam != "dns" {
		t.Fatalf("dns: got fam=%q ok=%v, want dns/true", fam, ok)
	}
	if data != `{"start_time":1784368102000,"query":"gsp-ssl.ls.apple.com","is_blocked":0}` {
		t.Fatalf("dns: data mismatch: %q", data)
	}

	// alert line — data JSON contains commas and nested braces; must not be split.
	alert := `daemon=zenarmor, index=alert, data={"alertinfo":{"category":["A"],"sid":"x"},"is_blocked":1}`
	fam, data, ok = parseSyslogPayload(alert)
	if !ok || fam != "alert" {
		t.Fatalf("alert: got fam=%q ok=%v, want alert/true", fam, ok)
	}
	if data != `{"alertinfo":{"category":["A"],"sid":"x"},"is_blocked":1}` {
		t.Fatalf("alert: data mismatch: %q", data)
	}

	// Not a Zenarmor body.
	if _, _, ok := parseSyslogPayload("some other program output"); ok {
		t.Fatal("non-zenarmor body: want ok=false")
	}
}

func TestSyslogProcessor_ProcessRealAlert(t *testing.T) {
	proc := &docProcessor{
		cfg:   Config{Enrich: false},
		cache: enrich.NewCache(),
		sink:  logship.NopMetricSink{},
		m:     newMetrics(prometheus.NewRegistry(), nil),
	}
	sp := &syslogProcessor{proc: proc}
	if !sp.Handles("zenarmor") || sp.Handles("sshd") {
		t.Fatal("Handles() wrong")
	}
	env := syslog.Envelope{
		Program: "zenarmor",
		Message: `daemon=zenarmor, index=alert, data={"is_blocked":1,` +
			`"alertinfo":{"category":["Application Category"],"signature":["Network Management"],` +
			`"severity":0,"sid":"appcategories.abc","action":"reject"}}`,
	}
	var got logship.Record
	n := 0
	handled := sp.Process(env, netip.Addr{}, nil, func(r logship.Record) { got = r; n++ })
	if !handled || n != 1 {
		t.Fatalf("handled=%v emitted=%d, want true/1", handled, n)
	}
	if got.Attributes["alertinfo.category"] != "Application Category" {
		t.Errorf("category = %q", got.Attributes["alertinfo.category"])
	}
	if got.Attributes["alertinfo.sid"] != "appcategories.abc" {
		t.Errorf("sid = %q", got.Attributes["alertinfo.sid"])
	}
	// Task S: a Zenarmor record delivered through the shared syslog receiver must
	// carry the override so the pipeline ships it as source="zenarmor", not "syslog".
	if got.Source != "zenarmor" {
		t.Errorf("Source = %q, want zenarmor", got.Source)
	}
}

func TestSyslogProcessor_EmittedSource(t *testing.T) {
	sp := &syslogProcessor{}
	if got := sp.EmittedSource(); got != "zenarmor" {
		t.Errorf("EmittedSource() = %q, want zenarmor", got)
	}
}
