package zenarmor

import "testing"

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
