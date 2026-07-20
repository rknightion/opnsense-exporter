package syslog

import "testing"

// configd.py runs at facility daemon (3); severity info (6).
func configdEnv(msg string) Envelope {
	return auditEnv("configd.py", 3, 6, msg)
}

// TestConfigdActionNotFound: an action a not-installed plugin never registered.
func TestConfigdActionNotFound(t *testing.T) {
	rec, ok := parseAudit(configdEnv("action wireguard.status not found for user root"), nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for an action-not-found line")
	}
	assertAttrs(t, rec, map[string]string{
		"event":        "authorization",
		"audit.result": "not_found",
		"audit.action": "wireguard.status",
		"audit.user":   "root",
		"user.name":    "root",
	})
}

// TestConfigdMessageResultOK: a completed configd command with a short status word.
func TestConfigdMessageResultOK(t *testing.T) {
	rec, ok := parseAudit(configdEnv("message 16ae3b8d-0588-4a04-a7b9-d89b1875cd4c [interface newipv6 pppoe0] returned OK "), nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for a message-result line")
	}
	assertAttrs(t, rec, map[string]string{
		"event":           "configd_result",
		"configd.task_id": "16ae3b8d-0588-4a04-a7b9-d89b1875cd4c",
		"configd.command": "interface newipv6 pppoe0",
		"configd.result":  "OK",
	})
}

// TestConfigdMessageResultJSONNotStored: a large JSON result stays in the raw body
// and is NOT promoted to a high-cardinality attribute.
func TestConfigdMessageResultJSONNotStored(t *testing.T) {
	rec, ok := parseAudit(configdEnv(`message f3a37b2f-39f2-4d71-9b97-11749f19db64 [qfeeds stats] returned {"feeds":[{"name":"malware_ip","total_entries":306172}]}`), nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for a JSON message-result line")
	}
	assertAttrs(t, rec, map[string]string{
		"event":           "configd_result",
		"configd.command": "qfeeds stats",
	})
	assertNoAttrs(t, rec, "configd.result")
}
