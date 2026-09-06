package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// OpenSSH auth lines. Every regexp here was written against lines captured
// verbatim from a live OPNsense 26.7 box (including a genuine failed login,
// forced for the purpose) — none of it is guessed from documentation.
//
// Attributes emitted:
//
//	auth.result          accepted | failed | invalid-user | disconnected
//	auth.user            the account named on the line, when it names one
//	auth.method          publickey | password | none | keyboard-interactive (when present)
//	auth.key_type        ED25519 / RSA / ... (publickey acceptance only)
//	auth.key_fingerprint SHA256:… (publickey acceptance only)
//	auth.valid           "false" when the line says "invalid user", "true" when it
//	                     names a user without that infix. Absent when the line names
//	                     no user at all — an absent value is not a claim.
//	src.ip / src.port    plus src.hostname / src.mac / src.scope from enrichment
//
// Two things about these lines drive the shape of the parser:
//
//   - ONE failed attempt emits SEVERAL lines (Invalid user … / Failed none … /
//     Failed password … / Connection closed by …). Each is parsed on its own terms;
//     nothing here tries to correlate them into a single event. Counting attempts
//     is a Loki query's job, and it should filter on the shape it means.
//
//   - The "invalid user" infix moves the capture: `Failed password for invalid user
//     bob from …` vs `Failed password for bob from …`. Getting that wrong captures
//     the literal word "invalid" as the username, so both forms are matched by one
//     optional group and covered by tests.
var (
	// Accepted publickey for root from 10.0.0.6 port 34776 ssh2: ED25519 SHA256:bbpr/…
	// Accepted password for root from 10.0.0.6 port 34776 ssh2
	// Failed password for invalid user nosuchuser_test from 127.0.0.1 port 36025 ssh2
	// Failed none for invalid user nosuchuser_test from 127.0.0.1 port 36025 ssh2
	reSSHDAuthAttempt = regexp.MustCompile(`^(Accepted|Failed) (\S+) for (invalid user )?(\S+) from (\S+) port (\d+)`)

	// The key fingerprint trails the "ssh2:" on a publickey acceptance.
	reSSHDKey = regexp.MustCompile(`ssh2:\s+(\S+)\s+(\S+)\s*$`)

	// Invalid user nosuchuser_test from 127.0.0.1 port 36025
	reSSHDInvalidUser = regexp.MustCompile(`^Invalid user (\S+) from (\S+) port (\d+)`)

	// Connection closed by invalid user nosuchuser_test 127.0.0.1 port 36025 [preauth]
	// Connection closed by 10.0.0.6 port 34776 [preauth]
	// Disconnected from user root 10.0.0.6 port 59138
	// Disconnected from invalid user nosuchuser_test 127.0.0.1 port 36025 [preauth]
	//
	// Note the address follows the username directly, with no "from" between them.
	reSSHDDisconnect = regexp.MustCompile(`^(?:Connection closed by|Disconnected from)(?: (?:(invalid|authenticating) )?user (\S+))? (\S+) port (\d+)`)

	// Received disconnect from 10.0.0.6 port 59138:11: disconnected by user
	// The ":11" is the SSH disconnect reason code, not part of the port.
	reSSHDReceivedDisconnect = regexp.MustCompile(`^Received disconnect from (\S+) port (\d+)`)
)

func init() {
	// OpenSSH 9.8 split the per-connection work into a separate binary and the
	// program name on the wire changed with it, so a box can log under either name.
	// sshd resolves its own positional source address, so BuildRecord does not
	// re-scan its body for peer.* addresses.
	RegisterParser(parseSSHD, "sshd", "sshd-session")
}

// parseSSHD turns an OpenSSH auth line into a structured record. It returns
// ok=false for any line matching none of the shapes above — session/pam chatter,
// listener startup, kex errors — so the caller degrades it to a generic record
// carrying the raw body. A line is never dropped, and enrichment is best-effort:
// a nil or cold snapshot yields an unenriched but otherwise complete record.
func parseSSHD(env Envelope, snap *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	msg := env.Message

	var result, user, method, keyType, keyFP, ip, port string
	var sawUser, invalid bool

	switch {
	case reSSHDAuthAttempt.MatchString(msg):
		m := reSSHDAuthAttempt.FindStringSubmatch(msg)
		if m[1] == "Accepted" {
			result = "accepted"
		} else {
			result = "failed"
		}
		method, invalid, user = m[2], m[3] != "", m[4]
		ip, port, sawUser = m[5], m[6], true
		if k := reSSHDKey.FindStringSubmatch(msg); k != nil {
			keyType, keyFP = k[1], k[2]
		}

	case reSSHDInvalidUser.MatchString(msg):
		m := reSSHDInvalidUser.FindStringSubmatch(msg)
		result, user, ip, port = "invalid-user", m[1], m[2], m[3]
		sawUser, invalid = true, true

	case reSSHDDisconnect.MatchString(msg):
		m := reSSHDDisconnect.FindStringSubmatch(msg)
		result = "disconnected"
		if m[2] != "" {
			user, sawUser, invalid = m[2], true, m[1] == "invalid"
		}
		ip, port = m[3], m[4]

	case reSSHDReceivedDisconnect.MatchString(msg):
		m := reSSHDReceivedDisconnect.FindStringSubmatch(msg)
		result, ip, port = "disconnected", m[1], m[2]

	default:
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set("auth.result", result)
	set("auth.user", user)
	set("user.name", user) // semconv: dual-emit the standard identity key alongside auth.user
	set("auth.method", method)
	set("auth.key_type", keyType)
	set("auth.key_fingerprint", keyFP)
	if sawUser {
		// Only claim validity when the line named an account. "false" on its own is a
		// strong security signal: nobody legitimately logs in as an account that does
		// not exist.
		if invalid {
			set("auth.valid", "false")
		} else {
			set("auth.valid", "true")
		}
	}
	set("src.ip", ip)
	set("src.port", port)

	// Best-effort enrichment of the source address. An unknown address is normal
	// here — a brute-force from the internet is exactly the case this lane exists
	// for — so a lookup miss is silent and NEVER signals a stale snapshot. The
	// service lookup is skipped (empty proto): an SSH client's ephemeral source
	// port names no service.
	enrichEndpoint(set, snap, "src", ip, "", "")
	// GeoIP (#528): auth attempts from the internet are exactly the case this lane
	// exists for. geoAttrs is a no-op unless a GeoIP source is configured.
	geoAttrs(set, "src", ip)

	// sshd logs a rejected login at syslog info, level with a successful one. A
	// failed or invalid-user attempt is a security event, so raise it — but only
	// from the two levels below Warn, never downgrade a box that shouted louder.
	if result == "failed" || result == "invalid-user" {
		if rec.Severity == logship.SeverityInfo || rec.Severity == logship.SeverityDebug {
			rec.Severity = logship.SeverityWarn
		}
	}

	return rec, true
}
