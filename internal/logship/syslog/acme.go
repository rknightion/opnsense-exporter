package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// acme.go structures certificate-lifecycle syslog lines from TWO distinct
// programs (#631):
//
//   - `acme.sh` — the acme.sh client's own progress log, one line per lifecycle
//     step, each prefixed with the client's own local-time bracketed timestamp
//     (e.g. `[Mon Jul 27 19:36:01 BST 2026] `). That timestamp is NOT the record
//     timestamp — the syslog envelope already carries one, resolved from the
//     wire, and it is more trustworthy than a string the shell script formatted
//     itself. It is stripped and never emitted anywhere.
//   - `opnsense` — the OPNsense ACME plugin's own lifecycle log, written from
//     PHP via its `AcmeClient` class.
//
// ONE program name is safe to claim outright: `acme.sh` is not shared with
// anything else on the box. `opnsense` IS NOT — see the warning below.
//
// CLAIMING `opnsense` IS THE RISK THIS FILE MANAGES, same shape as kernel.go's
// warning about facility-14 console output. `opnsense` is the generic syslog tag
// OPNsense's PHP webConfigurator uses for essentially every internal script and
// controller, so acme's `AcmeClient: ` lines are a small minority of what arrives
// under this program name. Every grammar below for the `opnsense` program is
// anchored on the literal `AcmeClient: ` prefix, and anything that does not match
// returns ok=false so it keeps shipping as the generic record it always was.
// TestOpnsenseCatchAllNonACMELineIsNotClaimed is the guard. IF THAT ANCHOR IS EVER
// LOOSENED, every unrelated PHP log line on the box risks being mislabelled as
// certificate activity.
//
// SECRETS. Several acme.sh lines carry material that must never become a log
// attribute value, only ever raw message body (which is unavoidable — the
// generic record already ships the verbatim line, exactly as it always has for
// anything this parser declines to structure):
//
//   - `ACCOUNT_THUMBPRINT='...'` — the ACME account's key thumbprint. This line
//     is deliberately left ENTIRELY UNMATCHED (ok=false): there is no grammar
//     for it below, so it can never produce a cert.* attribute of any kind.
//   - `Adding TXT value: <value> for domain: <domain>` and
//     `Removing txt: <value> for domain: <domain>` — the DNS-01 challenge VALUE
//     is matched with a non-capturing `\S+` and discarded; only the CHALLENGE
//     DOMAIN is captured, into cert.challenge_domain.
//   - `Le_OrderFinalize='...'` and `Le_LinkCert='...'` — ACME order/certificate
//     resource URLs. Left entirely unmatched for the same reason as the
//     thumbprint line.
//   - Filesystem paths to PRIVATE KEYS (`Installing key to:`,
//     `The domain key is here:`, `Your cert key is in:`) are left entirely
//     unmatched. The milestone value they would have carried is already
//     captured by other lines (cert_downloaded from "Cert success.",
//     cert_installed from the cert/CA/full-chain "Installing ... to:" lines),
//     so there is nothing to gain by parsing them and a real cost if a future
//     change tried to emit the path as an attribute.
//
// A future change to this file must not add an attribute carrying any of the
// above. TestACMESecretsNeverLeak asserts none of the captured secret values
// appear in ANY attribute across the whole corpus.
//
// DEVIATIONS FROM THE SUGGESTED EVENT VOCABULARY: two events were added because
// no suggested value fit a captured line — `ca_selected` for the "which CA are
// we using" lines on both programs, and `challenge_type_selected` for the
// opnsense plugin's "using challenge type" line. `issue_failed` from the
// suggestion list is NOT implemented: no captured line represents a failed issue
// attempt (only a failed *removal*, `removal_failed`), and lines are never
// invented ahead of a real capture.
//
// MANY acme.sh progress lines are DELIBERATELY LEFT GENERIC — not an oversight,
// a decision: "Account key creation OK.", "Registering account:", "Creating
// domain key", "Single domain=...", "Getting webroot for domain=...",
// "Adding record", "Added, OK", "The TXT record has been successfully added.",
// "Sleeping for N seconds...", "Verifying: ...", "Removing DNS records.",
// "Successfully removed", "Let's finalize the order.", "Downloading cert.",
// and the plain cert/intermediate/full-chain path-location lines
// ("Your cert is in:", "The intermediate CA cert is in:",
// "And the full-chain cert is in:"). None of them has a slot in the closed
// vocabulary that isn't already better represented by a neighbouring line
// (e.g. "Cert success." already fires cert_downloaded), and inventing one-off
// events for informational-only lines would grow the vocabulary without adding
// signal.
var (
	// acmeShTimestamp strips the client's own bracketed local-time stamp, e.g.
	// `[Mon Jul 27 19:36:01 BST 2026] `. It is intentionally unanchored beyond the
	// leading `^` and greedy only up to the first `] ` — acme.sh always emits
	// exactly one such bracket pair per line, immediately at the start.
	acmeShTimestamp = regexp.MustCompile(`^\[[^\]]+\] `)

	// --- opnsense (AcmeClient plugin log) grammars ---
	// Every one of these is anchored on the literal `AcmeClient: ` prefix. See the
	// file-level warning: this program name is a PHP catch-all and this anchor is
	// the only thing keeping unrelated lines from being claimed.
	reAcmeOpnRenewalNotRequired = regexp.MustCompile(`^AcmeClient: issue/renewal not required for certificate: (\S+)$`)
	reAcmeOpnRenewalRequired    = regexp.MustCompile(`^AcmeClient: certificate must be issued/renewed: (\S+)$`)
	reAcmeOpnIssueStarted       = regexp.MustCompile(`^AcmeClient: issue certificate: (\S+)$`)
	reAcmeOpnIssueSucceeded     = regexp.MustCompile(`^AcmeClient: successfully issued/renewed certificate: (\S+)$`)
	reAcmeOpnConfigWiped        = regexp.MustCompile(`^AcmeClient: wiping certificate config: (\S+)$`)
	reAcmeOpnRemovalFailed      = regexp.MustCompile(`^AcmeClient: error removing certificate (\S+)$`)
	reAcmeOpnUsingCA            = regexp.MustCompile(`^AcmeClient: using CA: (\S+)$`)
	reAcmeOpnAccountRegistered  = regexp.MustCompile(`^AcmeClient: account is registered: .+$`)
	reAcmeOpnChallengeType      = regexp.MustCompile(`^AcmeClient: using challenge type: (.+)$`)
	reAcmeOpnCAImported         = regexp.MustCompile(`^AcmeClient: imported ACME CA: (.+)$`)
	// The doubled `AcmeClient: AcmeClient: ` prefix on the shell-command lines is
	// REAL, not a transcription error — captured verbatim on the real box. Deliberately
	// NOT anchored at the end: the remainder of the line is the full acme.sh
	// invocation, whose flags differ between an --issue and a --remove call, and
	// none of that tail is captured into any attribute (see file-level doc comment).
	reAcmeOpnShellCommand = regexp.MustCompile(`^AcmeClient: AcmeClient: The shell command returned exit code '(\d+)':`)

	// --- acme.sh (client progress log) grammars ---
	// Matched against the message AFTER acmeShTimestamp has been stripped.
	reAcmeShDomainSkipped  = regexp.MustCompile(`^(\S+) is not an issued domain, skipping\.$`)
	reAcmeShUsingCA        = regexp.MustCompile(`^Using CA: (\S+)$`)
	reAcmeShRegistered     = regexp.MustCompile(`^Registered$`)
	reAcmeShTXTAdded       = regexp.MustCompile(`^Adding TXT value: \S+ for domain: (\S+)$`)
	reAcmeShPending        = regexp.MustCompile(`^Pending\. The CA is processing your order, please wait\. \((\d+)/(\d+)\)$`)
	reAcmeShSuccess        = regexp.MustCompile(`^Success$`)
	reAcmeShTXTRemoved     = regexp.MustCompile(`^Removing txt: \S+ for domain: (\S+)$`)
	reAcmeShSigningStarted = regexp.MustCompile(`^Verification finished, beginning signing\.$`)
	reAcmeShCertSuccess    = regexp.MustCompile(`^Cert success\.$`)
	// Deliberately excludes "key" from the alternation: "Installing key to: ..." is
	// a private-key path and must never be matched (see file-level secrets note).
	reAcmeShInstalling = regexp.MustCompile(`^Installing (?:cert|CA|full chain) to: `)
)

// Closed cert.event vocabulary. See the file-level doc comment for the two
// additions and the one suggested-but-unimplemented value (issue_failed).
const (
	acmeEventRenewalNotRequired  = "renewal_not_required"
	acmeEventRenewalRequired     = "renewal_required"
	acmeEventIssueStarted        = "issue_started"
	acmeEventIssueSucceeded      = "issue_succeeded"
	acmeEventConfigWiped         = "config_wiped"
	acmeEventRemovalFailed       = "removal_failed"
	acmeEventAccountRegistered   = "account_registered"
	acmeEventCAImported          = "ca_imported"
	acmeEventChallengeAdded      = "challenge_added"
	acmeEventChallengeRemoved    = "challenge_removed"
	acmeEventValidationPending   = "validation_pending"
	acmeEventValidationSucceeded = "validation_succeeded"
	acmeEventSigningStarted      = "signing_started"
	acmeEventCertDownloaded      = "cert_downloaded"
	acmeEventCertInstalled       = "cert_installed"
	acmeEventDomainSkipped       = "domain_skipped"
	acmeEventShellCommand        = "shell_command"
	// Additions beyond the suggested vocabulary — see file-level doc comment.
	acmeEventCASelected            = "ca_selected"
	acmeEventChallengeTypeSelected = "challenge_type_selected"
)

const (
	acmeResultSuccess = "success"
	acmeResultFailure = "failure"

	acmeSourceScript = "acme.sh"
	acmeSourcePlugin = "plugin"
)

func init() {
	RegisterParser(parseACME, "acme.sh", "opnsense")
}

// parseACME dispatches by program: the opnsense catch-all's AcmeClient lines,
// or the acme.sh client's own progress log. Anything else returns ok=false.
func parseACME(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	switch env.Program {
	case "opnsense":
		return parseACMEOpnsense(env)
	case "acme.sh":
		return parseACMEShellClient(env)
	default:
		// Unreachable given the RegisterParser call above, but a Parser must never
		// panic on an unexpected program — degrade to generic like everything else.
		return logship.Record{}, false
	}
}

// parseACMEOpnsense structures the OPNsense ACME plugin's own AcmeClient lines.
// Everything not anchored on the literal `AcmeClient: ` prefix returns ok=false,
// which is what keeps every OTHER PHP script logging under the `opnsense`
// program name shipping as a plain generic record, exactly as before this
// parser existed.
func parseACMEOpnsense(env Envelope) (logship.Record, bool) {
	msg := env.Message

	// Checked first: its own doubled prefix would not accidentally match any of
	// the single-prefix grammars below, but checking it first documents that it
	// is the odd one out.
	if m := reAcmeOpnShellCommand.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourcePlugin)
		set("cert.event", acmeEventShellCommand)
		set("cert.exit_code", m[1])
		if m[1] == "0" {
			set("cert.result", acmeResultSuccess)
		} else {
			set("cert.result", acmeResultFailure)
		}
		return rec, true
	}
	if m := reAcmeOpnRenewalNotRequired.FindStringSubmatch(msg); m != nil {
		return acmeOpnRecord(env, acmeEventRenewalNotRequired, m[1]), true
	}
	if m := reAcmeOpnRenewalRequired.FindStringSubmatch(msg); m != nil {
		return acmeOpnRecord(env, acmeEventRenewalRequired, m[1]), true
	}
	if m := reAcmeOpnIssueStarted.FindStringSubmatch(msg); m != nil {
		return acmeOpnRecord(env, acmeEventIssueStarted, m[1]), true
	}
	if m := reAcmeOpnIssueSucceeded.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourcePlugin)
		set("cert.event", acmeEventIssueSucceeded)
		set("cert.domain", m[1])
		set("cert.result", acmeResultSuccess)
		return rec, true
	}
	if m := reAcmeOpnConfigWiped.FindStringSubmatch(msg); m != nil {
		return acmeOpnRecord(env, acmeEventConfigWiped, m[1]), true
	}
	if m := reAcmeOpnRemovalFailed.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourcePlugin)
		set("cert.event", acmeEventRemovalFailed)
		set("cert.domain", m[1])
		set("cert.result", acmeResultFailure)
		return rec, true
	}
	if m := reAcmeOpnUsingCA.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourcePlugin)
		set("cert.event", acmeEventCASelected)
		set("cert.ca", m[1])
		return rec, true
	}
	if reAcmeOpnAccountRegistered.MatchString(msg) {
		rec, set := newRecord(env)
		set("cert.source", acmeSourcePlugin)
		set("cert.event", acmeEventAccountRegistered)
		return rec, true
	}
	if m := reAcmeOpnChallengeType.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourcePlugin)
		set("cert.event", acmeEventChallengeTypeSelected)
		set("cert.challenge_type", m[1])
		return rec, true
	}
	if m := reAcmeOpnCAImported.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourcePlugin)
		set("cert.event", acmeEventCAImported)
		set("cert.ca", m[1])
		return rec, true
	}
	return logship.Record{}, false
}

// acmeOpnRecord builds the common shape shared by the plain event+domain
// opnsense grammars that carry no extra attribute.
func acmeOpnRecord(env Envelope, event, domain string) logship.Record {
	rec, set := newRecord(env)
	set("cert.source", acmeSourcePlugin)
	set("cert.event", event)
	set("cert.domain", domain)
	return rec
}

// parseACMEShellClient structures the acme.sh client's own progress log. The
// client's bracketed local-time timestamp is stripped before matching and never
// emitted — see file-level doc comment for why.
func parseACMEShellClient(env Envelope) (logship.Record, bool) {
	msg := env.Message
	if loc := acmeShTimestamp.FindStringIndex(msg); loc != nil {
		msg = msg[loc[1]:]
	}

	if m := reAcmeShDomainSkipped.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourceScript)
		set("cert.event", acmeEventDomainSkipped)
		set("cert.domain", m[1])
		return rec, true
	}
	if m := reAcmeShUsingCA.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourceScript)
		set("cert.event", acmeEventCASelected)
		set("cert.ca", m[1])
		return rec, true
	}
	if reAcmeShRegistered.MatchString(msg) {
		rec, set := newRecord(env)
		set("cert.source", acmeSourceScript)
		set("cert.event", acmeEventAccountRegistered)
		return rec, true
	}
	if m := reAcmeShTXTAdded.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourceScript)
		set("cert.event", acmeEventChallengeAdded)
		set("cert.challenge_domain", m[1])
		return rec, true
	}
	if m := reAcmeShPending.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourceScript)
		set("cert.event", acmeEventValidationPending)
		set("cert.attempt", m[1])
		set("cert.attempt_max", m[2])
		return rec, true
	}
	if reAcmeShSuccess.MatchString(msg) {
		rec, set := newRecord(env)
		set("cert.source", acmeSourceScript)
		set("cert.event", acmeEventValidationSucceeded)
		set("cert.result", acmeResultSuccess)
		return rec, true
	}
	if m := reAcmeShTXTRemoved.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("cert.source", acmeSourceScript)
		set("cert.event", acmeEventChallengeRemoved)
		set("cert.challenge_domain", m[1])
		return rec, true
	}
	if reAcmeShSigningStarted.MatchString(msg) {
		rec, set := newRecord(env)
		set("cert.source", acmeSourceScript)
		set("cert.event", acmeEventSigningStarted)
		return rec, true
	}
	if reAcmeShCertSuccess.MatchString(msg) {
		rec, set := newRecord(env)
		set("cert.source", acmeSourceScript)
		set("cert.event", acmeEventCertDownloaded)
		set("cert.result", acmeResultSuccess)
		return rec, true
	}
	if reAcmeShInstalling.MatchString(msg) {
		rec, set := newRecord(env)
		set("cert.source", acmeSourceScript)
		set("cert.event", acmeEventCertInstalled)
		return rec, true
	}
	return logship.Record{}, false
}
