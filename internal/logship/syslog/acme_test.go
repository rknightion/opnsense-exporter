package syslog

import (
	"strings"
	"testing"
	"time"
)

// acmeEnv builds an Envelope for the given program, mirroring dpingerEnv's
// shape (dpinger_test.go) but parameterised on program since this file covers
// two of them.
func acmeEnv(t *testing.T, program, message string) Envelope {
	t.Helper()
	env, err := ParseEnvelope([]byte(
		"<134>1 2026-07-27T19:36:01Z test-firewall "+program+" 314 - [meta sequenceId=\"sanitized-sequence\"] "+message,
	), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

func TestACMERegistered(t *testing.T) {
	if _, ok := parserFor("acme.sh"); !ok {
		t.Fatal("no parser registered for program acme.sh")
	}
	if _, ok := parserFor("opnsense"); !ok {
		t.Fatal("no parser registered for program opnsense")
	}
}

// TestACMEOpnsenseCapturedLines exercises every AcmeClient shape captured from
// the OPNsense ACME plugin's own lifecycle log (program `opnsense`).
func TestACMEOpnsenseCapturedLines(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "renewal not required",
			msg:  "AcmeClient: issue/renewal not required for certificate: opnsense.rob-knight.net",
			want: map[string]string{
				"cert.source": "plugin",
				"cert.event":  "renewal_not_required",
				"cert.domain": "opnsense.rob-knight.net",
			},
		},
		{
			name: "renewal required",
			msg:  "AcmeClient: certificate must be issued/renewed: opnsense.rob-knight.net",
			want: map[string]string{
				"cert.source": "plugin",
				"cert.event":  "renewal_required",
				"cert.domain": "opnsense.rob-knight.net",
			},
		},
		{
			name: "issue started",
			msg:  "AcmeClient: issue certificate: opnsense.rob-knight.net",
			want: map[string]string{
				"cert.source": "plugin",
				"cert.event":  "issue_started",
				"cert.domain": "opnsense.rob-knight.net",
			},
		},
		{
			name: "issue succeeded",
			msg:  "AcmeClient: successfully issued/renewed certificate: opnsense.rob-knight.net",
			want: map[string]string{
				"cert.source": "plugin",
				"cert.event":  "issue_succeeded",
				"cert.domain": "opnsense.rob-knight.net",
				"cert.result": "success",
			},
		},
		{
			name: "config wiped",
			msg:  "AcmeClient: wiping certificate config: ovpn.rob-knight.net",
			want: map[string]string{
				"cert.source": "plugin",
				"cert.event":  "config_wiped",
				"cert.domain": "ovpn.rob-knight.net",
			},
		},
		{
			name: "removal failed",
			msg:  "AcmeClient: error removing certificate ovpn.rob-knight.net",
			want: map[string]string{
				"cert.source": "plugin",
				"cert.event":  "removal_failed",
				"cert.domain": "ovpn.rob-knight.net",
				"cert.result": "failure",
			},
		},
		{
			name: "using CA",
			msg:  "AcmeClient: using CA: letsencrypt",
			want: map[string]string{
				"cert.source": "plugin",
				"cert.event":  "ca_selected",
				"cert.ca":     "letsencrypt",
			},
		},
		{
			name: "account registered",
			msg:  "AcmeClient: account is registered: Rob Opnsense",
			want: map[string]string{
				"cert.source": "plugin",
				"cert.event":  "account_registered",
			},
		},
		{
			name: "challenge type",
			msg:  "AcmeClient: using challenge type: Cloudflare Validation",
			want: map[string]string{
				"cert.source":         "plugin",
				"cert.event":          "challenge_type_selected",
				"cert.challenge_type": "Cloudflare Validation",
			},
		},
		{
			name: "CA imported",
			msg:  "AcmeClient: imported ACME CA: YR1 (6a67a595db0ff)",
			want: map[string]string{
				"cert.source": "plugin",
				"cert.event":  "ca_imported",
				"cert.ca":     "YR1 (6a67a595db0ff)",
			},
		},
		{
			name: "shell command success",
			msg:  "AcmeClient: AcmeClient: The shell command returned exit code '0': '/usr/local/sbin/acme.sh --issue --syslog 6 --log-level 1 --server 'letsencrypt' --dns 'dns_cf' --dnssleep '120' --home '/var/etc/acme-client/home' ...",
			want: map[string]string{
				"cert.source":    "plugin",
				"cert.event":     "shell_command",
				"cert.exit_code": "0",
				"cert.result":    "success",
			},
		},
		{
			name: "shell command failure",
			msg:  "AcmeClient: AcmeClient: The shell command returned exit code '1': '/usr/local/sbin/acme.sh --remove --syslog 6 --log-level 1 --server 'letsencrypt' --home '/var/etc/acme-client/home' --cert-home ...",
			want: map[string]string{
				"cert.source":    "plugin",
				"cert.event":     "shell_command",
				"cert.exit_code": "1",
				"cert.result":    "failure",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := acmeEnv(t, "opnsense", tc.msg)
			rec, ok := parseACME(env, nil, func(string) {})
			if !ok {
				t.Fatalf("parseACME(%q) returned ok=false", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message %q", rec.Body, tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestACMEShellClientCapturedLines exercises every shape captured from the
// acme.sh client's own progress log (program `acme.sh`), including the
// bracketed local timestamp every line carries.
func TestACMEShellClientCapturedLines(t *testing.T) {
	const ts = "[Mon Jul 27 19:36:01 BST 2026] "

	tests := []struct {
		name string
		msg  string // WITHOUT the timestamp prefix; ts is prepended below
		want map[string]string
	}{
		{
			name: "domain skipped",
			msg:  "ovpn.rob-knight.net is not an issued domain, skipping.",
			want: map[string]string{
				"cert.source": "acme.sh",
				"cert.event":  "domain_skipped",
				"cert.domain": "ovpn.rob-knight.net",
			},
		},
		{
			name: "using CA",
			msg:  "Using CA: https://acme-v02.api.letsencrypt.org/directory",
			want: map[string]string{
				"cert.source": "acme.sh",
				"cert.event":  "ca_selected",
				"cert.ca":     "https://acme-v02.api.letsencrypt.org/directory",
			},
		},
		{
			name: "registered",
			msg:  "Registered",
			want: map[string]string{
				"cert.source": "acme.sh",
				"cert.event":  "account_registered",
			},
		},
		{
			name: "TXT challenge added",
			msg:  "Adding TXT value: eKqXCNVfgAaZ6nMtjcchmr_NvkWP8trVTv4_s3_9RYE for domain: _acme-challenge.opnsense.rob-knight.net",
			want: map[string]string{
				"cert.source":           "acme.sh",
				"cert.event":            "challenge_added",
				"cert.challenge_domain": "_acme-challenge.opnsense.rob-knight.net",
			},
		},
		{
			name: "validation pending",
			msg:  "Pending. The CA is processing your order, please wait. (1/30)",
			want: map[string]string{
				"cert.source":      "acme.sh",
				"cert.event":       "validation_pending",
				"cert.attempt":     "1",
				"cert.attempt_max": "30",
			},
		},
		{
			name: "validation succeeded",
			msg:  "Success",
			want: map[string]string{
				"cert.source": "acme.sh",
				"cert.event":  "validation_succeeded",
				"cert.result": "success",
			},
		},
		{
			name: "TXT challenge removed",
			msg:  "Removing txt: eKqXCNVfgAaZ6nMtjcchmr_NvkWP8trVTv4_s3_9RYE for domain: _acme-challenge.opnsense.rob-knight.net",
			want: map[string]string{
				"cert.source":           "acme.sh",
				"cert.event":            "challenge_removed",
				"cert.challenge_domain": "_acme-challenge.opnsense.rob-knight.net",
			},
		},
		{
			name: "signing started",
			msg:  "Verification finished, beginning signing.",
			want: map[string]string{
				"cert.source": "acme.sh",
				"cert.event":  "signing_started",
			},
		},
		{
			name: "cert downloaded",
			msg:  "Cert success.",
			want: map[string]string{
				"cert.source": "acme.sh",
				"cert.event":  "cert_downloaded",
				"cert.result": "success",
			},
		},
		{
			name: "cert installed",
			msg:  "Installing cert to: /var/etc/acme-client/certs/6a67a50e7b3296.89577807/cert.pem",
			want: map[string]string{
				"cert.source": "acme.sh",
				"cert.event":  "cert_installed",
			},
		},
		{
			name: "CA installed",
			msg:  "Installing CA to: /var/etc/acme-client/certs/6a67a50e7b3296.89577807/chain.pem",
			want: map[string]string{
				"cert.source": "acme.sh",
				"cert.event":  "cert_installed",
			},
		},
		{
			name: "full chain installed",
			msg:  "Installing full chain to: /var/etc/acme-client/certs/6a67a50e7b3296.89577807/fullchain.pem",
			want: map[string]string{
				"cert.source": "acme.sh",
				"cert.event":  "cert_installed",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fullMsg := ts + tc.msg
			env := acmeEnv(t, "acme.sh", fullMsg)
			rec, ok := parseACME(env, nil, func(string) {})
			if !ok {
				t.Fatalf("parseACME(%q) returned ok=false", fullMsg)
			}
			if rec.Body != fullMsg {
				t.Errorf("Body = %q, want raw message %q", rec.Body, fullMsg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestACMEShellClientLeavesUnmodelledLinesGeneric asserts every acme.sh line
// this brief deliberately declined to structure (see acme.go's file-level doc
// comment) degrades to a generic record rather than being silently absorbed
// into a nearby grammar.
func TestACMEShellClientLeavesUnmodelledLinesGeneric(t *testing.T) {
	const ts = "[Mon Jul 27 19:36:01 BST 2026] "

	lines := []string{
		"Account key creation OK.",
		"Registering account: https://acme-v02.api.letsencrypt.org/directory",
		"ACCOUNT_THUMBPRINT='hQwUv3gZtScrlHLiyr6jK3XYK4rChbcuw94mOCTInGs'",
		"Creating domain key",
		"The domain key is here: /var/etc/acme-client/cert-home/6a67a50e7b3296.89577807/opnsense.rob-knight.net/opnsense.rob-knight.net.key",
		"Single domain='opnsense.rob-knight.net'",
		"Getting webroot for domain='opnsense.rob-knight.net'",
		"Adding record",
		"Added, OK",
		"The TXT record has been successfully added.",
		"Sleeping for 120 seconds to wait for the the TXT records to take effect",
		"Verifying: opnsense.rob-knight.net",
		"Removing DNS records.",
		"Successfully removed",
		"Let's finalize the order.",
		"Le_OrderFinalize='https://acme-v02.api.letsencrypt.org/acme/finalize/3574489435/537437040185'",
		"Downloading cert.",
		"Le_LinkCert='https://acme-v02.api.letsencrypt.org/acme/cert/063e884eeee6250542b6eb215206e47a3ad0'",
		"Your cert is in: /var/etc/acme-client/cert-home/6a67a50e7b3296.89577807/opnsense.rob-knight.net/opnsense.rob-knight.net.cer",
		"Your cert key is in: /var/etc/acme-client/cert-home/6a67a50e7b3296.89577807/opnsense.rob-knight.net/opnsense.rob-knight.net.key",
		"The intermediate CA cert is in: /var/etc/acme-client/cert-home/6a67a50e7b3296.89577807/opnsense.rob-knight.net/ca.cer",
		"And the full-chain cert is in: /var/etc/acme-client/cert-home/6a67a50e7b3296.89577807/opnsense.rob-knight.net/fullchain.cer",
		"Installing key to: /var/etc/acme-client/keys/6a67a50e7b3296.89577807/private.key",
	}

	for _, msg := range lines {
		fullMsg := ts + msg
		t.Run(strings.ReplaceAll(msg, " ", "_"), func(t *testing.T) {
			env := acmeEnv(t, "acme.sh", fullMsg)
			rec, parsed := buildRecord(env, nil, func(string) {})
			if parsed {
				t.Fatalf("buildRecord(%q) parsed a line this parser deliberately leaves generic", fullMsg)
			}
			if rec.Body != fullMsg {
				t.Errorf("Body = %q, want generic body %q", rec.Body, fullMsg)
			}
			assertAttrs(t, rec, map[string]string{"program": "acme.sh"})
			assertNoAttrs(t, rec, "cert.event", "cert.domain", "cert.ca", "cert.source")
		})
	}
}

// TestOpnsenseCatchAllNonACMELineIsNotClaimed is the guard the acme.go
// file-level warning refers to: `opnsense` is a catch-all program shared with
// every other PHP script on the box, and this parser must never claim a line
// that is not one of the captured AcmeClient shapes.
func TestOpnsenseCatchAllNonACMELineIsNotClaimed(t *testing.T) {
	lines := []string{
		// A plausible unrelated OPNsense PHP log line under the same catch-all
		// program name.
		"WebGUI: user 'root' authenticated successfully",
		"rc.bootup: rc.bootup is Starting...",
		"check_reload_status: Reloading filter",
		// Near misses on our own AcmeClient grammars.
		"AcmeClient issue certificate: opnsense.rob-knight.net",            // missing colon after AcmeClient
		"acmeclient: issue certificate: opnsense.rob-knight.net",           // wrong case
		"AcmeClient: issue certificate for: opnsense.rob-knight.net",       // extra word
		"AcmeClient: The shell command returned exit code '0': '/bin/foo'", // single, not doubled, prefix
	}

	for _, line := range lines {
		t.Run(strings.ReplaceAll(line, " ", "_"), func(t *testing.T) {
			env := acmeEnv(t, "opnsense", line)
			if _, ok := parseACME(env, nil, func(string) {}); ok {
				t.Errorf("parseACME() claimed a non-AcmeClient opnsense line it must leave generic: %q", line)
			}
		})
	}
}

// TestACMESecretsNeverLeak is the hard security gate this parser exists under:
// the ACME account thumbprint and the DNS-01 challenge TXT values must never
// appear as an attribute VALUE anywhere in the corpus, structured or not. The
// raw message body is exempt (it always carries the verbatim line, as it does
// for every unparsed log line in this pipeline) — this test asserts about
// ATTRIBUTES only.
func TestACMESecretsNeverLeak(t *testing.T) {
	const thumbprint = "hQwUv3gZtScrlHLiyr6jK3XYK4rChbcuw94mOCTInGs"
	const txtValue = "eKqXCNVfgAaZ6nMtjcchmr_NvkWP8trVTv4_s3_9RYE"

	const shTS = "[Mon Jul 27 19:36:01 BST 2026] "

	corpus := []struct {
		program string
		msg     string
	}{
		{"opnsense", "AcmeClient: issue/renewal not required for certificate: opnsense.rob-knight.net"},
		{"opnsense", "AcmeClient: certificate must be issued/renewed: opnsense.rob-knight.net"},
		{"opnsense", "AcmeClient: issue certificate: opnsense.rob-knight.net"},
		{"opnsense", "AcmeClient: successfully issued/renewed certificate: opnsense.rob-knight.net"},
		{"opnsense", "AcmeClient: wiping certificate config: ovpn.rob-knight.net"},
		{"opnsense", "AcmeClient: error removing certificate ovpn.rob-knight.net"},
		{"opnsense", "AcmeClient: using CA: letsencrypt"},
		{"opnsense", "AcmeClient: account is registered: Rob Opnsense"},
		{"opnsense", "AcmeClient: using challenge type: Cloudflare Validation"},
		{"opnsense", "AcmeClient: imported ACME CA: YR1 (6a67a595db0ff)"},
		{"opnsense", "AcmeClient: AcmeClient: The shell command returned exit code '0': '/usr/local/sbin/acme.sh --issue --syslog 6 --log-level 1 --server 'letsencrypt' --dns 'dns_cf' --dnssleep '120' --home '/var/etc/acme-client/home' ..."},
		{"opnsense", "AcmeClient: AcmeClient: The shell command returned exit code '1': '/usr/local/sbin/acme.sh --remove --syslog 6 --log-level 1 --server 'letsencrypt' --home '/var/etc/acme-client/home' --cert-home ..."},

		{"acme.sh", shTS + "ovpn.rob-knight.net is not an issued domain, skipping."},
		{"acme.sh", shTS + "Using CA: https://acme-v02.api.letsencrypt.org/directory"},
		{"acme.sh", shTS + "Account key creation OK."},
		{"acme.sh", shTS + "Registering account: https://acme-v02.api.letsencrypt.org/directory"},
		{"acme.sh", shTS + "Registered"},
		{"acme.sh", shTS + "ACCOUNT_THUMBPRINT='" + thumbprint + "'"},
		{"acme.sh", shTS + "Creating domain key"},
		{"acme.sh", shTS + "The domain key is here: /var/etc/acme-client/cert-home/6a67a50e7b3296.89577807/opnsense.rob-knight.net/opnsense.rob-knight.net.key"},
		{"acme.sh", shTS + "Single domain='opnsense.rob-knight.net'"},
		{"acme.sh", shTS + "Getting webroot for domain='opnsense.rob-knight.net'"},
		{"acme.sh", shTS + "Adding TXT value: " + txtValue + " for domain: _acme-challenge.opnsense.rob-knight.net"},
		{"acme.sh", shTS + "Adding record"},
		{"acme.sh", shTS + "Added, OK"},
		{"acme.sh", shTS + "The TXT record has been successfully added."},
		{"acme.sh", shTS + "Sleeping for 120 seconds to wait for the the TXT records to take effect"},
		{"acme.sh", shTS + "Verifying: opnsense.rob-knight.net"},
		{"acme.sh", shTS + "Pending. The CA is processing your order, please wait. (1/30)"},
		{"acme.sh", shTS + "Success"},
		{"acme.sh", shTS + "Removing DNS records."},
		{"acme.sh", shTS + "Removing txt: " + txtValue + " for domain: _acme-challenge.opnsense.rob-knight.net"},
		{"acme.sh", shTS + "Successfully removed"},
		{"acme.sh", shTS + "Verification finished, beginning signing."},
		{"acme.sh", shTS + "Let's finalize the order."},
		{"acme.sh", shTS + "Le_OrderFinalize='https://acme-v02.api.letsencrypt.org/acme/finalize/3574489435/537437040185'"},
		{"acme.sh", shTS + "Downloading cert."},
		{"acme.sh", shTS + "Le_LinkCert='https://acme-v02.api.letsencrypt.org/acme/cert/063e884eeee6250542b6eb215206e47a3ad0'"},
		{"acme.sh", shTS + "Cert success."},
		{"acme.sh", shTS + "Your cert is in: /var/etc/acme-client/cert-home/6a67a50e7b3296.89577807/opnsense.rob-knight.net/opnsense.rob-knight.net.cer"},
		{"acme.sh", shTS + "Your cert key is in: /var/etc/acme-client/cert-home/6a67a50e7b3296.89577807/opnsense.rob-knight.net/opnsense.rob-knight.net.key"},
		{"acme.sh", shTS + "The intermediate CA cert is in: /var/etc/acme-client/cert-home/6a67a50e7b3296.89577807/opnsense.rob-knight.net/ca.cer"},
		{"acme.sh", shTS + "And the full-chain cert is in: /var/etc/acme-client/cert-home/6a67a50e7b3296.89577807/opnsense.rob-knight.net/fullchain.cer"},
		{"acme.sh", shTS + "Installing cert to: /var/etc/acme-client/certs/6a67a50e7b3296.89577807/cert.pem"},
		{"acme.sh", shTS + "Installing CA to: /var/etc/acme-client/certs/6a67a50e7b3296.89577807/chain.pem"},
		{"acme.sh", shTS + "Installing key to: /var/etc/acme-client/keys/6a67a50e7b3296.89577807/private.key"},
		{"acme.sh", shTS + "Installing full chain to: /var/etc/acme-client/certs/6a67a50e7b3296.89577807/fullchain.pem"},
	}

	for _, tc := range corpus {
		env := acmeEnv(t, tc.program, tc.msg)
		rec, _ := buildRecord(env, nil, func(string) {})
		for k, v := range rec.Attributes {
			if strings.Contains(v, thumbprint) {
				t.Errorf("program %s msg %q: attribute %s=%q leaked the account thumbprint", tc.program, tc.msg, k, v)
			}
			if strings.Contains(v, txtValue) {
				t.Errorf("program %s msg %q: attribute %s=%q leaked the DNS-01 challenge value", tc.program, tc.msg, k, v)
			}
		}
	}
}
