package logship

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeConfigChangeFetcher struct {
	revisions []ConfigChangeRevision
	diffs     map[string]string
	diffCalls []string
}

func (f *fakeConfigChangeFetcher) FetchConfigChangeRevisions(context.Context) ([]ConfigChangeRevision, error) {
	return append([]ConfigChangeRevision(nil), f.revisions...), nil
}

func (f *fakeConfigChangeFetcher) FetchConfigChangeDiff(_ context.Context, _ string, oldRevision, newRevision string) (string, error) {
	key := oldRevision + "->" + newRevision
	f.diffCalls = append(f.diffCalls, key)
	return f.diffs[key], nil
}

type blockingConfigChangeFetcher struct{ started chan struct{} }

func (f *blockingConfigChangeFetcher) FetchConfigChangeRevisions(ctx context.Context) ([]ConfigChangeRevision, error) {
	close(f.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (f *blockingConfigChangeFetcher) FetchConfigChangeDiff(ctx context.Context, _ string, _, _ string) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

func TestConfigChangeSource_PollHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fetcher := &blockingConfigChangeFetcher{started: make(chan struct{})}
	source := NewConfigChangeSource(fetcher, nil)
	done := make(chan error, 1)
	go func() {
		_, err := source.Poll(ctx)
		done <- err
	}()

	select {
	case <-fetcher.started:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("Poll did not start the revisions fetch")
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Poll error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Poll did not return after context cancellation")
	}
}

func TestConfigChangeSource_EmitsNewRevisionExactlyOnce(t *testing.T) {
	t0 := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	fetcher := &fakeConfigChangeFetcher{
		revisions: []ConfigChangeRevision{{ID: "config-r1.xml", Timestamp: t0}},
		diffs: map[string]string{
			"config-r1.xml->config-r2.xml": "--- old\n+++ new\n+&lt;rule/&gt;\n",
		},
	}
	source := NewConfigChangeSource(fetcher, nil)

	if got, err := source.Poll(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("initial poll = (%d records, %v), want baseline with no records", len(got), err)
	}

	fetcher.revisions = []ConfigChangeRevision{
		{ID: "config-r2.xml", Timestamp: t0.Add(time.Minute), User: "alice", URI: "/api/firewall/filter/addRule"},
		{ID: "config-r1.xml", Timestamp: t0},
	}
	got, err := source.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("new revision records = %d, want 1", len(got))
	}
	record := got[0]
	if record.Timestamp != t0.Add(time.Minute) {
		t.Fatalf("timestamp = %s, want %s", record.Timestamp, t0.Add(time.Minute))
	}
	if record.Body != "--- old\n+++ new\n+<rule/>\n" {
		t.Fatalf("body = %q, want HTML-unescaped unified diff", record.Body)
	}
	if got, want := record.Attributes, map[string]string{
		"revision": "config-r2.xml",
		"user":     "alice",
		"uri":      "/api/firewall/filter/addRule",
	}; !mapsEqual(got, want) {
		t.Fatalf("attributes = %#v, want %#v", got, want)
	}

	got, err = source.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("repeat poll emitted %d records, want 0", len(got))
	}
	if got, want := strings.Join(fetcher.diffCalls, ","), "config-r1.xml->config-r2.xml"; got != want {
		t.Fatalf("diff calls = %q, want %q", got, want)
	}
}

func TestConfigChangeSource_RedactsExpandedCredentialVocabulary(t *testing.T) {
	t0 := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	secrets := []string{
		"configchange-totp-seed",
		"configchange-ldap-bind-password",
		"configchange-encrypted-key",
		"configchange-snmp-community",
	}
	fetcher := &fakeConfigChangeFetcher{
		revisions: []ConfigChangeRevision{{ID: "config-r1.xml", Timestamp: t0}},
		diffs: map[string]string{
			"config-r1.xml->config-r2.xml": "+ <otp_seed>" + secrets[0] + "</otp_seed>\n" +
				"+ <ldap_bindpw>" + secrets[1] + "</ldap_bindpw>\n" +
				"+ <enckey>" + secrets[2] + "</enckey>\n" +
				"+ <community>" + secrets[3] + "</community>",
		},
	}
	source := NewConfigChangeSource(fetcher, nil)
	if _, err := source.Poll(context.Background()); err != nil {
		t.Fatalf("baseline poll: %v", err)
	}
	fetcher.revisions = []ConfigChangeRevision{
		{ID: "config-r2.xml", Timestamp: t0.Add(time.Minute)},
		{ID: "config-r1.xml", Timestamp: t0},
	}

	records, err := source.Poll(context.Background())
	if err != nil {
		t.Fatalf("changed-revision poll: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	for _, secret := range secrets {
		if strings.Contains(records[0].Body, secret) {
			t.Errorf("config-change record leaked %q: %s", secret, records[0].Body)
		}
	}
	if !strings.Contains(records[0].Body, configChangeRedactionMarker) {
		t.Errorf("config-change record has no redaction marker: %s", records[0].Body)
	}
}

func TestConfigChangeSource_RestoresCursorWithoutReplay(t *testing.T) {
	t0 := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	fetcher := &fakeConfigChangeFetcher{
		revisions: []ConfigChangeRevision{{ID: "config-r1.xml", Timestamp: t0}},
		diffs: map[string]string{
			"config-r1.xml->config-r2.xml": "r1 to r2",
			"config-r2.xml->config-r3.xml": "r2 to r3",
		},
	}
	source := NewConfigChangeSource(fetcher, nil)
	if _, err := source.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	fetcher.revisions = []ConfigChangeRevision{
		{ID: "config-r2.xml", Timestamp: t0.Add(time.Minute)},
		{ID: "config-r1.xml", Timestamp: t0},
	}
	if got, err := source.Poll(context.Background()); err != nil || len(got) != 1 {
		t.Fatalf("pre-restart poll = (%d records, %v), want one record", len(got), err)
	}
	state, ok := source.SaveState()
	if !ok {
		t.Fatal("SaveState reported no cursor after successful poll")
	}

	restarted := NewConfigChangeSource(fetcher, nil)
	restarted.LoadState(state)
	if got, err := restarted.Poll(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("restored poll = (%d records, %v), want no replay", len(got), err)
	}

	fetcher.revisions = append([]ConfigChangeRevision{{ID: "config-r3.xml", Timestamp: t0.Add(2 * time.Minute)}}, fetcher.revisions...)
	got, err := restarted.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Attributes["revision"] != "config-r3.xml" {
		t.Fatalf("post-restart records = %#v, want only config-r3.xml", got)
	}
}

func TestConfigChangeSource_UnescapesAndCapsDiffBody(t *testing.T) {
	t0 := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	largeEscapedDiff := "&lt;config&gt;" + strings.Repeat("x", configChangeMaxBodyBytes) + "&lt;/config&gt;"
	fetcher := &fakeConfigChangeFetcher{
		revisions: []ConfigChangeRevision{{ID: "config-r1.xml", Timestamp: t0}},
		diffs: map[string]string{
			"config-r1.xml->config-r2.xml": largeEscapedDiff,
		},
	}
	source := NewConfigChangeSource(fetcher, nil)
	if _, err := source.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	fetcher.revisions = []ConfigChangeRevision{
		{ID: "config-r2.xml", Timestamp: t0.Add(time.Minute)},
		{ID: "config-r1.xml", Timestamp: t0},
	}
	got, err := source.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("records = %d, want 1", len(got))
	}
	if len(got[0].Body) > configChangeMaxBodyBytes {
		t.Fatalf("body is %d bytes, cap is %d", len(got[0].Body), configChangeMaxBodyBytes)
	}
	if !strings.HasPrefix(got[0].Body, "<config>") {
		t.Fatalf("body = %q..., want HTML-unescaped prefix", got[0].Body[:32])
	}
	if !strings.HasSuffix(got[0].Body, configChangeTruncationMarker) {
		t.Fatalf("body does not end in truncation marker %q", configChangeTruncationMarker)
	}
}

func TestConfigChangeSource_ExtractsURIFromRevisionDescription(t *testing.T) {
	record := configChangeRecord(ConfigChangeRevision{
		Description: "/api/firewall/filter/addRule made changes",
	}, "")
	if got, want := record.Attributes["uri"], "/api/firewall/filter/addRule"; got != want {
		t.Fatalf("uri = %q, want %q", got, want)
	}
}

func mapsEqual(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, wantValue := range want {
		if got[k] != wantValue {
			return false
		}
	}
	return true
}

// TestRedactConfigChangeDiff_RemovesCredentials pins the vocabulary and the
// element shapes an OPNsense config.xml diff actually produces. Every case here
// is a credential that reached the shipped log body verbatim before redaction
// existed: the diff is the payload of this source, so a config.xml section
// carrying a secret is shipped in full the moment it changes.
func TestRedactConfigChangeDiff_RemovesCredentials(t *testing.T) {
	cases := []struct {
		name    string
		diff    string
		secret  string
		wantTag string
	}{
		{
			name:    "user password hash",
			diff:    "-      <password>$2y$10$OLDHASHVALUE</password>\n+      <password>$2y$10$NEWHASHVALUE</password>",
			secret:  "$2y$10$NEWHASHVALUE",
			wantTag: "<password>",
		},
		{
			name:    "camelCase api key",
			diff:    "+      <apiKey>AKIAEXAMPLEKEYVALUE</apiKey>",
			secret:  "AKIAEXAMPLEKEYVALUE",
			wantTag: "<apiKey>",
		},
		{
			name:    "kebab-case pre-shared key",
			diff:    "+      <pre-shared-key>ipsecPSKvalue</pre-shared-key>",
			secret:  "ipsecPSKvalue",
			wantTag: "<pre-shared-key>",
		},
		{
			name:    "snake_case radius secret",
			diff:    "+      <radius_secret>sharedRadiusValue</radius_secret>",
			secret:  "sharedRadiusValue",
			wantTag: "<radius_secret>",
		},
		{
			name:    "short certificate private half",
			diff:    "+      <prv>QkFTRTY0UFJJVkFURUtFWQ==</prv>",
			secret:  "QkFTRTY0UFJJVkFURUtFWQ==",
			wantTag: "<prv>",
		},
		{
			name:    "wireguard private key",
			diff:    "+      <privkey>wgPrivateKeyBase64Value=</privkey>",
			secret:  "wgPrivateKeyBase64Value=",
			wantTag: "<privkey>",
		},
		{
			name:    "TOTP seed",
			diff:    "+      <otp_seed>JBSWY3DPEHPK3PXP</otp_seed>",
			secret:  "JBSWY3DPEHPK3PXP",
			wantTag: "<otp_seed>",
		},
		{
			name:    "LDAP bind password",
			diff:    "+      <ldap_bindpw>ldapBindSecret</ldap_bindpw>",
			secret:  "ldapBindSecret",
			wantTag: "<ldap_bindpw>",
		},
		{
			name:    "encrypted key",
			diff:    "+      <enckey>encryptedKeyMaterial</enckey>",
			secret:  "encryptedKeyMaterial",
			wantTag: "<enckey>",
		},
		{
			name:    "Net-SNMP community",
			diff:    "+      <community>netSNMPCommunity</community>",
			secret:  "netSNMPCommunity",
			wantTag: "<community>",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactConfigChangeDiff(tc.diff)
			if strings.Contains(got, tc.secret) {
				t.Fatalf("redacted diff still contains the secret %q:\n%s", tc.secret, got)
			}
			if !strings.Contains(got, tc.wantTag) {
				t.Errorf("redacted diff dropped the element name %q, so an operator cannot see what changed:\n%s", tc.wantTag, got)
			}
			if !strings.Contains(got, configChangeRedactionMarker) {
				t.Errorf("redacted diff carries no redaction marker:\n%s", got)
			}
		})
	}
}

// TestRedactConfigChangeDiff_RedactsWrappedValues covers the shape that made a
// line-local regex insufficient. This is synthetic multiline material; standard
// OPNsense Trust writes encode private material as single-line base64.
func TestRedactConfigChangeDiff_RedactsWrappedValues(t *testing.T) {
	diff := strings.Join([]string{
		"@@ -10,4 +10,6 @@",
		"+      <privatekey>FIRSTBASE64CHUNK",
		"+SECONDBASE64CHUNK",
		"+THIRDBASE64CHUNK</privatekey>",
		"       <descr>the certificate description</descr>",
	}, "\n")

	got := redactConfigChangeDiff(diff)
	for _, secret := range []string{"FIRSTBASE64CHUNK", "SECONDBASE64CHUNK", "THIRDBASE64CHUNK"} {
		if strings.Contains(got, secret) {
			t.Fatalf("wrapped key material %q survived redaction:\n%s", secret, got)
		}
	}
	if !strings.Contains(got, "</privatekey>") {
		t.Errorf("redaction consumed the closing element:\n%s", got)
	}
	if !strings.Contains(got, "the certificate description") {
		t.Errorf("redaction ran past the closing element into unrelated content:\n%s", got)
	}
}

func TestRedactConfigChangeDiff_MixedPrefixSensitiveElement(t *testing.T) {
	// Synthetic XML text-node continuations exercise unified-diff prefix changes.
	for _, diff := range []string{
		"-<privatekey>SYNTH-FIRST\n SYNTH-LAST</privatekey>",
		"-<privatekey>SYNTH-OLD\n+<privatekey>SYNTH-NEW\n SYNTH-LAST</privatekey>",
		"+<privatekey>SYNTH-FIRST\n\n+SYNTH-LAST</privatekey>",
		" <privatekey>SYNTH-FIRST\n-SYNTH-OLD</privatekey>\n+SYNTH-NEW\n SYNTH-LAST</privatekey>",
	} {
		got := redactConfigChangeDiff(diff + "\n <descr>ordinary</descr>")
		if strings.Contains(got, "SYNTH-") {
			t.Errorf("sensitive continuation survived: %q", got)
		}
		if !strings.Contains(got, "</privatekey>") || !strings.Contains(got, "<descr>ordinary</descr>") {
			t.Errorf("closing tag or following ordinary content lost: %q", got)
		}
	}
}

// TestRedactConfigChangeDiff_KeepsNonSensitiveContent guards the other
// direction: the diff is the evidence this source exists to ship, so redaction
// that swallowed ordinary configuration would make the source useless.
func TestRedactConfigChangeDiff_KeepsNonSensitiveContent(t *testing.T) {
	diff := strings.Join([]string{
		"@@ -1,5 +1,5 @@",
		"       <hostname>firewall</hostname>",
		"-      <descr>old description</descr>",
		"+      <descr>new description</descr>",
		"       <publickey>notASecretValue=</publickey>",
	}, "\n")

	got := redactConfigChangeDiff(diff)
	if got != diff {
		t.Errorf("non-sensitive diff was altered:\ngot:\n%s\nwant:\n%s", got, diff)
	}
}

// TestRedactConfigChangeDiff_HunkHeaderBoundsOverRedaction pins the blast radius
// of an element the scanner never sees closed. It must not suppress the rest of
// the diff.
func TestRedactConfigChangeDiff_HunkHeaderBoundsOverRedaction(t *testing.T) {
	diff := strings.Join([]string{
		"+      <password>unterminatedSecretValue",
		"@@ -40,3 +40,3 @@",
		"       <hostname>firewall</hostname>",
	}, "\n")

	got := redactConfigChangeDiff(diff)
	if strings.Contains(got, "unterminatedSecretValue") {
		t.Fatalf("unterminated sensitive element leaked its value:\n%s", got)
	}
	if !strings.Contains(got, "<hostname>firewall</hostname>") {
		t.Errorf("an unterminated element suppressed content past the hunk header:\n%s", got)
	}
}

// TestConfigChangeRecord_RedactsBeforeTruncation pins the ordering. Redacting
// after the cut would ship every secret that fell inside the retained prefix.
func TestConfigChangeRecord_RedactsBeforeTruncation(t *testing.T) {
	secret := "$2y$10$SECRETHASHVALUE"
	diff := "-      <password>" + secret + "</password>\n" +
		strings.Repeat("       <descr>filler line to force truncation</descr>\n", 8000)

	record := configChangeRecord(ConfigChangeRevision{ID: "rev-2", User: "root"}, diff)

	if strings.Contains(record.Body, secret) {
		t.Fatalf("truncated body still carries the credential")
	}
	if !strings.Contains(record.Body, configChangeRedactionMarker) {
		t.Fatalf("truncated body carries no redaction marker, so redaction ran after the cut")
	}
	if len(record.Body) > configChangeMaxBodyBytes+len(configChangeTruncationMarker) {
		t.Fatalf("body is %d bytes, over the cap", len(record.Body))
	}
}
