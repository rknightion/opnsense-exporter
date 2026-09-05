---
id: OPN-0094
title: Shared sensitive-key vocabulary is imprecise in both directions
status: Done
assignee:
  - '@codex'
created_date: '2026-09-05 18:59'
updated_date: '2026-09-05 20:31'
labels:
  - bug
dependencies: []
priority: medium
ordinal: 48000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
opnsense/config_snapshot.go, SensitiveConfigKey. Two problems in one function, one leaking and one over-redacting.

Under-matching. SensitiveConfigKey("key") is false, while apikey, secret and prv are all true. The query-parameter path in the same package DOES match a bare key parameter and has a test for it, so one package disagrees with itself. Executed:

    {"key":"SYNTH-APIKEY-5","id":"12345"}  -> unchanged

That is not academic. Upstream ApiKeyField add returns key and secret, which addApiKeyAction returns with result/hostname. The key field is API credential material. searchApiKeyAction separately exposes key/id; the original brief conflated those response shapes. This client does not invoke add_api_key.

Adding key to the word-segment map rather than the substring list also covers dns_cf_key and the apikeys item shape, without matching keyexpiry or monkey.

Also currently false, and flagged as UNVERIFIED OPNsense element names rather than asserted: tls, auth_pass, salt, md5-hash, nt-hash, bearer, cookie, dns_gd_key. Check each against upstream source before adding it; do not add on plausibility.

Over-matching. OPNsense MVC validation failures key their messages by field path, so:

    {"validations":{"general.password":"This field is required"}}
      -> {"validations":{"general.password":"[REDACTED]"}}

The redacted content is a validator message. The illustrated generic message is value-free, but upstream forwards arbitrary validator text, which may interpolate values; a whole-envelope exemption is not proven safe. dnscrypt_shared_secret in opnsense/unbound_dns.go is a numeric cache-entry count, but normal decoded responses there do not traverse SensitiveConfigKey, so it does not justify a vocabulary exemption.

The C:\Users over-redaction is documented and deliberate and is NOT in scope here.

Keep the shared vocabulary strict. The confirmed under-match is repaired; safe preservation of validation messages is a separate policy boundary recorded below.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A bare key field is treated as sensitive, and keyexpiry is not
- [x] #2 Any additional element name added is justified against upstream OPNsense source in the notes
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 7 freezes the safe subset: add bare key to separator-aware sensitiveConfigTerms with failing-before vocabulary regressions. Do not exempt validations or weaken password/secret matching: upstream forwards arbitrary validator messages without a value-free guarantee. Preserve existing redaction; park message-preservation AC behind a demonstrated generic-value-free allowlist or explicit policy. No speculative names added.

Full gate exposed shared-vocabulary interaction: the exporter-generated key_owners aggregate is removed by the new key term. Rename that generated safe aggregate to access_owners and update its existing behavioral test, preserving owner/count values and strict redaction. No documented external field references found. Record this snapshot wire-field migration explicitly; do not add a sensitive-key exemption.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Upstream correction: ApiKeyField add returns key and secret, and addApiKeyAction returns those plus result/hostname; it is searchApiKeyAction that returns key/id. The client does not call add_api_key. Normal Trust private material is base64 single-line. Validation message content may interpolate values; whole-envelope exemption is unsafe without narrower evidence.

Vocabulary regression failed before for key and dns_cf_key, both false instead of true; keyexpiry and monkey controls remained nonsensitive. After separator-aware key term addition: ok github.com/rknightion/opnsense2otel/v4/opnsense 0.287s. No additional speculative element names added; validation-message redaction remains intact.

First integrated check failed TestSecurityPostureProvider_AggregatesFirmwareCertificatesAndOwners: API key owners = nil, want owner-sorted aggregates. This is a real regression from the vocabulary change and must be fixed before commit.

Decision by Rob 2026-09-05 (post wave 7): AC3/4 (preserve MVC validation-message text under a sensitive field path) are dropped, not deferred. Fail-closed redaction stays. Reasons: upstream forwards arbitrary validator text that may interpolate values, so no whole-envelope exemption is provably safe; the exporter issues no set/add calls, so validation envelopes are near-unreachable on its request paths; the C:\Users over-redaction remains documented and deliberate. No allowlist lane will be scheduled unless a live body shows the loss of a diagnostic message that matters.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Source landed in c67a6060d0d7ea09d95e3b155fe92a043a0f3dea. Final eight-file source-only CodeRabbit event: review_completed, findings=0. Full just check exit 0; terminal: Your code is affected by 0 vulnerabilities. Bare key and separated key terms are now sensitive; keyexpiry/monkey remain nonsensitive (regressions failed before). The full gate caught and repaired loss of the generated owner aggregate: security-posture snapshot field key_owners is now access_owners, preserving counts without a redaction exemption (ok internal/logship/configsnapshot 0.342s). The former AC3/4 (validation-message preservation) were removed by owner decision on 2026-09-05: fail-closed redaction is the accepted behaviour because upstream validator text is not proven value-free and the exporter never issues the calls that produce validation envelopes. No speculative vocabulary additions; the unverified element names stay listed in the description as unverified.
<!-- SECTION:FINAL_SUMMARY:END -->
