---
id: OPN-0094
title: Shared sensitive-key vocabulary is imprecise in both directions
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-05 18:59'
updated_date: '2026-09-05 19:17'
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

That is not academic. POST /api/auth/user/add_api_key returns an object whose id and key members are the two halves of an API credential, so key is OPNsense's own name for the bearer half. Verified against the OPNsense docs, not from memory.

Adding key to the word-segment map rather than the substring list also covers dns_cf_key and the apikeys item shape, without matching keyexpiry or monkey.

Also currently false, and flagged as UNVERIFIED OPNsense element names rather than asserted: tls, auth_pass, salt, md5-hash, nt-hash, bearer, cookie, dns_gd_key. Check each against upstream source before adding it; do not add on plausibility.

Over-matching. OPNsense MVC validation failures key their messages by field path, so:

    {"validations":{"general.password":"This field is required"}}
      -> {"validations":{"general.password":"[REDACTED]"}}

The redacted content is the message, never a credential, and it is the entire diagnostic value of that body. Same effect on dnscrypt_shared_secret in opnsense/unbound_dns.go:349, where the secret is a cache-entry count.

The C:\Users over-redaction is documented and deliberate and is NOT in scope here.

Both directions are one function, so fix them together or the second regresses the first.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A bare key field is treated as sensitive, and keyexpiry is not
- [ ] #2 Any additional element name added is justified against upstream OPNsense source in the notes
- [ ] #3 An MVC validation message keyed by a sensitive field path keeps its message text
- [ ] #4 Regressions cover both directions and fail before the fix
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
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
<!-- SECTION:NOTES:END -->
