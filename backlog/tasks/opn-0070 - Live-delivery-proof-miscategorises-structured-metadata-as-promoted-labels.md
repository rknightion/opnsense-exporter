---
id: OPN-0070
title: Live delivery proof miscategorises structured metadata as promoted labels
status: Done
assignee: []
created_date: '2026-09-04 08:33'
updated_date: '2026-09-04 08:38'
labels:
  - bug
dependencies: []
ordinal: 24000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
live_delivery_proof.py queried Loki without the categorize-labels response encoding. In that default encoding Loki MERGES structured metadata into each stream's label map and omits the per-entry metadata element entirely, so the harness read:

- every structured-metadata key as a promoted stream label. Wave 5 reported 202 keys outside the documented seven-key set and recorded it as an unexplained current-build label expansion.
- an always-empty metadata map, which makes has_domain_metadata structurally incapable of returning true. The OPN-0038 placement assertion could never have passed.

Both were measurement artifacts. Re-querying the same three Wave 5 proof instances with X-Loki-Response-Encoding-Flags: categorize-labels shows stream labels of exactly opnsense_action, opnsense_source, opnsense_subsystem, service_instance_id, service_name (all inside the documented seven), dst_domain present in structuredMetadata with the expected value, and dst_domain absent from stream labels in every stream.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Loki queries request the categorize-labels response encoding
- [x] #2 records() reads the structuredMetadata member of the per-entry category map
- [x] #3 An uncategorized response yields empty metadata so the domain assertion fails closed rather than reading merged labels as exporter behaviour
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in scripts/testbed/live_delivery_proof.py: loki_query sends X-Loki-Response-Encoding-Flags: categorize-labels, and records() reads the structuredMetadata member of the per-entry category map.

Verified live against the retained Wave 5 data rather than only in tests. Querying m7kni Loki for instances delivery-proof-33843852532, delivery-proof-33848582974 and delivery-proof-33849420068 both ways:

- default encoding: values tuples arrive with length 2 (no metadata element at all) and the stream map carries 9+ merged keys.
- categorize-labels: stream labels are exactly opnsense_action, opnsense_source, opnsense_subsystem, service_instance_id, service_name in all three runs, with 203 distinct structured-metadata keys held separately.

So the Wave 5 '202 unexpected promoted label keys' figure is 203 structured-metadata keys minus the one that is also a stream label. No label expansion exists.

Tests: test_records_reads_the_categorized_structured_metadata_member, test_records_yields_no_metadata_for_an_uncategorized_response (fails closed rather than reading merged labels as exporter behaviour) and test_loki_query_requests_categorized_labels. The former test_records_keeps_structured_metadata_separate_from_labels encoded the bug in its fixture and was replaced. 16 tests OK.

CodeRabbit: 1 pass, complete, zero findings.
<!-- SECTION:NOTES:END -->
