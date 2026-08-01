# Changelog

## [4.0.0](https://github.com/rknightion/opnsense2otel/compare/v3.0.0...v4.0.0) (2026-08-01)


### ⚠ BREAKING CHANGES

* The default OTLP/log service.name and Pyroscope application name, plus the Grafana annotation base tag, change from opnsense-exporter to opnsense2otel in v4. Update identity-based selectors or explicitly retain the configurable v3 names.
* **grafana:** move the alert folders to opnsense2otel-*
* the environment variable prefix OPNSENSE_EXPORTER_* is now OPN2OTEL_*, with no back-compat aliases. Operators rewrite it with `sed -i 's/OPNSENSE_EXPORTER_/OPN2OTEL_/g'` over their compose/env files. The unprefixed *_FILE secret aliases (OPS_API_KEY_FILE and friends) are a separate convention and are unchanged. The container image is now ghcr.io/rknightion/opnsense2otel and the Helm chart lives at charts/opnsense2otel. docs/upgrading.md carries the full migration.
* **cpu:** opnsense_activity_cpu_{user,nice,system,interrupt,idle}_percent are removed. CPU utilisation is now opnsense_cpu_seconds_total{mode="user|nice|system|interrupt|idle"}, so panels and alerts move to 100 * rate(...). The bundled dashboard and rules are migrated.
* **logship:** `organization`, `policyid`, `scope_name` and the four geo coordinate keys are no longer shipped as Loki structured metadata on Zenarmor records. They remain in the log body, which is unchanged. A LogQL filter naming one of them stops matching; read it from the body with `| json` instead. `--logs.zenarmor.exclude` rules naming `organization` or `policyid` now fail at startup as unknown fields.
* **telemetry:** opnsense_exporter_otlp_enabled, opnsense_exporter_otlp_exports_total, opnsense_exporter_otlp_consecutive_failures and opnsense_exporter_otlp_last_success_timestamp_seconds now carry an opnsense_instance label. A query that aggregates them without `by (opnsense_instance)` returns one series per exporter instead of one overall; add the grouping or use `sum without (opnsense_instance) (...)` to keep the old shape. Single-instance deployments see no change beyond the extra label. The bundled dashboard and rules are already updated. See docs/upgrading.md.
* **metrics:** nine counters are renamed with a _total suffix: opnsense_ipsec_phase{1,2}_{bytes,packets}_{in,out} (eight series, e.g. opnsense_ipsec_phase1_bytes_in -> opnsense_ipsec_phase1_bytes_in_total) and opnsense_vnstat_total_bytes -> opnsense_vnstat_bytes_total. Direct-scrape consumers must update; OTLP consumers will only ever have seen the suffixed names once the series exists. See docs/upgrading.md.
* **metrics:** the eight opnsense_firewall_*_packets series are renamed to opnsense_firewall_*_packets_total. Direct-scrape consumers must update; OTLP consumers already saw the suffixed names. See docs/upgrading.md.
* **logship:** make delivery and freshness outcomes explicit
* **container:** add native health and config checks
* **config:** remove obsolete scrape deadline surfaces

### Features

* **activity:** aggregate the process table we already fetch and discard ([0d0d6a5](https://github.com/rknightion/opnsense2otel/commit/0d0d6a5f47cae357585d7223bda516bc1bb7d666)), closes [#552](https://github.com/rknightion/opnsense2otel/issues/552)
* **activity:** export the ZFS ARC composition breakdown ([e6427a6](https://github.com/rknightion/opnsense2otel/commit/e6427a6f5c5b3bcfa22683e5fd8274f90c87aafd)), closes [#551](https://github.com/rknightion/opnsense2otel/issues/551)
* **annotations:** link pushed annotations back to the dashboard ([7b943b6](https://github.com/rknightion/opnsense2otel/commit/7b943b60df7f0865611ca85dd1b40e6a8317d4de))
* **apidrift:** stamp the OPNsense generation into the canary report ([c268df4](https://github.com/rknightion/opnsense2otel/commit/c268df493735d4e5fc5a2bb046ef69ddf430e33b)), closes [#490](https://github.com/rknightion/opnsense2otel/issues/490)
* **autodiscovery:** probe every plugin-gated collector, not just the opt-in three ([a53d2c5](https://github.com/rknightion/opnsense2otel/commit/a53d2c5345d56820359a67f2d1bd16a3dac885dc)), closes [#525](https://github.com/rknightion/opnsense2otel/issues/525)
* **autodiscovery:** report and enable available-but-off collectors ([#517](https://github.com/rknightion/opnsense2otel/issues/517)) ([eef61c7](https://github.com/rknightion/opnsense2otel/commit/eef61c764538fa81278ec074b760759a9b2b0feb))
* **canary:** per-profile scoping on the coverage ledger ([78d20f4](https://github.com/rknightion/opnsense2otel/commit/78d20f4751aef381d1d396b7949ae01d77617276)), closes [#611](https://github.com/rknightion/opnsense2otel/issues/611)
* **collector:** capacity context, mbuf pools, and the audit-tooling hardening ([b0728fc](https://github.com/rknightion/opnsense2otel/commit/b0728fc46feaf39e266187067e547e85d842022a)), closes [#595](https://github.com/rknightion/opnsense2otel/issues/595)
* **collector:** export four more fields the API already hands us ([5b5da4b](https://github.com/rknightion/opnsense2otel/commit/5b5da4bb66f50866f20ee7781d406a2b6654cd00)), closes [#557](https://github.com/rknightion/opnsense2otel/issues/557)
* **collector:** export the dropped-data residue for SMART, IPsec, pf, FRR and unbound ([4439d18](https://github.com/rknightion/opnsense2otel/commit/4439d182fc738214ec928303e64f0a786fc81af1))
* **collector:** kernel memory zones, collapsed dimensions restored, flow country label on ([49913c9](https://github.com/rknightion/opnsense2otel/commit/49913c923a31873fa2a327d95b8e0cdf50521f30)), closes [#534](https://github.com/rknightion/opnsense2otel/issues/534) [#537](https://github.com/rknightion/opnsense2otel/issues/537) [#543](https://github.com/rknightion/opnsense2otel/issues/543)
* **collector:** kernel telemetry wave — netisr per-CPU, netmap, WAN DHCP, pf refs, TCP recovery ([b04cd2c](https://github.com/rknightion/opnsense2otel/commit/b04cd2c3efa7e056e0e625a331e451837fae9a59)), closes [#536](https://github.com/rknightion/opnsense2otel/issues/536) [#538](https://github.com/rknightion/opnsense2otel/issues/538) [#541](https://github.com/rknightion/opnsense2otel/issues/541) [#542](https://github.com/rknightion/opnsense2otel/issues/542) [#545](https://github.com/rknightion/opnsense2otel/issues/545)
* **collector:** re-audit every collector's poll tier against the [#568](https://github.com/rknightion/opnsense2otel/issues/568) rule ([20b38b4](https://github.com/rknightion/opnsense2otel/commit/20b38b474154f251fba5a090b9e22d48a251e851)), closes [#569](https://github.com/rknightion/opnsense2otel/issues/569)
* **container:** add native health and config checks ([ed8fa84](https://github.com/rknightion/opnsense2otel/commit/ed8fa848d69b1aa39acc5c0fbfc21426ae308f73)), closes [#438](https://github.com/rknightion/opnsense2otel/issues/438) [#446](https://github.com/rknightion/opnsense2otel/issues/446)
* **contract:** detect unexpected nested response keys ([53da29f](https://github.com/rknightion/opnsense2otel/commit/53da29fd81bf2e0ca01855df0543f6bb553f4056)), closes [#376](https://github.com/rknightion/opnsense2otel/issues/376)
* **cpu:** consume cpu_usage/stream over SSE into cumulative CPU counters ([316641e](https://github.com/rknightion/opnsense2otel/commit/316641e2a5adab58cb912a55fce44959d360a541)), closes [#559](https://github.com/rknightion/opnsense2otel/issues/559)
* **deploy:** make supported paths executable ([80e3e46](https://github.com/rknightion/opnsense2otel/commit/80e3e468208f436aeacdd581fa0d4875516e4e48)), closes [#437](https://github.com/rknightion/opnsense2otel/issues/437) [#440](https://github.com/rknightion/opnsense2otel/issues/440) [#444](https://github.com/rknightion/opnsense2otel/issues/444)
* **dhcp6c:** lease gauges for the WAN IPv6 address, the IA_NA twin of [#546](https://github.com/rknightion/opnsense2otel/issues/546) ([63709b4](https://github.com/rknightion/opnsense2otel/commit/63709b4edbfeb7ff07331842f8ca1ffb012ab2f5)), closes [#560](https://github.com/rknightion/opnsense2otel/issues/560)
* **dhcp:** keep the raw interface id on every lease grid, not just its description ([6166221](https://github.com/rknightion/opnsense2otel/commit/6166221d147a2472666cc108465143502c9895e4)), closes [#556](https://github.com/rknightion/opnsense2otel/issues/556)
* **docs:** generate example configs covering every flag ([b0f4338](https://github.com/rknightion/opnsense2otel/commit/b0f4338a88972a92c304a9220714f6b0d02cec09)), closes [#515](https://github.com/rknightion/opnsense2otel/issues/515)
* **firewall:** export per-rule protocol, and nothing else from that payload ([6094b7a](https://github.com/rknightion/opnsense2otel/commit/6094b7a9ab1c674b5aedbad4f65d337d6aa38861)), closes [#558](https://github.com/rknightion/opnsense2otel/issues/558)
* **firmware:** expose update-check health and pending download size ([2d0769b](https://github.com/rknightion/opnsense2otel/commit/2d0769b0d048200e30a1391bce18a163eaa946da)), closes [#373](https://github.com/rknightion/opnsense2otel/issues/373) [#380](https://github.com/rknightion/opnsense2otel/issues/380)
* **flow:** alert on conclusively dead NetFlow hooks ([9a05d9e](https://github.com/rknightion/opnsense2otel/commit/9a05d9e0c210a32cedeec312674c0c6edd84ec41)), closes [#402](https://github.com/rknightion/opnsense2otel/issues/402)
* **flow:** count repair 4's four silent exits ([749b473](https://github.com/rknightion/opnsense2otel/commit/749b4733b1408c568f5fdd443423d995c608a7dd)), closes [#624](https://github.com/rknightion/opnsense2otel/issues/624)
* **flow:** NetFlow debug capture, and stop stepping over the unidentified in silence ([689ef5b](https://github.com/rknightion/opnsense2otel/commit/689ef5bb78ccd3c67be86e1693f6af885cd593f6)), closes [#360](https://github.com/rknightion/opnsense2otel/issues/360)
* **flow:** preserve event time and interval fields ([6caece7](https://github.com/rknightion/opnsense2otel/commit/6caece73e36efb84e92e88938b0852cc1d6821cd)), closes [#391](https://github.com/rknightion/opnsense2otel/issues/391) [#411](https://github.com/rknightion/opnsense2otel/issues/411)
* **flow:** publish the ifIndex map so device and description space can be joined ([ff5b9c7](https://github.com/rknightion/opnsense2otel/commit/ff5b9c77c6aa1889e0b58455cce98596ca535c27)), closes [#368](https://github.com/rknightion/opnsense2otel/issues/368)
* **flow:** publish the unmapped-record counter so the cold-start window is visible ([70c9b2b](https://github.com/rknightion/opnsense2otel/commit/70c9b2b5332b77b49c15b1683ffef578d6d860ba)), closes [#367](https://github.com/rknightion/opnsense2otel/issues/367)
* **flow:** resolve policy-routed egress from pf's own state table ([e5deddb](https://github.com/rknightion/opnsense2otel/commit/e5deddbda26e33120f8e9bb7da91384e5f6ca70b)), closes [#603](https://github.com/rknightion/opnsense2otel/issues/603)
* **flow:** split policy-route refusals by the interface they are attributed to ([75a9241](https://github.com/rknightion/opnsense2otel/commit/75a92417ea7075e2558a36a25a40a9c4257b91af))
* **geoip:** enrich flow records from local MaxMind databases ([a6fa9c9](https://github.com/rknightion/opnsense2otel/commit/a6fa9c9a512933f8f0ae28cf1d387b0a32ebd824)), closes [#520](https://github.com/rknightion/opnsense2otel/issues/520)
* **geoip:** extend enrichment to filterlog, sshd/auth and Suricata logs ([2fd9cc1](https://github.com/rknightion/opnsense2otel/commit/2fd9cc10f491dd52bb851a254a5c614ccfa5f7ab)), closes [#528](https://github.com/rknightion/opnsense2otel/issues/528)
* **geoip:** ship DB-IP Lite in the image and default enrichment on ([21b97af](https://github.com/rknightion/opnsense2otel/commit/21b97af5195710de3916c680835c22cf08c567df)), closes [#549](https://github.com/rknightion/opnsense2otel/issues/549)
* **grafana:** add a generated event-annotation timeline and push it to Grafana ([9f20ac9](https://github.com/rknightion/opnsense2otel/commit/9f20ac9a277603abded8560cb36da9074c2efd8b))
* **grafana:** add a tested Grafana 11/12 compatibility dashboard ([8e49f4e](https://github.com/rknightion/opnsense2otel/commit/8e49f4e569cf542ca95a5bc3301c630e71b82608)), closes [#420](https://github.com/rknightion/opnsense2otel/issues/420)
* **grafana:** alert when one exporter vanishes and the others do not ([4c529e3](https://github.com/rknightion/opnsense2otel/commit/4c529e3721c90debcc8197fc70f73668bb177c7c)), closes [#427](https://github.com/rknightion/opnsense2otel/issues/427)
* **grafana:** close the consumption gaps, add the posture set, and end three classes of gate blindness ([954d82a](https://github.com/rknightion/opnsense2otel/commit/954d82a2b55aa0fef7663203184cd883c0f82a3a)), closes [#578](https://github.com/rknightion/opnsense2otel/issues/578) [#579](https://github.com/rknightion/opnsense2otel/issues/579) [#581](https://github.com/rknightion/opnsense2otel/issues/581) [#582](https://github.com/rknightion/opnsense2otel/issues/582) [#583](https://github.com/rknightion/opnsense2otel/issues/583) [#589](https://github.com/rknightion/opnsense2otel/issues/589) [#591](https://github.com/rknightion/opnsense2otel/issues/591) [#592](https://github.com/rknightion/opnsense2otel/issues/592)
* **grafana:** generate context-preserving drilldowns from a frozen UID registry ([6100ad6](https://github.com/rknightion/opnsense2otel/commit/6100ad676f410c90811695e9647cb015e5edaa7e)), closes [#419](https://github.com/rknightion/opnsense2otel/issues/419)
* **grafana:** link every alert to its canonical dashboard panel ([49eb77a](https://github.com/rknightion/opnsense2otel/commit/49eb77a8ced02f9c5e0cf949ad1ad0f920f097d6)), closes [#530](https://github.com/rknightion/opnsense2otel/issues/530)
* **grafana:** make the Zenarmor client picker enumerable ([e543af8](https://github.com/rknightion/opnsense2otel/commit/e543af84fe6ab50d57568f39874f517b494c1430)), closes [#474](https://github.com/rknightion/opnsense2otel/issues/474)
* **grafana:** move the alert folders to opnsense2otel-* ([0bb033f](https://github.com/rknightion/opnsense2otel/commit/0bb033f25a70a375ec88675ef8c00d189dc75e01))
* **grafana:** route exporter self-health alerts to their own folder ([4a33aa5](https://github.com/rknightion/opnsense2otel/commit/4a33aa55d23b7f3906736bac7b3aac1983db1314)), closes [#431](https://github.com/rknightion/opnsense2otel/issues/431)
* **grafana:** split exporter self-observability onto its own dashboard ([a486d0c](https://github.com/rknightion/opnsense2otel/commit/a486d0cf4275405cce519e84a8866da5a6dd4ac4)), closes [#431](https://github.com/rknightion/opnsense2otel/issues/431)
* **interfaces:** export the driver and HW offload capabilities we already fetch ([99571ed](https://github.com/rknightion/opnsense2otel/commit/99571edfc2b03fb35dbe40d295ce48bc99873546)), closes [#555](https://github.com/rknightion/opnsense2otel/issues/555)
* **interfaces:** expose unknown-protocol packets and the stats-reset epoch ([3699176](https://github.com/rknightion/opnsense2otel/commit/369917642cc6fcdef0769ba9c56c4454f41fc898)), closes [#375](https://github.com/rknightion/opnsense2otel/issues/375)
* **logship,grafana,schemas:** close the consumption-audit follow-ons from [#593](https://github.com/rknightion/opnsense2otel/issues/593) ([b847b6d](https://github.com/rknightion/opnsense2otel/commit/b847b6d70b848d3489d818c149fdffe30f49e4cf)), closes [#596](https://github.com/rknightion/opnsense2otel/issues/596) [#597](https://github.com/rknightion/opnsense2otel/issues/597) [#598](https://github.com/rknightion/opnsense2otel/issues/598) [#599](https://github.com/rknightion/opnsense2otel/issues/599) [#600](https://github.com/rknightion/opnsense2otel/issues/600)
* **logship:** dhcp6c and kea-dhcp6 coverage — the IPv6 twin of [#541](https://github.com/rknightion/opnsense2otel/issues/541) ([b15d78f](https://github.com/rknightion/opnsense2otel/commit/b15d78f7e1d0c18d77f63a1fa0327f5df15854af)), closes [#546](https://github.com/rknightion/opnsense2otel/issues/546)
* **logship:** parse ppp, firewall aliases, acme and unbound's dnsbl chatter ([a02e9ee](https://github.com/rknightion/opnsense2otel/commit/a02e9eec02df2d859005a39d5c199055c8277582)), closes [#631](https://github.com/rknightion/opnsense2otel/issues/631)
* **logship:** put device category and interface on the log resource ([ea161c7](https://github.com/rknightion/opnsense2otel/commit/ea161c7e25c3a67733dcdda4913c5be330f0e25e)), closes [#473](https://github.com/rknightion/opnsense2otel/issues/473)
* model three canary-found data gaps and add a soft series budget ([1c54c58](https://github.com/rknightion/opnsense2otel/commit/1c54c58d203890e1d10f99bbf38a0f97d8bda50f))
* **netflow:** expose the configured capture set and time since last record ([0f83056](https://github.com/rknightion/opnsense2otel/commit/0f8305657f2b7ee64401ffa3aab53fb1f11e4445)), closes [#366](https://github.com/rknightion/opnsense2otel/issues/366)
* **netflow:** model TOS, prefix masks and next hop so a stock box reports no unknown elements ([183fd43](https://github.com/rknightion/opnsense2otel/commit/183fd434f47a0a081c204d1102c2b33221c9b5b8)), closes [#630](https://github.com/rknightion/opnsense2otel/issues/630)
* **otlp:** gzip by default on both signals, one exporter per worker ([669f524](https://github.com/rknightion/opnsense2otel/commit/669f52465337fb342e5955903f9e4a6c91198c3a)), closes [#505](https://github.com/rknightion/opnsense2otel/issues/505)
* **protocol:** break down TCP connection drops by timeout reason ([9fc10ba](https://github.com/rknightion/opnsense2otel/commit/9fc10ba680e1e21c171c47d08e81d876d293e184)), closes [#374](https://github.com/rknightion/opnsense2otel/issues/374)
* rename the project opnsense-exporter -&gt; opnsense2otel ([bed4889](https://github.com/rknightion/opnsense2otel/commit/bed488952952280f647e24704155ab5d30f7dd81))
* **scheduler:** poll cadence follows the export lane that consumes it ([286b3f5](https://github.com/rknightion/opnsense2otel/commit/286b3f50557f81dcb516b69e84a30d42e08671dd)), closes [#550](https://github.com/rknightion/opnsense2otel/issues/550)
* **schema:** scope canary ledger entries to a probe profile ([1d97e0e](https://github.com/rknightion/opnsense2otel/commit/1d97e0e32d17b8cb7602018ce747be47bb283033))
* **security:** generate collector ACL guidance ([d8a7824](https://github.com/rknightion/opnsense2otel/commit/d8a782421febe08598b09c4e4f1a72945011b1ed)), closes [#442](https://github.com/rknightion/opnsense2otel/issues/442)
* **server:** instrument the /metrics serving path ([a73f84c](https://github.com/rknightion/opnsense2otel/commit/a73f84c4debd1728f837f1857bb0b953a2a77d09)), closes [#426](https://github.com/rknightion/opnsense2otel/issues/426)
* **startup:** log the resolved config and the discovered plugin inventory ([73d2205](https://github.com/rknightion/opnsense2otel/commit/73d2205f6b8feda80d3d38f867c48d78c4e6a964)), closes [#526](https://github.com/rknightion/opnsense2otel/issues/526)
* **syslog:** add privacy-safe FreeRADIUS events ([18b4b90](https://github.com/rknightion/opnsense2otel/commit/18b4b9034e72666bdd6d7e574c65ce3977981c2f)), closes [#407](https://github.com/rknightion/opnsense2otel/issues/407)
* **syslog:** derive CARP state and demotion events ([f0f1a26](https://github.com/rknightion/opnsense2otel/commit/f0f1a26a115e527d11585d21f8c92fc8682db9e9)), closes [#405](https://github.com/rknightion/opnsense2otel/issues/405)
* **syslog:** derive gateway alarm transitions ([8ef49ed](https://github.com/rknightion/opnsense2otel/commit/8ef49ed847aa20bfecf47c1b0c1f838b61bc3b42))
* **syslog:** derive miniupnpd mapping expiry and failure events ([6d812f8](https://github.com/rknightion/opnsense2otel/commit/6d812f8d05ac8441a488e456143d37e9f986bdc5))
* **syslog:** normalize IPsec and OpenVPN lifecycle events ([3c51776](https://github.com/rknightion/opnsense2otel/commit/3c517764526f33c5cd01079bae283cf547100cf4)), closes [#406](https://github.com/rknightion/opnsense2otel/issues/406)
* **telemetry:** honest data age, upstream health, and OTLP delivery visibility ([58a51e5](https://github.com/rknightion/opnsense2otel/commit/58a51e5a8bbcc452325d956da8e9ab1186e4401d)), closes [#382](https://github.com/rknightion/opnsense2otel/issues/382) [#384](https://github.com/rknightion/opnsense2otel/issues/384) [#388](https://github.com/rknightion/opnsense2otel/issues/388) [#389](https://github.com/rknightion/opnsense2otel/issues/389) [#390](https://github.com/rknightion/opnsense2otel/issues/390)
* **testbed:** power the lab down outside the canary window ([3a8f9be](https://github.com/rknightion/opnsense2otel/commit/3a8f9bed74e1ec46d676b50aa07fcbbff1730504)), closes [#625](https://github.com/rknightion/opnsense2otel/issues/625)


### Bug Fixes

* **alerts:** delete OPNsenseFlowSourceDivergence, its threshold sits below the metric's floor ([fc8a370](https://github.com/rknightion/opnsense2otel/commit/fc8a370c7703b492e0da7f0cd997ba0e20cde4bf)), closes [#602](https://github.com/rknightion/opnsense2otel/issues/602)
* **alerts:** stop OPNsenseDHCP6AllocationFailures firing on a single event ([144992e](https://github.com/rknightion/opnsense2otel/commit/144992e95d7163248e2d38ff70051af2979621b8)), closes [#594](https://github.com/rknightion/opnsense2otel/issues/594)
* **annotations:** bound the annotation dedupe set ([af78295](https://github.com/rknightion/opnsense2otel/commit/af7829551baa4149847b7373e7cf5d795e220c15)), closes [#421](https://github.com/rknightion/opnsense2otel/issues/421)
* **annotations:** cap posts per cycle by attempts, not successes ([eec1461](https://github.com/rknightion/opnsense2otel/commit/eec14610e7ed6fb679becb9a4b48c76b0959624b)), closes [#519](https://github.com/rknightion/opnsense2otel/issues/519)
* **annotations:** never follow a redirect with the bearer token attached ([c16fc37](https://github.com/rknightion/opnsense2otel/commit/c16fc37db0643f648c11f30bbd60fa30e648ad9d)), closes [#566](https://github.com/rknightion/opnsense2otel/issues/566)
* **annotations:** stop pushing threat-feed events the dashboard defaults off ([a53bba9](https://github.com/rknightion/opnsense2otel/commit/a53bba91f126fb4b0bef6eb70fc4f61e2af588fa)), closes [#540](https://github.com/rknightion/opnsense2otel/issues/540)
* **canary:** camden's prod canary closes its own issue, and stops calling breaking drift clean ([8148653](https://github.com/rknightion/opnsense2otel/commit/8148653565c702fbda8a15e22248e1560b10569e)), closes [#612](https://github.com/rknightion/opnsense2otel/issues/612)
* **canary:** give each probe target its own drift issue ([f7e95ab](https://github.com/rknightion/opnsense2otel/commit/f7e95ab38b3d6cbc017fdcfea66a09138ac0671c)), closes [#490](https://github.com/rknightion/opnsense2otel/issues/490)
* **canary:** scope the tailscaleStatus Self.KeyExpiry exemption to prod ([d28029b](https://github.com/rknightion/opnsense2otel/commit/d28029b0be69dd1bfbbc69d04e30d28e9900aafc)), closes [#614](https://github.com/rknightion/opnsense2otel/issues/614)
* **canary:** stop apidrift validating ipsecSad against the placeholder row ([b8475fe](https://github.com/rknightion/opnsense2otel/commit/b8475fe3d1bb2adcd6096b3a1f98c3f59adf06cc)), closes [#618](https://github.com/rknightion/opnsense2otel/issues/618)
* **captiveportal:** skip the session search when no zones are configured ([d1bd9e0](https://github.com/rknightion/opnsense2otel/commit/d1bd9e070c1946d7d289aceedb70e36d4fb34a0c)), closes [#524](https://github.com/rknightion/opnsense2otel/issues/524)
* **carp:** a disabled VIP is not an unparseable one ([f4b3c4e](https://github.com/rknightion/opnsense2otel/commit/f4b3c4e9c9629ec5fd24d4cd9d0eec0b01ba97d5)), closes [#503](https://github.com/rknightion/opnsense2otel/issues/503)
* **ci:** allowlist the well-known resolver literals in the [#581](https://github.com/rknightion/opnsense2otel/issues/581) unbound infra fixtures ([3dc2005](https://github.com/rknightion/opnsense2otel/commit/3dc2005caafbef0886c510c0791a706a3db8b293))
* **ci:** give fuzz-smoke a timeout that is not consumed by build time ([0a838db](https://github.com/rknightion/opnsense2otel/commit/0a838dbe86f88e215cf3761fb3685dc1b8b6f6b9)), closes [#469](https://github.com/rknightion/opnsense2otel/issues/469)
* **ci:** post the compat dashboard body from a file, not an argument ([3f6ac71](https://github.com/rknightion/opnsense2otel/commit/3f6ac71aaecf6e1023a319ac262c32e6299e417b))
* **ci:** unbreak main — hide the GOOS-dependent flag, guard the availability map ([d3d5790](https://github.com/rknightion/opnsense2otel/commit/d3d579017b1a216c40de9c0a8877bd2fef14bc76)), closes [#532](https://github.com/rknightion/opnsense2otel/issues/532)
* **collector:** one inventory row per Zenarmor device, not one per attribute set ([96a35b7](https://github.com/rknightion/opnsense2otel/commit/96a35b7627dc497979c49de17d22ebfc80460ede)), closes [#476](https://github.com/rknightion/opnsense2otel/issues/476)
* **config:** remove obsolete scrape deadline surfaces ([0168186](https://github.com/rknightion/opnsense2otel/commit/01681865a39a196fe883fa95f33a49430ec41303)), closes [#439](https://github.com/rknightion/opnsense2otel/issues/439)
* correct opnsense_up semantics and cover three untested subsystems ([2203852](https://github.com/rknightion/opnsense2otel/commit/22038524ef5f26d4d9e76d71cc0df038fd1aa8ca)), closes [#488](https://github.com/rknightion/opnsense2otel/issues/488)
* **deploy:** make hosted contracts portable ([af16b85](https://github.com/rknightion/opnsense2otel/commit/af16b8502b705c9a2a55ca2d1d90a18d1112cccd)), closes [#440](https://github.com/rknightion/opnsense2otel/issues/440) [#444](https://github.com/rknightion/opnsense2otel/issues/444)
* **deploy:** set secret mode before ownership ([428df7e](https://github.com/rknightion/opnsense2otel/commit/428df7e538d53ad32b77772975bce8075b7e49bd)), closes [#440](https://github.com/rknightion/opnsense2otel/issues/440)
* **deps:** revert the phantom go.yaml.in/yaml/v3 require and block the major ([f58126d](https://github.com/rknightion/opnsense2otel/commit/f58126d6c2faf8e6d7308caa9014be0b3c16c633)), closes [#533](https://github.com/rknightion/opnsense2otel/issues/533)
* **deps:** update module github.com/prometheus/client_golang to v1.24.1 ([#369](https://github.com/rknightion/opnsense2otel/issues/369)) ([348caef](https://github.com/rknightion/opnsense2otel/commit/348caef0d22c37ec8ed00e49e7d01d39ca96eb31))
* **deps:** update module github.com/prometheus/prometheus to v0.313.2 ([#570](https://github.com/rknightion/opnsense2otel/issues/570)) ([93fbe64](https://github.com/rknightion/opnsense2otel/commit/93fbe6449049a9b2f7ac962c2edeeda97c644f1e))
* **deps:** update module go.opentelemetry.io/proto/otlp to v1.11.0 ([#463](https://github.com/rknightion/opnsense2otel/issues/463)) ([a9f2e21](https://github.com/rknightion/opnsense2otel/commit/a9f2e214353494baf8867cda7a2ad10a8d2ec094))
* **deps:** update module go.yaml.in/yaml/v2 to v3 ([#527](https://github.com/rknightion/opnsense2otel/issues/527)) ([dd0957d](https://github.com/rknightion/opnsense2otel/commit/dd0957dc509ddcf3a46c6757f2295a70d0009e56))
* **deps:** update module google.golang.org/grpc to v1.83.0 ([#554](https://github.com/rknightion/opnsense2otel/issues/554)) ([769a33e](https://github.com/rknightion/opnsense2otel/commit/769a33eba14f94375cb4251b3446b8e25465b4ba))
* **flow,annotations,config:** triage-able ifIndex conflicts, 429 backoff, full preflight summary ([4fde7ba](https://github.com/rknightion/opnsense2otel/commit/4fde7ba4338b510cabccc0146d3de707edc8550a)), closes [#516](https://github.com/rknightion/opnsense2otel/issues/516) [#518](https://github.com/rknightion/opnsense2otel/issues/518) [#519](https://github.com/rknightion/opnsense2otel/issues/519)
* **flow:** attribute VLAN child flows by subnet evidence instead of arrival order ([1b203ee](https://github.com/rknightion/opnsense2otel/commit/1b203ee4e850f1a6cac1e56def08d60981a8a77a))
* **flow:** bound the Zenarmor-controlled interface keys behind distinct-destinations ([8ab7d28](https://github.com/rknightion/opnsense2otel/commit/8ab7d28e0d1bc25aa4b51967c02004db9c7efc27)), closes [#563](https://github.com/rknightion/opnsense2otel/issues/563)
* **flow:** close the expiry half of the policy-route miss window, and poll pf faster ([8b0a506](https://github.com/rknightion/opnsense2otel/commit/8b0a506ee1f25dbcd0ec4192699080136b33e521)), closes [#620](https://github.com/rknightion/opnsense2otel/issues/620)
* **flow:** correct the API's attach order into ifinfo order for the ifIndex map ([9c39af6](https://github.com/rknightion/opnsense2otel/commit/9c39af60755760fc8ace496b5da179679bbba28a)), closes [#363](https://github.com/rknightion/opnsense2otel/issues/363)
* **flow:** count records a nil ifIndex map cannot label, and close the cold window ([b214f4c](https://github.com/rknightion/opnsense2otel/commit/b214f4cdac939b9e4be55893318aab5f2c472951)), closes [#365](https://github.com/rknightion/opnsense2otel/issues/365)
* **flow:** de-duplicate the two copies of a NAT'd conversation ([e7b1504](https://github.com/rknightion/opnsense2otel/commit/e7b1504d95fed1528e25b78c13af38bd38c8641a)), closes [#623](https://github.com/rknightion/opnsense2otel/issues/623)
* **flow:** decide a merged record's orientation by evidence, not arrival order ([f88f7f9](https://github.com/rknightion/opnsense2otel/commit/f88f7f916d849c5a1045fde2d72bfe342cdc21b5)), closes [#605](https://github.com/rknightion/opnsense2otel/issues/605)
* **flow:** derive the ifIndex enumeration from kernel indexes, not a rank heuristic ([d829cff](https://github.com/rknightion/opnsense2otel/commit/d829cffd4356ac008ce1936a29e16a0f8644f445)), closes [#364](https://github.com/rknightion/opnsense2otel/issues/364)
* **flow:** do not advise enabling a NetFlow capture that is already running ([765405b](https://github.com/rknightion/opnsense2otel/commit/765405b37737e3e19e263964eb63ec15f578b39c)), closes [#360](https://github.com/rknightion/opnsense2otel/issues/360)
* **flow:** do not treat a nameless ifIndex map as final ([7305d63](https://github.com/rknightion/opnsense2otel/commit/7305d63b73a59b0c788960be55b2c769c9b43ebb)), closes [#522](https://github.com/rknightion/opnsense2otel/issues/522)
* **flow:** label a cold-start interface "unresolved" instead of its kernel device ([80d8f62](https://github.com/rknightion/opnsense2otel/commit/80d8f62b56a2134cf162ab3a5bf246e6aab459ab)), closes [#606](https://github.com/rknightion/opnsense2otel/issues/606)
* **flow:** read the NetFlow ifIndex enumeration from the box, not from a row count ([fb1c7f3](https://github.com/rknightion/opnsense2otel/commit/fb1c7f302f483548785a01c54aa6cb1f229b89cd)), closes [#361](https://github.com/rknightion/opnsense2otel/issues/361)
* **flow:** resolve VLAN duplicates to the child copy, not the first arrival ([f63b391](https://github.com/rknightion/opnsense2otel/commit/f63b391c2219cfee7612e78bd57b17b0fa5af022)), closes [#357](https://github.com/rknightion/opnsense2otel/issues/357)
* **flow:** split a merged record's two halves into Tx and Rx ([92d5256](https://github.com/rknightion/opnsense2otel/commit/92d5256a620c059b39425aec96905f0363d48520)), closes [#617](https://github.com/rknightion/opnsense2otel/issues/617)
* **flow:** state the byte basis on merged records, and stop comparing a window partial against a whole connection ([2e3057e](https://github.com/rknightion/opnsense2otel/commit/2e3057ec963443b9400007f540715145e8e16ea2)), closes [#604](https://github.com/rknightion/opnsense2otel/issues/604)
* **flow:** union repair markers across a conversation's fragments ([b1a8c96](https://github.com/rknightion/opnsense2otel/commit/b1a8c9617703d0a36423011d4050926c9fccd1bb))
* **frr:** compose the OSPFv3 route type from destinationType and pathType ([f199ef4](https://github.com/rknightion/opnsense2otel/commit/f199ef442bbf076d10ca8b3d3f70bf5229746fee)), closes [#458](https://github.com/rknightion/opnsense2otel/issues/458)
* **frr:** surface OSPF overview decode failures instead of partial success ([9355aa4](https://github.com/rknightion/opnsense2otel/commit/9355aa48234a4c85b9aaafdbf41baadbaf967d9d)), closes [#378](https://github.com/rknightion/opnsense2otel/issues/378)
* **grafana:** deep-link the CPU stream alert and bump the rule count pins ([449f0f4](https://github.com/rknightion/opnsense2otel/commit/449f0f4b92c97c3142167d244247028052249472))
* **grafana:** floor the pending window at 10m in --stack mode ([444cbfa](https://github.com/rknightion/opnsense2otel/commit/444cbfadb8b64ce3cad7c9daff9a2c53097859af)), closes [#629](https://github.com/rknightion/opnsense2otel/issues/629)
* **grafana:** give loki_table a real key column instead of a label set ([a81fc38](https://github.com/rknightion/opnsense2otel/commit/a81fc38f5fa23f3a34c3b4d57e071ad4b5e99dbb)), closes [#471](https://github.com/rknightion/opnsense2otel/issues/471)
* **grafana:** keep the alert folder UIDs, retitle them instead ([7b7c984](https://github.com/rknightion/opnsense2otel/commit/7b7c984e4009ed7ce9b1c9eec010918e3ce4b1b2))
* **grafana:** make every Loki top-N table an instant query, ranked to 200 ([df1a448](https://github.com/rknightion/opnsense2otel/commit/df1a4486086c6b7b9695f96fafd6040a8bc4f836)), closes [#479](https://github.com/rknightion/opnsense2otel/issues/479)
* **grafana:** make log delivery loss-aware ([e0b497d](https://github.com/rknightion/opnsense2otel/commit/e0b497db91960573305392c0ab6271e7ee900d73)), closes [#393](https://github.com/rknightion/opnsense2otel/issues/393) [#394](https://github.com/rknightion/opnsense2otel/issues/394) [#395](https://github.com/rknightion/opnsense2otel/issues/395) [#399](https://github.com/rknightion/opnsense2otel/issues/399) [#400](https://github.com/rknightion/opnsense2otel/issues/400)
* **grafana:** move rarely-toggled annotation layers and links into the controls menu ([db30892](https://github.com/rknightion/opnsense2otel/commit/db30892c4578e8b86db152cb739e6a318b80ca0a)), closes [#470](https://github.com/rknightion/opnsense2otel/issues/470)
* **grafana:** normalise threshold steps too, and assert the shape not the field ([bf13e4e](https://github.com/rknightion/opnsense2otel/commit/bf13e4ecf2bc307ca61cfa35a891977ef4c6b1d9)), closes [#616](https://github.com/rknightion/opnsense2otel/issues/616)
* **grafana:** pin the unbounded-label Loki tables to their own window ([7ed2631](https://github.com/rknightion/opnsense2otel/commit/7ed26313f0b3a2efe46004068d93ecf5e16a3ae3))
* **grafana:** populate the device variable from every device-bearing source ([4002fb1](https://github.com/rknightion/opnsense2otel/commit/4002fb111493294882231e7e34bbfa1457ec4715)), closes [#424](https://github.com/rknightion/opnsense2otel/issues/424)
* **grafana:** preserve exporter-instance identity through aggregations and tables ([875641f](https://github.com/rknightion/opnsense2otel/commit/875641f5f2cbdcbb40c8c00107ced5a2c27a8875)), closes [#468](https://github.com/rknightion/opnsense2otel/issues/468)
* **grafana:** repair dashboard-health's field overrides and verify the sync landed ([109e36e](https://github.com/rknightion/opnsense2otel/commit/109e36e683da17bcb184ef9e64c142325dcd9c2a))
* **grafana:** repair the rendering layer the [#491](https://github.com/rknightion/opnsense2otel/issues/491) sweep found broken ([ef9b911](https://github.com/rknightion/opnsense2otel/commit/ef9b91175630edd2899a49494e16ed2657a5a4da)), closes [#509](https://github.com/rknightion/opnsense2otel/issues/509) [#510](https://github.com/rknightion/opnsense2otel/issues/510) [#511](https://github.com/rknightion/opnsense2otel/issues/511) [#512](https://github.com/rknightion/opnsense2otel/issues/512) [#513](https://github.com/rknightion/opnsense2otel/issues/513) [#514](https://github.com/rknightion/opnsense2otel/issues/514)
* **grafana:** run the builder unit tests in CI and repair the three that had rotted ([52ef4b2](https://github.com/rknightion/opnsense2otel/commit/52ef4b269b7a01fde26b818a1bc43bff9f4befe4))
* **grafana:** scope feature sentinels and Loki panels to the selected instance ([d55384c](https://github.com/rknightion/opnsense2otel/commit/d55384c6a7047a99a799fbd4d722234f40afe127)), closes [#413](https://github.com/rknightion/opnsense2otel/issues/413) [#414](https://github.com/rknightion/opnsense2otel/issues/414) [#466](https://github.com/rknightion/opnsense2otel/issues/466)
* **grafana:** separate event and byte rates in the three ingest panels ([7aca7f5](https://github.com/rknightion/opnsense2otel/commit/7aca7f59e9718abd7ae02858d56e8a5b2f15195a)), closes [#416](https://github.com/rknightion/opnsense2otel/issues/416)
* **grafana:** stop fabricating severity thresholds on bar gauges ([4b59030](https://github.com/rknightion/opnsense2otel/commit/4b59030d9f6ce3771368813e0db13f25ca3e4563)), closes [#415](https://github.com/rknightion/opnsense2otel/issues/415)
* **grafana:** stop injecting synthetic thresholds into radial gauges ([b386df6](https://github.com/rknightion/opnsense2otel/commit/b386df6848232a0e95ea1088e5f88bd194262f3e)), closes [#467](https://github.com/rknightion/opnsense2otel/issues/467)
* **grafana:** three of the [#491](https://github.com/rknightion/opnsense2otel/issues/491) fixes did not survive being rendered ([615f850](https://github.com/rknightion/opnsense2otel/commit/615f850602db3bc19f8e1724d7dd4a9765d9cda0))
* **grafana:** validate generated PromQL ([9470bf6](https://github.com/rknightion/opnsense2otel/commit/9470bf6568382e8636e30184a53d0ec28d90f317)), closes [#412](https://github.com/rknightion/opnsense2otel/issues/412)
* **interfaces:** emit SFP RX optical power in both mW and dBm ([8098023](https://github.com/rknightion/opnsense2otel/commit/8098023b7fe2a989c5f36f02427c597b63a8e4c0)), closes [#456](https://github.com/rknightion/opnsense2otel/issues/456)
* **interfaces:** suppress a queue-drop figure that has wrapped through uint32 ([12abef6](https://github.com/rknightion/opnsense2otel/commit/12abef6e1716ecc1e2ab0b125ec7af91786fd57f)), closes [#548](https://github.com/rknightion/opnsense2otel/issues/548)
* **logevents:** netmap ring-full counts per kernel line, not per interval ([34c1524](https://github.com/rknightion/opnsense2otel/commit/34c1524ea129007ee0ac2ede28bba8b51929e90a)), closes [#610](https://github.com/rknightion/opnsense2otel/issues/610)
* **logship:** bound a drained batch by bytes, not just by record count ([e334c9e](https://github.com/rknightion/opnsense2otel/commit/e334c9e5800b21d3a1bae4f41261f208baff1788)), closes [#506](https://github.com/rknightion/opnsense2otel/issues/506)
* **logship:** export resource partitions concurrently, raise queue defaults ([5394a5c](https://github.com/rknightion/opnsense2otel/commit/5394a5c98a53cc37808402a76640d5f418cbc11d)), closes [#505](https://github.com/rknightion/opnsense2otel/issues/505)
* **logship:** keep one example per shape in the syslog debug capture ([8b6997c](https://github.com/rknightion/opnsense2otel/commit/8b6997ccba3dfc0149f56062456f4b41f5521baa)), closes [#362](https://github.com/rknightion/opnsense2otel/issues/362)
* **logship:** make delivery and freshness outcomes explicit ([adabcad](https://github.com/rknightion/opnsense2otel/commit/adabcad01e4622203dc4fee6074fefe4c95f7b22)), closes [#392](https://github.com/rknightion/opnsense2otel/issues/392) [#394](https://github.com/rknightion/opnsense2otel/issues/394) [#395](https://github.com/rknightion/opnsense2otel/issues/395)
* **logship:** redact reusable credentials before request headers reach a capture ([3bf1dd5](https://github.com/rknightion/opnsense2otel/commit/3bf1dd5a2f003d03fef43f5f84677612f14659ae)), closes [#561](https://github.com/rknightion/opnsense2otel/issues/561)
* **metrics:** suffix PF packet counters with _total ([3514a9e](https://github.com/rknightion/opnsense2otel/commit/3514a9eecd30646e659558fcbc1752b472c6906b)), closes [#418](https://github.com/rknightion/opnsense2otel/issues/418)
* **metrics:** suffix the nine remaining counters that lack _total ([ae0f13d](https://github.com/rknightion/opnsense2otel/commit/ae0f13da2b25eb14dfff5b0ecd7da878a432f732)), closes [#464](https://github.com/rknightion/opnsense2otel/issues/464)
* **netflow:** bound the v9 template cache ([4cd385f](https://github.com/rknightion/opnsense2otel/commit/4cd385f97a2d1e7b45428145b8461611888d22b4)), closes [#564](https://github.com/rknightion/opnsense2otel/issues/564)
* **netflow:** mark PPPoE devices capture-unsupported and stop alerting on them ([2b61ca7](https://github.com/rknightion/opnsense2otel/commit/2b61ca713e3061fde32d34a2b77f8cae878ef456)), closes [#521](https://github.com/rknightion/opnsense2otel/issues/521)
* **nginx,logship,schemas:** overCounts is an object, netbird's real app-name, and the prod-vs-testbed canary correction ([2148c3d](https://github.com/rknightion/opnsense2otel/commit/2148c3d5a5787241e8b1ce077f706ba481e89833)), closes [#609](https://github.com/rknightion/opnsense2otel/issues/609) [#601](https://github.com/rknightion/opnsense2otel/issues/601)
* **nginx:** model overCounts per zone kind instead of one union struct ([db05cf5](https://github.com/rknightion/opnsense2otel/commit/db05cf5dbb01a5326a52876b369e73313d05105b))
* **opnsense:** correct BFD counter json tags and ledger the untriaged canary keys ([c7d8007](https://github.com/rknightion/opnsense2otel/commit/c7d8007b162532fe40b81f8819cff413a63524dc)), closes [#480](https://github.com/rknightion/opnsense2otel/issues/480)
* **opnsense:** name the right endpoint in missing-endpoint errors ([48e5fe7](https://github.com/rknightion/opnsense2otel/commit/48e5fe7d54d14beeb24de74932e2340a94a3c693)), closes [#576](https://github.com/rknightion/opnsense2otel/issues/576)
* **opnsense:** split plugin-gating from 404-cacheability ([66eb588](https://github.com/rknightion/opnsense2otel/commit/66eb588a3b43e57b9b00167c825d566a64345d4d)), closes [#495](https://github.com/rknightion/opnsense2otel/issues/495)
* **opnsense:** tolerate rule_stats returning an empty array ([83ec406](https://github.com/rknightion/opnsense2otel/commit/83ec4062c55f3f7453eee5e64a661e432e3614b3)), closes [#481](https://github.com/rknightion/opnsense2otel/issues/481)
* **opnsense:** tolerate the empty-cache [] shape from netflow cacheStats ([9226132](https://github.com/rknightion/opnsense2otel/commit/9226132d1b7541374b165e0cf17346a284e833f8)), closes [#499](https://github.com/rknightion/opnsense2otel/issues/499)
* **options:** drop the doubled prefix from the enable-all-available env var ([c5fb503](https://github.com/rknightion/opnsense2otel/commit/c5fb50376966bcf8c27435d66196a49929091e86)), closes [#517](https://github.com/rknightion/opnsense2otel/issues/517)
* **release:** restore third-party notices pipeline ([3ad3966](https://github.com/rknightion/opnsense2otel/commit/3ad39660a559a9d7e10258aa3c6ef12ec0582165)), closes [#436](https://github.com/rknightion/opnsense2otel/issues/436)
* **scheduler:** make poll clocks, reachability and health cadence honest ([f159ad3](https://github.com/rknightion/opnsense2otel/commit/f159ad3ce2a2276daa8c82b5b4757c300a5ea70d)), closes [#381](https://github.com/rknightion/opnsense2otel/issues/381) [#383](https://github.com/rknightion/opnsense2otel/issues/383) [#385](https://github.com/rknightion/opnsense2otel/issues/385) [#386](https://github.com/rknightion/opnsense2otel/issues/386) [#387](https://github.com/rknightion/opnsense2otel/issues/387)
* **schema:** model nd6 as the object upstream actually serves ([7754b36](https://github.com/rknightion/opnsense2otel/commit/7754b36dd10dc0db1f0415fc5601b5bb87b54ad1)), closes [#371](https://github.com/rknightion/opnsense2otel/issues/371)
* **scripts:** restore the executable bit the rename sed stripped ([2785d77](https://github.com/rknightion/opnsense2otel/commit/2785d777eb46e16aea84d5521894168772596102))
* **smart:** decode smartctl's wear percentages as objects, not numbers ([d293332](https://github.com/rknightion/opnsense2otel/commit/d293332ec2699e4b760b7a291498d902a05d1c1f)), closes [#615](https://github.com/rknightion/opnsense2otel/issues/615)
* **smart:** endurance_used has no threshold_percent, so stop modelling one ([2583827](https://github.com/rknightion/opnsense2otel/commit/25838278d6be79e7a040a61567132c07e0aa8c7f))
* **syslog:** count pre-record connection rejections ([8283826](https://github.com/rknightion/opnsense2otel/commit/8283826a0fbd4ab33abc61b3961a759ad8aa5f33)), closes [#399](https://github.com/rknightion/opnsense2otel/issues/399)
* **syslog:** derive dnsmasq DHCP metrics ([cd5fdcb](https://github.com/rknightion/opnsense2otel/commit/cd5fdcb2ac88dbcef1eb8adf88bd6553bc194d0c)), closes [#396](https://github.com/rknightion/opnsense2otel/issues/396)
* **syslog:** preserve malformed structured data ([d164384](https://github.com/rknightion/opnsense2otel/commit/d1643845b5f394d6141741fc3914cf4582401827)), closes [#397](https://github.com/rknightion/opnsense2otel/issues/397)
* **syslog:** recover from oversized TCP frames ([b64a790](https://github.com/rknightion/opnsense2otel/commit/b64a7902e982c6619fa47a115349f9c55da88079)), closes [#398](https://github.com/rknightion/opnsense2otel/issues/398)
* **telemetry:** drop service.version from the metrics resource ([00a1672](https://github.com/rknightion/opnsense2otel/commit/00a167266f7d8d29c44c0b881db1247e75740547)), closes [#472](https://github.com/rknightion/opnsense2otel/issues/472)
* **telemetry:** give the otlp_* self-metrics an opnsense_instance label ([46e90f5](https://github.com/rknightion/opnsense2otel/commit/46e90f5f505f67298799826d340d921ba3134f06)), closes [#466](https://github.com/rknightion/opnsense2otel/issues/466)
* **web:** refuse a client-SAN config that lets a certificate-less peer panic ([d94bff9](https://github.com/rknightion/opnsense2otel/commit/d94bff90928f38a1b3ae52babcf450261fb017f9)), closes [#562](https://github.com/rknightion/opnsense2otel/issues/562)


### Performance

* **cache:** body-TTL seven config GETs, shorten the global TTL to 30m ([1d97337](https://github.com/rknightion/opnsense2otel/commit/1d973372020be3c6aa0c7e2d4cd64e75aa10bbee)), closes [#574](https://github.com/rknightion/opnsense2otel/issues/574)
* **crowdsec:** split the hub inventory onto a slower sub-cadence ([c509793](https://github.com/rknightion/opnsense2otel/commit/c509793e5cdfa9596b0138cdaea4b6896e7859e4)), closes [#575](https://github.com/rknightion/opnsense2otel/issues/575)
* **enrich:** stop the refresher re-fetching what the collectors just decoded ([cc8a5a1](https://github.com/rknightion/opnsense2otel/commit/cc8a5a16599226f43f7821ed3aaf3ae97f95d49e)), closes [#571](https://github.com/rknightion/opnsense2otel/issues/571)
* **grafana:** bound cold-load query fan-out with a measured budget ([421bf96](https://github.com/rknightion/opnsense2otel/commit/421bf966c1439f4f0521d51b93aa815dae359e63)), closes [#422](https://github.com/rknightion/opnsense2otel/issues/422)
* **grafana:** scope presence sentinels to the tab that consumes them ([4da1b31](https://github.com/rknightion/opnsense2otel/commit/4da1b311c1e7eab275c0ed8665e14577f04b6240)), closes [#619](https://github.com/rknightion/opnsense2otel/issues/619)
* **logship:** stop re-extracting six redundant Zenarmor metadata keys ([e3a957c](https://github.com/rknightion/opnsense2otel/commit/e3a957cb8d2f7c90d7734498c30af76dcde4315f)), closes [#475](https://github.com/rknightion/opnsense2otel/issues/475)
* **netflow,interfaces:** the first two fast-tier body caches ([568d84a](https://github.com/rknightion/opnsense2otel/commit/568d84a5a9751369d0d896a15dc4d3563a051d20))


### Refactoring

* **collector:** justify fast-tier body caches per endpoint, don't ban them ([cc0c20b](https://github.com/rknightion/opnsense2otel/commit/cc0c20b562393e1f83379cb2d92a47786fefee3a)), closes [#567](https://github.com/rknightion/opnsense2otel/issues/567)
* **grafana:** describe dashboards by spec instead of by module globals ([474605f](https://github.com/rknightion/opnsense2otel/commit/474605fa06c5c9677800059bf2ab19d8c6cb862f)), closes [#431](https://github.com/rknightion/opnsense2otel/issues/431)
* **grafana:** make the coverage gate span the dashboard family ([076971a](https://github.com/rknightion/opnsense2otel/commit/076971af0c9ed33f78b3bc4bd1a202e0caaeb765)), closes [#431](https://github.com/rknightion/opnsense2otel/issues/431)
* **grafana:** merge the Zenarmor companion's unique content and retire its UID ([59c4dfe](https://github.com/rknightion/opnsense2otel/commit/59c4dfe458c33e7a825d8d2937b7ef998785e77e)), closes [#435](https://github.com/rknightion/opnsense2otel/issues/435)
* **grafana:** retire the Observability domain, rework the health dashboard IA ([d4f45b3](https://github.com/rknightion/opnsense2otel/commit/d4f45b35c55f72f639dc9645947873d6e98fdc35)), closes [#523](https://github.com/rknightion/opnsense2otel/issues/523)
* **grafana:** split the seven oversized leaves and add autogrid_row ([f5070ac](https://github.com/rknightion/opnsense2otel/commit/f5070ac4172af7c84eff9f6c03ecc257efb20307)), closes [#619](https://github.com/rknightion/opnsense2otel/issues/619)
* **syslog:** make processor rebuilds safe ([81b983f](https://github.com/rknightion/opnsense2otel/commit/81b983fdf6b5b714778e46507c136781637ff625)), closes [#401](https://github.com/rknightion/opnsense2otel/issues/401)


### Miscellaneous

* **deps:** update anthropics/claude-code-action action to v1.0.182 ([#370](https://github.com/rknightion/opnsense2otel/issues/370)) ([34e4f00](https://github.com/rknightion/opnsense2otel/commit/34e4f005ee9ce1b8d55426819cfb13d83c5ed1b3))
* **deps:** update anthropics/claude-code-action action to v1.0.183 ([#454](https://github.com/rknightion/opnsense2otel/issues/454)) ([34e0f04](https://github.com/rknightion/opnsense2otel/commit/34e0f04ad6a204d7f0cf850745083c789d8aa90b))
* **deps:** update module github.com/anchore/syft to v1.50.0 ([#498](https://github.com/rknightion/opnsense2otel/issues/498)) ([5cdd8b7](https://github.com/rknightion/opnsense2otel/commit/5cdd8b7ca8682e9d0a5921f204fd124c3e698048))
* **deps:** update module github.com/anchore/syft/cmd/syft to v1.50.0 ([#500](https://github.com/rknightion/opnsense2otel/issues/500)) ([f1d50c0](https://github.com/rknightion/opnsense2otel/commit/f1d50c056b0f7ec6733b9e19ee5d1af1dad3b1e0))
* **deps:** update opnsense-docs digest to 2c46934 ([#501](https://github.com/rknightion/opnsense2otel/issues/501)) ([af2513d](https://github.com/rknightion/opnsense2otel/commit/af2513d524c19b4e230b5c20840a604c4a52b597))
* **deps:** update opnsense-docs digest to 691b61a ([#461](https://github.com/rknightion/opnsense2otel/issues/461)) ([26dc26c](https://github.com/rknightion/opnsense2otel/commit/26dc26cfa1506dfceed1d33dadce52653cb52833))
* **deps:** update opnsense-docs digest to bf303ba ([#359](https://github.com/rknightion/opnsense2otel/issues/359)) ([ab035e6](https://github.com/rknightion/opnsense2otel/commit/ab035e676cc86b3c98a8c0517e2761edc186267d))
* pin the GoReleaser project name and ignore local Claude state ([cb27a80](https://github.com/rknightion/opnsense2otel/commit/cb27a80d414f663c7fa568ddb819453301d152af))
* regenerate docs, dashboards and rules for the field-export wave ([e56014d](https://github.com/rknightion/opnsense2otel/commit/e56014d40ffed39fc56605bf4ec73c256b86ed76))
* **release:** declare GoReleaser v2 schema ([05eb570](https://github.com/rknightion/opnsense2otel/commit/05eb5705da2c70dd2bc3e7c5958a3dd5c8b8badf)), closes [#634](https://github.com/rknightion/opnsense2otel/issues/634)
* **repo:** repair ownership and intake ([1753ddf](https://github.com/rknightion/opnsense2otel/commit/1753ddfb0442395f0564bd53c8cf223d68388a38))
* **schemas:** ledger the first per-target canary batch ([0a58534](https://github.com/rknightion/opnsense2otel/commit/0a58534ff7f102558aea7c78f5e78cac39a29546))
* **schemas:** ledger the nightly-box canary findings ([9850b0e](https://github.com/rknightion/opnsense2otel/commit/9850b0e1f7436053314bdd10a3d94c6544327e1d))
* **schemas:** ledger the release-box canary findings ([26549e8](https://github.com/rknightion/opnsense2otel/commit/26549e85e2bc507f027c762af0b29ecc02e0b9d0)), closes [#496](https://github.com/rknightion/opnsense2otel/issues/496)
* **testbed:** lint firewall configs for silently-inert settings ([52c9cf1](https://github.com/rknightion/opnsense2otel/commit/52c9cf1d179cc94c17872e2d151bde689e5d486f)), closes [#504](https://github.com/rknightion/opnsense2otel/issues/504)


### Documentation

* **canary:** correct the false 404 claim in smartInfo's exemption note ([540f3ac](https://github.com/rknightion/opnsense2otel/commit/540f3ac265eafcb169ea60b4346a63f395726dd1)), closes [#613](https://github.com/rknightion/opnsense2otel/issues/613)
* **canary:** correct the trafficShaper blocker — the shaper was configured all along ([f497233](https://github.com/rknightion/opnsense2otel/commit/f4972333b2d10fac7e124cbdb003399ce37aa793)), closes [#621](https://github.com/rknightion/opnsense2otel/issues/621)
* **canary:** ledger the 17 firewallStates row keys the pf-state repair does not model ([731ddf8](https://github.com/rknightion/opnsense2otel/commit/731ddf861f3db1f3eed14c76219f6072114055a9))
* **canary:** ledger verdict for healthCheck's seven subsystem notice fields ([957cc1e](https://github.com/rknightion/opnsense2otel/commit/957cc1e81130e8d172291a736dbc51ba71cdcb5d)), closes [#613](https://github.com/rknightion/opnsense2otel/issues/613)
* **canary:** ledger verdict for unboundBlocklistPolicies' ten config fields ([36b0c79](https://github.com/rknightion/opnsense2otel/commit/36b0c79f0d54c45585a1b32c066274d658962b93)), closes [#613](https://github.com/rknightion/opnsense2otel/issues/613)
* **canary:** ledger verdicts for the 17 quaggaOspfOverview per-area fields ([d029712](https://github.com/rknightion/opnsense2otel/commit/d02971265a9a474ebca1ef0384051985fe7a7b4e)), closes [#613](https://github.com/rknightion/opnsense2otel/issues/613)
* **canary:** profile-scope smartInfo's wear fields, and correct my own wrong note ([16fbfd1](https://github.com/rknightion/opnsense2otel/commit/16fbfd1722b7aab45f9e2b5253ba3552eac01637)), closes [#613](https://github.com/rknightion/opnsense2otel/issues/613)
* **collector:** write the fast-tier admission rule as a test, not a description ([025e54f](https://github.com/rknightion/opnsense2otel/commit/025e54fb85f374a3b531441b22b859061ee6e169)), closes [#568](https://github.com/rknightion/opnsense2otel/issues/568)
* document v4 telemetry identity migration ([bded064](https://github.com/rknightion/opnsense2otel/commit/bded064b6097bd7099634d73398acc627a1a253b)), closes [#633](https://github.com/rknightion/opnsense2otel/issues/633)
* **flowanon:** stop naming the device WAN2 used to be on ([012ff0d](https://github.com/rknightion/opnsense2otel/commit/012ff0dcc1d0a39d85e3aaea1ed2e58fa0906ecb))
* **flow:** correct the refusal-floor claim I got wrong this morning ([ae91385](https://github.com/rknightion/opnsense2otel/commit/ae91385a66b59468c0c17c876ab774dc369bc2d3)), closes [#624](https://github.com/rknightion/opnsense2otel/issues/624)
* **flow:** correct why the stated ifIndex and the derived position diverge ([f2bae6e](https://github.com/rknightion/opnsense2otel/commit/f2bae6e6930c3ff9e076cdea67bd98c48e8a063d))
* **flow:** point --flow.netflow.ifindex-map at the whole enumeration ([f9517a3](https://github.com/rknightion/opnsense2otel/commit/f9517a3d8020b565c2d3d170f31f6d7880a4919b))
* **flow:** state the multi-WAN attribution limits and correct the refusal-floor claim ([1d900e6](https://github.com/rknightion/opnsense2otel/commit/1d900e656591548446b2f7450399a2ba169bbf58))
* **grafana:** describe the panels whose semantics the title cannot carry ([1c3ce49](https://github.com/rknightion/opnsense2otel/commit/1c3ce49b5c73c982bbc301b6eccf55a78041007d)), closes [#423](https://github.com/rknightion/opnsense2otel/issues/423)
* **grafana:** generate a runbook per alert instead of one shared anchor ([2d303c1](https://github.com/rknightion/opnsense2otel/commit/2d303c1a943bfa5f6e1d3857e64af41f31c8267b)), closes [#430](https://github.com/rknightion/opnsense2otel/issues/430)
* **grafana:** generate the feature-sentinel contract ([fd94cbd](https://github.com/rknightion/opnsense2otel/commit/fd94cbd3267fbe98c9b0e90f5b8f803a865afa90)), closes [#417](https://github.com/rknightion/opnsense2otel/issues/417)
* **grafana:** record the per-folder permission that made the folder move 403 twice ([41ab129](https://github.com/rknightion/opnsense2otel/commit/41ab12962d12e0cd7a5381c02097341d0f9e6555))
* **logship:** ship-concurrency is a no-op on gRPC, and not for the reason stated ([24cf485](https://github.com/rknightion/opnsense2otel/commit/24cf485cbf74287953c9b5f97d65c52c1e6bdc76)), closes [#505](https://github.com/rknightion/opnsense2otel/issues/505)
* re-pin the dashboard metric count after the ifIndex guard metric ([a4e4dae](https://github.com/rknightion/opnsense2otel/commit/a4e4daed274a3c3e7b9ad24805bb24856df2230c))
* **readme:** voice and de-AI pass ([db16f8a](https://github.com/rknightion/opnsense2otel/commit/db16f8a765a1aa2e3e6d072fb4e686e129dcd8ff))
* settle the cross-poller OTLP attribute contract ([a4340cc](https://github.com/rknightion/opnsense2otel/commit/a4340ccde1d97d6fc98428d41dc7c969db85aeb8)), closes [#477](https://github.com/rknightion/opnsense2otel/issues/477)
* **syslog:** document the ppp, firewall-alias, acme and unbound-dnsbl parsers ([823f45a](https://github.com/rknightion/opnsense2otel/commit/823f45a8e8c118f42af5938307151c3d9d1c0a23)), closes [#631](https://github.com/rknightion/opnsense2otel/issues/631)
* update documentation ([4206f8d](https://github.com/rknightion/opnsense2otel/commit/4206f8d4dd49e1043243bfd60df04a2bf7c63a92))
* update documentation ([08d9fb1](https://github.com/rknightion/opnsense2otel/commit/08d9fb15406178b2cfc2f292253a5c0a6660f999))
* update documentation ([2ed53ab](https://github.com/rknightion/opnsense2otel/commit/2ed53abd48cade48ace937ec214f0fe8de2a824e))


### Build & Infrastructure

* type-aware check for API fields decoded and never read ([6ff859d](https://github.com/rknightion/opnsense2otel/commit/6ff859dcdf8874043460ca4b4e07fda13893fcda)), closes [#544](https://github.com/rknightion/opnsense2otel/issues/544)


### Tests

* **alerts:** model Grafana's rule state machine against the shipped manifests ([b5afdac](https://github.com/rknightion/opnsense2otel/commit/b5afdacabc0d1540fc5dbdf4af50915aef2ee929)), closes [#429](https://github.com/rknightion/opnsense2otel/issues/429)
* **collector:** drain collectMetrics concurrently instead of buffering 500 ([8cdc140](https://github.com/rknightion/opnsense2otel/commit/8cdc140a796b6a9bfa0cb165bf315d1971671b88)), closes [#547](https://github.com/rknightion/opnsense2otel/issues/547)
* **collector:** drain Describe concurrently so a new metric cannot deadlock CI ([804670d](https://github.com/rknightion/opnsense2otel/commit/804670d28895e49924d77d22bd03502783c4c7f7))
* **contract:** make unexpected nested keys a warning again ([206026a](https://github.com/rknightion/opnsense2otel/commit/206026a81d2f7df66461fcfedf1470918ea44b31)), closes [#457](https://github.com/rknightion/opnsense2otel/issues/457)
* **contract:** reflect through RawMessage envelopes so their paths are checked ([0a24a5a](https://github.com/rknightion/opnsense2otel/commit/0a24a5a1a7c506c603109fef2fdb9f8afed0abcd)), closes [#459](https://github.com/rknightion/opnsense2otel/issues/459)
* **contract:** track live coverage for metric-bearing response paths ([b171804](https://github.com/rknightion/opnsense2otel/commit/b1718045be8da1c9e6e2244eb9899e4e46886f13)), closes [#377](https://github.com/rknightion/opnsense2otel/issues/377)
* **grafana:** contract-check the alert fields Prometheus cannot model ([55d3ce9](https://github.com/rknightion/opnsense2otel/commit/55d3ce9a52c2ec2078c48555a7d6b5a01c3e0563)), closes [#429](https://github.com/rknightion/opnsense2otel/issues/429)
* **grafana:** gate zero-filled panels on same-collector sentinel provenance ([a62b25a](https://github.com/rknightion/opnsense2otel/commit/a62b25a012c665eabad26b1e8d2bddcacc214bb3)), closes [#478](https://github.com/rknightion/opnsense2otel/issues/478)
* **grafana:** inventory the exporter's self-metrics and gate them ([bf581a7](https://github.com/rknightion/opnsense2otel/commit/bf581a779f7810e0bd7d5203378ecfc2de286cbb)), closes [#428](https://github.com/rknightion/opnsense2otel/issues/428) [#455](https://github.com/rknightion/opnsense2otel/issues/455)
* **grafana:** pin coverage() to panel queries only ([81d14c0](https://github.com/rknightion/opnsense2otel/commit/81d14c035e8420526c30f37877b8f2bec7fd1685)), closes [#619](https://github.com/rknightion/opnsense2otel/issues/619)
* **grafana:** syntax-check alert and recording expressions in CI ([7db33f3](https://github.com/rknightion/opnsense2otel/commit/7db33f3554ec3083860770ae904ea67e27c6317c))
* **grafana:** update the rule-count pins for the GeoIP stale alert ([b7c2e1e](https://github.com/rknightion/opnsense2otel/commit/b7c2e1e15560611c69289904ef856f78e0853bb3))
* **parsers:** continuously fuzz network inputs ([d47b09a](https://github.com/rknightion/opnsense2otel/commit/d47b09a540446ef255e315d5f36cef9ec67bae37)), closes [#443](https://github.com/rknightion/opnsense2otel/issues/443)
* **syslog:** use RFC 5737 documentation addresses in the ppp fixtures ([a493795](https://github.com/rknightion/opnsense2otel/commit/a493795f6d1d70e11484480e674a39560144d221))
* **testbed:** cover hasync and CARP from a real two-node HA pair ([4f0da1d](https://github.com/rknightion/opnsense2otel/commit/4f0da1d2e9d8e557e39140b037df5e512eda30c9)), closes [#460](https://github.com/rknightion/opnsense2otel/issues/460)


### CI/CD

* **grafana:** publish dashboards and rules to the m7kni stack on push to main ([a62f248](https://github.com/rknightion/opnsense2otel/commit/a62f2483ca5d5805e16b1b505c03ae46cd566cf6)), closes [#529](https://github.com/rknightion/opnsense2otel/issues/529)

## [3.0.0](https://github.com/rknightion/opnsense-exporter/compare/v2.2.1...v3.0.0) (2026-07-23)


### ⚠ BREAKING CHANGES

* **zenarmor,syslog:** close username-only auth bypass, bound receiver resources
* **zenarmor:** the receiver no longer ships records describing its own ingest connection. Set --logs.zenarmor.drop-self-traffic=false to restore the old behaviour.
* **logship:** opnsense_exporter_logs_parse_errors_total and opnsense_exporter_logs_rejected_total gain a `source` label. Aggregations such as sum by (stage) / sum by (reason) are unaffected; only exact full-label-set matches need updating.
* **pyroscope:** --pyroscope.enable-mutex-block (default off) is replaced by --pyroscope.disable-mutex-block (default off = contention profiling ON), following the repo disable-* convention for default-on features. Env var is now OPNSENSE_EXPORTER_PYROSCOPE_DISABLE_MUTEX_BLOCK.
* **logship:** --logs.diaglog.enabled DEFAULTED TO TRUE, so this is not a quiet opt-in removal -- every existing log-shipping user loses the config-change/gateway/CARP/portal audit trail until they configure a syslog target on the firewall pointing at the exporter. --logs.firewall.enabled and --logs.scopes are removed with it.

### Features

* **collector:** add StatusTracker + RunCollector for web UI ([33e4976](https://github.com/rknightion/opnsense-exporter/commit/33e4976c5e9c2439aa3f2a08a9272bb45043ca4e)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **collector:** decouple serving from collection via internal poll scheduler ([#336](https://github.com/rknightion/opnsense-exporter/issues/336) phase 1) ([ac86cb9](https://github.com/rknightion/opnsense-exporter/commit/ac86cb9828cd10c6fd588efa6a0870cf1f824b9f))
* **collector:** derive bounded counters from Zenarmor records ([a632f14](https://github.com/rknightion/opnsense-exporter/commit/a632f1406ea1977817eac50fec3de35a82800e78)), closes [#276](https://github.com/rknightion/opnsense-exporter/issues/276)
* **collector:** flow volume metrics, flags, docs and dashboard ([280dcb5](https://github.com/rknightion/opnsense-exporter/commit/280dcb5ca5c6a329ab0cb94bb416773032bd6846)), closes [#346](https://github.com/rknightion/opnsense-exporter/issues/346)
* **collector:** per-collector poll tiers + interval config ([#336](https://github.com/rknightion/opnsense-exporter/issues/336) phase 2) ([165d400](https://github.com/rknightion/opnsense-exporter/commit/165d400631262ad7e04b330773894ee9978bb7a0))
* **collector:** poll-observability metrics + interval in status snapshot ([#336](https://github.com/rknightion/opnsense-exporter/issues/336) phase 3) ([8edea9c](https://github.com/rknightion/opnsense-exporter/commit/8edea9cec8ad9edf9218fb86ad80e2add1b0a291))
* **flow:** bounded top-N rollup with monotone __other__ folding ([c266b48](https://github.com/rknightion/opnsense-exporter/commit/c266b4834570129486a44b297fc37acbb960fbc8)), closes [#346](https://github.com/rknightion/opnsense-exporter/issues/346)
* **flow:** correlator + DNS answer cache ([#346](https://github.com/rknightion/opnsense-exporter/issues/346) phase 3 seam) ([8e35af9](https://github.com/rknightion/opnsense-exporter/commit/8e35af96540d99c9d971e90da7b0dcf3e51960a7))
* **flow:** DNS-domain enrichment, §9 metrics, Zenarmor conn attrs in place ([#353](https://github.com/rknightion/opnsense-exporter/issues/353)) ([8c1be6c](https://github.com/rknightion/opnsense-exporter/commit/8c1be6cf116e4b73ac3d8264bcbc45a650612f2a))
* **flow:** interface topology and the NetFlow ifIndex map ([b303514](https://github.com/rknightion/opnsense-exporter/commit/b303514deaa4d9c317c7c91d0688a1ad8c8f4bc2))
* **flow:** NetFlow pipeline, metrics, flags, docs and dashboard ([20d5684](https://github.com/rknightion/opnsense-exporter/commit/20d5684a3c2cf1a1c618dfde3610e91bfaa4ac8f))
* **flow:** NetFlow v5/v9 decoder and hardened UDP receiver ([d56d1c6](https://github.com/rknightion/opnsense-exporter/commit/d56d1c6ca71a3d0d0f7c2de5cc072ace3c264c8d))
* **flow:** normalized flow.Record seam and community-id join key ([0f14ede](https://github.com/rknightion/opnsense-exporter/commit/0f14edeeb303a961f8ad467a1c963e05287ce6f6)), closes [#346](https://github.com/rknightion/opnsense-exporter/issues/346)
* **flow:** OTLP flow-log emission path ([#346](https://github.com/rknightion/opnsense-exporter/issues/346) phase 3) ([c00e524](https://github.com/rknightion/opnsense-exporter/commit/c00e5245c1aedc9c9df8ea00cd10557c2b8d9da5))
* **flow:** VLAN de-dup, WAN egress correction and direction inference ([06701db](https://github.com/rknightion/opnsense-exporter/commit/06701dbd5af5b55aa7dfa89400cd281327bcd8da))
* **flow:** wire correlator -&gt; OTLP flow logs, phase-4 dashboard + rules ([#346](https://github.com/rknightion/opnsense-exporter/issues/346)) ([c974d21](https://github.com/rknightion/opnsense-exporter/commit/c974d21655d2fa238e5a786ef2f7bd0da6082dc9))
* **grafana:** comprehensive coverage — Zenarmor tab, mixed Prometheus+Loki panels, curated alerts/recording rules ([8818c03](https://github.com/rknightion/opnsense-exporter/commit/8818c039788aec37f5b64dc3207e68ed37dc8479)), closes [#301](https://github.com/rknightion/opnsense-exporter/issues/301)
* **grafana:** overhaul OPNsense dashboard ([659c98a](https://github.com/rknightion/opnsense-exporter/commit/659c98afd38a130bf3c1f4d99e909a4170367b49)), closes [#303](https://github.com/rknightion/opnsense-exporter/issues/303)
* **logship:** add debug-capture mode for unmodelled receiver signals ([f973082](https://github.com/rknightion/opnsense-exporter/commit/f973082e519fa3b401ce4c3f038e6423c9a715a1)), closes [#330](https://github.com/rknightion/opnsense-exporter/issues/330)
* **logship:** add opnsense.action, a binary pass/block resource attribute ([19d407b](https://github.com/rknightion/opnsense-exporter/commit/19d407beeef17c5d33920a6126d58c17176ebd7a)), closes [#276](https://github.com/rknightion/opnsense-exporter/issues/276)
* **logship:** add the Zenarmor Elasticsearch receiver ([02edcdc](https://github.com/rknightion/opnsense-exporter/commit/02edcdcd3ee65405752b805b50f16fdeabfc4870)), closes [#276](https://github.com/rknightion/opnsense-exporter/issues/276)
* **logship:** align syslog log attributes with OTel semantic conventions ([f461953](https://github.com/rknightion/opnsense-exporter/commit/f461953d2ca1c42495e3da10df391d996f7d44c1)), closes [#266](https://github.com/rknightion/opnsense-exporter/issues/266)
* **logship:** map every lane's disposition onto opnsense.action ([1060108](https://github.com/rknightion/opnsense-exporter/commit/1060108e1eb29076ebff9d6f2ac079a530054f68)), closes [#276](https://github.com/rknightion/opnsense-exporter/issues/276)
* **logship:** per-record source override for transport-agnostic sources ([47c4476](https://github.com/rknightion/opnsense-exporter/commit/47c447667336260eb7dbf5b551cefac8e3084fa3))
* **logship:** replace the firewall and diaglog poll lanes with the syslog receiver ([6f98b35](https://github.com/rknightion/opnsense-exporter/commit/6f98b350d90ac5dbfbff2e1ed0a4b58f9990ed92)), closes [#238](https://github.com/rknightion/opnsense-exporter/issues/238) [#248](https://github.com/rknightion/opnsense-exporter/issues/248)
* **logship:** source-label the receiver self-metrics ([c990cc7](https://github.com/rknightion/opnsense-exporter/commit/c990cc7c9735267633425738f555961c912a4c80)), closes [#276](https://github.com/rknightion/opnsense-exporter/issues/276)
* **logship:** syslog receiver with OPNsense API log enrichment ([174212d](https://github.com/rknightion/opnsense-exporter/commit/174212d5246bb16a6ca7b320133f25f152ec78b3)), closes [#248](https://github.com/rknightion/opnsense-exporter/issues/248)
* **metricsnap:** passive last-scrape family recorder ([7b815cc](https://github.com/rknightion/opnsense-exporter/commit/7b815cce53b19104fabfd9f989109166ead554f2)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **opnsense:** CacheSnapshot accessor for web UI freshness card ([39d9323](https://github.com/rknightion/opnsense-exporter/commit/39d9323dcf0504ace9e1d799f748a1a216c4c3bc)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **options:** add --logs.zenarmor.transport selector (elasticsearch|syslog) ([cf87f79](https://github.com/rknightion/opnsense-exporter/commit/cf87f79f641080eca1ad06315ea7a8be0be874fa))
* **options:** require the syslog receiver for zenarmor transport=syslog ([f6610a5](https://github.com/rknightion/opnsense-exporter/commit/f6610a5f3d9457ffea08597892cd5f07debd8558))
* **options:** web UI flags + redacted EffectiveConfig ([53081ff](https://github.com/rknightion/opnsense-exporter/commit/53081ff8a9195d45b8b8e4008125458b08edace7)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **options:** wire the Zenarmor receiver behind --logs.zenarmor.* ([6d0cbae](https://github.com/rknightion/opnsense-exporter/commit/6d0cbae39fb3c5c0ddf4e4562aebfda68e158a36)), closes [#276](https://github.com/rknightion/opnsense-exporter/issues/276)
* **pyroscope:** collect all profile types by default incl. goroutine-leak ([f5ab4d8](https://github.com/rknightion/opnsense-exporter/commit/f5ab4d86111d00c58765f62f2e99c9ee6eabfb49)), closes [#269](https://github.com/rknightion/opnsense-exporter/issues/269)
* **syslog:** add optional ProgramProcessor delegation hook ([4d27493](https://github.com/rknightion/opnsense-exporter/commit/4d27493c09a13219b98e8817be0b70599c1299df))
* **syslog:** derive metrics from received logs, sample raw lines, and add TLS transport ([18c2024](https://github.com/rknightion/opnsense-exporter/commit/18c2024f9d8a5eddc4e0a8526f3c77841eb466d7)), closes [#258](https://github.com/rknightion/opnsense-exporter/issues/258) [#259](https://github.com/rknightion/opnsense-exporter/issues/259)
* **syslog:** enrich every record, not just filterlog (+ parser registry) ([310dd28](https://github.com/rknightion/opnsense-exporter/commit/310dd28735883cc0c1ab252f6ebf05c67aefa457)), closes [#261](https://github.com/rknightion/opnsense-exporter/issues/261)
* **syslog:** optional program and severity filtering ([269c7e9](https://github.com/rknightion/opnsense-exporter/commit/269c7e9ca91147779125b04c0370b1703e7fb603)), closes [#261](https://github.com/rknightion/opnsense-exporter/issues/261)
* **syslog:** parse Suricata EVE alerts, and refuse to double-ship them ([8ce1e9b](https://github.com/rknightion/opnsense-exporter/commit/8ce1e9b86c09d17a2aa9ebd345e0b2c294d4ba4a)), closes [#261](https://github.com/rknightion/opnsense-exporter/issues/261)
* **syslog:** parse the residual unparsed tail (cron, radvd, kea-dhcp6, dnsmasq-dhcp, configd.py) ([2d1a718](https://github.com/rknightion/opnsense-exporter/commit/2d1a7186abc0b29a5bcf67a1e6257d2b3a7a002b)), closes [#335](https://github.com/rknightion/opnsense-exporter/issues/335)
* **syslog:** parse unbound local-zone query log ([fecf5e3](https://github.com/rknightion/opnsense-exporter/commit/fecf5e38aa457db019059656e490ddf62a2a31ee)), closes [#332](https://github.com/rknightion/opnsense-exporter/issues/332)
* **syslog:** structure unbound SERVFAIL resolution failures ([b169933](https://github.com/rknightion/opnsense-exporter/commit/b1699333eeffe4f11d0bcfdf0df4ffdff52ae542)), closes [#334](https://github.com/rknightion/opnsense-exporter/issues/334)
* **syslog:** structured parsers for audit, sshd, DHCP and HAProxy + tunnel names ([e829bf6](https://github.com/rknightion/opnsense-exporter/commit/e829bf6d391c9d84dc97fe3c2b68f207c6f910c5)), closes [#261](https://github.com/rknightion/opnsense-exporter/issues/261)
* **webui:** active-series, log-throughput and fleet trend charts ([58e48bb](https://github.com/rknightion/opnsense-exporter/commit/58e48bbd74549035ee24b4980f9a024dd8e886bc)), closes [#347](https://github.com/rknightion/opnsense-exporter/issues/347)
* **webui:** cardinality suite (hub, drill-downs, label-values, export) ([68cc734](https://github.com/rknightion/opnsense-exporter/commit/68cc734c6481316a099f63de9d62744aa29c93f9)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **webui:** connected-devices page with embedded OUI lookup ([8211cce](https://github.com/rknightion/opnsense-exporter/commit/8211cce73ca2a8a7178876f7e1071de511f1ab0d)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **webui:** fold cardinality into status snapshot for the single-page tabs ([#337](https://github.com/rknightion/opnsense-exporter/issues/337)) ([1705605](https://github.com/rknightion/opnsense-exporter/commit/170560582fbfd786f52a9e072303a36f3b16ef6f))
* **webui:** per-collector interval/next-run/freshness on CollectorRow ([#337](https://github.com/rknightion/opnsense-exporter/issues/337)) ([e5f55b2](https://github.com/rknightion/opnsense-exporter/commit/e5f55b21bfcdf50bea36c99d271281d8024e7421))
* **webui:** redacted /config page with kill switch ([d37523d](https://github.com/rknightion/opnsense-exporter/commit/d37523de2b9dafe5b010862a41fedc900211e36b)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **webui:** Run Now trigger endpoint + live-polling/filter/sort JS ([6f2ce75](https://github.com/rknightion/opnsense-exporter/commit/6f2ce75284405ce89482c6bf8481250cbb4d4c78)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **webui:** runtime-stats sampler for Overview parity ([#337](https://github.com/rknightion/opnsense-exporter/issues/337)) ([3f0e3bc](https://github.com/rknightion/opnsense-exporter/commit/3f0e3bccefd736d1cd9a67ed0029abe70b517e4b))
* **webui:** show pretty + raw collector names on /config ([d9ed4fd](https://github.com/rknightion/opnsense-exporter/commit/d9ed4fdfadbac3008801bf6037f9cba8c0054b58)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **webui:** single inline tabbed console page ([#337](https://github.com/rknightion/opnsense-exporter/issues/337)) ([99630de](https://github.com/rknightion/opnsense-exporter/commit/99630de000ce033be0806c43206a49cc0ac36d06))
* **webui:** status console page + /api/status.json + render core ([5e7a5b1](https://github.com/rknightion/opnsense-exporter/commit/5e7a5b15b21c757d9fe17f2c64ce8642aa7f80be)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **webui:** wire operator console into main + passive metrics recorder ([0d34fcd](https://github.com/rknightion/opnsense-exporter/commit/0d34fcdd2cbc1729ab34d034495df018f0111621)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **zenarmor:** derive flow.Record from conn documents ([fbf51a1](https://github.com/rknightion/opnsense-exporter/commit/fbf51a1a79ebfad91444202bad3457cd1ab87266)), closes [#346](https://github.com/rknightion/opnsense-exporter/issues/346)
* **zenarmor:** drive the shared processor from the syslog receiver ([142575f](https://github.com/rknightion/opnsense-exporter/commit/142575f6043a59154a333b3338003be292b69320))
* **zenarmor:** drop records describing our own ingest connection ([b454b0e](https://github.com/rknightion/opnsense-exporter/commit/b454b0e896a1db6d69ad4994466598f690d5074f)), closes [#278](https://github.com/rknightion/opnsense-exporter/issues/278)
* **zenarmor:** handle _alias / _settings control-plane probes ([b74523a](https://github.com/rknightion/opnsense-exporter/commit/b74523af2a6ca3b89eae360f88496cc5014af7c4)), closes [#331](https://github.com/rknightion/opnsense-exporter/issues/331)
* **zenarmor:** let operators exclude known-boring traffic from the log stream ([d31296f](https://github.com/rknightion/opnsense-exporter/commit/d31296ff8f92403656ff01e293ef559171b5a59b)), closes [#279](https://github.com/rknightion/opnsense-exporter/issues/279)
* **zenarmor:** parse the daemon=zenarmor syslog message envelope ([f2e1fba](https://github.com/rknightion/opnsense-exporter/commit/f2e1fba6e0058ac38695633728874201ef443f60))


### Bug Fixes

* **canary:** exempt firmware upgrade_packages[].size as box state, not drift ([47c8d9b](https://github.com/rknightion/opnsense-exporter/commit/47c8d9b5a3efca9891223e6dd172962fb74635ef))
* **canary:** triage the live-box drift, and stop plugin-gated 404s warning ([1473097](https://github.com/rknightion/opnsense-exporter/commit/1473097a1072c4c8d7552fd579348d227a0b9e3b)), closes [#243](https://github.com/rknightion/opnsense-exporter/issues/243)
* **config:** reject telemetry paths that collide with health/ready routes ([f3a96b1](https://github.com/rknightion/opnsense-exporter/commit/f3a96b192a8026c695060299eee144c9a614947c)), closes [#291](https://github.com/rknightion/opnsense-exporter/issues/291)
* **deps:** update module github.com/prometheus/client_golang to v1.24.0 ([#339](https://github.com/rknightion/opnsense-exporter/issues/339)) ([9b126b8](https://github.com/rknightion/opnsense-exporter/commit/9b126b8affc432f917a2f7a9f927810825242617))
* **deps:** update module github.com/prometheus/common to v0.70.1 ([#352](https://github.com/rknightion/opnsense-exporter/issues/352)) ([1e60b7f](https://github.com/rknightion/opnsense-exporter/commit/1e60b7fcec564b01c8475c22aaca644a4fdc5378))
* **deps:** update module google.golang.org/grpc to v1.82.1 ([#273](https://github.com/rknightion/opnsense-exporter/issues/273)) ([3eb0fac](https://github.com/rknightion/opnsense-exporter/commit/3eb0fac58001289535a6e6da48dd3c9f09f6de28))
* **logship,collector:** bound sender-controlled derived metric cardinality ([8dc167f](https://github.com/rknightion/opnsense-exporter/commit/8dc167fb9e82b78d21bf4b50b9cd1ba944ef874c)), closes [#311](https://github.com/rknightion/opnsense-exporter/issues/311) [#326](https://github.com/rknightion/opnsense-exporter/issues/326) [#327](https://github.com/rknightion/opnsense-exporter/issues/327)
* **logship:** actually rename subsystem to opnsense.subsystem on the wire ([1ea8afd](https://github.com/rknightion/opnsense-exporter/commit/1ea8afdb31c8199455d1002fa5e36f1ae4abeb6e)), closes [#266](https://github.com/rknightion/opnsense-exporter/issues/266)
* **logship:** HAProxy status_class label was always empty ([e312922](https://github.com/rknightion/opnsense-exporter/commit/e31292242dcdd0284ced9db4de72ee9b61b8452e)), closes [#277](https://github.com/rknightion/opnsense-exporter/issues/277)
* **logship:** make OTLP delivery observable with in-memory at-least-once ([736289b](https://github.com/rknightion/opnsense-exporter/commit/736289b0a487353627e47eef4fdb700482c4b786)), closes [#290](https://github.com/rknightion/opnsense-exporter/issues/290)
* **logship:** publish labelled counters at zero from startup ([9f64c66](https://github.com/rknightion/opnsense-exporter/commit/9f64c6671a394f3895f11f6b4fed5ee2251f677b)), closes [#280](https://github.com/rknightion/opnsense-exporter/issues/280)
* **logship:** stop a permanently-refused batch wedging delivery, bound queue bytes ([f697018](https://github.com/rknightion/opnsense-exporter/commit/f6970186720f8b88913e4cb72aff231eeabf6a1f)), closes [#304](https://github.com/rknightion/opnsense-exporter/issues/304) [#318](https://github.com/rknightion/opnsense-exporter/issues/318) [#325](https://github.com/rknightion/opnsense-exporter/issues/325)
* **opnsense:** block credential-forwarding redirects, redact URL secrets, reject non-finite floats ([2be2b4c](https://github.com/rknightion/opnsense-exporter/commit/2be2b4ca7c45c5835e4696d7eba867781e9caaa1)), closes [#305](https://github.com/rknightion/opnsense-exporter/issues/305) [#306](https://github.com/rknightion/opnsense-exporter/issues/306) [#307](https://github.com/rknightion/opnsense-exporter/issues/307) [#321](https://github.com/rknightion/opnsense-exporter/issues/321) [#323](https://github.com/rknightion/opnsense-exporter/issues/323)
* **opnsense:** drop the metadata.subsystems model; it exists on no release ([80649b1](https://github.com/rknightion/opnsense-exporter/commit/80649b19b5092a5a8f97393830de0caadd44efe9)), closes [#284](https://github.com/rknightion/opnsense-exporter/issues/284)
* **pyroscope:** always collect goroutine profiles, not just under mutex/block ([31d2aa7](https://github.com/rknightion/opnsense-exporter/commit/31d2aa710fa0ff2eab54a8eb3eba7dd3aae358e9)), closes [#268](https://github.com/rknightion/opnsense-exporter/issues/268)
* **pyroscope:** cap backend response bodies and make the flush timeout bound shutdown ([1bb8c2e](https://github.com/rknightion/opnsense-exporter/commit/1bb8c2ebc542205a062821cd3d02a4e545f9615e)), closes [#309](https://github.com/rknightion/opnsense-exporter/issues/309) [#310](https://github.com/rknightion/opnsense-exporter/issues/310)
* **server,otlp:** bound scrape admission and stop echoing header secrets ([342d15e](https://github.com/rknightion/opnsense-exporter/commit/342d15e08f54d6cea8160c1239b7d5c98fe1e8ce)), closes [#308](https://github.com/rknightion/opnsense-exporter/issues/308) [#313](https://github.com/rknightion/opnsense-exporter/issues/313) [#324](https://github.com/rknightion/opnsense-exporter/issues/324)
* **server:** gate /-/ready on poll-scheduler warm-up ([9d43334](https://github.com/rknightion/opnsense-exporter/commit/9d4333453683e6e425e0636a7d1dab1b4d5feed8)), closes [#341](https://github.com/rknightion/opnsense-exporter/issues/341) [#338](https://github.com/rknightion/opnsense-exporter/issues/338)
* **syslog:** reassemble multi-line messages, and put promotable keys on the resource ([9763ebf](https://github.com/rknightion/opnsense-exporter/commit/9763ebf06dc28f99c9b8132246ecd2fdad5076f9)), closes [#262](https://github.com/rknightion/opnsense-exporter/issues/262) [#263](https://github.com/rknightion/opnsense-exporter/issues/263)
* **syslog:** satisfy errcheck and staticcheck ([1788afb](https://github.com/rknightion/opnsense-exporter/commit/1788afbb873cd791a51caf7d60108b12d3eaf7bf)), closes [#248](https://github.com/rknightion/opnsense-exporter/issues/248)
* **zenarmor,syslog:** close username-only auth bypass, bound receiver resources ([4865dca](https://github.com/rknightion/opnsense-exporter/commit/4865dca00291f405d9864500c1a5e1bfd716f674)), closes [#314](https://github.com/rknightion/opnsense-exporter/issues/314) [#315](https://github.com/rknightion/opnsense-exporter/issues/315) [#316](https://github.com/rknightion/opnsense-exporter/issues/316) [#317](https://github.com/rknightion/opnsense-exporter/issues/317) [#328](https://github.com/rknightion/opnsense-exporter/issues/328)
* **zenarmor:** bound decompressed body size and request-body time ([1605294](https://github.com/rknightion/opnsense-exporter/commit/16052940126c6fbe9cd6683bb10778a0ef21f4ac)), closes [#288](https://github.com/rknightion/opnsense-exporter/issues/288) [#289](https://github.com/rknightion/opnsense-exporter/issues/289)
* **zenarmor:** decode alertinfo arrays/number/string sid ([9b2a0fb](https://github.com/rknightion/opnsense-exporter/commit/9b2a0fbb001cc223a650ac2243214d0877d61cf2)), closes [#297](https://github.com/rknightion/opnsense-exporter/issues/297)
* **zenarmor:** log which endpoint an unhandled call hit ([bc800b0](https://github.com/rknightion/opnsense-exporter/commit/bc800b08b887cd6270c3286525f3a252bf6ad51c)), closes [#285](https://github.com/rknightion/opnsense-exporter/issues/285)
* **zenarmor:** match self-traffic against any bound syslog port ([ccf8b9d](https://github.com/rknightion/opnsense-exporter/commit/ccf8b9decf7ce984ee7b004d0ef03eab389ecc55)), closes [#299](https://github.com/rknightion/opnsense-exporter/issues/299)


### Performance

* **collector:** tier wholly-static collectors cold/slow, dedupe plugin-gated list ([bcb5caf](https://github.com/rknightion/opnsense-exporter/commit/bcb5cafe81b4e4f9083ed33a3b1e1072c0efb732)), closes [#344](https://github.com/rknightion/opnsense-exporter/issues/344)
* **runtime:** bound concurrent OPNsense API fan-out during scrapes ([8847e3f](https://github.com/rknightion/opnsense-exporter/commit/8847e3f99d8c7b22dc8d289c251e0dfd14980acc)), closes [#294](https://github.com/rknightion/opnsense-exporter/issues/294)


### Refactoring

* remove per-collector Run Now (POST trigger + inflight guard + RunCollector plumbing) ([#337](https://github.com/rknightion/opnsense-exporter/issues/337)) ([0d4b061](https://github.com/rknightion/opnsense-exporter/commit/0d4b0616dbbfb15d2b3efae648cb9e5635dcf626))
* **zenarmor:** extract shared docProcessor from handleDoc ([6e8e988](https://github.com/rknightion/opnsense-exporter/commit/6e8e98828679331c7b1b73d6700629daf1ec2191))


### Miscellaneous

* **deps:** update actions/checkout action to v7.0.1 ([#340](https://github.com/rknightion/opnsense-exporter/issues/340)) ([527651d](https://github.com/rknightion/opnsense-exporter/commit/527651df12db96077b8802f8e5d72c36c33538e6))
* **deps:** update actions/setup-go action to v7 ([#275](https://github.com/rknightion/opnsense-exporter/issues/275)) ([0896994](https://github.com/rknightion/opnsense-exporter/commit/08969948de2d90af1218bcbf6063c3f6af737b18))
* **deps:** update actions/setup-python action to v7 ([#333](https://github.com/rknightion/opnsense-exporter/issues/333)) ([bbe5c45](https://github.com/rknightion/opnsense-exporter/commit/bbe5c45ec215243456a8e5c8b9c607de28e353b8))
* **deps:** update anthropics/claude-code-action action to v1.0.172 ([#245](https://github.com/rknightion/opnsense-exporter/issues/245)) ([260c8da](https://github.com/rknightion/opnsense-exporter/commit/260c8da4a2280f0cd6aa5820ef9671ca994b9c85))
* **deps:** update anthropics/claude-code-action action to v1.0.173 ([#247](https://github.com/rknightion/opnsense-exporter/issues/247)) ([373c8dc](https://github.com/rknightion/opnsense-exporter/commit/373c8dc8c3fb889b41045837d1bafe9ec57eaa63))
* **deps:** update anthropics/claude-code-action action to v1.0.174 ([#265](https://github.com/rknightion/opnsense-exporter/issues/265)) ([b4ae77e](https://github.com/rknightion/opnsense-exporter/commit/b4ae77ec4480dd04fbf4f60edb786bd15780c82f))
* **deps:** update anthropics/claude-code-action action to v1.0.175 ([#272](https://github.com/rknightion/opnsense-exporter/issues/272)) ([27eeb7a](https://github.com/rknightion/opnsense-exporter/commit/27eeb7ac4bc56b5cb33048279a0326833866fe2f))
* **deps:** update anthropics/claude-code-action action to v1.0.176 ([#287](https://github.com/rknightion/opnsense-exporter/issues/287)) ([a334691](https://github.com/rknightion/opnsense-exporter/commit/a3346914f5feb9ff2d964d9304f495630f5291d8))
* **deps:** update anthropics/claude-code-action action to v1.0.177 ([#300](https://github.com/rknightion/opnsense-exporter/issues/300)) ([7e1fa25](https://github.com/rknightion/opnsense-exporter/commit/7e1fa25d9a64831e7476c832f925987e517e0e60))
* **deps:** update anthropics/claude-code-action action to v1.0.178 ([#329](https://github.com/rknightion/opnsense-exporter/issues/329)) ([84d20d2](https://github.com/rknightion/opnsense-exporter/commit/84d20d247c48a63795fdff2eeb92fe0403fd5330))
* **deps:** update anthropics/claude-code-action action to v1.0.179 ([#342](https://github.com/rknightion/opnsense-exporter/issues/342)) ([892c72c](https://github.com/rknightion/opnsense-exporter/commit/892c72c02b32fd262e6cb82d4f459467fa451942))
* **deps:** update anthropics/claude-code-action action to v1.0.180 ([#351](https://github.com/rknightion/opnsense-exporter/issues/351)) ([842351d](https://github.com/rknightion/opnsense-exporter/commit/842351d8c9c3147012d18598e50e21834ef7b204))
* **deps:** update anthropics/claude-code-action action to v1.0.181 ([#354](https://github.com/rknightion/opnsense-exporter/issues/354)) ([d20f894](https://github.com/rknightion/opnsense-exporter/commit/d20f8943cd2199d824088b6b8539cffc3b2df74a))
* **deps:** update gcr.io/distroless/static-debian13:nonroot docker digest to f7f8f72 ([#244](https://github.com/rknightion/opnsense-exporter/issues/244)) ([047ef4e](https://github.com/rknightion/opnsense-exporter/commit/047ef4edc4ce19560be938f2c67cc9badf7c7461))
* **deps:** update module github.com/anchore/syft to v1.47.0 ([#274](https://github.com/rknightion/opnsense-exporter/issues/274)) ([c3bfe94](https://github.com/rknightion/opnsense-exporter/commit/c3bfe94a8f46bfb05e219f6b3f55b01ea1431930))
* **deps:** update module github.com/anchore/syft to v1.48.0 ([#282](https://github.com/rknightion/opnsense-exporter/issues/282)) ([b2a1da5](https://github.com/rknightion/opnsense-exporter/commit/b2a1da58b6e4182bc0528f00ac32d69fb6543e70))
* **deps:** update module github.com/anchore/syft to v1.49.0 ([#345](https://github.com/rknightion/opnsense-exporter/issues/345)) ([9cc3f33](https://github.com/rknightion/opnsense-exporter/commit/9cc3f330a0f7adef3bf80121a33b568206bdd279))
* **deps:** update module github.com/anchore/syft/cmd/syft to v1.47.0 ([#281](https://github.com/rknightion/opnsense-exporter/issues/281)) ([94a3eec](https://github.com/rknightion/opnsense-exporter/commit/94a3eeceaed82385ada7e250d3d0963b7824e943))
* **deps:** update module github.com/anchore/syft/cmd/syft to v1.48.0 ([#283](https://github.com/rknightion/opnsense-exporter/issues/283)) ([98b3166](https://github.com/rknightion/opnsense-exporter/commit/98b3166c07ccb31ffa620259f2bdc75d950f56b6))
* **deps:** update module github.com/anchore/syft/cmd/syft to v1.49.0 ([#348](https://github.com/rknightion/opnsense-exporter/issues/348)) ([310c0c3](https://github.com/rknightion/opnsense-exporter/commit/310c0c36c5ac4a17a5026284ee9d3f2c72ad2a43))
* **deps:** update opnsense-docs digest to aced3de ([#355](https://github.com/rknightion/opnsense-exporter/issues/355)) ([46f85a4](https://github.com/rknightion/opnsense-exporter/commit/46f85a412ba80ed554e58e46822437f6089c9713))
* **deps:** update opnsense-docs digest to c296d26 ([#264](https://github.com/rknightion/opnsense-exporter/issues/264)) ([12de5b4](https://github.com/rknightion/opnsense-exporter/commit/12de5b48cc7182c3f50b542cbf5b0b6e2957785e))
* **deps:** update opnsense-docs digest to ee0a0c6 ([#343](https://github.com/rknightion/opnsense-exporter/issues/343)) ([92e8b7d](https://github.com/rknightion/opnsense-exporter/commit/92e8b7d8d18e6e74f8c124a8e6abb446eed6aa5a))
* **deps:** update opnsense-docs digest to f9807ac ([#349](https://github.com/rknightion/opnsense-exporter/issues/349)) ([a8da466](https://github.com/rknightion/opnsense-exporter/commit/a8da4664fc797a124270dbcde5bb66c211366f76))


### Documentation

* **assets:** replace the hub's social card with a real project card ([efda35b](https://github.com/rknightion/opnsense-exporter/commit/efda35b7d67c504f0a04ebff2ded9bfca4222075))
* **canary:** record healthCheck subsystems and nginxVts cacheZones as box state ([dfd73ee](https://github.com/rknightion/opnsense-exporter/commit/dfd73ee165fe71d0d4a935f3c96625753eadff78)), closes [#271](https://github.com/rknightion/opnsense-exporter/issues/271)
* **claude:** add box-state as the fifth canary drift verdict ([5a5c62a](https://github.com/rknightion/opnsense-exporter/commit/5a5c62a7861e872c890470c0cacd8407cb51c5f5))
* **collector:** document the poll model + fix stale references ([#336](https://github.com/rknightion/opnsense-exporter/issues/336) phase 4) ([7ebc2cb](https://github.com/rknightion/opnsense-exporter/commit/7ebc2cb71c7f29be90e7d36bd687ed3c670f1556))
* **config:** regenerate flag reference for the web UI flags ([9b19a00](https://github.com/rknightion/opnsense-exporter/commit/9b19a00c84f1df646a854bdf26c4d67ef97bb95f))
* correct two false claims left behind by [#92](https://github.com/rknightion/opnsense-exporter/issues/92) and [#248](https://github.com/rknightion/opnsense-exporter/issues/248) ([c1ae453](https://github.com/rknightion/opnsense-exporter/commit/c1ae45320e0c506954d307504c05cba05dad6738))
* **deployment:** document the web UI operator console ([28ff317](https://github.com/rknightion/opnsense-exporter/commit/28ff317879119291d9ae0c783c9aba158b8a8fd2)), closes [#302](https://github.com/rknightion/opnsense-exporter/issues/302)
* **docker:** show the receiver ports in the compose example ([37a0e7f](https://github.com/rknightion/opnsense-exporter/commit/37a0e7f3aee2a9e61a989ac67543dc29570f0692))
* **nav:** add the syslog receiver page to the site nav ([7fd56da](https://github.com/rknightion/opnsense-exporter/commit/7fd56da377c913478c262532f8a41b0554dc90e1)), closes [#248](https://github.com/rknightion/opnsense-exporter/issues/248)
* **readme,site:** lead with OTLP, syslog and flow differentiators; add GitHub backlinks ([ce54152](https://github.com/rknightion/opnsense-exporter/commit/ce54152c40fa35f7468f1f1a39621b9e1d3ce050))
* **security:** fix distroless private-CA trust recipe ([ea9b864](https://github.com/rknightion/opnsense-exporter/commit/ea9b86478b4108bf9a1a5d6e045c352ced2263f9)), closes [#292](https://github.com/rknightion/opnsense-exporter/issues/292)
* **syslog:** align prose with the phase-4 receiver features ([0dd307e](https://github.com/rknightion/opnsense-exporter/commit/0dd307ed0c463bd961e30f6b86ab0688497d3b82)), closes [#267](https://github.com/rknightion/opnsense-exporter/issues/267)
* **syslog:** document the LogQL name mangling, and fix a duplicated bullet ([69a7a62](https://github.com/rknightion/opnsense-exporter/commit/69a7a62c197b92d7f0a06156d18d59a4fd878434))
* **syslog:** document the parsers, universal enrichment and filtering ([cabb84a](https://github.com/rknightion/opnsense-exporter/commit/cabb84a5c09a32a5f47de3705132cc0c31b08f78)), closes [#261](https://github.com/rknightion/opnsense-exporter/issues/261)
* **syslog:** setup guide, k8s manifests and dashboard panels for the receiver ([f41a600](https://github.com/rknightion/opnsense-exporter/commit/f41a6004082cf313b6e4c5b760870d429893afee)), closes [#248](https://github.com/rknightion/opnsense-exporter/issues/248)
* **telemetry:** document the OTLP resource-attribute convention ([eee3006](https://github.com/rknightion/opnsense-exporter/commit/eee3006230b559a41888113d400c60c8998c14ba)), closes [#270](https://github.com/rknightion/opnsense-exporter/issues/270)
* voice + de-AI pass across the docs base ([63fb0ef](https://github.com/rknightion/opnsense-exporter/commit/63fb0ef6a1666875b8c00ba21a4dd6fd497b7279)), closes [#267](https://github.com/rknightion/opnsense-exporter/issues/267)
* **webui:** describe the single-page tabbed console; drop multi-page/Run-Now refs ([#337](https://github.com/rknightion/opnsense-exporter/issues/337)) ([eaa00c5](https://github.com/rknightion/opnsense-exporter/commit/eaa00c535da6ed06fbc3cf177fa8b8e6413434e0))
* **zenarmor:** document the elasticsearch|syslog transport selector ([410b0f0](https://github.com/rknightion/opnsense-exporter/commit/410b0f0272612715689a7076a5df8b5850848e94))
* **zenarmor:** document the receiver and add its dashboard panels ([9e217a8](https://github.com/rknightion/opnsense-exporter/commit/9e217a8ed3b02f796d68fc1b34dd80e2a47a453f)), closes [#276](https://github.com/rknightion/opnsense-exporter/issues/276)


### Tests

* **cache:** guard body TTLs against fast-polling collectors ([e43abb4](https://github.com/rknightion/opnsense-exporter/commit/e43abb40d9097f9432d13cd55b55824fde0053b2))
* **flow:** fix flaky TestReplayRepair_VLANParentDuplicateSuppressed ([06e5262](https://github.com/rknightion/opnsense-exporter/commit/06e52629e7b5bbb462d7e83cadb188e727c0a055))
* **flow:** golden NetFlow v9 replay fixture from real capture ([#346](https://github.com/rknightion/opnsense-exporter/issues/346)) ([2d20aeb](https://github.com/rknightion/opnsense-exporter/commit/2d20aebe3d81f323e379bf094beb8bbf60310df0))
* **syslog:** benchmark the enrichment path and pin its allocations ([54e62fc](https://github.com/rknightion/opnsense-exporter/commit/54e62fcdeae299b97c445a9eec22c6ea25c4bd12)), closes [#286](https://github.com/rknightion/opnsense-exporter/issues/286)
* **zenarmor:** cover the syslog-transport factory branch; note filter bypass ([cf5f150](https://github.com/rknightion/opnsense-exporter/commit/cf5f1501485ee98ad4250032f32db21f350b92fd))
* **zenarmor:** end-to-end syslog transport across all five families ([20ca1b7](https://github.com/rknightion/opnsense-exporter/commit/20ca1b7f47d25beeae6ed4e54324355fd3ad8fd0))


### CI/CD

* add a clean go test -race gate ([87b705e](https://github.com/rknightion/opnsense-exporter/commit/87b705ef2826c7f3c4fc5e9c5b8ee452755b64f1)), closes [#295](https://github.com/rknightion/opnsense-exporter/issues/295)

## [2.2.1](https://github.com/rknightion/opnsense-exporter/compare/v2.2.0...v2.2.1) (2026-07-13)


### CI/CD

* **release:** repin shared binaries workflow, grant attestations: write ([9fb6409](https://github.com/rknightion/opnsense-exporter/commit/9fb640920f52602937eec241872c48349ab7331d))

## [2.2.0](https://github.com/rknightion/opnsense-exporter/compare/v2.1.0...v2.2.0) (2026-07-13)


### Features

* **otlp:** emit synthetic `up` series in OTLP push mode ([#240](https://github.com/rknightion/opnsense-exporter/issues/240)) ([80049a6](https://github.com/rknightion/opnsense-exporter/commit/80049a616b5230ba5f6871174df24a38d4877081))


### Bug Fixes

* **grafana:** set targetDatasourceUID on recording-rule manifests ([514d0ca](https://github.com/rknightion/opnsense-exporter/commit/514d0ca8ea9a7d12dbcd327d2356ffaa5a5fe4d2))

## [2.1.0](https://github.com/rknightion/opnsense-exporter/compare/v2.0.2...v2.1.0) (2026-07-13)


### Features

* **apidrift:** live schema canary binary for the devel box ([4c73097](https://github.com/rknightion/opnsense-exporter/commit/4c7309707a36759aeeb95cb6e8b6c1630caf768b))
* **apidrift:** subtree-prefix exemptions and the cross-version compat ledger ([e207e3f](https://github.com/rknightion/opnsense-exporter/commit/e207e3faa10ea7c8a518d77668d3a4f6ba502fe2)), closes [#236](https://github.com/rknightion/opnsense-exporter/issues/236)
* **auth:** local user / group / API-key security-posture counts ([97c4ac5](https://github.com/rknightion/opnsense-exporter/commit/97c4ac50a2b6a1e295c7a88970a0c276d8874458)), closes [#222](https://github.com/rknightion/opnsense-exporter/issues/222)
* **captiveportal:** voucher inventory by state ([fdec957](https://github.com/rknightion/opnsense-exporter/commit/fdec957e321e080dd97faa117148162da76bac9e)), closes [#207](https://github.com/rknightion/opnsense-exporter/issues/207)
* **clamav:** engine version and signature database freshness ([e22020e](https://github.com/rknightion/opnsense-exporter/commit/e22020eb31bcb1d7b1c0efca15a908b37670af27)), closes [#204](https://github.com/rknightion/opnsense-exporter/issues/204)
* **client:** cache slow-moving API responses; cache firmware for 12h ([9ec1801](https://github.com/rknightion/opnsense-exporter/commit/9ec1801d872a1f94ee336253ebfc4224f7c622e7)), closes [#193](https://github.com/rknightion/opnsense-exporter/issues/193)
* **core:** config backup freshness + ZFS boot environment inventory ([96174f0](https://github.com/rknightion/opnsense-exporter/commit/96174f03250be83acd673858d880bdcdbeec70da)), closes [#220](https://github.com/rknightion/opnsense-exporter/issues/220)
* **crowdsec:** hub component health (tainted/outdated) + engine version ([8d7fca5](https://github.com/rknightion/opnsense-exporter/commit/8d7fca5dfc2f39d4b039344df8e02504102033f9)), closes [#205](https://github.com/rknightion/opnsense-exporter/issues/205)
* **firewall:** GeoIP database freshness + optional NAT rule inventory ([c9b55c9](https://github.com/rknightion/opnsense-exporter/commit/c9b55c96503610eda724b1e6b3d6904a36a5a9ef)), closes [#221](https://github.com/rknightion/opnsense-exporter/issues/221)
* **frr:** BGP neighbor detail, OSPF/OSPFv3 interface parity, route volumes ([c846f42](https://github.com/rknightion/opnsense-exporter/commit/c846f42deb1d6e8b4f0d118176f1d7f42c050092)), closes [#197](https://github.com/rknightion/opnsense-exporter/issues/197) [#198](https://github.com/rknightion/opnsense-exporter/issues/198) [#199](https://github.com/rknightion/opnsense-exporter/issues/199)
* **haproxy:** stick-table occupancy + show-stat latency/health/capacity ([77d94bf](https://github.com/rknightion/opnsense-exporter/commit/77d94bfb7f5e743ee13bf4dfefabe905793d3414)), closes [#201](https://github.com/rknightion/opnsense-exporter/issues/201)
* **hardware:** DMI system identity (dmidecode) + Deciso PSU status (dechw) ([27c3509](https://github.com/rknightion/opnsense-exporter/commit/27c35090687ec86838b67b5033d48584ed06cffd)), closes [#217](https://github.com/rknightion/opnsense-exporter/issues/217)
* **hostdiscovery:** discovered-host inventory counts ([0a22773](https://github.com/rknightion/opnsense-exporter/commit/0a22773081a33f8dae9eba388b79757f3df85fd4)), closes [#223](https://github.com/rknightion/opnsense-exporter/issues/223)
* **ids:** Suricata service status, alert activity, ruleset and rule inventory ([1be18bf](https://github.com/rknightion/opnsense-exporter/commit/1be18bfa6e1e62575012970d2c83b1ea523b0e4c)), closes [#203](https://github.com/rknightion/opnsense-exporter/issues/203)
* **interfaces:** LAGG member state, SFP/DOM optics, bridge membership ([e62ddb8](https://github.com/rknightion/opnsense-exporter/commit/e62ddb828417da460fce6463d9b67d707ec7318e)), closes [#214](https://github.com/rknightion/opnsense-exporter/issues/214)
* **ipsec:** kernel SAD/SPD tables, per-lease detail, pending-config flag ([6c7c946](https://github.com/rknightion/opnsense-exporter/commit/6c7c946004d125f6efd194c07a71729aa4bfb053)), closes [#213](https://github.com/rknightion/opnsense-exporter/issues/213)
* **kea:** lease state/type breakdown, PD pool capacity, pool utilization ([b68eadb](https://github.com/rknightion/opnsense-exporter/commit/b68eadb2f4ec74dcea17c668d7a6553c6ec5fe6b)), closes [#208](https://github.com/rknightion/opnsense-exporter/issues/208)
* **lldpd:** LLDP neighbor table collector ([8fa19ab](https://github.com/rknightion/opnsense-exporter/commit/8fa19aba18ed62d75955374fa44ae9e6aec99aa2)), closes [#216](https://github.com/rknightion/opnsense-exporter/issues/216)
* **logship:** crowdsec source — alert/decision records (opt-in) ([402cc29](https://github.com/rknightion/opnsense-exporter/commit/402cc297839c422085ac2e7fef532d6aaf6a8dc7)), closes [#232](https://github.com/rknightion/opnsense-exporter/issues/232)
* **logship:** firewall log source — digest-cursor tailing with rule labels ([bacc16e](https://github.com/rknightion/opnsense-exporter/commit/bacc16e92d716e34bbd9db5b2e0b71040eddba8f)), closes [#229](https://github.com/rknightion/opnsense-exporter/issues/229)
* **logship:** generic diagnostics-log source — audit, gateway, CARP, portal, configd ([0d4314a](https://github.com/rknightion/opnsense-exporter/commit/0d4314a9da529f6c1d3c719c0589b3765d914dfe)), closes [#230](https://github.com/rknightion/opnsense-exporter/issues/230)
* **logship:** IDS source — full Suricata EVE alert records (opt-in) ([0c6dcea](https://github.com/rknightion/opnsense-exporter/commit/0c6dcea5bd85dece7d1fe5e116115d9ab7f9aace)), closes [#231](https://github.com/rknightion/opnsense-exporter/issues/231)
* **logship:** log-shipping foundation — internal/logship pipeline (opt-in) ([0a27446](https://github.com/rknightion/opnsense-exporter/commit/0a274460ff97b94d3e9dce84bf31657590578fb6)), closes [#228](https://github.com/rknightion/opnsense-exporter/issues/228)
* **logship:** unbound source — per-query DNS log (opt-in, accepted loss) ([55a49ab](https://github.com/rknightion/opnsense-exporter/commit/55a49ab76deb31b3679be011772517befd00e8ca)), closes [#233](https://github.com/rknightion/opnsense-exporter/issues/233)
* **metrics:** cache hit/miss self-metrics for the response cache ([884a849](https://github.com/rknightion/opnsense-exporter/commit/884a849e6a977d75ada5f546ff25392ed3f6cba4)), closes [#196](https://github.com/rknightion/opnsense-exporter/issues/196)
* **metrics:** minor extension candidates — ntpd GPS, siproxd, shaper last-match ([3f29b3d](https://github.com/rknightion/opnsense-exporter/commit/3f29b3dcfadd03db205081c3355e296f833111fe)), closes [#224](https://github.com/rknightion/opnsense-exporter/issues/224)
* **metrics:** struct extensions from new 26.1.11/26.7 payload keys ([f80174f](https://github.com/rknightion/opnsense-exporter/commit/f80174fd205c85fbf1403ff9134fed7e1e639c87)), closes [#237](https://github.com/rknightion/opnsense-exporter/issues/237)
* **monit:** per-check resource telemetry ([a44ef75](https://github.com/rknightion/opnsense-exporter/commit/a44ef7582412d5aa8f55f7f895fca0fa62f6f522)), closes [#219](https://github.com/rknightion/opnsense-exporter/issues/219)
* **netbird:** management/signal connectivity, relays, per-peer telemetry ([06c02f6](https://github.com/rknightion/opnsense-exporter/commit/06c02f68680bb0ac7405996445940fd9e74604f0)), closes [#211](https://github.com/rknightion/opnsense-exporter/issues/211)
* **nginx:** cache zones, latency counters, cache-status, reload timestamp + bans ([555f59e](https://github.com/rknightion/opnsense-exporter/commit/555f59e4e24689ed4f6e6ae413847f06885cfbd4)), closes [#200](https://github.com/rknightion/opnsense-exporter/issues/200)
* **openvpn:** per-session traffic counters and connected-since ([5f6a9ce](https://github.com/rknightion/opnsense-exporter/commit/5f6a9ce82c672b6d35f10eb4f7ab155bf9ceac0d)), closes [#212](https://github.com/rknightion/opnsense-exporter/issues/212)
* **relayd:** virtual server / table / host health via status/sum ([2b81bf9](https://github.com/rknightion/opnsense-exporter/commit/2b81bf9a626b0d906ec77077621c62c1abbcfce6)), closes [#202](https://github.com/rknightion/opnsense-exporter/issues/202)
* **schema:** capture request bodies for every POST endpoint ([5a7d74d](https://github.com/rknightion/opnsense-exporter/commit/5a7d74d4b09c618ca0ded9b7ffe0cf9694646edc))
* **schema:** committed golden schemas + make schemas staleness gate ([dfc36d6](https://github.com/rknightion/opnsense-exporter/commit/dfc36d686e429f57a2949b842d1ba3fc4fc5454f))
* **schema:** endpoint→response-struct registry covering the full 107-endpoint manifest ([2601327](https://github.com/rknightion/opnsense-exporter/commit/26013273c13cf4d82e0613ca1e596578ba12e1ed))
* **schema:** live-payload structural validator ([93967a4](https://github.com/rknightion/opnsense-exporter/commit/93967a4121c204083ed6fd95a6008eb2a1ed4c5d))
* **schema:** reflection walker deriving structure-only schemas from response structs ([aae08d2](https://github.com/rknightion/opnsense-exporter/commit/aae08d2211e0fc9a5348174b18175b3a69c980ad))
* **system:** export all system-status subsystems from the health payload ([7ea8cb9](https://github.com/rknightion/opnsense-exporter/commit/7ea8cb96867fab7fc81deaa7e0b445b6880e1384)), closes [#218](https://github.com/rknightion/opnsense-exporter/issues/218)
* **tor:** circuit and stream telemetry from the control port (opt-in) ([18da737](https://github.com/rknightion/opnsense-exporter/commit/18da737b3057a4dc9d030983963f20ed0bda460a)), closes [#206](https://github.com/rknightion/opnsense-exporter/issues/206)
* **unbound:** DNSBL query-stats totals and blocklist size (opt-in) ([0289a3d](https://github.com/rknightion/opnsense-exporter/commit/0289a3d0164f429f891016769fd264f2358c8cc3)), closes [#209](https://github.com/rknightion/opnsense-exporter/issues/209)
* **vnstat:** persistent per-interface traffic accounting (opt-in) ([8c71d6d](https://github.com/rknightion/opnsense-exporter/commit/8c71d6def96a2d5e4f7df04ebcc11eb7c068bc16)), closes [#215](https://github.com/rknightion/opnsense-exporter/issues/215)


### Bug Fixes

* **apidrift:** fail fast when the box is unreachable ([e4e1f95](https://github.com/rknightion/opnsense-exporter/commit/e4e1f955b276c4e03f88dda4331e4c6fbc48a5a2))
* **apidrift:** force HTTP/2 and retry transient transport failures ([0ba9482](https://github.com/rknightion/opnsense-exporter/commit/0ba9482513bc30d962acba20811f89f65f5eab66)), closes [#236](https://github.com/rknightion/opnsense-exporter/issues/236)
* **deps:** update module github.com/grafana/pyroscope-go to v1.4.1 ([#189](https://github.com/rknightion/opnsense-exporter/issues/189)) ([58505a0](https://github.com/rknightion/opnsense-exporter/commit/58505a08d9f8411a2d6dd04428f8d0f5ad3a84ca))
* **deps:** update module github.com/prometheus/common to v0.70.0 ([#191](https://github.com/rknightion/opnsense-exporter/issues/191)) ([f9a28ee](https://github.com/rknightion/opnsense-exporter/commit/f9a28eee30d3a591e93ac5ca180b417e30172eae))
* **grafana:** regenerate dashboard artifacts to a fixed point ([83e74cf](https://github.com/rknightion/opnsense-exporter/commit/83e74cf4020e174b63fe2d47d51ce54571633915))
* **lint:** stop misspell rewriting ECT as ETC ([5a75f97](https://github.com/rknightion/opnsense-exporter/commit/5a75f97958675eabd3e3986df6456c2acd7b9191)), closes [#236](https://github.com/rknightion/opnsense-exporter/issues/236)
* **opnsense:** gate unbound extended-statistics series on payload presence ([f25dae2](https://github.com/rknightion/opnsense-exporter/commit/f25dae2d21e4286457ea3ed2f4d042ec1df2ae99)), closes [#236](https://github.com/rknightion/opnsense-exporter/issues/236)
* **opnsense:** read per-subsystem health detail from metadata.subsystems ([0bda657](https://github.com/rknightion/opnsense-exporter/commit/0bda65717e758fbe993651d30abf6f9a4d868430)), closes [#236](https://github.com/rknightion/opnsense-exporter/issues/236)
* **opnsense:** resolve the 26.1.11 jumbo-page mbuf key renames ([bd06b50](https://github.com/rknightion/opnsense-exporter/commit/bd06b506924b3c1350b8c2410d221e694fe609bf)), closes [#236](https://github.com/rknightion/opnsense-exporter/issues/236)
* **opnsense:** resolve the 26.1.11 tcp ECN counter renames ([1b78b94](https://github.com/rknightion/opnsense-exporter/commit/1b78b944fcc22350e428cd9ee29b407d9cac9939)), closes [#236](https://github.com/rknightion/opnsense-exporter/issues/236)
* **schema:** model json.Number as 'numeric' (accepts number or numeric string) ([d2edbb6](https://github.com/rknightion/opnsense-exporter/commit/d2edbb682f0531329f2e8ab29aec97fa9cc9f6ec))
* **unbound:** migrate off deprecated overview/isBlockListEnabled ([a849c38](https://github.com/rknightion/opnsense-exporter/commit/a849c383dcfdafea1c74998e548be9d3fc534e1f)), closes [#210](https://github.com/rknightion/opnsense-exporter/issues/210)


### Performance

* **client:** negative-cache plugin-absent 404s on POST endpoints too ([5e9f561](https://github.com/rknightion/opnsense-exporter/commit/5e9f56191112b67defa1869fe2b4b2a6a21ca500)), closes [#194](https://github.com/rknightion/opnsense-exporter/issues/194)
* **client:** negative-cache plugin-absent 404s; cache slow-moving endpoints ([3b709ce](https://github.com/rknightion/opnsense-exporter/commit/3b709ce59e6bfb94711722b143d0560a68cebf5e)), closes [#194](https://github.com/rknightion/opnsense-exporter/issues/194)


### Miscellaneous

* **deps:** update anthropics/claude-code-action action to v1.0.166 ([#177](https://github.com/rknightion/opnsense-exporter/issues/177)) ([3158c01](https://github.com/rknightion/opnsense-exporter/commit/3158c013c70b9d0a78bd958c1847b762d69138a5))
* **deps:** update anthropics/claude-code-action action to v1.0.167 ([#182](https://github.com/rknightion/opnsense-exporter/issues/182)) ([e9d0532](https://github.com/rknightion/opnsense-exporter/commit/e9d053274b278f2b8aa67aca55adbcc9f312b318))
* **deps:** update anthropics/claude-code-action action to v1.0.168 ([#183](https://github.com/rknightion/opnsense-exporter/issues/183)) ([83457fe](https://github.com/rknightion/opnsense-exporter/commit/83457fe61e9ec92d02f4a68c6da5e63191be96dc))
* **deps:** update anthropics/claude-code-action action to v1.0.169 ([#186](https://github.com/rknightion/opnsense-exporter/issues/186)) ([509bcb3](https://github.com/rknightion/opnsense-exporter/commit/509bcb32327b52d87256f9f7b8df1201713de117))
* **deps:** update anthropics/claude-code-action action to v1.0.170 ([#190](https://github.com/rknightion/opnsense-exporter/issues/190)) ([ea3d2f8](https://github.com/rknightion/opnsense-exporter/commit/ea3d2f8dfa2dd94b6771cc74b54ede20937d339f))
* **deps:** update anthropics/claude-code-action action to v1.0.171 ([#192](https://github.com/rknightion/opnsense-exporter/issues/192)) ([d9ed73e](https://github.com/rknightion/opnsense-exporter/commit/d9ed73e4c0aff88542d3ba78e02ef7d0c9ba2ffd))
* **deps:** update gcr.io/distroless/static-debian13:nonroot docker digest to d29e660 ([#184](https://github.com/rknightion/opnsense-exporter/issues/184)) ([0e55c5b](https://github.com/rknightion/opnsense-exporter/commit/0e55c5b629115f98b31b50390be1b988381b6274))
* **deps:** update mirror.gcr.io/library/golang:1.26-alpine docker digest to 0178a64 ([#185](https://github.com/rknightion/opnsense-exporter/issues/185)) ([c4b0f77](https://github.com/rknightion/opnsense-exporter/commit/c4b0f77c02298f7ffe13d5e1089b88214f2f5ba2))
* **deps:** update mirror.gcr.io/library/golang:1.26-alpine docker digest to 9097beb ([#180](https://github.com/rknightion/opnsense-exporter/issues/180)) ([fcf47a7](https://github.com/rknightion/opnsense-exporter/commit/fcf47a7aed5905e8f5aa1ebd4027a7dfb1961b3d))
* **deps:** update opnsense-docs digest to 5d84fe3 ([#181](https://github.com/rknightion/opnsense-exporter/issues/181)) ([25ce2dd](https://github.com/rknightion/opnsense-exporter/commit/25ce2dd5f3d3c26e9792a5681fb553a7e746ca4d))
* **deps:** update opnsense-docs digest to 77f33a4 ([#187](https://github.com/rknightion/opnsense-exporter/issues/187)) ([d6dfe82](https://github.com/rknightion/opnsense-exporter/commit/d6dfe821c6b00c16d5658f1218b4f00edcdb15ac))
* **deps:** update opnsense-docs digest to 95acbed ([#188](https://github.com/rknightion/opnsense-exporter/issues/188)) ([904e3d0](https://github.com/rknightion/opnsense-exporter/commit/904e3d0b92fb1ae300d34f3dfff1ecbd1c644b93))
* **deps:** update step-security/harden-runner action to v2.20.0 ([#179](https://github.com/rknightion/opnsense-exporter/issues/179)) ([411ba8f](https://github.com/rknightion/opnsense-exporter/commit/411ba8f34f1248c36addfe9e2814e9a020cdefcb))
* lint ([a749c6b](https://github.com/rknightion/opnsense-exporter/commit/a749c6bbb02a6065c69a9354ef2d1bbf2e3add94))


### Documentation

* add the OPNsense compatibility policy page and canary triage recipe ([feafbc6](https://github.com/rknightion/opnsense-exporter/commit/feafbc6ec44f8a91f8c63d206311e42a9c6a5219)), closes [#236](https://github.com/rknightion/opnsense-exporter/issues/236)
* add the schema-registry step to the new-collector recipe ([f84963d](https://github.com/rknightion/opnsense-exporter/commit/f84963d7b7d2ef0287a770249c767856a1496635))
* API-absent telemetry — no SSH channel, node_exporter + textfile recipe ([c622632](https://github.com/rknightion/opnsense-exporter/commit/c6226329f4a019da7fd20ea6fbbd7eb4a84f84d7)), closes [#225](https://github.com/rknightion/opnsense-exporter/issues/225)
* native log-export recipe and exporter-vs-native decision matrix ([33fe5b3](https://github.com/rknightion/opnsense-exporter/commit/33fe5b3ea109e9e13c17bea358af455e79e7ecad)), closes [#234](https://github.com/rknightion/opnsense-exporter/issues/234)
* re-pin dashboard panel counts after [#218](https://github.com/rknightion/opnsense-exporter/issues/218) regeneration ([ce7cfcb](https://github.com/rknightion/opnsense-exporter/commit/ce7cfcbc34b15cd6070d9657c6b20efdf5af0da0))
* record do-not-scrape API landmines and confirmed-empty modules ([1341145](https://github.com/rknightion/opnsense-exporter/commit/134114526d409683201baf7e70b601f3adf8b5d2)), closes [#226](https://github.com/rknightion/opnsense-exporter/issues/226)


### Tests

* **kea:** regression fixtures from live dev-box captures ([c6399a2](https://github.com/rknightion/opnsense-exporter/commit/c6399a2edda9d686776a75a27ec533a8d28e1da1)), closes [#208](https://github.com/rknightion/opnsense-exporter/issues/208)


### CI/CD

* **api-contract:** run the endpoint-manifest canary daily ([7c5a397](https://github.com/rknightion/opnsense-exporter/commit/7c5a397aaafbe6d828828b7a37950da892e60c9c)), closes [#195](https://github.com/rknightion/opnsense-exporter/issues/195)
* **live-canary:** adjust the metric-name floor for gated unbound extended stats ([965f6fb](https://github.com/rknightion/opnsense-exporter/commit/965f6fb99f723465bbd8f199839c8cc855adea59)), closes [#236](https://github.com/rknightion/opnsense-exporter/issues/236)
* **live-canary:** close the drift issue on any clean run, not just scheduled ([140ef06](https://github.com/rknightion/opnsense-exporter/commit/140ef063f140b02f6d5d17aced9916fc4345b52c)), closes [#236](https://github.com/rknightion/opnsense-exporter/issues/236)
* **live-canary:** daily schema+smoke canary against the devel box over tailnet ([6266019](https://github.com/rknightion/opnsense-exporter/commit/626601950468a6ff6cd7f9c0cabc5a6b99dfcabc))
* **live-canary:** drop the stale 'scheduled' wording from the close comment ([d9a0a83](https://github.com/rknightion/opnsense-exporter/commit/d9a0a83fdc2f221438d0d9015e6ed4a14bf5b09f))
* **live-canary:** harden the tailnet-credentialed workflow ([22704c2](https://github.com/rknightion/opnsense-exporter/commit/22704c289bc7c64b03ca74799617298157dd2d05))
* **live-canary:** keep runner DNS after the tailnet join ([34e19cf](https://github.com/rknightion/opnsense-exporter/commit/34e19cf7f867993d4c89e34620a07312d1ee0367))
* **live-canary:** place the SC2016 directive where actionlint's shellcheck honours it ([0ec4e83](https://github.com/rknightion/opnsense-exporter/commit/0ec4e839fd15f969b2731b5482d38644ec7bd5e7))

## [2.0.2](https://github.com/rknightion/opnsense-exporter/compare/v2.0.1...v2.0.2) (2026-07-05)


### Miscellaneous

* **deps:** update anthropics/claude-code-action action to v1.0.165 ([#174](https://github.com/rknightion/opnsense-exporter/issues/174)) ([d8c75d9](https://github.com/rknightion/opnsense-exporter/commit/d8c75d9e1f648c9cf6f7957f9087366a292ee97b))


### Documentation

* **upgrading:** add v2.0 breaking-changes section and fix instance-label note ([#176](https://github.com/rknightion/opnsense-exporter/issues/176)) ([22dcb32](https://github.com/rknightion/opnsense-exporter/commit/22dcb32329237c3dba4bc9ddd78395d858a9b56d))

## [2.0.1](https://github.com/rknightion/opnsense-exporter/compare/v2.0.0...v2.0.1) (2026-07-04)


### Bug Fixes

* **grafana:** emit valid alert noDataState "Ok" (was "OK", rejected by the API) ([d75d02c](https://github.com/rknightion/opnsense-exporter/commit/d75d02cc2e26a2672c6287fa8be6176f59fea33c))


### Miscellaneous

* **deps:** update anthropics/claude-code-action action to v1.0.164 ([#172](https://github.com/rknightion/opnsense-exporter/issues/172)) ([345f0e1](https://github.com/rknightion/opnsense-exporter/commit/345f0e16c6fd21b2c059bb44aff91453c93166ed))

## [2.0.0](https://github.com/rknightion/opnsense-exporter/compare/v1.0.1...v2.0.0) (2026-07-04)


### ⚠ BREAKING CHANGES

* **smart:** the SMART collector is now off by default. Set --exporter.enable-smart (env OPNSENSE_EXPORTER_ENABLE_SMART=true) to restore the opnsense_smart_* metrics.
* **arp,ndp:** opnsense_arp_table_entries and opnsense_ndp_entries per-entry series are no longer emitted by default. Set --exporter.enable-arp-details / --exporter.enable-ndp-details to restore them; otherwise use the new opnsense_arp_table_entries_total / opnsense_ndp_entries_total aggregates.
* **interfaces:** distinguish unknown link state from down so PPPoE WANs aren't reported down
* when --exporter.instance-label is unset, the instance label now defaults to the configured OPNsense address rather than the API hostname. Set --exporter.instance-use-hostname to keep hostname-derived labels, or set --exporter.instance-label explicitly.
* **firewall:** opnsense_firewall_interface_hits_total is renamed to opnsense_firewall_interface_log_entries_recent and changed from counter to gauge. Any user dashboards/alerts using rate()/increase() on the old name must switch to plotting the new gauge directly. The shipped dashboard is updated.
* **grafana:** grafana/alerts/opnsense.rules.yaml is removed. Users loading that file into Prometheus/Mimir/the Grafana Cloud ruler should migrate to the Grafana-managed manifests under grafana/alerts/grafana-managed/ (gcx resources push).

### Features

* **apicapture:** resolve OPS_API_KEY_FILE/OPS_API_SECRET_FILE like the exporter ([428353b](https://github.com/rknightion/opnsense-exporter/commit/428353b5e782ac7af061c528e66caa886e3f24f5)), closes [#157](https://github.com/rknightion/opnsense-exporter/issues/157)
* **arp,ndp:** gate per-entry metrics behind opt-in details flags ([2ac1221](https://github.com/rknightion/opnsense-exporter/commit/2ac12210a1a5ec203571939b0bbe76f7ac29505a)), closes [#125](https://github.com/rknightion/opnsense-exporter/issues/125)
* **collector:** add disable switches for interfaces, protocol, services ([ef94751](https://github.com/rknightion/opnsense-exporter/commit/ef94751b5c60bf4f41958a3d78712bb25b494dbf)), closes [#143](https://github.com/rknightion/opnsense-exporter/issues/143)
* **config:** make OPNsense API timeout and retry count configurable ([045571f](https://github.com/rknightion/opnsense-exporter/commit/045571f41eb01162d25ba19838843c086c0ee0e0)), closes [#140](https://github.com/rknightion/opnsense-exporter/issues/140)
* **docs:** align docs site with m7kni.io brand + server-side SEO/LLM metadata ([9bca073](https://github.com/rknightion/opnsense-exporter/commit/9bca07380d5696b31505e026c70006147be6dfc8)), closes [#70](https://github.com/rknightion/opnsense-exporter/issues/70)
* **grafana:** drop portable Prometheus rules format, ship Grafana-managed alerting only ([2af458a](https://github.com/rknightion/opnsense-exporter/commit/2af458acaf4653eb51471456700a44757e9f33cf)), closes [#76](https://github.com/rknightion/opnsense-exporter/issues/76) [#95](https://github.com/rknightion/opnsense-exporter/issues/95)
* **metrics:** add per-endpoint API request count and duration self-metrics ([802c53a](https://github.com/rknightion/opnsense-exporter/commit/802c53a8c069452fa38b0ac17e679f41350890a2)), closes [#126](https://github.com/rknightion/opnsense-exporter/issues/126)
* **security:** warn at startup when --opnsense.insecure disables TLS verification ([2d3914d](https://github.com/rknightion/opnsense-exporter/commit/2d3914d5fdab0c18e93e6c269f96aa966f6733d2)), closes [#159](https://github.com/rknightion/opnsense-exporter/issues/159)
* **smart:** make SMART collector opt-in (--exporter.enable-smart, default-off) ([4c8af5c](https://github.com/rknightion/opnsense-exporter/commit/4c8af5c937c76ecaa9fc7af792889370d9204e78)), closes [#139](https://github.com/rknightion/opnsense-exporter/issues/139)


### Bug Fixes

* **activity:** parse thread states independently so zombie/stopped states don't zero metrics ([73ba3f8](https://github.com/rknightion/opnsense-exporter/commit/73ba3f8d5d5e42062cdfecffd898d190ea30b0a3)), closes [#82](https://github.com/rknightion/opnsense-exporter/issues/82)
* **alerts:** make OPNsenseEndpointErrors for:15m require sustained errors ([586563a](https://github.com/rknightion/opnsense-exporter/commit/586563a991ab6b95a582c60898b124629e516bfe)), closes [#94](https://github.com/rknightion/opnsense-exporter/issues/94)
* **apicontract:** filter abstract-controller phantom endpoints from the manifest ([9ab2ee9](https://github.com/rknightion/opnsense-exporter/commit/9ab2ee961bbcb20653359109e878d5de902333a3)), closes [#146](https://github.com/rknightion/opnsense-exporter/issues/146)
* **apicontract:** isolate per-controller parse failures in extract.py ([fca0054](https://github.com/rknightion/opnsense-exporter/commit/fca0054685d6631d5342d5ba60cf02d3237b0403)), closes [#111](https://github.com/rknightion/opnsense-exporter/issues/111)
* **captiveportal:** decode zones map serialized as a JSON array ([27fef5b](https://github.com/rknightion/opnsense-exporter/commit/27fef5b12125705b723a16df01ca60cc6f3cc772)), closes [#73](https://github.com/rknightion/opnsense-exporter/issues/73)
* **carp:** source VIP label from the subnet field and dedupe multi-address vhids ([30641c1](https://github.com/rknightion/opnsense-exporter/commit/30641c1936531582be82cab79907e2fb482f1ac1)), closes [#166](https://github.com/rknightion/opnsense-exporter/issues/166)
* **certificates:** omit valid_from/valid_to for pending CSRs instead of epoch 0 ([b80a1da](https://github.com/rknightion/opnsense-exporter/commit/b80a1da69c8deaf20f2522d0b21765085df14f70)), closes [#167](https://github.com/rknightion/opnsense-exporter/issues/167)
* **chrony:** skip sources metrics on sub-fetch failure instead of false zero ([4aed2cf](https://github.com/rknightion/opnsense-exporter/commit/4aed2cfd5947fc9d2c0f6a72d90afc4160c191e7)), closes [#163](https://github.com/rknightion/opnsense-exporter/issues/163)
* **ci:** match drift issue by label+title, not the broken bot-login filter ([5944a81](https://github.com/rknightion/opnsense-exporter/commit/5944a817415cf8565f7e0a9108c5e4129ebef622)), closes [#83](https://github.com/rknightion/opnsense-exporter/issues/83)
* **ci:** surface api-contract verb-drift warnings instead of burying them ([e8cfff8](https://github.com/rknightion/opnsense-exporter/commit/e8cfff872399f6d03afbbfaf4824a639b9aae057)), closes [#93](https://github.com/rknightion/opnsense-exporter/issues/93)
* **collector:** bound no-deadline collections to stop a stalled box blackout ([4baabb8](https://github.com/rknightion/opnsense-exporter/commit/4baabb89011561736f664e0c88fd860e817a6954)), closes [#128](https://github.com/rknightion/opnsense-exporter/issues/128)
* **collector:** dedupe services/wireguard/ntp label tuples to prevent scrape-wide 500s ([45e3403](https://github.com/rknightion/opnsense-exporter/commit/45e340392b379e691506876f9235146e01f5106b)), closes [#85](https://github.com/rknightion/opnsense-exporter/issues/85)
* **collector:** distinguish deadline-expired skipped scrapes from completed ones ([6664350](https://github.com/rknightion/opnsense-exporter/commit/66643509f2e9b9b4adb2f2c386b1611ddcf454c9)), closes [#122](https://github.com/rknightion/opnsense-exporter/issues/122)
* **collector:** emit cumulative counters as CounterValue in firewall/ipsec/protocol ([5621823](https://github.com/rknightion/opnsense-exporter/commit/562182380cc607d7ff6cfac96bb255dc9fcde940)), closes [#106](https://github.com/rknightion/opnsense-exporter/issues/106)
* **collector:** keep dhcpv4/acme/smart/dyndns silent when their plugin is absent ([52a72d8](https://github.com/rknightion/opnsense-exporter/commit/52a72d8d49f5d1f3ad4baaffd8ef7f96d8a66b2d)), closes [#87](https://github.com/rknightion/opnsense-exporter/issues/87)
* **collector:** skip scalar metrics whose backing sub-call failed in pf-stats/system ([47145c2](https://github.com/rknightion/opnsense-exporter/commit/47145c24b35ca42f3c5a1c296784ac0ed8767419)), closes [#91](https://github.com/rknightion/opnsense-exporter/issues/91)
* **collector:** surface interfaces-overview fetch failures via success/errors ([14d9190](https://github.com/rknightion/opnsense-exporter/commit/14d91904901105c47aa9a265574295ded3effbfe)), closes [#123](https://github.com/rknightion/opnsense-exporter/issues/123)
* **collector:** use panic: sentinel on endpoint-errors label, not subsystem slug ([86326fc](https://github.com/rknightion/opnsense-exporter/commit/86326fcf58898c256a748d8a720ab94b2dfcc6db)), closes [#120](https://github.com/rknightion/opnsense-exporter/issues/120)
* **config:** consistent env-var surface — telemetry-path envar + prefixed *_FILE aliases ([6a4d64e](https://github.com/rknightion/opnsense-exporter/commit/6a4d64e81bbfdcc1fa91ee3732ce0103ad0bbf35)), closes [#141](https://github.com/rknightion/opnsense-exporter/issues/141)
* **config:** empty OPS_API_KEY_FILE/OPS_API_SECRET_FILE falls back to flag ([9e56123](https://github.com/rknightion/opnsense-exporter/commit/9e56123562b831d626bc65230832f9609aa2fa75)), closes [#109](https://github.com/rknightion/opnsense-exporter/issues/109)
* **config:** reject empty/invalid --web.telemetry-path instead of panicking ([945cfb4](https://github.com/rknightion/opnsense-exporter/commit/945cfb4d0807a5aa863b81355f75f36e7e89536a)), closes [#108](https://github.com/rknightion/opnsense-exporter/issues/108)
* **config:** validate Pyroscope server-address scheme at startup ([e328a7c](https://github.com/rknightion/opnsense-exporter/commit/e328a7c1df0dc142e236085f701882fdf31a847a)), closes [#142](https://github.com/rknightion/opnsense-exporter/issues/142)
* **crowdsec:** mark bouncers/machines absent on row decode failure instead of false zero ([75c758f](https://github.com/rknightion/opnsense-exporter/commit/75c758f5249482009b7990ef6d366dfea0477981)), closes [#104](https://github.com/rknightion/opnsense-exporter/issues/104)
* **dashboard:** add $device variable so pf-traffic/netflow panels stop blanking ([b8506a5](https://github.com/rknightion/opnsense-exporter/commit/b8506a520cc09d62e2a3c30e448a536e9aa154a2)), closes [#98](https://github.com/rknightion/opnsense-exporter/issues/98)
* **dashboard:** gate DHCP backend rows on presence, not lease count ([2d16b13](https://github.com/rknightion/opnsense-exporter/commit/2d16b13a52e1c940d5eca68d81464995078614cb)), closes [#114](https://github.com/rknightion/opnsense-exporter/issues/114)
* **dashboard:** key multi-query table renames/units on Value #A..N, not metric names ([4800d96](https://github.com/rknightion/opnsense-exporter/commit/4800d96a1be717cce257d0c9e25c72fd55c110d9)), closes [#97](https://github.com/rknightion/opnsense-exporter/issues/97)
* **dashboard:** match Exporter Runtime panels on job=~"opnsense.*", not hardcoded job ([479560e](https://github.com/rknightion/opnsense-exporter/commit/479560e5afc0b0e5a65e16ba66b01a35aa0e32f5)), closes [#113](https://github.com/rknightion/opnsense-exporter/issues/113)
* **dashboard:** scale epoch-seconds timestamps to ms for dateTimeAsIso panels ([baacea2](https://github.com/rknightion/opnsense-exporter/commit/baacea2c77b99ccf97e68f9430ef2b38535ab0c0)), closes [#78](https://github.com/rknightion/opnsense-exporter/issues/78)
* **dashboard:** show lease-expiry column in dnsmasq/Kea lease-detail tables ([0dbfe5c](https://github.com/rknightion/opnsense-exporter/commit/0dbfe5caf26bbcdbc550dff8ca512447e7f2aee8)), closes [#112](https://github.com/rknightion/opnsense-exporter/issues/112)
* **deps:** update module github.com/grafana/pyroscope-go to v1.4.0 ([#69](https://github.com/rknightion/opnsense-exporter/issues/69)) ([fb582e6](https://github.com/rknightion/opnsense-exporter/commit/fb582e60fdc239bd6b7437a92b6dbf457e53d47c))
* **deps:** update module github.com/prometheus/exporter-toolkit to v0.17.0 ([#62](https://github.com/rknightion/opnsense-exporter/issues/62)) ([0783001](https://github.com/rknightion/opnsense-exporter/commit/0783001e3dbe9e9e76922b9cfe9f121a7ae42798))
* **deps:** update module github.com/prometheus/exporter-toolkit to v0.17.1 ([#65](https://github.com/rknightion/opnsense-exporter/issues/65)) ([77f9eb2](https://github.com/rknightion/opnsense-exporter/commit/77f9eb24d9eaa33bc1e5b3aee64e5c7c4c0bfc57))
* **deps:** update module google.golang.org/grpc to v1.82.0 ([#63](https://github.com/rknightion/opnsense-exporter/issues/63)) ([637e901](https://github.com/rknightion/opnsense-exporter/commit/637e901faf901f3c9f417c2822cb4b32dfb73cc7))
* **docgen:** cover top-level Collector metrics + fatal on unparsed constructors ([02a90a2](https://github.com/rknightion/opnsense-exporter/commit/02a90a26b82d56e37a69b6bb2c146f04642d1f80)), closes [#119](https://github.com/rknightion/opnsense-exporter/issues/119)
* **docgen:** derive metric Type from emission ValueType, not _total suffix ([3dc7c1c](https://github.com/rknightion/opnsense-exporter/commit/3dc7c1c543dd5c046a46a6122e877455d33a675c)), closes [#100](https://github.com/rknightion/opnsense-exporter/issues/100)
* **docgen:** make doclint flag/env extraction shape-based and lint grafana tabs ([f6fbbde](https://github.com/rknightion/opnsense-exporter/commit/f6fbbde420aaa7986bd392327ea04dce19011dcb)), closes [#151](https://github.com/rknightion/opnsense-exporter/issues/151)
* **docker:** rename build ARG Version→VERSION so published images embed the version ([c92830e](https://github.com/rknightion/opnsense-exporter/commit/c92830e15d3fcee843668a382da63f878807e78f)), closes [#79](https://github.com/rknightion/opnsense-exporter/issues/79)
* **docs:** correct container UID to 65532 (distroless nonroot), not 65534 ([44fa537](https://github.com/rknightion/opnsense-exporter/commit/44fa537ff815e60eab5c4610ca475794d0770ec0)), closes [#115](https://github.com/rknightion/opnsense-exporter/issues/115)
* **docs:** pin grafana/README tab list + alert/recording counts to generated data ([53061bb](https://github.com/rknightion/opnsense-exporter/commit/53061bb7599110638f966eb8953ae265caf4a4df)), closes [#116](https://github.com/rknightion/opnsense-exporter/issues/116)
* **docs:** pin sub-collector count (47) in CLAUDE.md + 3 docs pages, close drift gap ([1774373](https://github.com/rknightion/opnsense-exporter/commit/1774373d3723c839c5e92c71e7b5ad27addab1ab)), closes [#117](https://github.com/rknightion/opnsense-exporter/issues/117)
* **docs:** replace oversized gradient hero with a compact docs-friendly intro ([fca3dc6](https://github.com/rknightion/opnsense-exporter/commit/fca3dc6b263bc2af596db8ee4d90f8fd07149008)), closes [#70](https://github.com/rknightion/opnsense-exporter/issues/70)
* **firewall:** filter pfctl pseudo-entries and strip mutable (skip) suffix from interface label ([9009e04](https://github.com/rknightion/opnsense-exporter/commit/9009e0494d2cc5f38ed36c6fa24507a31536883f)), closes [#105](https://github.com/rknightion/opnsense-exporter/issues/105)
* **firewall:** re-type interface hit count as a sliding-window gauge, not a counter ([8b3fdfa](https://github.com/rknightion/opnsense-exporter/commit/8b3fdfa301d4ab477a2b92045d2e357016654eff)), closes [#74](https://github.com/rknightion/opnsense-exporter/issues/74)
* **frr:** make frrAFLabel lossless per SAFI to avoid duplicate BGP series ([3fda9d2](https://github.com/rknightion/opnsense-exporter/commit/3fda9d231bc225ab364069ad848d328fa40d965c)), closes [#162](https://github.com/rknightion/opnsense-exporter/issues/162)
* **gateways:** emit status for enabled monitor-disabled gateways (GatewayDown blind spot) ([85a95ec](https://github.com/rknightion/opnsense-exporter/commit/85a95ec40720ee99294c7e99f2c2c38256de27aa)), closes [#77](https://github.com/rknightion/opnsense-exporter/issues/77)
* **haproxy:** omit HTTP response-code counters for tcp-mode proxies ([4b6cc40](https://github.com/rknightion/opnsense-exporter/commit/4b6cc40c6bce51a4ea6868760dd36a016c0d7e5b)), closes [#164](https://github.com/rknightion/opnsense-exporter/issues/164)
* **interfaces:** distinguish unknown link state from down so PPPoE WANs aren't reported down ([cfd1d63](https://github.com/rknightion/opnsense-exporter/commit/cfd1d634dbba642e041297f9a3d3e6e947481748)), closes [#86](https://github.com/rknightion/opnsense-exporter/issues/86)
* **interfaces:** parse counter fields tolerantly so one bad field doesn't drop all interface metrics ([b0f9ee0](https://github.com/rknightion/opnsense-exporter/commit/b0f9ee0484fb54297f56268514c39f76b6ce99cb)), closes [#102](https://github.com/rknightion/opnsense-exporter/issues/102)
* **k8s:** pin image tag and add seccomp/SA-token hardening to example manifest ([7f5df45](https://github.com/rknightion/opnsense-exporter/commit/7f5df45586483389347fe09972a8cff36555d48b)), closes [#147](https://github.com/rknightion/opnsense-exporter/issues/147)
* **k8s:** raise example scrapeTimeout to 30s and use resolvable Service DNS ([393f998](https://github.com/rknightion/opnsense-exporter/commit/393f998e858957918d395669cd84dbea1e5bc991)), closes [#99](https://github.com/rknightion/opnsense-exporter/issues/99)
* **main:** gracefully drain HTTP server on SIGTERM/SIGINT instead of os.Exit(0) ([123b774](https://github.com/rknightion/opnsense-exporter/commit/123b774576b00fd6799b34d4145986c0020abab2)), closes [#161](https://github.com/rknightion/opnsense-exporter/issues/161)
* **make:** pass API creds to local-run/capture via env, not world-readable argv ([8729693](https://github.com/rknightion/opnsense-exporter/commit/8729693ed9ef971feff31e57e7f642244dbf4c85)), closes [#160](https://github.com/rknightion/opnsense-exporter/issues/160)
* **ntp:** parse unit-suffixed ntpq when/poll intervals instead of coercing to 0 ([f9001f0](https://github.com/rknightion/opnsense-exporter/commit/f9001f0140778fbb753fd2eefddfeae2294b9d3b)), closes [#89](https://github.com/rknightion/opnsense-exporter/issues/89)
* **openvpn:** count only real client rows as sessions ([a0b9c70](https://github.com/rknightion/opnsense-exporter/commit/a0b9c7068d41e0f916dffbd630d5f9a2cc6eee08)), closes [#88](https://github.com/rknightion/opnsense-exporter/issues/88)
* **opnsense:** widen byte/packet counter fields to int64 for 32-bit source builds ([4ef3662](https://github.com/rknightion/opnsense-exporter/commit/4ef3662bbd5090a8dff53d800e33dc2b0048a146)), closes [#103](https://github.com/rknightion/opnsense-exporter/issues/103)
* **otlp:** close three config-validation gaps that silently break export ([dcd76f3](https://github.com/rknightion/opnsense-exporter/commit/dcd76f3c1bdd10864d41a76da0e016142681e910)), closes [#92](https://github.com/rknightion/opnsense-exporter/issues/92)
* **otlp:** isolate gatherers so one bad collector can't black out export ([ab0fdcc](https://github.com/rknightion/opnsense-exporter/commit/ab0fdcc4ccdc8a05df791ab2e17cc8839fb8abab)), closes [#101](https://github.com/rknightion/opnsense-exporter/issues/101)
* **otlp:** post to the /v1/metrics signal path for base-URL endpoints ([22d841e](https://github.com/rknightion/opnsense-exporter/commit/22d841eaceba1a0f1b2efd5ce33394eac5f4002a)), closes [#80](https://github.com/rknightion/opnsense-exporter/issues/80)
* **profiling:** flush final Pyroscope window on shutdown instead of dropping it ([962bead](https://github.com/rknightion/opnsense-exporter/commit/962beadced8cb9c8779fd9e95fed495802d76334)), closes [#121](https://github.com/rknightion/opnsense-exporter/issues/121)
* **protocol:** expose IPv6/ICMPv6 stats instead of silently dropping them ([579a2b2](https://github.com/rknightion/opnsense-exporter/commit/579a2b2d8de0de30ded7d9cdcea40b50f5f341b3)), closes [#165](https://github.com/rknightion/opnsense-exporter/issues/165)
* **resilience:** short-circuit when firewall unreachable + backoff/jitter retries ([d228260](https://github.com/rknightion/opnsense-exporter/commit/d22826018e235a735a007612c6bf4a49a9d62e0f)), closes [#127](https://github.com/rknightion/opnsense-exporter/issues/127)
* resolve instance label deterministically instead of via a startup race ([3ec7122](https://github.com/rknightion/opnsense-exporter/commit/3ec7122997e1052f97bec6d808139ba38e70d5f6)), closes [#75](https://github.com/rknightion/opnsense-exporter/issues/75)
* **server,collectors:** stop duplicate label tuples from 500-ing the whole scrape ([6980c93](https://github.com/rknightion/opnsense-exporter/commit/6980c93a767e6461afe9f2fb900746fef17d879c)), closes [#81](https://github.com/rknightion/opnsense-exporter/issues/81)
* **server:** reject NaN/Inf/absurd scrape-timeout header values ([c8e574b](https://github.com/rknightion/opnsense-exporter/commit/c8e574b31b5f23008cd6edfa5f6a35d767e958fc)), closes [#124](https://github.com/rknightion/opnsense-exporter/issues/124)
* **system:** correct DST-transition skew in uptime and config_last_change ([f49edc2](https://github.com/rknightion/opnsense-exporter/commit/f49edc2627be7b72ef4c036dcdca913acf5ff506)), closes [#107](https://github.com/rknightion/opnsense-exporter/issues/107)
* **unbound:** capture all RR query types, not a fixed 16-field whitelist ([6b955fd](https://github.com/rknightion/opnsense-exporter/commit/6b955fddfadcda630bbb9339889fc8de3509e24b)), closes [#138](https://github.com/rknightion/opnsense-exporter/issues/138)
* **unbound:** skip stats series when unbound-control is unavailable ([c6b652e](https://github.com/rknightion/opnsense-exporter/commit/c6b652ec44a768386706f7ef200e823f01869f14)), closes [#90](https://github.com/rknightion/opnsense-exporter/issues/90)
* **unbound:** stop clamp_min(denom,1) collapsing cache hit ratio below 1 qps ([0381b26](https://github.com/rknightion/opnsense-exporter/commit/0381b26c2ba9e55a040b77f1fbfc20f9ca6b733e)), closes [#96](https://github.com/rknightion/opnsense-exporter/issues/96)


### Performance

* **mbuf:** read extended fields from systemMbuf, skip redundant API call ([3712561](https://github.com/rknightion/opnsense-exporter/commit/3712561cf17aa5a02bfa64ec92d0826c7ac3d88c)), closes [#137](https://github.com/rknightion/opnsense-exporter/issues/137)
* **opnsense:** parallelize independent multi-endpoint Fetch functions ([baa4964](https://github.com/rknightion/opnsense-exporter/commit/baa4964a5dd3513db30c926b7b77c0515d867b11)), closes [#129](https://github.com/rknightion/opnsense-exporter/issues/129)


### Miscellaneous

* **deps:** update anthropics/claude-code-action action to v1.0.160 ([#61](https://github.com/rknightion/opnsense-exporter/issues/61)) ([4966911](https://github.com/rknightion/opnsense-exporter/commit/4966911e4ad67297152b394c7655d425fce6c62d))
* **deps:** update anthropics/claude-code-action action to v1.0.161 ([#64](https://github.com/rknightion/opnsense-exporter/issues/64)) ([511cee1](https://github.com/rknightion/opnsense-exporter/commit/511cee1bd1f822611afa9ea97a51d638d7ad7d16))
* **deps:** update anthropics/claude-code-action action to v1.0.162 ([#66](https://github.com/rknightion/opnsense-exporter/issues/66)) ([a442589](https://github.com/rknightion/opnsense-exporter/commit/a442589ab0f5aff6d74d4b8b39510c3c13cf14f2))
* **deps:** update anthropics/claude-code-action action to v1.0.163 ([#71](https://github.com/rknightion/opnsense-exporter/issues/71)) ([5196a33](https://github.com/rknightion/opnsense-exporter/commit/5196a33cb227c99874809447f22e6af2a3ceffb7))
* **deps:** update docker/build-push-action action to v7.3.0 ([#67](https://github.com/rknightion/opnsense-exporter/issues/67)) ([54eba0e](https://github.com/rknightion/opnsense-exporter/commit/54eba0ec684d4309085b43c1c1c548c7ef7857f5))
* **deps:** update docker/setup-buildx-action action to v4.2.0 ([#68](https://github.com/rknightion/opnsense-exporter/issues/68)) ([4b6eb3e](https://github.com/rknightion/opnsense-exporter/commit/4b6eb3e2b5b012255b84eb0bb719ae8d2a722760))
* **deps:** update module github.com/anchore/syft to v1.46.0 ([#169](https://github.com/rknightion/opnsense-exporter/issues/169)) ([0960135](https://github.com/rknightion/opnsense-exporter/commit/09601353132d7d7b77e8ac370e2f77f79e263a8d))
* **deps:** update module github.com/anchore/syft/cmd/syft to v1.46.0 ([#170](https://github.com/rknightion/opnsense-exporter/issues/170)) ([7a86913](https://github.com/rknightion/opnsense-exporter/commit/7a86913ac15cc79e16b45d8c3d1dca18b8e0cdbf))
* **deps:** update module github.com/google/go-licenses to v2 ([#171](https://github.com/rknightion/opnsense-exporter/issues/171)) ([c10f69e](https://github.com/rknightion/opnsense-exporter/commit/c10f69e8f78246bdde4029fd4f895efe69d35a58))
* **docs:** remove committed zensical site/ build output and gitignore it ([224998e](https://github.com/rknightion/opnsense-exporter/commit/224998e476a1d84f1ac024f4f0dc286c172b331a)), closes [#152](https://github.com/rknightion/opnsense-exporter/issues/152)
* remove Snyk from CI ([0c80fcf](https://github.com/rknightion/opnsense-exporter/commit/0c80fcf8d9421aaa876b2292d8b6a306776f4ff2))


### Documentation

* **apicontract:** correct false "live-box stage (P3)" exemption claim ([7b777a1](https://github.com/rknightion/opnsense-exporter/commit/7b777a1c5f4dd753a4b9931f100c71690db83d6a)), closes [#110](https://github.com/rknightion/opnsense-exporter/issues/110)
* drop false promhttp_* claim from --web.disable-exporter-metrics help ([360e12d](https://github.com/rknightion/opnsense-exporter/commit/360e12d1e3ccfed05cb16cce7efc7e3811f99040)), closes [#149](https://github.com/rknightion/opnsense-exporter/issues/149)
* **firmware:** correct misleading needs_reboot help text ([1d66d54](https://github.com/rknightion/opnsense-exporter/commit/1d66d5494f4633c92b3d4933326c732b2831a1bf)), closes [#168](https://github.com/rknightion/opnsense-exporter/issues/168)
* **geo:** content-shape pass for LLM/search retrievability ([eb025ae](https://github.com/rknightion/opnsense-exporter/commit/eb025ae05c7a7d9e12a6443c1d1a37e42111db4f))
* mark shipped collectors COMPLETED in stale todos.txt ([7fe6e8b](https://github.com/rknightion/opnsense-exporter/commit/7fe6e8b96ccf24746ae237807579b4c3f9089277)), closes [#158](https://github.com/rknightion/opnsense-exporter/issues/158)
* **troubleshooting:** flag the activity collector as the top scrape-latency cost ([6be042e](https://github.com/rknightion/opnsense-exporter/commit/6be042ee44f4689c2a0c51cf36fa9b6225a8a636)), closes [#150](https://github.com/rknightion/opnsense-exporter/issues/150)


### Build & Infrastructure

* **docker:** digest-pin the golang builder image + Renovate pinDigests ([b6069f8](https://github.com/rknightion/opnsense-exporter/commit/b6069f83e955d08768c5d9ca7f2a3363a5f54d49)), closes [#148](https://github.com/rknightion/opnsense-exporter/issues/148)


### Tests

* **contract:** derive postEndpoints from POST call sites to catch drift ([2e54b96](https://github.com/rknightion/opnsense-exporter/commit/2e54b96f680df591cffc5dde5b8806dc81c657fb)), closes [#145](https://github.com/rknightion/opnsense-exporter/issues/145)
* **contract:** extend response-shape contracts beyond healthCheck ([dabe778](https://github.com/rknightion/opnsense-exporter/commit/dabe778918592f2c90b5959b997b5e22740d0880)), closes [#144](https://github.com/rknightion/opnsense-exporter/issues/144)
* **main:** gate that every collector disable switch is wired in main.go ([4f99761](https://github.com/rknightion/opnsense-exporter/commit/4f99761a5ba3e34991b95f4d127ff82176ba9aa1)), closes [#153](https://github.com/rknightion/opnsense-exporter/issues/153)
* **opnsense:** drop duplicated testEndpoints(), build test clients from defaultEndpoints() ([386aa39](https://github.com/rknightion/opnsense-exporter/commit/386aa39c5695c7a2544b895ffccbf4a52b12fce3)), closes [#154](https://github.com/rknightion/opnsense-exporter/issues/154)
* **opnsense:** pin hasync single-node {"response": false} shape ([ed8dec9](https://github.com/rknightion/opnsense-exporter/commit/ed8dec98d43ff38b26cc2f94f053c8804e16b16c)), closes [#156](https://github.com/rknightion/opnsense-exporter/issues/156)
* **opnsense:** use raw JSON fixtures for services/arp/ntp/carp instead of mustMarshal(struct) ([10b1831](https://github.com/rknightion/opnsense-exporter/commit/10b1831cb1f16522e5a976733e8994b56634a84a)), closes [#155](https://github.com/rknightion/opnsense-exporter/issues/155)


### CI/CD

* add OpenSSF Scorecard via shared reusable workflow ([3759427](https://github.com/rknightion/opnsense-exporter/commit/3759427932505b049ad5a3a5f9fbe188e0824bab))
* bump shared rknightion reusables v1.0.0 -&gt; v1.3.1 ([f8c2fa0](https://github.com/rknightion/opnsense-exporter/commit/f8c2fa09531628d38d8d76e9f82b2d1e19e877b2))
* drop CodeQL pull_request trigger to trim Actions fan-out ([3bb206c](https://github.com/rknightion/opnsense-exporter/commit/3bb206c2489d71ab2f06858dda14946068dee345))
* **grafana:** enforce dashboard coverage, regen freshness & manifest validity ([311267e](https://github.com/rknightion/opnsense-exporter/commit/311267e7918528b8cdb174f30404c9402e33fa0d)), closes [#84](https://github.com/rknightion/opnsense-exporter/issues/84)
* **lint:** pin golangci-lint version and enforce gofmt in CI ([ee2e1c2](https://github.com/rknightion/opnsense-exporter/commit/ee2e1c2a3b61d011ffb0d877dd1e9f42a54986d7)), closes [#132](https://github.com/rknightion/opnsense-exporter/issues/132)
* **release:** fall back to github.token when RELEASE_PLEASE_TOKEN is absent ([7aa5d42](https://github.com/rknightion/opnsense-exporter/commit/7aa5d42f04723266450c5f6e56b61292afa7eb37)), closes [#131](https://github.com/rknightion/opnsense-exporter/issues/131)
* remove claude issue-triage workflow ([b70aa01](https://github.com/rknightion/opnsense-exporter/commit/b70aa01bddf311635312ff78a113995f9f3abe92))
* remove dead build-telemetry OTEL config referencing non-existent secrets ([03a748d](https://github.com/rknightion/opnsense-exporter/commit/03a748d92ef460313ee8cae62a35aaef7bf1499e)), closes [#133](https://github.com/rknightion/opnsense-exporter/issues/133)
* remove notify-maintainer-on-new-issue workflow ([91e343f](https://github.com/rknightion/opnsense-exporter/commit/91e343f6e87a423aeb29cf40c743a17c6b3b5b1b))
* **renovate:** track pinned syft / go-licenses versions via custom managers ([65b3e38](https://github.com/rknightion/opnsense-exporter/commit/65b3e38f742fe5419922f5e2e51516859b6df88c)), closes [#135](https://github.com/rknightion/opnsense-exporter/issues/135)
* run extract_test.py parser-contract tests in the api-contract job ([457802b](https://github.com/rknightion/opnsense-exporter/commit/457802b6726922d982af6fe9458ae0fceec553ae)), closes [#136](https://github.com/rknightion/opnsense-exporter/issues/136)
* **security:** narrow api-contract-enrich agent gh allowlist + document ingress ([e34e288](https://github.com/rknightion/opnsense-exporter/commit/e34e2889ee6c1c8c0c5326bcf0012a06420d18e9)), closes [#134](https://github.com/rknightion/opnsense-exporter/issues/134)
* **security:** pin opnsense/docs SHA and parser pip deps in api-contract ([b2cf72e](https://github.com/rknightion/opnsense-exporter/commit/b2cf72e796fbc498c3a80be11f529f82ed1f7cf6)), closes [#130](https://github.com/rknightion/opnsense-exporter/issues/130)

## [1.0.1](https://github.com/rknightion/opnsense-exporter/compare/v1.0.0...v1.0.1) (2026-06-29)


### Bug Fixes

* resolve review findings in gateway collector, client, and registration ([8f1ba70](https://github.com/rknightion/opnsense-exporter/commit/8f1ba70f7329c657fc2620a30e729ccac84b5418))


### Miscellaneous

* **deps:** update golangci/golangci-lint-action action to v9.3.0 ([#59](https://github.com/rknightion/opnsense-exporter/issues/59)) ([7d46c39](https://github.com/rknightion/opnsense-exporter/commit/7d46c39c2ad1542d78842419b1cd6dd16a2c2e55))
* **deps:** update goreleaser/goreleaser-action action to v7.2.3 ([#57](https://github.com/rknightion/opnsense-exporter/issues/57)) ([763504e](https://github.com/rknightion/opnsense-exporter/commit/763504ec0ef0e15a802d21f37427a4f4fa100c9c))
* **renovate:** group lockstep dependency families ([cbef9d7](https://github.com/rknightion/opnsense-exporter/commit/cbef9d78586f039325ad862ef322b0656b3b043e))


### CI/CD

* add Snyk -&gt; Snyk Cloud monitor (SCA/SAST/IaC/container) ([2109b7e](https://github.com/rknightion/opnsense-exporter/commit/2109b7eb0fea5186bd684df7e232f17eee02b72b))
* build release binaries via shared binaries reusable ([35396fc](https://github.com/rknightion/opnsense-exporter/commit/35396fc8b20f2269c5b9c61bc2e75997a0ba4aca))
* **codacy:** align exclude_paths convention; use project token for coverage ([df73e81](https://github.com/rknightion/opnsense-exporter/commit/df73e811e9e05aa283e5e213909b29d006ae3b4e))
* open the release-please PR under a PAT so CI runs without manual approval ([8471e9c](https://github.com/rknightion/opnsense-exporter/commit/8471e9c5d0f375a97f8741e714adf077bafee4dd))
* pin shared rknightion reusables to v1.0.0 ([3d3d6e9](https://github.com/rknightion/opnsense-exporter/commit/3d3d6e98e9a63cccb1a842e9a5726a329efa5e24))
* publish image via shared container-publish reusable ([a0a680b](https://github.com/rknightion/opnsense-exporter/commit/a0a680b7dffb359d192609c35f612e0e3ad34690))
* sign release binaries + emit archive SBOMs (supply-chain parity) ([ece4d2b](https://github.com/rknightion/opnsense-exporter/commit/ece4d2b606816176d006ffe3af0b6088b77c463b))

## [1.0.0](https://github.com/rknightion/opnsense-exporter/compare/v0.4.0...v1.0.0) (2026-06-28)


### ⚠ BREAKING CHANGES

* **health:** opnsense_up no longer flips to 0 for a reachable box that OPNsense self-reports as degraded (e.g. a leftover crash report). Such a box now triggers the warning-level OPNsenseCrashReports / OPNsenseFirewallUnhealthy alerts instead of the critical OPNsenseExporterDown. Users of the bundled alert rules should expect that severity change.
* **readme:** thin README — hard-fork notice replaces upstream changelog, docs site is canonical
* **collectors:** opnsense_openvpn_sessions is no longer emitted by default (set --exporter.enable-openvpn-details to restore it), and IPsec phase2 metrics no longer carry spi_in/spi_out labels.

### Features

* **alias:** firewall alias table size collector with opt-in pf counters ([763adc7](https://github.com/rknightion/opnsense-exporter/commit/763adc74ed440c2c0c013b60ba348147f868d6b5))
* **apcupsd:** APC UPS metrics collector (plugin-gated) ([6040ba1](https://github.com/rknightion/opnsense-exporter/commit/6040ba1fbc0c814c1f7a0772f64885e62b5b9f24))
* **apicontract:** API contract diff tool ([fb12ea0](https://github.com/rknightion/opnsense-exporter/commit/fb12ea0a7364381ef75e6c6f48b01949ca7fb417))
* **bpf:** BPF listener statistics collector ([b4983ab](https://github.com/rknightion/opnsense-exporter/commit/b4983abbc90dbb16e057ea6dc6b1b0d706439f05))
* **build:** docs/docs-check make targets and install-hooks pre-commit gate ([a94de13](https://github.com/rknightion/opnsense-exporter/commit/a94de130c39c1ab51926a72863b1712f57f4c72d))
* **captiveportal:** captive portal zone and session collector ([bc6dc5a](https://github.com/rknightion/opnsense-exporter/commit/bc6dc5a0b2487943d59dd8007c3c7f06746b3367))
* **certificates:** CA certificate expiry metrics ([19c634b](https://github.com/rknightion/opnsense-exporter/commit/19c634bf64f5f6f9769b6162b6f99b44e911c97f))
* **chrony:** chrony tracking/source metrics collector (plugin-gated) ([9ba2f75](https://github.com/rknightion/opnsense-exporter/commit/9ba2f754c93bbdb4462d994edeafdffcdfdcec7f))
* **client:** register interfaces overview and unbound dumpinfra endpoints ([b141b10](https://github.com/rknightion/opnsense-exporter/commit/b141b10eb24e72dda05e8c4bd2f9bf93de7cd60f))
* **collector:** export SubsystemDisplayNames and AllCollectors for docgen ([70431b5](https://github.com/rknightion/opnsense-exporter/commit/70431b557f15539174da085a98147a11a9d21bfd))
* **collectors:** freeze stream-C seams (endpoints, subsystem consts) ([c8bb99b](https://github.com/rknightion/opnsense-exporter/commit/c8bb99b1330dac54d407a27231e73b8d2f8e5481))
* **collectors:** freeze stream-D phase-1 seams (endpoints, subsystem consts) ([8b2d1ab](https://github.com/rknightion/opnsense-exporter/commit/8b2d1abb19a866b1a110a8eb4cdceb3d0aa78429))
* **collectors:** freeze stream-D phase-2 seams (endpoints, subsystem consts) ([c432ec7](https://github.com/rknightion/opnsense-exporter/commit/c432ec767a2c3a92e034c05f7eec375b0569c26d))
* **collectors:** freeze stream-D phase-3 seams (endpoints, subsystem consts) ([c8c997e](https://github.com/rknightion/opnsense-exporter/commit/c8c997e12269d592d2f00b4911b4e2ce3df7d7f8))
* **collectors:** opt-in OpenVPN session details, drop IPsec SPI labels, gateways disable flag ([bb60966](https://github.com/rknightion/opnsense-exporter/commit/bb609661f25151af1cf0f150159b7aa9281b83f6))
* **collectors:** wire CrowdSec, NUT, apcupsd and captive portal collectors (phase 2 plugin-gated set) ([a1610bd](https://github.com/rknightion/opnsense-exporter/commit/a1610bdabf19d0ec71ab5bed71b1267487d97459))
* **collectors:** wire HAProxy, nginx, FRR and Monit collectors (phase 1 plugin-gated set) ([da0cd05](https://github.com/rknightion/opnsense-exporter/commit/da0cd05daf308688d77e9150fbeb312224785079))
* **collectors:** wire syslog, qfeeds, tailscale, alias collectors and regenerate docs ([9cf501c](https://github.com/rknightion/opnsense-exporter/commit/9cf501c5b5fb753befc25e2ca5b87d6e2ebf397b))
* **collectors:** wire traffic shaper, HA sync, chrony, DHCPv6 and BPF collectors (phase 3 set) ([de88e48](https://github.com/rknightion/opnsense-exporter/commit/de88e48e8908dab4054de257256244c91b40e88b))
* **contract:** add response-shape canary for payload drift at unchanged endpoints ([2522b21](https://github.com/rknightion/opnsense-exporter/commit/2522b21f7a7e1f2b8507bc5e8bffa34aa90a54c5))
* **crowdsec:** CrowdSec alert/decision/bouncer/machine collector (plugin-gated) ([87280a4](https://github.com/rknightion/opnsense-exporter/commit/87280a4fa09ffdc9773e508f24807f0d31c12a78))
* **dhcp:** pool-size metrics for kea and dnsmasq, kea service status ([d37f733](https://github.com/rknightion/opnsense-exporter/commit/d37f7332dec42fd0d6de750d79d85e75a1c17497))
* **dhcpv6:** ISC DHCPv6 lease and delegated-prefix collector (plugin-gated) ([6309da8](https://github.com/rknightion/opnsense-exporter/commit/6309da8b5f48c57589a2afdfe202725422499304))
* **docgen:** doclint token validation and Describe() registry verification gate ([69b75a1](https://github.com/rknightion/opnsense-exporter/commit/69b75a132b19a4196be3895ac03b5128a774775f))
* **docgen:** marker-region injection and stat-rule engines ([4c47cfa](https://github.com/rknightion/opnsense-exporter/commit/4c47cfa1bce0a6f089553351c57b10f30c85e180))
* **docgen:** render grouped flag tables from the kingpin model ([db2f6c6](https://github.com/rknightion/opnsense-exporter/commit/db2f6c6709a3d60a2c59f9259c2e3b8041bc6bcd))
* **docs:** generate configuration.md flag tables in-place; wire doclint, registry gate and -check mode into docgen ([4f839c5](https://github.com/rknightion/opnsense-exporter/commit/4f839c5dfd6d185bd018a5df1ea98176910998c4))
* **firewall-rules:** configured-rule inventory gauge in details mode ([5c277b6](https://github.com/rknightion/opnsense-exporter/commit/5c277b62a4811e276ec6f59f53360e9747236a50))
* **firmware:** opt-in package_update_available and plugin_installed metrics ([e19cafd](https://github.com/rknightion/opnsense-exporter/commit/e19cafd6a23ebdab9e121a30d31363aa4246b31f))
* **frr:** FRR routing collector — BGP, OSPF and BFD (plugin-gated) ([5cfa890](https://github.com/rknightion/opnsense-exporter/commit/5cfa890cff3ddb3f8afcdb793bb2889618752c88))
* **grafana:** emit dashboard-stats.json for docs count injection ([2b274d9](https://github.com/rknightion/opnsense-exporter/commit/2b274d9eacb74733a4dd9b47e8d21e68081e9043))
* **grafana:** gateway status values 4-6, firmware package detail panels ([ad27d5e](https://github.com/rknightion/opnsense-exporter/commit/ad27d5e9b561a4b4a65c43961a266a6bede92c5d))
* **grafana:** panels for SMART attributes/NVMe, interface identity, unbound infra, rule inventory ([952300f](https://github.com/rknightion/opnsense-exporter/commit/952300f41d5448a092555383ca45164a593e9841))
* **grafana:** per-collector scrape duration and success panels ([b54df15](https://github.com/rknightion/opnsense-exporter/commit/b54df157b66409caf6938a8d1dc0a29b5d4bf134))
* **grafana:** syslog, qfeeds, tailscale and alias tabs; DHCP pool and CA expiry panels ([0203029](https://github.com/rknightion/opnsense-exporter/commit/020302910739798e8fe2e16272dc81bbf07a11ef))
* **haproxy:** HAProxy statistics collector (plugin-gated) ([69c4266](https://github.com/rknightion/opnsense-exporter/commit/69c426623ed4cfd86b109b2ac8ca82dc90f88143))
* **hasync:** opt-in HA sync status collector ([e1fa4f0](https://github.com/rknightion/opnsense-exporter/commit/e1fa4f0604bf482c5212b7914ec9e55b5f18297e))
* **interfaces:** admin_up and info enrichment from interfaces overview ([18df78e](https://github.com/rknightion/opnsense-exporter/commit/18df78e3339b7ea291aedaf2d3da115e51707887))
* **ipsec:** mode-cfg pool utilization metrics ([cc1ce8f](https://github.com/rknightion/opnsense-exporter/commit/cc1ce8f614626bf6ed60ce9b70471973ec3bd895))
* **monit:** Monit service check collector ([ab2cd92](https://github.com/rknightion/opnsense-exporter/commit/ab2cd92a7d9c15b0bc62e8a104d1771973194d1b))
* **nginx:** nginx VTS statistics collector (plugin-gated) ([fc0ab05](https://github.com/rknightion/opnsense-exporter/commit/fc0ab056a008fe748d25778cb3bf96e129327b0b))
* **nut:** NUT UPS metrics collector (plugin-gated) ([3ecb8b0](https://github.com/rknightion/opnsense-exporter/commit/3ecb8b0268b51c9aa6c077cb4307a3f0793040f3))
* **openvpn:** real_address label on opt-in session details (upstream [#97](https://github.com/rknightion/opnsense-exporter/issues/97)) ([b3ef0e8](https://github.com/rknightion/opnsense-exporter/commit/b3ef0e8c5d53d02ba2c884b31fd6baa40661e9b1))
* **opnsense:** add FetchServiceStatusOptional with 404-as-absent semantics ([bbc9ca9](https://github.com/rknightion/opnsense-exporter/commit/bbc9ca914ae1f0f491036fc7b25ee1bbe93dbe54))
* **opnsense:** endpoint contract manifest with HTTP verbs ([664923a](https://github.com/rknightion/opnsense-exporter/commit/664923ad6d88dad2f7575b0d5abcb14948be4754))
* **opnsense:** register core/firmware/info endpoint ([e78c1ce](https://github.com/rknightion/opnsense-exporter/commit/e78c1ce47c46a68f6dcb4295fed8b737dc9b65fd))
* **opnsense:** request-scoped context support via Client.WithContext ([7247845](https://github.com/rknightion/opnsense-exporter/commit/7247845df3f1bcc96d738878cb3febe4e9e812a1))
* **options:** --exporter.enable-firmware-package-details flag and wiring ([699efbf](https://github.com/rknightion/opnsense-exporter/commit/699efbf9c5a931ad4d0c4ab4f761dda84096999d))
* **options:** CollectorFlags metadata + RegisterAllFlags for docgen; fix flag help typos ([8e221d7](https://github.com/rknightion/opnsense-exporter/commit/8e221d7f420b65ea5f8c70fe772936dbf1845d52))
* **otlp:** add OpenTelemetry OTLP metrics export with Prometheus parity ([2e8dda9](https://github.com/rknightion/opnsense-exporter/commit/2e8dda9f146c3708ab16d2f1cb8eb48cf696803a))
* **qfeeds:** Q-Feeds threat-intel collector (plugin-gated) ([7e149bb](https://github.com/rknightion/opnsense-exporter/commit/7e149bb9a1a90b80bd5a7c9b2766522584195873))
* **server:** /-/healthy and /-/ready endpoints, collect[]/exclude[] filtering, scrape-timeout deadline handler ([5e323d3](https://github.com/rknightion/opnsense-exporter/commit/5e323d347e7ab4d559572b18aa449c786bf1b1a6))
* **server:** wire health endpoints, filtered metrics handler and scrape deadline into main ([31fc19f](https://github.com/rknightion/opnsense-exporter/commit/31fc19f9adbba07dcbd8fcb51e3ef2085adb201c))
* **smart:** per-attribute SATA table and NVMe health-log metrics ([3feff7f](https://github.com/rknightion/opnsense-exporter/commit/3feff7f935f772167e40edc512b29a28c580ba15))
* **syslog:** syslog-ng statistics collector ([09c21f9](https://github.com/rknightion/opnsense-exporter/commit/09c21f935f4cd0667eb250b9cda2a2078a6cf398))
* **tailscale:** node-local Tailscale collector, complementary to tailscale2otel ([5cb6512](https://github.com/rknightion/opnsense-exporter/commit/5cb6512a49c846914be5913061ccf7f5e681fa19))
* **tools:** OPNsense API endpoint extractor shim ([2751521](https://github.com/rknightion/opnsense-exporter/commit/27515210da3bdc7f884e1bbcf3e6a18ea3641408))
* **trafficshaper:** pipe/queue/rule statistics collector ([bdcfa5b](https://github.com/rknightion/opnsense-exporter/commit/bdcfa5b6d2f7619bddd0da59242b497c3a4a7e55))
* **unbound:** opt-in infra cache RTT/RTO metrics (--exporter.enable-unbound-infra) ([91ddf9f](https://github.com/rknightion/opnsense-exporter/commit/91ddf9f938cfa8c0e64ca8085998434e53eec2b0))


### Bug Fixes

* **apicontract:** exempt kea leases4/6 (inherited-controller parser blind spot) ([049487a](https://github.com/rknightion/opnsense-exporter/commit/049487a63aff2976ed02123dfe127ba51185cfce))
* **ci:** gate image publish on docs job; doclint also scans CLAUDE.md ([790db7d](https://github.com/rknightion/opnsense-exporter/commit/790db7d7239bdcfb5a171298d059d77d7bd4c1e7))
* **deps:** bump golang.org/x/crypto to v0.52.0 and Go to 1.26.4 ([bafaf29](https://github.com/rknightion/opnsense-exporter/commit/bafaf299c33cfff0464e013452f145739df6fd3d))
* **deps:** update module github.com/prometheus/common to v0.69.0 ([#47](https://github.com/rknightion/opnsense-exporter/issues/47)) ([3dfa4dd](https://github.com/rknightion/opnsense-exporter/commit/3dfa4dd03363e8b11652733dff19a683f4dd1cbe))
* **firmware:** use last_check for validity (upstream [#101](https://github.com/rknightion/opnsense-exporter/issues/101)), parse UnixDate timestamps, add FetchFirmwareInfo ([03afc7c](https://github.com/rknightion/opnsense-exporter/commit/03afc7c0e4e75a25fdffabb60746c071a5e63cc1))
* **gateways:** document status enum 4-6, skip rtt/rttd/loss when probe data unavailable ([4995f0f](https://github.com/rknightion/opnsense-exporter/commit/4995f0f337751aae28060754a0bc3d762b1ad8d2))
* **gateways:** parse Packetloss/Latency/forced-offline statuses, '~' probe values, null force_down (upstream [#103](https://github.com/rknightion/opnsense-exporter/issues/103), [#106](https://github.com/rknightion/opnsense-exporter/issues/106)) ([b249ada](https://github.com/rknightion/opnsense-exporter/commit/b249ada237f6e9ced1a05e93ffdd34997bae21f2))
* harden API drift enrichment workflow ([f892fe9](https://github.com/rknightion/opnsense-exporter/commit/f892fe94a4d6c233b1d436ee0f487efcd951be4d))
* harden API drift enrichment workflow ([740f445](https://github.com/rknightion/opnsense-exporter/commit/740f445078cb9bef9164f832125e5cbb93692a53))
* **health:** parse OPNsense 26.1 status shape; opnsense_up is reachability-only ([6443052](https://github.com/rknightion/opnsense-exporter/commit/644305270e4c6649026d4aa25d603f07c8cc17cd))
* **kea:** tolerate string-typed expire values across OPNsense API variants ([e095d76](https://github.com/rknightion/opnsense-exporter/commit/e095d7633db6b2e1e041b55f5a7113aed2276f7f))
* **opnsense:** align captive portal service-status endpoint name with frozen seam ([654813f](https://github.com/rknightion/opnsense-exporter/commit/654813f1db97abc69f88b1406bc333ed8c0f0c33))
* **opnsense:** migrate string-to-int parsing to int64 for 32-bit safety (upstream [#81](https://github.com/rknightion/opnsense-exporter/issues/81), extended) ([7f58a29](https://github.com/rknightion/opnsense-exporter/commit/7f58a291e2ee2ef16b935d496f4566cc97f560ff))
* **security:** harden HTTP server, API client, and CI workflows ([27bfc19](https://github.com/rknightion/opnsense-exporter/commit/27bfc191159e215ce9fb742b3c2fe47406a395fb))
* **security:** redact CA private keys (prv/prv_payload) in error log excerpts ([6129acb](https://github.com/rknightion/opnsense-exporter/commit/6129acbf022863087a1044fcfe99fc2cc9731cc5))
* **security:** redact credentials in error log excerpts, pin GoReleaser, drop CDN JavaScript ([7b49f2f](https://github.com/rknightion/opnsense-exporter/commit/7b49f2ff3c785270797df1d354f65aee56ba8602))
* **security:** set TLS 1.2 minimum and run container as non-root ([d19fdd7](https://github.com/rknightion/opnsense-exporter/commit/d19fdd7c0229bead9399bd0272a54cc1e491c7e6))


### Refactoring

* **collector:** thread context through CollectorInstance.Update, add per-collector scrape metrics and ScrapeView filtering ([1814ef5](https://github.com/rknightion/opnsense-exporter/commit/1814ef523e59b723c4a50b52406772b143747998))
* **docgen:** source flag and display-name metadata from code via kingpin model ([5ced3ce](https://github.com/rknightion/opnsense-exporter/commit/5ced3ce627c7b05f385e7b569f03c372d36c94f8))
* **opnsense:** extract defaultEndpoints() for contract tooling ([ca0a84c](https://github.com/rknightion/opnsense-exporter/commit/ca0a84cae0da221737781b97997500fc55d9e3b1))


### Miscellaneous

* **codacy:** exclude fixtures/scratch from analysis and drop unused import ([0c7fc40](https://github.com/rknightion/opnsense-exporter/commit/0c7fc4080243988a5cabc2d28e9e49dc80432dfb))
* **deps:** pin rknightion/.github action to 8629ccb ([#54](https://github.com/rknightion/opnsense-exporter/issues/54)) ([0074388](https://github.com/rknightion/opnsense-exporter/commit/0074388edd1bb2253fb9ffdfefc43e1de2247354))
* **deps:** update actions/checkout action to v6.0.3 ([#50](https://github.com/rknightion/opnsense-exporter/issues/50)) ([88b7eb7](https://github.com/rknightion/opnsense-exporter/commit/88b7eb71d348bfcb84522a43f87c83fac5801be1))
* **deps:** update anthropics/claude-code-action action to v1.0.158 ([#49](https://github.com/rknightion/opnsense-exporter/issues/49)) ([d402091](https://github.com/rknightion/opnsense-exporter/commit/d402091ef1c5e9400890f6ad6d8998cdfb760599))
* **deps:** update anthropics/claude-code-action action to v1.0.159 ([#52](https://github.com/rknightion/opnsense-exporter/issues/52)) ([e6a7117](https://github.com/rknightion/opnsense-exporter/commit/e6a71172aa5e6c4dddba9aecbbf66a7e0d2f17db))
* **deps:** update gcr.io/distroless/static-debian13:nonroot docker digest to 963fa6c ([#53](https://github.com/rknightion/opnsense-exporter/issues/53)) ([287c936](https://github.com/rknightion/opnsense-exporter/commit/287c93649c7233b666ff31f38579a50303ecec50))
* **deps:** update github actions ([#46](https://github.com/rknightion/opnsense-exporter/issues/46)) ([11b8436](https://github.com/rknightion/opnsense-exporter/commit/11b84364e8f3b8042e967fba86585d39b7ca2bab))
* **deps:** update github actions ([#48](https://github.com/rknightion/opnsense-exporter/issues/48)) ([11922e8](https://github.com/rknightion/opnsense-exporter/commit/11922e8deb5b9e9008292b277a05ce9ef3bd8206))
* **deps:** update github actions ([#51](https://github.com/rknightion/opnsense-exporter/issues/51)) ([05ea078](https://github.com/rknightion/opnsense-exporter/commit/05ea07869e280480bf8c060c7e99a2d919aaab5f))
* **deps:** update rknightion/.github digest to 0e80ff5 ([#56](https://github.com/rknightion/opnsense-exporter/issues/56)) ([a77b9c2](https://github.com/rknightion/opnsense-exporter/commit/a77b9c2dce16023f8f376c64a03016b386b59c8b))
* **deps:** update rknightion/.github digest to 17626c1 ([#55](https://github.com/rknightion/opnsense-exporter/issues/55)) ([daa4910](https://github.com/rknightion/opnsense-exporter/commit/daa4910fcd59f5b2940055ba5c258a4e5ac04263))
* gitignore local roadmap.md ([7ec2842](https://github.com/rknightion/opnsense-exporter/commit/7ec28428f24db7d0391bbe16a7e516c43d719e90))
* **renovate:** slim to repo-specific overrides ([1dcb6a3](https://github.com/rknightion/opnsense-exporter/commit/1dcb6a372e374bbd6f1447a517ce43e6c059a178))
* resolve Codacy quality findings and tune doc linting ([9793e91](https://github.com/rknightion/opnsense-exporter/commit/9793e914ff93355ab0ad7f9a25b34e8bb81eb341))
* **security:** add Snyk policy excluding vendor + offline dev tooling ([e35a9c0](https://github.com/rknightion/opnsense-exporter/commit/e35a9c089007183c8a1449806bcfdf8f11cc4dfc))


### Documentation

* **codacy:** note that path excludes also gate default-on tools ([a7b53d2](https://github.com/rknightion/opnsense-exporter/commit/a7b53d2b05c584d184d5882daa59608db77bb2b7))
* **dev:** document generated-docs workflow, drop fork-changelog convention ([9eff6d4](https://github.com/rknightion/opnsense-exporter/commit/9eff6d4b093558d0911b4cdbec01f5edf6168504))
* note contract manifest step when adding a collector ([540c501](https://github.com/rknightion/opnsense-exporter/commit/540c501fcaf9950b8f0a192e8d59b25c38d61887))
* pin metric/collector/dashboard counts via docgen stat rules (305/30/16) ([6673cea](https://github.com/rknightion/opnsense-exporter/commit/6673cea9a03aa72f830099aa6babfc1e08eacec3))
* **readme:** thin README — hard-fork notice replaces upstream changelog, docs site is canonical ([56aec9c](https://github.com/rknightion/opnsense-exporter/commit/56aec9c01194a0974acaefffe25fa4d1dafafc6e))
* regenerate for gateway status enum 4-6 and firmware package details flag ([9c18429](https://github.com/rknightion/opnsense-exporter/commit/9c1842927fe339c9fa4a7398216e1205f7c44f8d))
* regenerate for per-collector scrape metrics and scrape-timeout-offset flag ([1c0baba](https://github.com/rknightion/opnsense-exporter/commit/1c0baba3c420131f065e5bc174264ccc68f569bb))
* regenerate for stream E collector enhancements ([0803709](https://github.com/rknightion/opnsense-exporter/commit/0803709f26e8c80a85975e426644c857cb2d3e27))
* **site:** add troubleshooting and upgrading pages, promote security in nav, custom-CA example ([033068b](https://github.com/rknightion/opnsense-exporter/commit/033068b2c7cd9eb53bedaccd6bf5e46292664cea))


### Tests

* **dhcp:** pool helper unit tests ([7905998](https://github.com/rknightion/opnsense-exporter/commit/790599833a80b619a197185dbccbae2813257c9f))


### CI/CD

* add Claude issue-triage workflow ([42e64c7](https://github.com/rknightion/opnsense-exporter/commit/42e64c7a23b057e12c462ef7af377333dc521dcd))
* add hadolint + trivy Docker security scans ([bcda939](https://github.com/rknightion/opnsense-exporter/commit/bcda939d6af2911a82c7e2c4c5b8b71fff1b5974))
* adopt shared rknightion/.github reusable security workflows ([6c309b3](https://github.com/rknightion/opnsense-exporter/commit/6c309b3463a764d67adf3b0efe904d1ae1fef72c))
* auto-assign maintainer on new issues (notify by email) ([0f8197c](https://github.com/rknightion/opnsense-exporter/commit/0f8197cf150eaeaa9996480e26488365440fac40))
* fail the build when generated docs drift from code ([e73c073](https://github.com/rknightion/opnsense-exporter/commit/e73c07309b7047997a308c9fc9d0f85c6e1d1511))
* fix Renovate automerge stall + add required ci-success gate ([a94ed62](https://github.com/rknightion/opnsense-exporter/commit/a94ed62e37ebfe53a9ac8be417b807ed24984b0e))
* harden GitHub Actions workflows (zizmor) ([1349dc4](https://github.com/rknightion/opnsense-exporter/commit/1349dc4eab722cf61b98364517504b2fc1fe2019))
* hybrid issue-triage (no-tools AI analysis + deterministic apply) ([93cba4a](https://github.com/rknightion/opnsense-exporter/commit/93cba4ad3a5624a9ac056d98d3197d018131ada7))
* OPNsense API contract canary + Claude enrichment workflows ([689cd4f](https://github.com/rknightion/opnsense-exporter/commit/689cd4f4aac748318d9e26b4605ba3e227e76bd6))
* reference rknightion/.github reusables [@main](https://github.com/main) (unpin from digest) ([f2c44d4](https://github.com/rknightion/opnsense-exporter/commit/f2c44d4be8c459bbb900810ad3d9020450c777c3))
* report coverage to Codacy and ship SBOMs + third-party notices ([7ea83cb](https://github.com/rknightion/opnsense-exporter/commit/7ea83cb38ae232b70b80b98e7c0e05b92e413d53))
* resolve actionlint/shellcheck + zizmor workflow findings ([ceab80f](https://github.com/rknightion/opnsense-exporter/commit/ceab80f07247c1f9f09d0d4e20ec811071e63fe7))
* **security:** drop unused id-token: write from issue-triage ([65deb99](https://github.com/rknightion/opnsense-exporter/commit/65deb991227ec2feb324883a1338fd23204429fd))
* **security:** replace LLM issue-triage with deterministic labeler ([48acd41](https://github.com/rknightion/opnsense-exporter/commit/48acd41d7dadbf71ce7ae365d9395d69ba0312ee))

## [0.4.0](https://github.com/rknightion/opnsense-exporter/compare/v0.3.0...v0.4.0) (2026-06-09)


### Features

* **options:** add pyroscope profiling configuration ([061d893](https://github.com/rknightion/opnsense-exporter/commit/061d89334cd0b4c557b97930aabd59c40085023d))
* **profiling:** add pyroscope SDK integration package ([df888e5](https://github.com/rknightion/opnsense-exporter/commit/df888e53e72e46834ce403d69c313ec4988860e5))
* push profiles to pyroscope and drop unauthenticated pprof endpoints ([99577df](https://github.com/rknightion/opnsense-exporter/commit/99577df7ad47289f930eb5e7bab32040a0ee625b))


### Documentation

* document pyroscope profiling and pprof removal ([16e6f84](https://github.com/rknightion/opnsense-exporter/commit/16e6f843d7dd515ea197419fafd0efe8e5955333))
* remove stale pprof references from architecture and index ([a047bd6](https://github.com/rknightion/opnsense-exporter/commit/a047bd6a72f1a30e4c08ce475254b71cd49a912d))


### Build & Infrastructure

* tidy vendor after pyroscope integration ([78486ef](https://github.com/rknightion/opnsense-exporter/commit/78486ef3900c114e5a4dba8fe6c7abd0caae41fb))

## [0.3.0](https://github.com/rknightion/opnsense-exporter/compare/v0.2.2...v0.3.0) (2026-06-08)


### Features

* **collector:** add DHCPv4, ACME and SMART disk collectors ([83b0a8e](https://github.com/rknightion/opnsense-exporter/commit/83b0a8ebb930aadfc6a07ef4047714de87c2f4a5))
* **collector:** add DynDNS (ddclient) account status collector ([da5216e](https://github.com/rknightion/opnsense-exporter/commit/da5216e5c2b6aee0bf72cf19b676b1311f9cfc35))
* **collector:** add exporter build and collector-enabled self-observability metrics ([ca82ebb](https://github.com/rknightion/opnsense-exporter/commit/ca82ebb6ca31e7215791363db56e2053016f84db))
* **collector:** export crash-reporter health status ([58c838d](https://github.com/rknightion/opnsense-exporter/commit/58c838db623f914b70e2364d696536547a1630e8))
* default instance label to the OPNsense hostname ([f49855b](https://github.com/rknightion/opnsense-exporter/commit/f49855be734e584aadc0c4b406a1aea0f53b6dfa))
* **gateways:** export force_down, virtual, dynamic and priority metrics ([d48d484](https://github.com/rknightion/opnsense-exporter/commit/d48d484bec636aa92824542e3421fed0ec2b5efe))
* **grafana:** comprehensive v2 dynamic dashboard with alerts and recording rules ([81d36dd](https://github.com/rknightion/opnsense-exporter/commit/81d36dd43852e907b7a690f52cd8c82bf3556eed))
* **smart:** enable collector by default and degrade gracefully when absent ([7c49635](https://github.com/rknightion/opnsense-exporter/commit/7c49635949ef9005dacdc1b275168c0f5d26b23e))
* **wireguard:** add peer handshake-age gauge and fix last-handshake type ([b1f68b1](https://github.com/rknightion/opnsense-exporter/commit/b1f68b12c52dc5b439e9cbbfe6cebde72c5bf63f))


### Bug Fixes

* **client:** close response body to prevent gzip connection leak ([2182b99](https://github.com/rknightion/opnsense-exporter/commit/2182b9919311f202bde8dcd2d744002acc8f3ad9))
* **collector:** recover from panics in sub-collector goroutines ([12fa832](https://github.com/rknightion/opnsense-exporter/commit/12fa832ca757a91487caa62f765123e606dfc50b))
* **health:** stop reporting a healthy firewall as unhealthy on OPNsense 25.1+ ([f292a50](https://github.com/rknightion/opnsense-exporter/commit/f292a50207e752fadfd86ee5daf9a7de2cba0bfa))
* **ntp:** avoid narrowing int conversion of NTP reach value ([02b687a](https://github.com/rknightion/opnsense-exporter/commit/02b687a568aa9e88da85b78e251d4642ea202578))
* **opnsense:** correct seven API-shape mismatches found in OPNsense 26.1 audit ([baf14f0](https://github.com/rknightion/opnsense-exporter/commit/baf14f0d47302bb1a34a895fb27a6a4028ae54dc))
* **startup:** bound the instance-label hostname lookup with a short timeout ([258205c](https://github.com/rknightion/opnsense-exporter/commit/258205c81d3a0f6a180f0b9f592a75116596dedd))
* **system:** correct uptime/config-change skew in non-UTC timezones ([9d561e5](https://github.com/rknightion/opnsense-exporter/commit/9d561e57ae84a3c5dd6f4503bd3f2638e1050184))


### Documentation

* align documentation with code reality ([721305a](https://github.com/rknightion/opnsense-exporter/commit/721305a3f7d6c88822329c4b337d77df4f7f2e1c))
* **claude:** note the dashboard coverage gate in the add-a-collector flow ([532c636](https://github.com/rknightion/opnsense-exporter/commit/532c63656c7967a427eadaf8769dcf1b8dd4d4da))
* **claude:** require docgen + doc-table updates when adding a collector ([8078c80](https://github.com/rknightion/opnsense-exporter/commit/8078c8034eddcd18dbe62b9df991d0838737fa9d))
* document new collector flags and regenerate generated docs ([1674ba7](https://github.com/rknightion/opnsense-exporter/commit/1674ba752a02952d435664f2d369e0d943c10116))
* **readme:** update fork changelog for new collectors, enhancements and fixes ([5682bda](https://github.com/rknightion/opnsense-exporter/commit/5682bdad34fb7e3aa0183a0565fb1b2e71fb6260))


### CI/CD

* pull Go build image from mirror.gcr.io to drop Docker Hub dependency ([23069fb](https://github.com/rknightion/opnsense-exporter/commit/23069fbf70e9cfb23e1461a3447aa9c76ad13550))

## [0.2.2](https://github.com/rknightion/opnsense-exporter/compare/v0.2.1...v0.2.2) (2026-06-08)


### Bug Fixes

* **collectors:** tolerate OPNsense 25.7 API model drift ([0e6b9bc](https://github.com/rknightion/opnsense-exporter/commit/0e6b9bc3cc276fc6f0438a6ff4d2ce2d0908ed8d))
* **deps:** update module github.com/grafana/pyroscope-go/godeltaprof to v0.1.10 ([#38](https://github.com/rknightion/opnsense-exporter/issues/38)) ([8bc67f1](https://github.com/rknightion/opnsense-exporter/commit/8bc67f1600bfa34e078eaf881ac7b73b0722836d))
* **deps:** update module github.com/grafana/pyroscope-go/godeltaprof to v0.1.11 ([#41](https://github.com/rknightion/opnsense-exporter/issues/41)) ([fb21d9f](https://github.com/rknightion/opnsense-exporter/commit/fb21d9fe412ee97b3cabf9bf0c095cf7c3e1efa3))
* **deps:** update module github.com/prometheus/exporter-toolkit to v0.16.0 ([#30](https://github.com/rknightion/opnsense-exporter/issues/30)) ([9c0094e](https://github.com/rknightion/opnsense-exporter/commit/9c0094e3f2abcc2e8f606c23b9c2beca50d70285))
* **docs:** remove glightbox slide_effect option (rejected by zensical 0.0.44) ([42a31e6](https://github.com/rknightion/opnsense-exporter/commit/42a31e6bec0bf453a39afd790027199abfef4ca9))


### Miscellaneous

* automerge Renovate vulnerability-fix PRs ([d3b0977](https://github.com/rknightion/opnsense-exporter/commit/d3b0977d9b5c41ddad08d0756b96a6c7c8783faa))
* **deps:** update actions/setup-go digest to 4a36011 ([#28](https://github.com/rknightion/opnsense-exporter/issues/28)) ([9d094ca](https://github.com/rknightion/opnsense-exporter/commit/9d094ca9e8478a20f887b5e406473c9d8f7f5309))
* **deps:** update actions/upload-artifact digest to 043fb46 ([#32](https://github.com/rknightion/opnsense-exporter/issues/32)) ([d0f2ae2](https://github.com/rknightion/opnsense-exporter/commit/d0f2ae24c0182f574d506ead6c7b5a32661defb9))
* **deps:** update docker/build-push-action digest to bcafcac ([#31](https://github.com/rknightion/opnsense-exporter/issues/31)) ([02232b6](https://github.com/rknightion/opnsense-exporter/commit/02232b6c9004c7900a6a572cb48ae877fd494809))
* **deps:** update docker/login-action digest to 4907a6d ([#29](https://github.com/rknightion/opnsense-exporter/issues/29)) ([8b4ff11](https://github.com/rknightion/opnsense-exporter/commit/8b4ff11568f29099e4ff72834331eaf7c1cb3fbd))
* **deps:** update github actions ([#34](https://github.com/rknightion/opnsense-exporter/issues/34)) ([06fc36e](https://github.com/rknightion/opnsense-exporter/commit/06fc36e50d58c7e5bb4d0e8d881da20f881163c7))
* **deps:** update github/codeql-action digest to 3869755 ([#25](https://github.com/rknightion/opnsense-exporter/issues/25)) ([d196062](https://github.com/rknightion/opnsense-exporter/commit/d1960623297ea8b29d2f8fb2458be9d793dd56b2))
* **deps:** update github/codeql-action digest to 68bde55 ([#39](https://github.com/rknightion/opnsense-exporter/issues/39)) ([fdf085c](https://github.com/rknightion/opnsense-exporter/commit/fdf085c907ee3ee96cad22314861be782b991d67))
* **deps:** update github/codeql-action digest to b8bb9f2 ([#26](https://github.com/rknightion/opnsense-exporter/issues/26)) ([d7ba908](https://github.com/rknightion/opnsense-exporter/commit/d7ba9085645f5644e8c38406d0444695fdb05da4))
* **deps:** update github/codeql-action digest to c10b806 ([#27](https://github.com/rknightion/opnsense-exporter/issues/27)) ([7f9164a](https://github.com/rknightion/opnsense-exporter/commit/7f9164a11a48348dc430d3a0bf17417ef7164159))
* **deps:** update github/codeql-action digest to c6f9311 ([#23](https://github.com/rknightion/opnsense-exporter/issues/23)) ([5ed9dbe](https://github.com/rknightion/opnsense-exporter/commit/5ed9dbe1ad72f8c2d808657518271443c2e460fe))
* **deps:** update github/codeql-action digest to e46ed2c ([#37](https://github.com/rknightion/opnsense-exporter/issues/37)) ([60ecb55](https://github.com/rknightion/opnsense-exporter/commit/60ecb552b95fdee7ddd1c558f6bf3103eb6ae88e))
* **deps:** update googleapis/release-please-action action to v5 ([#35](https://github.com/rknightion/opnsense-exporter/issues/35)) ([9f57415](https://github.com/rknightion/opnsense-exporter/commit/9f574156123e3332abb4b28232ba09ebf3e9f066))
* **deps:** update googleapis/release-please-action digest to 5c625bf ([#33](https://github.com/rknightion/opnsense-exporter/issues/33)) ([2b9008e](https://github.com/rknightion/opnsense-exporter/commit/2b9008e4d169265a7b5a764eeedec55ca5f1de44))
* **deps:** update goreleaser/goreleaser-action digest to 1a80836 ([#36](https://github.com/rknightion/opnsense-exporter/issues/36)) ([21925be](https://github.com/rknightion/opnsense-exporter/commit/21925be280c8322f448199174874fb961c78bd8c))

## [0.2.1](https://github.com/rknightion/opnsense-exporter/compare/v0.2.0...v0.2.1) (2026-03-16)


### Miscellaneous

* **deps:** update gcr.io/distroless/static-debian13:nonroot docker digest to e3f9456 ([#20](https://github.com/rknightion/opnsense-exporter/issues/20)) ([a542a93](https://github.com/rknightion/opnsense-exporter/commit/a542a93a8759d7a3e9b843e03f145d43cdde767c))
* **deps:** update github/codeql-action digest to b1bff81 ([#21](https://github.com/rknightion/opnsense-exporter/issues/21)) ([3378bb1](https://github.com/rknightion/opnsense-exporter/commit/3378bb1fce54983dec72d6d00faa327f7cb6e25a))
* replace old Grafana dashboard with comprehensive v2 dashboard ([da5a351](https://github.com/rknightion/opnsense-exporter/commit/da5a35183f12b659478ef9aefd34d170e5982a62))

## [0.2.0](https://github.com/rknightion/opnsense-exporter/compare/v0.1.0...v0.2.0) (2026-03-14)


### Features

* **client:** add new API endpoints for enhanced collectors ([6c6cde9](https://github.com/rknightion/opnsense-exporter/commit/6c6cde9d56b936ff3763ad186a8961812793e29d))
* **collectors:** add NDP collector for IPv6 neighbor discovery table ([2a2dffe](https://github.com/rknightion/opnsense-exporter/commit/2a2dffe542657c3b09cc426bd37fdebb406a96cc))
* **collectors:** add PF statistics deep dive collector ([28ec3d6](https://github.com/rknightion/opnsense-exporter/commit/28ec3d64c387eb2592389969360a0af37a3c19f7))
* **collectors:** enhance firewall collector with per-interface hit counters ([499eb01](https://github.com/rknightion/opnsense-exporter/commit/499eb016685c638b9a31a7209ef83164eee05de8))
* **collectors:** enhance mbuf collector with additional memory statistics ([cb78df6](https://github.com/rknightion/opnsense-exporter/commit/cb78df6df8af670baf4ace4008b25e31f2d19407))
* **collectors:** enhance network diagnostics collector with pfsync HA metrics ([a03b23d](https://github.com/rknightion/opnsense-exporter/commit/a03b23d7bdafd68be9b6a4068a8d9a7a1eccade9))
* **collectors:** enhance system collector with detailed system information ([b123643](https://github.com/rknightion/opnsense-exporter/commit/b123643a17b6c701eb0105e3f6bb4004695b2737))
* **netflow:** add configuration options and CLI flags ([546ccfe](https://github.com/rknightion/opnsense-exporter/commit/546ccfeff092b4417960961d53e800eed2814b7e))
* **netflow:** add NetFlow collector implementation ([63e5154](https://github.com/rknightion/opnsense-exporter/commit/63e51540cc923b11e819a101a60b5204905b1a95))


### Bug Fixes

* add markdown attribute to hero-badges div ([fb6884f](https://github.com/rknightion/opnsense-exporter/commit/fb6884f8fc446955a16769318b32fd511377d735))
* use direct type conversion to satisfy staticcheck S1016 ([2964580](https://github.com/rknightion/opnsense-exporter/commit/29645809a3377e2dce44acc3de5b846a40bf2444))


### Refactoring

* **docgen:** replace if-else chain with switch statement for metric parsing ([65d7dd4](https://github.com/rknightion/opnsense-exporter/commit/65d7dd436525b2962272566a81b6df26266a55f6))
* remove GOMAXPROCS configuration option ([190bd1e](https://github.com/rknightion/opnsense-exporter/commit/190bd1e4ea4bc91f978774ce720156810ee2597d))


### Miscellaneous

* **deps:** pin dependencies ([#5](https://github.com/rknightion/opnsense-exporter/issues/5)) ([f28c389](https://github.com/rknightion/opnsense-exporter/commit/f28c389d3bd8ded5428118edbe300c1d177ef021))
* **deps:** update actions/checkout action to v6 ([#10](https://github.com/rknightion/opnsense-exporter/issues/10)) ([e2493c8](https://github.com/rknightion/opnsense-exporter/commit/e2493c883c01dc13cd10be264e5b56c927772df1))
* **deps:** update actions/download-artifact digest to 3e5f45b ([#6](https://github.com/rknightion/opnsense-exporter/issues/6)) ([98e119d](https://github.com/rknightion/opnsense-exporter/commit/98e119d8ab951db90efe6b39e85a88d78d43bbad))
* **deps:** update actions/setup-go action to v6 ([#11](https://github.com/rknightion/opnsense-exporter/issues/11)) ([9d83482](https://github.com/rknightion/opnsense-exporter/commit/9d83482616498604a6a101d82b3192ab64baba50))
* **deps:** update actions/setup-go digest to 40f1582 ([#8](https://github.com/rknightion/opnsense-exporter/issues/8)) ([5f1a7a5](https://github.com/rknightion/opnsense-exporter/commit/5f1a7a53dd3c217e2705b84d899dba68f6f6860f))
* **deps:** update docker/build-push-action action to v7 ([#12](https://github.com/rknightion/opnsense-exporter/issues/12)) ([733c911](https://github.com/rknightion/opnsense-exporter/commit/733c911220c3f9b5627fb8df6f28bd30b698ec3b))
* **deps:** update docker/login-action action to v4 ([#13](https://github.com/rknightion/opnsense-exporter/issues/13)) ([89b8997](https://github.com/rknightion/opnsense-exporter/commit/89b8997d43a158610f86b03ae2b42ef507676425))
* **deps:** update docker/metadata-action action to v6 ([#14](https://github.com/rknightion/opnsense-exporter/issues/14)) ([3adce41](https://github.com/rknightion/opnsense-exporter/commit/3adce419c40a39cc8d4642f72b7fa223fc0b6cdb))
* **deps:** update docker/setup-buildx-action action to v4 ([#15](https://github.com/rknightion/opnsense-exporter/issues/15)) ([a2a0a05](https://github.com/rknightion/opnsense-exporter/commit/a2a0a05d38469f8d7abb29fcdab1093e8ac233f8))
* **deps:** update github/codeql-action action to v4 ([#16](https://github.com/rknightion/opnsense-exporter/issues/16)) ([da86204](https://github.com/rknightion/opnsense-exporter/commit/da86204df7e81e052d5cea29f5f311ca7d48c4b1))
* **deps:** update golangci/golangci-lint-action action to v9 ([#17](https://github.com/rknightion/opnsense-exporter/issues/17)) ([21b76d0](https://github.com/rknightion/opnsense-exporter/commit/21b76d0ce78db50aa2db592db894c98ca87ecf02))
* **deps:** update goreleaser/goreleaser-action action to v7 ([#18](https://github.com/rknightion/opnsense-exporter/issues/18)) ([647277e](https://github.com/rknightion/opnsense-exporter/commit/647277e2d6d2e2f0f3f1eb844655c026436c9823))
* **deps:** update goreleaser/goreleaser-action digest to e435ccd ([#9](https://github.com/rknightion/opnsense-exporter/issues/9)) ([494a4cc](https://github.com/rknightion/opnsense-exporter/commit/494a4cc6edf0fcf74180bda28f908d540ecf92c9))


### Documentation

* add auto-generated collector reference and update metrics documentation structure ([d41b180](https://github.com/rknightion/opnsense-exporter/commit/d41b18059c4ab912fde3dc371c0dde8c218d00cd))
* add comprehensive documentation infrastructure with automated generation ([e519f1a](https://github.com/rknightion/opnsense-exporter/commit/e519f1a747e1453ac2c1fdb05f77025199ba6a85))
* add comprehensive documentation infrastructure with mkdocs ([3854de8](https://github.com/rknightion/opnsense-exporter/commit/3854de87476fb3d63f13c3bbe2ea08858dac4ca8))
* reorganize completed TODOs and expand remaining tasks ([0b942d0](https://github.com/rknightion/opnsense-exporter/commit/0b942d07aa51bbd50b1da259f5d8ca9719b8cb26))
* restructure and expand metrics documentation ([bf1d7a0](https://github.com/rknightion/opnsense-exporter/commit/bf1d7a06402a20a59330915a6e10b91b0b0dbf06))
* update README and metrics documentation for NetFlow collector ([3cb4185](https://github.com/rknightion/opnsense-exporter/commit/3cb418596b4380ca18193de4db75faa8851e31e4))
* update README with new collector descriptions ([45feac4](https://github.com/rknightion/opnsense-exporter/commit/45feac49d981637b8ddc1283207eaca06ccaf7b3))
* update todos with completed implementation status ([b2aa505](https://github.com/rknightion/opnsense-exporter/commit/b2aa5059064733cfe9a1d4bf207202418cd34a4a))


### CI/CD

* restrict docs sync trigger to docs-related path changes ([746c084](https://github.com/rknightion/opnsense-exporter/commit/746c084123eeaa5726c4f9cdfa4f3b201ba82203))
* trigger PR checks for branch protection ([5b9d965](https://github.com/rknightion/opnsense-exporter/commit/5b9d9652f17258cf29c7dc13832219da5c156b48))
* trigger PR checks for branch protection setup ([5a49761](https://github.com/rknightion/opnsense-exporter/commit/5a49761f7affcbc2b6130f678c294185f09ff196))

## [0.1.0](https://github.com/rknightion/opnsense-exporter/compare/v0.0.13...v0.1.0) (2026-03-03)


### Features

* **activity:** add system activity collector ([7f1893c](https://github.com/rknightion/opnsense-exporter/commit/7f1893c9abbd1f2c28e38e8f0fdb6fd659ebeeed))
* add certificate expiry collector ([acd8503](https://github.com/rknightion/opnsense-exporter/commit/acd8503ff0585c6b509d6abea9d5e5efe250a425))
* add CLI flags for new collectors ([dfd501f](https://github.com/rknightion/opnsense-exporter/commit/dfd501f83d19434b87033165beed75096b5811a7))
* add collector configuration options ([c2dbe10](https://github.com/rknightion/opnsense-exporter/commit/c2dbe106dc9b064e1259c4b3794ad2a054e11c68))
* Add default_gateway label to status metric ([#54](https://github.com/rknightion/opnsense-exporter/issues/54)) ([5010f43](https://github.com/rknightion/opnsense-exporter/commit/5010f43223054d5c02cb5252ffb0d25627d343c1))
* add dnsmasq DHCP lease collector with configuration options ([a838de2](https://github.com/rknightion/opnsense-exporter/commit/a838de243f038239ceebc3ca1d7a73bb8377654c))
* add firewall rules statistics collector ([9b173c9](https://github.com/rknightion/opnsense-exporter/commit/9b173c90f5051d708b17c7f47527c98a67b17720))
* Add ipsec_phase1_status ([#71](https://github.com/rknightion/opnsense-exporter/issues/71)) ([260b70a](https://github.com/rknightion/opnsense-exporter/commit/260b70a9b1829cbdd3984242a674060e573469d9))
* add mbuf statistics collector ([6b344a1](https://github.com/rknightion/opnsense-exporter/commit/6b344a1fbd41e0c6bf20f06a515becd13bcc57ea))
* add more ipsec phase1/phase2 metrics ([#86](https://github.com/rknightion/opnsense-exporter/issues/86)) ([5a2621d](https://github.com/rknightion/opnsense-exporter/commit/5a2621df8d544b1c790dfdf42e4b2f8ef2ea9a32))
* add NTP status collector ([1c19562](https://github.com/rknightion/opnsense-exporter/commit/1c195628bb34606cf2d38ebf5c59a188759ffd1d))
* add profiling support with pprof and godeltaprof ([278334d](https://github.com/rknightion/opnsense-exporter/commit/278334d13e570856b7157c4dd4583ec7de2972b6))
* add system resources collector ([68c02fa](https://github.com/rknightion/opnsense-exporter/commit/68c02faf4fe7824e4243d512b1153dacef71720e))
* add system status code to health metrics ([8a833da](https://github.com/rknightion/opnsense-exporter/commit/8a833da397315edb70717db0ce4329bd7ba75bf6))
* add temperature collector ([76515a3](https://github.com/rknightion/opnsense-exporter/commit/76515a3d7dcf4f1deac7809b90506dc4183e6d6b))
* **carp:** add CARP/VIP status collector ([c8280f3](https://github.com/rknightion/opnsense-exporter/commit/c8280f3fa511200e5363f12bf504d4b960043393))
* **client:** add new collector endpoints ([651d11d](https://github.com/rknightion/opnsense-exporter/commit/651d11dedd4f2fd98a770f7d9618d786bd6ef4d4))
* Collect more gateway information ([#50](https://github.com/rknightion/opnsense-exporter/issues/50)) ([fcdd2d6](https://github.com/rknightion/opnsense-exporter/commit/fcdd2d620ecb111398ac73cc3665a7aafa60121e))
* **collector:** add network diagnostics collector with netisr, socket, and route metrics ([bab3bf0](https://github.com/rknightion/opnsense-exporter/commit/bab3bf0856c5245202e635fa3bddc250c633d9d8))
* **collector:** add service running metrics to network service collectors ([d8bc04f](https://github.com/rknightion/opnsense-exporter/commit/d8bc04fe1c1b181b28d465fbeec631c017f54d72))
* **collector:** integrate new collectors ([7837e97](https://github.com/rknightion/opnsense-exporter/commit/7837e977f1908143a1d7c94c976f8853f2d4ea60))
* **docs:** opnsense permissions ([#40](https://github.com/rknightion/opnsense-exporter/issues/40)) ([bc6ff67](https://github.com/rknightion/opnsense-exporter/commit/bc6ff67ee068d094ada6e5c985da1e101b6c231f))
* **docs:** update README to reflect new collector structure and options ([ee547ca](https://github.com/rknightion/opnsense-exporter/commit/ee547caee802faee83937a090719dd222c3133c3))
* enhance firewall collector with bytes and states ([05551da](https://github.com/rknightion/opnsense-exporter/commit/05551da96a56e3f64a3103dff29a10e89051c531))
* enhance protocol statistics collector with comprehensive network protocol metrics ([271fca8](https://github.com/rknightion/opnsense-exporter/commit/271fca83ddee45f49c3fa47ddba15da8c54ce312))
* enhance unbound DNS collector with comprehensive metrics ([02748e5](https://github.com/rknightion/opnsense-exporter/commit/02748e57afed895ff71bdaa951b7e6c12f76ad74))
* enhance unbound DNS with additional metrics ([8f0d1b8](https://github.com/rknightion/opnsense-exporter/commit/8f0d1b842f6d3145e249f4305bf74fa0bf10b583))
* expand interfaces collector with additional network metrics ([f876193](https://github.com/rknightion/opnsense-exporter/commit/f876193cdb06e0f057ce03a6e684f8cb75472b4d))
* expand protocol statistics metrics ([642fa1c](https://github.com/rknightion/opnsense-exporter/commit/642fa1ce1000042d9b4f3b5b4151b096645768d1))
* **kea:** add Kea DHCP lease collector ([76a2194](https://github.com/rknightion/opnsense-exporter/commit/76a21941e03fa6927f107f69645f4c8aa8658814))
* **main:** wire new collector options ([e8213f1](https://github.com/rknightion/opnsense-exporter/commit/e8213f1dd377dcfb268c379831c1f09f92411852))
* **opnsense:** implement network diagnostics API clients ([ed93071](https://github.com/rknightion/opnsense-exporter/commit/ed930717e6e4e045c30de24888fa2dd6f69ac627))
* **options:** add collector configuration flags ([800c443](https://github.com/rknightion/opnsense-exporter/commit/800c443e52c0a67c1d6a2b876f613c338cf7e526))
* register new API endpoints in client ([3e5faf7](https://github.com/rknightion/opnsense-exporter/commit/3e5faf759f6dd32ce8fdcf38097421de76fcc08f))
* wire new collectors into main application ([962dfd5](https://github.com/rknightion/opnsense-exporter/commit/962dfd5b630808969b351f1911a7bb71e9e077b2))


### Bug Fixes

* allow opnsense http client to handle gzip responses ([#2](https://github.com/rknightion/opnsense-exporter/issues/2)) ([395aca9](https://github.com/rknightion/opnsense-exporter/commit/395aca97b149ddbae96667b471d54d18f8540b4a))
* Change Docker CMD for ENTRYPOINT ([#11](https://github.com/rknightion/opnsense-exporter/issues/11)) ([4c83613](https://github.com/rknightion/opnsense-exporter/commit/4c83613788eec985bf1d9272a2c9806122c6893a))
* correct gateway config fallback logic ([a68980c](https://github.com/rknightion/opnsense-exporter/commit/a68980cbce3949ffa5c5f86b2ecc58f93c6f6a6f))
* fix startup checks and k8s health-check ([#20](https://github.com/rknightion/opnsense-exporter/issues/20)) ([b2da78b](https://github.com/rknightion/opnsense-exporter/commit/b2da78bb485245d2be091daab998da729b46917f))
* health check; flags; metrics list ([#19](https://github.com/rknightion/opnsense-exporter/issues/19)) ([98788e8](https://github.com/rknightion/opnsense-exporter/commit/98788e843f67256a6e4fa0dddb2dbc12070ce40b))
* **kea:** handle disabled DHCP service response ([2e47279](https://github.com/rknightion/opnsense-exporter/commit/2e472794068da50904ff4baa679e424783934de1))
* let the CI run on pushed to main as well ([30436b9](https://github.com/rknightion/opnsense-exporter/commit/30436b952fc8111c7ebc8a19254309ef9751a11f))
* let the docker push happen only on tags ([30436b9](https://github.com/rknightion/opnsense-exporter/commit/30436b952fc8111c7ebc8a19254309ef9751a11f))
* let the docker push happen only on tags ([30436b9](https://github.com/rknightion/opnsense-exporter/commit/30436b952fc8111c7ebc8a19254309ef9751a11f))
* parse interface line rate with unit suffix ([428fd41](https://github.com/rknightion/opnsense-exporter/commit/428fd41b8faa34ceddf4d86611d6198f5d905d71))
* protocolStatistics API path ([#69](https://github.com/rknightion/opnsense-exporter/issues/69)) ([e59e0d3](https://github.com/rknightion/opnsense-exporter/commit/e59e0d31ea8a94ca243a1ef437bbaeab1e8d3120))
* resolve gateway probe_period emission bug ([4c577cb](https://github.com/rknightion/opnsense-exporter/commit/4c577cbf3c2d383b06dbe4dae30ca510ee2ca986))
* sync README with the latest state ([7523d61](https://github.com/rknightion/opnsense-exporter/commit/7523d61ad0769a5045820e2217570616c7d65d06))
* System status API changes in OPNsense&gt;=25.1 ([#60](https://github.com/rknightion/opnsense-exporter/issues/60)) ([6207256](https://github.com/rknightion/opnsense-exporter/commit/62072564b5f18f8bcd51b6e3cf66459f502e0d90))


### Refactoring

* **firmware:** rework metrics to follow Prometheus best practices ([a3e4057](https://github.com/rknightion/opnsense-exporter/commit/a3e4057dfb19a05890dc3d36e06f7583a3a4b16a))
* fix import ordering across collectors ([2e928d8](https://github.com/rknightion/opnsense-exporter/commit/2e928d8bbca5fcd43e10250904988683f7be35da))
* fork project from AthennaMind to rknightion ([d080810](https://github.com/rknightion/opnsense-exporter/commit/d080810a7846a1f73bdc418709835f7a5addbe1b))
* modernize Go syntax patterns ([ea2d70f](https://github.com/rknightion/opnsense-exporter/commit/ea2d70f3905a9fe3876e491f67943f08bb1509b7))


### Miscellaneous

* add completed TODO documentation ([a0b1c03](https://github.com/rknightion/opnsense-exporter/commit/a0b1c0336d533327d6b95f4d9ed4871311576118))
* add utility functions for safe string parsing ([3ac6bed](https://github.com/rknightion/opnsense-exporter/commit/3ac6bedae25cec1c6f2f8e8a0acaac13377ade45))
* remove dead system.go code ([20e9860](https://github.com/rknightion/opnsense-exporter/commit/20e986054534817b1373b1c10d25c0b4968a21c8))
* rename VERSION to version.txt ([04e8094](https://github.com/rknightion/opnsense-exporter/commit/04e80942d495d3ef1ec44dcac64b804be33c83d2))


### Documentation

* add Claude AI development guidance ([03ec5b5](https://github.com/rknightion/opnsense-exporter/commit/03ec5b551c7515c2d261a89a345858949a6a4dea))
* Add metrics list ([#15](https://github.com/rknightion/opnsense-exporter/issues/15)) ([e422536](https://github.com/rknightion/opnsense-exporter/commit/e4225361672676dd14b73f7348800d03d3a6e1d4))
* clarify firewall rules collector description ([7ddcad5](https://github.com/rknightion/opnsense-exporter/commit/7ddcad5688cc462debe281787ed1d2bd72f5cafd))
* document new collectors ([fa26340](https://github.com/rknightion/opnsense-exporter/commit/fa26340988e29c90c2d41e66ebe3d7ebb4188d7e))
* mark completed TODOs in task list ([5279015](https://github.com/rknightion/opnsense-exporter/commit/5279015fd48f22c34cc3fe0866509de247a64253))
* **todos:** mark TODO 19, 20, and 21 as complete ([e40122b](https://github.com/rknightion/opnsense-exporter/commit/e40122bd913d396c5daafd18961b0e7aaf4c0161))
* update README with new collector features ([0f01325](https://github.com/rknightion/opnsense-exporter/commit/0f01325f904aaec4c5945fa452f21962476e09fe))
* update README with new collector features ([d04b53f](https://github.com/rknightion/opnsense-exporter/commit/d04b53f45212f3d264c67bf4290050be522fcf09))


### Build & Infrastructure

* add prometheus client_model dependency ([47a20ad](https://github.com/rknightion/opnsense-exporter/commit/47a20ad43145ac6f328cc4d4479b4025ff1b0ca6))
* modernize goreleaser configuration ([d6f37cf](https://github.com/rknightion/opnsense-exporter/commit/d6f37cf9d7fbb7c8ba19fdcd5c1992b53a32b5e0))
* optimize Docker build for performance ([7eeb896](https://github.com/rknightion/opnsense-exporter/commit/7eeb8968d1a2cedf4b850c48a4a51ebf2abada1d))
* update Dockerfile with version labels ([09a745a](https://github.com/rknightion/opnsense-exporter/commit/09a745a0e07df2342ab18f7581fed119a322dcc0))
* upgrade Go version from 1.25 to 1.26 ([ea3eb6b](https://github.com/rknightion/opnsense-exporter/commit/ea3eb6b55ddaa6b5b6e7ac36f6e5aad3f57ceea3))


### Tests

* add comprehensive test coverage for collectors ([eef6317](https://github.com/rknightion/opnsense-exporter/commit/eef6317eb33f1388bf5ccc088fceac51c7ea4991))
* expand utility function coverage ([04c4078](https://github.com/rknightion/opnsense-exporter/commit/04c40780107efed802aea52d1c878546445fa83e))
* update collector tests for new collectors ([81fc4d3](https://github.com/rknightion/opnsense-exporter/commit/81fc4d347f8f1e88eaeafa83d71235aa2a5efb39))


### CI/CD

* add comprehensive release-please workflow ([76e14a0](https://github.com/rknightion/opnsense-exporter/commit/76e14a03e5ab53e12028e48d5b1207567c2b3fae))
* implement release-please automation ([e0d814c](https://github.com/rknightion/opnsense-exporter/commit/e0d814c05800efdf71322fa99e763fced57f02f4))
* modernize main CI workflow ([3e43475](https://github.com/rknightion/opnsense-exporter/commit/3e43475f705d571f0dcb9fee2cbea0200fb7a52b))
* remove arm/v6 platform support ([78b80f9](https://github.com/rknightion/opnsense-exporter/commit/78b80f960b72514621a837885354e03cf8abd769))
* remove legacy workflow files ([fb8120a](https://github.com/rknightion/opnsense-exporter/commit/fb8120aa7bbf5d14830764529e2c6377a73947e6))
