# Changelog

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
