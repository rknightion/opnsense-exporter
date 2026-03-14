# Changelog

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
