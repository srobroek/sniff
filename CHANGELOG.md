# Changelog

## [0.4.0](https://github.com/srobroek/sniff/compare/sniff-v0.3.2...sniff-v0.4.0) (2026-11-04)


### ⚠ BREAKING CHANGES

* **intake:** interactive:false intake no longer approves its own plan. The MCP server needs form elicitation and the OMP extension needs a UI to confirm it, unless the operator sets SNIFF_UNATTENDED_INTAKE=1 in the server's environment. Headless scripts that relied on automatic approval must set it.

### Features

* add a native OpenCode V2 plugin adapter ([#46](https://github.com/srobroek/sniff/issues/46)) ([6a13597](https://github.com/srobroek/sniff/commit/6a135972b6a0d10c6da4060f322a38cf3cad1ecb))
* **opencode:** add a /sniff command that starts an audit with the skill loaded ([#55](https://github.com/srobroek/sniff/issues/55)) ([3440da9](https://github.com/srobroek/sniff/commit/3440da99e0893ce8f48d282ec5a8e354a13ca750))


### Bug Fixes

* **core:** scope runs and artifacts to their owner, validate reports once, and save them durably ([#52](https://github.com/srobroek/sniff/issues/52)) ([2e69968](https://github.com/srobroek/sniff/commit/2e699684c405ac0b14dea7f22909d2e08e05dd2b))
* harden analyzer execution, report persistence, and run leases ([#49](https://github.com/srobroek/sniff/issues/49)) ([6e7d076](https://github.com/srobroek/sniff/commit/6e7d07640ede080b6fee417bd1cc62d392ff11f8))
* **intake:** require approval for unattended intake and let objectives choose analyzers ([#50](https://github.com/srobroek/sniff/issues/50)) ([44f5ef4](https://github.com/srobroek/sniff/commit/44f5ef435417d6b7a7b5a8fabfa45aaff1fac370))
* **process:** keep analyzer process groups owned and serialize toolkit installs with a kernel lock ([#53](https://github.com/srobroek/sniff/issues/53)) ([71a90b8](https://github.com/srobroek/sniff/commit/71a90b8339bf907fd90c1d74e0ddfc508d569221))
* resolve target files exactly and keep the MCP server within its protocol ([#48](https://github.com/srobroek/sniff/issues/48)) ([2855cd3](https://github.com/srobroek/sniff/commit/2855cd30dac53c08fd45f03a8fb860744103a15c))
* **target:** derive PR and MR files from git, fetch minimal checkouts, and keep history windows exact ([#51](https://github.com/srobroek/sniff/issues/51)) ([cbfd23c](https://github.com/srobroek/sniff/commit/cbfd23ce14c0a8ca28cb184de0a2dbaba12689b8))
* **target:** read since-date windows as an explicit UTC instant ([#54](https://github.com/srobroek/sniff/issues/54)) ([d9d9ccb](https://github.com/srobroek/sniff/commit/d9d9ccb1e506524cf146b4b50e40133ef70bd2dc))

## [0.3.2](https://github.com/srobroek/sniff/compare/sniff-v0.3.1...sniff-v0.3.2) (2026-10-08)


### Bug Fixes

* **agents:** bloodhound never runs analyzers directly ([78d6852](https://github.com/srobroek/sniff/commit/78d68521c208a56fbbb97f4f35eff1b52cebf012))
* **install:** require digest-bound interactive confirmation for OMP installs ([78d6852](https://github.com/srobroek/sniff/commit/78d68521c208a56fbbb97f4f35eff1b52cebf012))
* **omp:** load the OMP skill tree instead of the Claude copy ([78d6852](https://github.com/srobroek/sniff/commit/78d68521c208a56fbbb97f4f35eff1b52cebf012))
* **omp:** mount only the native tools by declaring no MCP servers ([78d6852](https://github.com/srobroek/sniff/commit/78d68521c208a56fbbb97f4f35eff1b52cebf012))
* **report:** keep report page details consistent with delivered content ([78d6852](https://github.com/srobroek/sniff/commit/78d68521c208a56fbbb97f4f35eff1b52cebf012))
* **skill:** correct language reference follow-ups and tool facts ([#42](https://github.com/srobroek/sniff/issues/42)) ([261f568](https://github.com/srobroek/sniff/commit/261f56877283d71bc6f2e3b158aebc807c36d003))
* **skill:** correct workflow references and reject mechanical breaking changes ([#41](https://github.com/srobroek/sniff/issues/41)) ([4fd8738](https://github.com/srobroek/sniff/commit/4fd87385edb01575ec94548255d629f82d53a4ab))
* **skill:** treat language-doc tools as operator follow-ups and correct tool facts ([78d6852](https://github.com/srobroek/sniff/commit/78d68521c208a56fbbb97f4f35eff1b52cebf012))

## [0.3.1](https://github.com/srobroek/sniff/compare/sniff-v0.3.0...sniff-v0.3.1) (2026-09-29)


### Bug Fixes

* **agents:** grant bloodhound and refactor-challenger the find tool ([#37](https://github.com/srobroek/sniff/issues/37)) ([2a1a79b](https://github.com/srobroek/sniff/commit/2a1a79b41ef8d9ece2ceb3028d481e384eadf694))
* **deps:** keep bun.lock at version 1 for Dependabot ([e8ac3fe](https://github.com/srobroek/sniff/commit/e8ac3feb3e53bd67583127ade236817386a6de6f))

## [0.3.0](https://github.com/srobroek/sniff/compare/sniff-v0.2.3...sniff-v0.3.0) (2026-09-19)


### Features

* declarative analyzer recipes with a generic SARIF ingester ([#32](https://github.com/srobroek/sniff/issues/32)) ([18b2440](https://github.com/srobroek/sniff/commit/18b2440b8a6069076489c64a2f5ec788f4051d26))


### Bug Fixes

* argument-dependent approval tiers and one tool schema authority ([#30](https://github.com/srobroek/sniff/issues/30)) ([2c5acc9](https://github.com/srobroek/sniff/commit/2c5acc9802d90802d7169cb2f4c889127ecb1cdf))
* harden analyzer lifecycle, toolkit locking, and artifact retention ([#29](https://github.com/srobroek/sniff/issues/29)) ([284c6ed](https://github.com/srobroek/sniff/commit/284c6ed86c14c4b6d35f7541cecf69d8cc32cd39))

## [0.2.3](https://github.com/srobroek/sniff/compare/sniff-v0.2.2...sniff-v0.2.3) (2026-09-13)


### Bug Fixes

* **deps:** update MCP SDK to 1.30.0 ([#24](https://github.com/srobroek/sniff/issues/24)) ([f3d4205](https://github.com/srobroek/sniff/commit/f3d4205d08c90d55b2efbed982d9097727e68510))

## [0.2.2](https://github.com/srobroek/sniff/compare/sniff-v0.2.1...sniff-v0.2.2) (2026-09-13)


### Bug Fixes

* isolate managed Rust toolchains ([#16](https://github.com/srobroek/sniff/issues/16)) ([1bc1bff](https://github.com/srobroek/sniff/commit/1bc1bffdbaac5cc3ac82c49cddffeb2c2dd11dd9))
* **rust:** extend cold mise install timeout ([#19](https://github.com/srobroek/sniff/issues/19)) ([2271e8e](https://github.com/srobroek/sniff/commit/2271e8eccf8c5e66803cb64c5646e1f8fa7410bf))
* **rust:** hydrate pinned target toolchains ([#18](https://github.com/srobroek/sniff/issues/18)) ([850131f](https://github.com/srobroek/sniff/commit/850131f270e2e15d005a1169a86bde4726883946))

## [0.2.1](https://github.com/srobroek/sniff/compare/sniff-v0.2.0...sniff-v0.2.1) (2026-09-12)


### Bug Fixes

* provision analyzers through isolated mise toolkits ([#11](https://github.com/srobroek/sniff/issues/11)) ([cb88d84](https://github.com/srobroek/sniff/commit/cb88d844d64ae9a7f3bf3e236809830bd70683ab))

## [0.2.0](https://github.com/srobroek/sniff/compare/sniff-v0.1.0...sniff-v0.2.0) (2026-09-12)


### Features

* add adaptive Sniff intake runtime ([#4](https://github.com/srobroek/sniff/issues/4)) ([7d0f403](https://github.com/srobroek/sniff/commit/7d0f403a6e43ddbde55b22c2dfb2644fcbee3328))
* add canonical structured Sniff reports ([#3](https://github.com/srobroek/sniff/issues/3)) ([2a09bdd](https://github.com/srobroek/sniff/commit/2a09bdd4519bf3bdd0b689c221d12287a3086fe2))
* add portable Sniff support for OMP, Claude Code, and Codex ([#6](https://github.com/srobroek/sniff/issues/6)) ([b123b2c](https://github.com/srobroek/sniff/commit/b123b2c3844867879c05471a8ed73252d338ece5))


### Bug Fixes

* bound initial release history ([#8](https://github.com/srobroek/sniff/issues/8)) ([9c8db46](https://github.com/srobroek/sniff/commit/9c8db46031d6471bf6a819ceb7e1df099dc89a66))
* release every harness at one version ([#10](https://github.com/srobroek/sniff/issues/10)) ([bdffb09](https://github.com/srobroek/sniff/commit/bdffb09f5ea96b704fd23b2c056b4e89dc008576))
