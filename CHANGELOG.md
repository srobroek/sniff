# Changelog

## [1.0.0](https://github.com/srobroek/sniff/compare/sniff-v0.1.0...sniff-v1.0.0) (2026-09-12)


### ⚠ BREAKING CHANGES

* Drop support for APM formats and sidecar agent contracts.

### Features

* add adaptive Sniff intake runtime ([#4](https://github.com/srobroek/sniff/issues/4)) ([7d0f403](https://github.com/srobroek/sniff/commit/7d0f403a6e43ddbde55b22c2dfb2644fcbee3328))
* add canonical structured Sniff reports ([#3](https://github.com/srobroek/sniff/issues/3)) ([2a09bdd](https://github.com/srobroek/sniff/commit/2a09bdd4519bf3bdd0b689c221d12287a3086fe2))
* add portable Sniff support for OMP, Claude Code, and Codex ([#6](https://github.com/srobroek/sniff/issues/6)) ([b123b2c](https://github.com/srobroek/sniff/commit/b123b2c3844867879c05471a8ed73252d338ece5))
* migrate the APM estate into 31 OMP plugins ([4e4836e](https://github.com/srobroek/sniff/commit/4e4836ed316eb3fdfa5994dc88316c688fbbe2cd))
* native tools everywhere, 23-plugin consolidation, full test coverage ([0559e25](https://github.com/srobroek/sniff/commit/0559e25f8ff1032f43ce26d36ab9469e116ae079))
* per-package optimisation pass onto OMP-native constructs ([42279eb](https://github.com/srobroek/sniff/commit/42279ebe895409efac2aec559480e2dc143cc7d8))
* **quality:** enforce atomic sniff analyzer runs ([2c03c2c](https://github.com/srobroek/sniff/commit/2c03c2cf86af92dc043e619916d1f8920e5f5e7e))
* retire APM formats and add staged lint ([#68](https://github.com/srobroek/sniff/issues/68)) ([fe1bbc4](https://github.com/srobroek/sniff/commit/fe1bbc47f163fa5821f82ae01935af0cefbe8a01))
* **session:** revive session plugin with resume-session skill ([c4e38dc](https://github.com/srobroek/sniff/commit/c4e38dc8b7360c1536df2d57b15cfefa47abe322))
* **speckit:** recover spec-modes rule lost in the docs rollup ([1affd56](https://github.com/srobroek/sniff/commit/1affd56d408055ac301eb519c13a2ca010d219e1))


### Bug Fixes

* **ci:** reject stale packages and incomplete checker runs ([dd8ffee](https://github.com/srobroek/sniff/commit/dd8ffee6eca46b01686c6db2b18d88a781645782))
* **quality:** assert hosted analyzer plugins never become runtime tools ([eacffe0](https://github.com/srobroek/sniff/commit/eacffe032ef217a5b6749bcfb61e7505f7f8874d))
* **quality:** move bloodhound off the duplicate [@architect](https://github.com/architect) role ([#37](https://github.com/srobroek/sniff/issues/37)) ([066a99f](https://github.com/srobroek/sniff/commit/066a99f4807ce4eeea825b747b2a5709bada9ff2))
* **quality:** reduce sniff skill density ([c4bef49](https://github.com/srobroek/sniff/commit/c4bef49e859eb16df175e29ba6a98680577f76c9))
* **speckit:** retire the spec-id TTSR as a contextual false positive ([743f838](https://github.com/srobroek/sniff/commit/743f838a86a61bb093c4a2ddee19e7f55161ef5e))
* **verification:** report missing checks and use installed toolchains ([4a20ae2](https://github.com/srobroek/sniff/commit/4a20ae2c292ec405404fb05480c7f375918e629e))
