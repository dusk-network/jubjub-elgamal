# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2025-03-12

### Added

- Add `Encryption` structs

### Changed

- Change `encrypt` method to allow optional generator

## [0.3.0] - 2025-02-25

### Added

- Add encryption methods for u64 values [#9]

### Changed

- Change methods to return shared_key and allow decryption from it [#7]
- Change encryption gadget to include bad encryption check [#8]
- Change encryption methods to allow custom generators [#11]

## [0.2.0] - 2025-02-06

### Changed

- Change the in-circuit decryption to use `component_sub_point` [#4]
- Update `dusk-jubjub` dependency to version `0.15`
- Update `dusk-plonk` dependency to version `0.21`

## [0.1.0] - 2024-11-25

### Added

- Add initial implementation [#1]

<!-- ISSUES -->
[#9]: https://github.com/dusk-network/jubjub-elgamal/issues/9
[#11]: https://github.com/dusk-network/jubjub-elgamal/issues/11
[#8]: https://github.com/dusk-network/jubjub-elgamal/issues/8
[#7]: https://github.com/dusk-network/jubjub-elgamal/issues/7
[#4]: https://github.com/dusk-network/jubjub-elgamal/issues/4
[#1]: https://github.com/dusk-network/jubjub-elgamal/issues/1

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/jubjub-elgamal/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/dusk-network/jubjub-elgamal/releases/tag/v0.4.0
[0.3.0]: https://github.com/dusk-network/jubjub-elgamal/releases/tag/v0.3.0
[0.2.0]: https://github.com/dusk-network/jubjub-elgamal/releases/tag/v0.2.0
[0.1.0]: https://github.com/dusk-network/jubjub-elgamal/releases/tag/v0.1.0
