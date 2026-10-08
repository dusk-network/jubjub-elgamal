# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Change `Encryption::encrypt` and `Encryption::encrypt_u64` to return a
  `Result` that rejects a ciphertext component not of prime order [#32]
- Change `Encryption::default` to the generator in both components [#32]
- Adapt ZK gadgets to Plonk's torsion-free witness point API [#28]
- Update `dusk-plonk` to v0.24 and `dusk-jubjub` to v0.16 [#28]
- Raise the MSRV to Rust 1.96.1 [#33]
- Archive `Encryption` using its validated canonical byte representation [#31]

### Fixed

- Reject an identity shared key in `Encryption::encrypt` and
  `Encryption::encrypt_u64` [#32]
- Constrain the mapped point in the `encrypt_u64` gadget to the prime-order
  subgroup [#28]
- Constrain the mapped point in the `encrypt_u64` and `decrypt_u64` gadgets to
  a canonical `y` with the plaintext as its low 64 bits, and an even `x` [#35]

## [0.5.0] - 2026-02-27

### Added

- Add v0.2.0-compatible `encrypt` and `decrypt` free functions to zk module [#25]

### Changed

- Move to stable MSRV 1.85
- Move to edition 2024
- Update `dusk-plonk` to v0.22.0-rc.0
- Update `dusk-jubjub` to v0.15

## [0.4.3] - 2025-03-12

### Added

- Added Rkyv derivation for Encryption struct

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
[#32]: https://github.com/dusk-network/jubjub-elgamal/issues/32
[#28]: https://github.com/dusk-network/jubjub-elgamal/issues/28
[#35]: https://github.com/dusk-network/jubjub-elgamal/issues/35
[#33]: https://github.com/dusk-network/jubjub-elgamal/issues/33
[#31]: https://github.com/dusk-network/jubjub-elgamal/issues/31
[#25]: https://github.com/dusk-network/jubjub-elgamal/issues/25
[#9]: https://github.com/dusk-network/jubjub-elgamal/issues/9
[#11]: https://github.com/dusk-network/jubjub-elgamal/issues/11
[#8]: https://github.com/dusk-network/jubjub-elgamal/issues/8
[#7]: https://github.com/dusk-network/jubjub-elgamal/issues/7
[#4]: https://github.com/dusk-network/jubjub-elgamal/issues/4
[#1]: https://github.com/dusk-network/jubjub-elgamal/issues/1

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/jubjub-elgamal/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/dusk-network/jubjub-elgamal/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/dusk-network/jubjub-elgamal/compare/v0.4.0...v0.4.2
[0.4.0]: https://github.com/dusk-network/jubjub-elgamal/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dusk-network/jubjub-elgamal/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dusk-network/jubjub-elgamal/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/jubjub-elgamal/releases/tag/v0.1.0
