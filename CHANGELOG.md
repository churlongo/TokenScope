# Changelog

All notable changes to TokenScope are documented here. The format follows Keep
a Changelog, and the project uses semantic versioning.

## [Unreleased]

### Changed

- Claim coverage wording is under review for the next patch.

## [1.0.1] - 2026-06-24

### Fixed

- Tokens with an unpadded base64url segment decode correctly instead of
  reporting a structural error.

## [1.0.0] - 2025-10-28

### Added

- Stable CLI contract for audit, claims, policy, and version, exit codes 0/1/2.
- Tests pin the decoder edges: unpadded segments and empty claims.

## [0.9.5] - 2024-05-16

### Changed

- Maintenance release: documentation pass and sample refresh.

## [0.9.0] - 2023-08-09

### Added

- Multi token audit mode over a file of tokens.
- Claim coverage summary across the audited set.

## [0.8.0] - 2022-11-15

### Added

- JSON output for the audit and claims commands.
- Coverage view per registered claim.

## [0.7.0] - 2021-03-23

### Added

- Bundled sample tokens with a generator script.
- README walkthrough captured from a real audit run.

## [0.6.0] - 2020-10-06

### Added

- Test suite covering decoding, claims, and the CLI.

## [0.5.0] - 2019-06-19

### Added

- Report renderer with stable finding names.
- CLI entry point with subcommands.

## [0.4.0] - 2018-09-27

### Added

- Structural verify pass for the header and signature shape.

## [0.3.0] - 2017-05-11

### Added

- Policy checks: algorithm allow list, expiry, and audience rules.

## [0.2.0] - 2016-08-02

### Added

- Claims model with registered claim names and types.

## [0.1.0] - 2015-04-14

### Added

- Initial base64url decoder and a single token audit entry point.

<!-- draft note 1520 -->
