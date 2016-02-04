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
