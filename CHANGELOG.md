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

