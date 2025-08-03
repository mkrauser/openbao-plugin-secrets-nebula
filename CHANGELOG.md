# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2025-08-05

### Added
- Changelog

### Changed
- fixed small typo in goreleaser config

## [1.0.0] - 2025-08-05

### Added
- Basic CA certificate management
  - Generate new CA certificates
  - Import existing CA certificates
  - Read CA certificate information
- Node certificate management
  - Issue node certificates
  - List issued certificates
  - View certificate details
  - Revoke certificates
- CA certificate rotation functionality
  - Support for rotating CA with backup preservation
  - Ability to read both current and old CA certificates
  - Automatic backup of old CA during rotation
- Automated certificate cleanup (tidy) functionality
  - Configurable cleanup of expired certificates
  - Configurable cleanup of revoked certificates
  - Safety buffer period configuration
  - Manual and scheduled cleanup operations

### Changed
- Improved CA certificate management
  - Added validation for CA rotation operations
  - Enhanced error messages for CA operations
- Updated README with comprehensive documentation
- Restructured project layout for better maintainability

### Security
- Added validation to prevent unintended CA overwrites
- Added safety checks for CA rotation operations

[Unreleased]: https://github.com/mkrauser/openbao-plugin-secrets-nebula/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mkrauser/openbao-plugin-secrets-nebula/releases/tag/v1.0.0