# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] - 2025-11-27
### Security
- Replaced custom lockfile parsers with `js-yaml` (pnpm) and `@yarnpkg/lockfile` (yarn) for robust and safe parsing.
- Enforced HTTPS for all API requests to prevent SSRF.
- Added input validation for project paths to prevent traversal attacks.

## [1.0.2] - 2025-11-27
### Changed
- Migrated repository to `BranLang/worm-sign`.
- Updated metadata and links.

## [1.0.1] - 2025-11-27
### Fixed
- Fixed publishing issues.
- Added documentation screenshots.

## [1.0.0] - 2025-11-27
### Added
- Initial release of `worm-sign`.
- Core scanning logic in `src/index.js`.
- CLI entry point `bin/scan.js` with premium visuals (tables, banners).
- Support for `npm`, `yarn`, and `pnpm` lockfiles.
- Bundled `vuls.csv` with known Shai Hulud compromised packages.
- `--fetch` flag to retrieve the latest vulnerability list from a remote API.
- `--url` flag to specify a custom API endpoint.
- GitHub Actions workflow for automated scanning.
- Added screenshots to README.
