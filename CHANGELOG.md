# Changelog

## [2.0.10] - 2025-11-27
### Changed
- **Theming**: Updated package description to be more thematic ("A prescient scanner...").

## [2.0.9] - 2025-11-27
### Changed
- **Data Sources**: Reordered default fetch priority. Now checks `datadog` first, then `koi`, and `ibm` last.

## [2.0.8] - 2025-11-27
### Added
- **CLI**: Implemented `--debug` flag to enable verbose logging during scans.

## [2.0.7] - 2025-11-27
### Fixed
- **Data Sources**: Fixed `koi.csv` download (was a redirect) and added missing header to `aikido.csv` to ensure correct parsing.

## [2.0.6] - 2025-11-27
### Added
- **Data Sources**: Bundled `koi.csv` and `aikido.csv` alongside `datadog.csv`. All three sources are now checked by default during local scans.

## [2.0.5] - 2025-11-27
### Added
- **Data Source**: Bundled `datadog.csv` (Shai Hulud 2.0 feed) so it is checked by default during local scans.
- **Documentation**: Added attribution to DataDog Security Labs in README.

## [2.0.4] - 2025-11-27
### Fixed
- **Packaging**: Included `sources` directory in the npm package so local scans work correctly out of the box.

## [2.0.3] - 2025-11-27
### Changed
- **Thematic Output**: Updated success message to "No wormsign detected" to better fit the Dune theme.

## [2.0.2] - 2025-11-27
### Fixed
- **Documentation**: Updated README and Changelog for accuracy.

## [2.0.1] - 2025-11-27

### Added
- **Hash-Based Detection**: Added support for detecting compromised packages by their integrity hash (SHA-1/SHA-512) in `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`.
- **pnpm Support**: Added full support for parsing `pnpm-lock.yaml` files.
- **Enhanced Heuristics**: Improved `package.json` script analysis to detect:
    - Destructive commands (`rm -rf`)
    - Reverse shells (`nc -e`)
    - Inline code execution (`python -c`, `node -e`)
    - IP addresses
- **CI/CD**: Added GitHub Actions workflow to run tests, linting, and security audits on all branches.

### Fixed
- **Smoke Tests**: Fixed path resolution issue when running smoke tests against the built `dist` directory.
- **Linting**: Resolved various linting errors in the codebase.



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
