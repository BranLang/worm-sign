# Changelog

## [3.1.0] - 2025-11-30

### Security & Transparency

- **Removed Obfuscation**: Removed the "Vial" XOR encryption protocol. All malware signatures are now stored in plain text (`src/generated/signatures.ts`) to ensure full transparency and distinguish the tool from the malware it detects.
- **Build Safety**: Excluded `tests/` directory from the npm package build to prevent test fixtures (like `setup_bun.js`) from being shipped to users.

### Changed

- **Documentation**: Added a "Transparency & Signatures" section to README explaining the decision to use plain text signatures.

## [3.0.1] - 2025-11-30

### Fixed

- **Yarn & pnpm Support**: Fixed `scanProject` to correctly fallback to `yarn.lock` and `pnpm-lock.yaml` parsing when `package-lock.json` is missing.
- **Error Handling**: Fixed a crash in `loadJson` when encountering missing files or invalid JSON.
- **Test Coverage**: Improved unit test coverage for error handling and edge cases in core scanning logic.

### Added

- **Documentation**: Added CI status, NPM version, and License badges to README.
- **Smoke Tests**: Enhanced smoke tests to verify detection of multiple compromised packages.

## [3.0.0] - 2025-11-30

### Added

- **Safe Static Analysis**: Migrated to `@npmcli/arborist` to scan lockfiles without executing scripts, neutralizing the "Dead Man's Switch".
- **Signature Obfuscation**: Implemented the "Vial" protocol to XOR-encrypt internal signatures, preventing the scanner from being flagged by AV/EDR.
- **Trusted Publishing**: Configured OIDC for npm provenance to establish a verifiable chain of custody.

### Changed

- **Breaking Change**: Removed support for legacy lockfile parsing in favor of Arborist.
- **Metadata**: Updated `package.json` keywords to improve discovery (added `supply-chain`, `devsecops`, `audit`, etc.).

## [2.3.0] - 2025-11-30

### Added

- **Consolidated Sources**: Consolidated all local banned package sources into a single `sources/known-threats.csv` file (2214 unique packages).
- **Source Management**: Added `scripts/add-source.ts` utility to easily add new sources (URL or file) to the master list with deduplication.
- **New Intelligence**: Added 27 new compromised packages related to Shai Hulud 2.0 (Sept/Nov 2025 attacks) including `@zapier/zapier-sdk` and `@posthog/agent`.
- **Offline Mode**: Added `--offline` flag to explicitly disable network requests (implies `--no-fetch`).
- **SSL Bypass**: Added `--insecure` flag to disable SSL certificate verification (use with caution, primarily for internal corporate networks).
- **Advanced Heuristics**: Added entropy analysis to detect high-entropy obfuscated files (>5MB).
- **Behavioral Detection**: Added detection for destructive commands (`shred`, `del`), PowerShell Bun installation vectors, and C2 signatures.

### Changed

- **Refactoring**: Renamed "Banned" to "Compromised" throughout the codebase for more accurate terminology.
- **Refactoring**: Extracted CSV parsing logic to `src/utils/csv.ts` for better code reuse and robustness.
- **Gitignore**: Updated `.gitignore` to exclude archived sources (`sources/archive/`), verification folders (`verify_installs/`), and test output (`test_output/`).
- **Source Updates**: Updated `datadog` and `koi` source URLs in `src/index.ts`.

### Fixed

- **CLI Execution**: Fixed `ts-node` execution issues in `bin/scan.ts` by ensuring correct reporter import paths and handling.
- **CSV Parsing**: Improved robustness of CSV parsing to handle various column names and formats.

## [2.2.0] - 2025-11-28

### Added

- **Shai Hulud 2.0 Detection**: Added specific detection for Shai Hulud 2.0 malware indicators:
  - Detects malicious files: `setup_bun.js` and `bun_environment.js`.
  - Verifies SHA-256 hashes of these files against known malware signatures.
  - Detects suspicious scripts: `node setup_bun.js` and downloads from `bun.sh`.
- **Documentation**: Updated README with new detection capabilities and IBM X-Force acknowledgement.

## [2.1.7] - 2025-11-28

### Added

- **New Source**: Added `ibm2.csv` containing 547 additional banned package signatures.
- **Dev Experience**: Integrated **Husky** and **lint-staged** for automated pre-commit checks.

## [2.1.6] - 2025-11-28

### Fixed

- **Enterprise Usage**: Fixed a bug where `--offline` prevented fetching from a custom `--url`. Now, `--offline` only disables default remote sources, allowing custom internal mirrors to be used as intended.

### Added

- **SSL**: Added `--insecure` flag to bypass SSL certificate verification for internal servers with self-signed certificates.

## [2.1.5] - 2025-11-28

### Fixed

- **Remote Fetching**: Fixed a bug where the scanner would silently ignore non-200 HTTP responses (e.g., 404 Not Found) from custom URLs. It now correctly reports these as errors/warnings.

### Added

- **Testing**: Added a comprehensive regression test suite (`tests/readme_commands.test.ts`) that verifies all commands documented in the README to ensure documentation accuracy and CLI stability.

## [2.1.4] - 2025-11-28

### Fixed

- **Permissions**: Fixed `Permission denied` error in CI/CD environments by ensuring the executable bit is correctly set on the CLI binary (`dist/bin/scan.js`) during the build process.

## [2.1.3] - 2025-11-28

### Documentation

- **Enterprise Usage**: Expanded the "Enterprise Usage" section in README to provide clear instructions for using internal mirrors with the CLI (via `--offline` and `--url`) versus maintaining a fork.

## [2.1.2] - 2025-11-28

### Improved

- **Error Handling**: The scanner now gracefully handles partial failures when fetching from multiple remote sources. If one source fails (e.g., a custom URL), it warns the user but continues scanning with data from other successful sources.
- **Documentation**: Clarified custom URL usage in README, explicitly noting that `--fetch` is not required when `--url` is provided.

## [2.1.1] - 2025-11-28

### Fixed

- **Dependencies**: Removed circular dependency on `worm-sign` itself.

## [2.1.0] - 2025-11-28

### Added

- **New Sources**: Added `cobenian` (1700+ packages) and `manual-research` sources.
- **Offline Mode**: Added `--offline` flag to disable remote fetching and rely solely on bundled data.
- **Acknowledgements**: Added credits for Cobenian, Phylum, and Truesec in README.

### Changed

- **Source Loading**: Refactored source loading to be dynamic. The scanner now automatically loads all `.csv` and `.json` files from the `sources` directory.
- **Remote Sources**: Remote sources are now configured via JSON files in the `sources` directory instead of hardcoded in the binary.
- **CLI**: deprecated `--source` flag. The scanner now fetches from all configured remote sources by default (if `--fetch` is used) and fails gracefully if a source is unavailable.
- **Data Sources**: Removed hardcoded IBM datasource.

### Fixed

- **CSV Parsing**: Fixed parsing issues in `socket.csv` (non-standard format) and `cobenian.csv` (comments/headers).

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
