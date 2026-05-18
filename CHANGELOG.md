# Changelog

## [4.1.0] - 2026-05-18

### Added

- **TanStack Wave 4 Detection (May 2026)**: Full coverage for the May 11, 2026 TanStack supply chain attack (CVE-2026-45321 / GHSA-g7cv-rxg3-hmpx), republished by attacker group TeamPCP via GitHub Actions cache poisoning and OIDC token theft.
  - **84 Compromised Versions**: All 42 affected `@tanstack/*` packages × 2 versions each added to `sources/known-threats.csv`, plus secondary victim `@mistralai/mistralai@2.2.2–2.2.4`.
  - **Payload Hashes (SHA-256)**: Added `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c` (`router_init.js`) and `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96` (`tanstack_runner.js`). New `TANSTACK_MALWARE_HASHES` export.
  - **Malware Filenames**: `router_init.js`, `tanstack_runner.js`, `router_runtime.js`, `gh-token-monitor.sh`, `gh-token-monitor.service`, `com.user.gh-token-monitor.plist`.
  - **Campaign Strings**: `EveryBoiWeBuildIsAWormyBoi`, `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`, `OhNoWhatsGoingOnWithGitHub`, `svksjrhjkcejg` (PBKDF2 salt), `0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2186c40aa` (master key), `__DAEMONIZED`.
  - **C2 Infrastructure**: `filev2.getsession.org`, `api.masscan.cloud`, `git-tanstack.com`, `litter.catbox.moe/h8nc9u.js`, `litter.catbox.moe/7rrc6l.mjs`.
  - **Worm Forensics**: `dependabout/` branch impersonation pattern and the `claude@users.noreply.github.com` spoofed commit author.
- **Manifest Tampering Heuristic** (`analyzeManifest`): New analyzer inspects `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`, and `bundleDependencies` for the patterns used by the TanStack worm.
  - `malicious-git-ref`: Flags entries pinning the known-bad commit `79ac49eedf774dd4b0cfa308722bc463cfe5885c` (full or truncated). Severity: critical.
  - `tanstack-setup-phantom-dep`: Flags `@tanstack/setup` in `optionalDependencies`. Severity: critical.
  - `commit-pinned-optional-dep`: Flags any `optionalDependencies` entry pinning a 40-char git commit hash. Severity: high.

### Changed

- **Package Count**: 1,727 → 1,813 versioned entries in `sources/known-threats.csv` (+86: 84 TanStack + 3 Mistral, with one overlap deduplicated).
- **README**: New "TanStack Supply Chain Attack (May 2026)" section leading the document.
- **Features list**: Now reflects multi-campaign coverage (TanStack + Axios + Shai-Hulud) and the new manifest-tampering detection layer.

## [4.0.0] - 2026-04-01

### Added

- **Axios Supply Chain Attack Detection**: Full coverage for the March 31, 2026 axios npm compromise. Detects `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1`/`4.2.0`, `@shadanai/openclaw`, and `@qqbrowser/openclaw-qbot`.
- **C2 Infrastructure Signatures**: Detects C2 domains (`sfrclak.com`, `calltan.com`, `callnrwise.com`), C2 IP (`142.11.206.73`), beacon identifiers (`packages.npm.org/product`), and the spoofed IE8 User-Agent string.
- **RAT Payload Hashes**: SHA-256 verification for stage-2 payloads — macOS (`com.apple.act.mond`), Windows (`6202033.ps1`), and Linux (`ld.py`).
- **New Heuristic Rules**:
  - `execsync-nohup`: Detects background process execution via `execSync`+`nohup` (RAT dropper pattern). Severity: critical.
  - `self-deleting-script`: Detects `fs.unlink` on `setup.js`/`setup.ts` (dropper self-destruction). Severity: critical.
  - `powershell-remote-exec`: Detects `irm|iex` PowerShell remote execution. Severity: critical.
  - `xor-obfuscation`: Detects XOR-based string obfuscation patterns. Severity: high.
- **Malware File Detection**: Added 5 new filenames to monitor: `setup.js`, `com.apple.act.mond`, `ld.py`, `6202033.ps1`, `6202033.vbs`.
- **Campaign-Aware Reporting**: Warning messages now identify which campaign a detection belongs to (Axios vs Shai Hulud).

### Changed

- **Breaking**: Package count increased from 1,717 to 1,726+ with 9 new axios-related entries in `known-threats.csv`.
- **README**: Restructured to lead with the Axios attack. Shai-Hulud 2.0 section condensed and moved below Safety & Trust.
- **Description**: Updated package description to reflect multi-campaign scanning capability.
- **Dependencies**: Updated all semver-compatible dependencies to latest versions.
- **Acknowledgements**: Added axios research sources (Socket.dev, Snyk, Huntress, StepSecurity, Aikido) and reorganized with axios sources first.

## [3.1.2] - 2025-12-02

### Changed

- **Data Hygiene**: Removed 497 rows without versions from `sources/known-threats.csv`, leaving 1,717 versioned entries to avoid ambiguous matches.
- **Docs**: Updated README to reflect the new package count and clarify the optional `reason`/`integrity` headers retained for upstream metadata.

## [3.1.1] - 2025-12-01

### Enterprise Hardening

- **Governance**: Added `CODEOWNERS` and `SECURITY.md` to define project maintainers and vulnerability reporting policies.
- **Configuration**: Added support for `.wormsignrc` (JSON/YAML) to enforce security policies:
    - `offline`: Force offline mode.
    - `allowedSources`: Whitelist specific threat intelligence sources.
    - `suppressedRules`: Suppress specific heuristic rules.
- **Heuristics**: Introduced severity levels (Low, Medium, High, Critical) for findings and improved CLI output with color-coded severity.
- **Documentation**: Added `docs/enterprise-deployment.md` playbook for enterprise integration and internal mirroring.

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
