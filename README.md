# Worm Sign 🪱🚫

[![CI Status](https://github.com/BranLang/worm-sign/actions/workflows/ci.yml/badge.svg)](https://github.com/BranLang/worm-sign/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/worm-sign.svg)](https://badge.fury.io/js/worm-sign)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm provenance](https://img.shields.io/badge/provenance-verified-green)](https://docs.npmjs.com/generating-provenance-statements)

> "We have wormsign the likes of which even God has never seen."

**Worm Sign** is a security scanner that detects npm packages compromised by supply chain attacks. It scans your project's `package.json` and lockfiles against **1,813+ known compromised packages** using hash verification, signature matching, and behavioral heuristics.

> **Now detecting the [May 2026 TanStack supply chain attack](#tanstack-supply-chain-attack-may-2026)** — the fourth wave of the Shai-Hulud worm, which republished 42 `@tanstack/*` packages (84 versions) with valid SLSA provenance after extracting an OIDC token via GitHub Actions cache poisoning.

## TanStack Supply Chain Attack (May 2026)

On May 11, 2026, attacker group **TeamPCP** poisoned the `tanstack/router` GitHub Actions cache via a fork pull request, extracted the legitimate OIDC publishing token, and republished 42 `@tanstack/*` packages with malware — **producing valid SLSA Build Level 3 attestations**. The worm then propagated to 170+ secondary victim packages (including `@mistralai/mistralai`, `@uipath/*`, `@draftlab/*`, `@squawk/*`, `safe-action`, `cmux-agent-mcp`, `nextmove-mcp`, `ts-dna`, `cross-stitch`).

Tracked as **CVE-2026-45321** / **GHSA-g7cv-rxg3-hmpx**.

**If you installed any `@tanstack/*` package between 11:29 UTC and 19:15 UTC on May 11, 2026, run `worm-sign` immediately.**

Worm Sign detects this attack through multiple layers:

- **84 Compromised Versions**: All 42 affected `@tanstack/*` packages × 2 versions each from GHSA-g7cv-rxg3-hmpx, plus secondary victim `@mistralai/mistralai@2.2.2–2.2.4`.
- **Payload Hashes**: SHA-256 verification of `router_init.js` (`ab4fcadaec…`) and `tanstack_runner.js` (`2ec78d556d…`).
- **Manifest Tampering**: New `analyzeManifest` heuristic flags the malicious `optionalDependencies` entry `"@tanstack/setup": "github:tanstack/router#79ac49eedf…"`, including the truncated form and any commit-pinned git ref in `optionalDependencies`.
- **Campaign Strings**: Detects `EveryBoiWeBuildIsAWormyBoi` (campaign ID), `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` (dead-man's-switch trigger that runs `rm -rf ~/` on token revocation), `OhNoWhatsGoingOnWithGitHub` (token-recovery magic string), and the unique PBKDF2 salt `svksjrhjkcejg`.
- **C2 Infrastructure**: Detects `filev2.getsession.org`, `api.masscan.cloud`, `git-tanstack.com`, and second-stage payload URLs at `litter.catbox.moe/h8nc9u.js` / `litter.catbox.moe/7rrc6l.mjs`.
- **Persistence Files**: Flags dropped files `router_init.js`, `tanstack_runner.js`, `router_runtime.js`, `gh-token-monitor.sh`, `gh-token-monitor.service`, and `com.user.gh-token-monitor.plist`.
- **Worm Forensics**: Detects `dependabout/` branch impersonation and `claude@users.noreply.github.com` spoofed commit author used by the worm to push exfiltration commits.

## Axios Supply Chain Attack (March 2026)

On March 31, 2026, the `axios` HTTP client was compromised after the primary maintainer's npm account was hijacked. Two malicious versions (`1.14.1` and `0.30.4`) injected `plain-crypto-js` as a phantom dependency — a package whose sole purpose was to execute a `postinstall` script that drops a cross-platform RAT targeting macOS, Windows, and Linux.

**If you installed axios between ~00:21 and ~03:30 UTC on March 31, run `worm-sign` immediately.**

Worm Sign detects this attack through multiple layers:

- **Compromised Packages**: Flags `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1`/`4.2.0`, and related attacker packages (`@shadanai/openclaw`, `@qqbrowser/openclaw-qbot`).
- **C2 Infrastructure**: Detects C2 domains (`sfrclak.com`, `calltan.com`, `callnrwise.com`) and IP (`142.11.206.73`).
- **RAT Payload Hashes**: SHA-256 verification of stage-2 payloads for macOS (`com.apple.act.mond`), Windows (`6202033.ps1`), and Linux (`ld.py`).
- **Dropper Patterns**: Identifies `execSync`+`nohup` background execution, self-deleting `setup.js` scripts, XOR obfuscation with key `OrDeR_7077`, and the spoofed IE8 User-Agent string.
- **PowerShell Vectors**: Catches `irm|iex` remote execution patterns used in Windows payload delivery.

## Features

- **Safe Static Analysis**: Uses `@npmcli/arborist` to inspect the dependency tree without executing any lifecycle scripts — the malware never gets a chance to run.
- **Multi-Campaign Detection**: Covers the TanStack wave 4 attack (May 2026), the Axios supply chain attack (March 2026), and the Shai-Hulud malware campaign (1,717+ packages).
- **Manifest Tampering Detection**: Flags malicious `optionalDependencies` entries and commit-pinned git refs used to smuggle payloads (the TanStack wave 4 vector).
- **Hash-Based Detection**: Verifies packages by integrity hash (SHA-1/SHA-512), catching variants even if renamed or version-spoofed.
- **Heuristic Analysis**: Scans `package.json` scripts for suspicious patterns — RAT droppers, `curl | bash`, reverse shells, XOR obfuscation, self-deleting scripts, and more.
- **Entropy Analysis**: Detects high-entropy files (>5MB) that indicate packed/obfuscated malware payloads.
- **C2 Signature Matching**: Identifies known command & control domains, IPs, and beacon patterns.
- **Lockfile Support**: Scans `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`.
- **SARIF Output**: Generates SARIF 2.1.0 reports for GitHub Security integration.
- **CI/CD Ready**: Integrates into GitHub Actions or any CI pipeline. Fails the build on detection (exit code 1).

## Safety & Trust

### 🛡️ Safe Static Analysis
Worm Sign parses your lockfile directly (using `Arborist.loadVirtual()`) to build an in-memory dependency graph. It **never** runs `npm install` or executes `preinstall`/`postinstall` scripts during scanning — this is critical because both the Axios attack (postinstall RAT dropper) and Shai-Hulud 2.0 (retaliatory wiper "Dead Man's Switch") activate through lifecycle scripts.

### 🔍 Transparency & Signatures
All malware signatures (filenames, patterns, hashes) are stored in plain text within the source code. We explicitly avoid obfuscation techniques to distinguish this security tool from the malware it detects. You can inspect the signatures in `src/generated/signatures.ts`.

### 🔐 Trusted Publishing
This package is published with **npm provenance**. You can verify the build attestation on the npm registry to confirm that the package you are installing was built from this specific GitHub repository and has not been tampered with.

## Shai-Hulud 2.0 Detection

Worm Sign also covers the **Shai-Hulud 2.0** worm campaign (1,717+ compromised packages) with detection for high-entropy packed payloads, destructive wiper commands (`shred`, `del`), PowerShell installation vectors, and C2 signatures.

## Installation

```bash
npm install -g worm-sign
```

## Usage

### Basic Scan

Run the scanner in your project root. It uses the bundled list of banned packages by default.

```bash
worm-sign
```

### Fetch Latest Data

Fetch the latest list of vulnerable packages from configured remote sources (e.g., Datadog, Koi).

```bash
worm-sign --fetch
```

**Configured Remote Sources:**

- **Datadog**: [consolidated_iocs.csv](https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv)
- **Koi**: [export?format=csv](https://docs.google.com/spreadsheets/d/16aw6s7mWoGU7vxBciTEZSaR5HaohlBTfVirvI-PypJc/export?format=csv&gid=1289659284)

### Custom Data Source

You can also fetch from a custom URL. You must specify the data format (`json` or `csv`).

**JSON Format:**
Expects an object with a `packages` array: `{ "packages": [ { "name": "pkg", "version": "1.0.0" } ] }`.

```bash
worm-sign --url "https://example.com/vulns.json" --data-format json
```

> **Note:** The scanner will attempt to fetch from this URL in addition to other configured sources. If the fetch fails, it will warn you but continue scanning with other available sources.

**CSV Format:**
Expects a CSV with `name` and `version` columns (headers are ignored if they don't look like package names, but standard format is `name,version`).

```bash
worm-sign --url "https://example.com/vulns.csv" --data-format csv
```

**Hash Support:**
The CSV format also supports an optional `integrity` column (or `hash`, `shasum`). If provided, the scanner will verify the package integrity against your lockfile.

```csv
name,version,integrity
safe-package,1.0.0,sha512-badhash...
```


### Output Formats

Generate a SARIF report for security tools:

```bash
worm-sign --format sarif > results.sarif
```

### Git Hook

Install a pre-commit hook to automatically scan before every commit:

```bash
worm-sign --install-hook
```

### Caching

Disable caching if you need to force a fresh fetch:

```bash
worm-sign --fetch --no-cache
```

## CI/CD Integration

Add this to your GitHub Actions workflow:

```yaml
- name: Run Worm Sign
  run: npx worm-sign --format sarif
```

By default, `worm-sign` will:

1. Load all local `.csv` package lists from the `sources/` directory.
2. Fetch updates from any remote sources configured in `sources/*.json` (e.g., Datadog, Koi).
3. Fail the build if any banned packages are found (exit code 1).

You do not need to pass `--fetch` explicitly; the scanner automatically processes all configured sources.

## Network Requirements

Worm Sign fetches threat intelligence from the following public endpoints. Ensure your firewall allows outbound HTTPS (443) access to:

- **Datadog**: `raw.githubusercontent.com`
- **Koi**: `docs.google.com`

### Proxy Support
Worm Sign respects standard proxy environment variables. If you are behind a corporate proxy, set:

- `HTTPS_PROXY` (or `https_proxy`)
- `HTTP_PROXY` (or `http_proxy`)
- `NO_PROXY` (or `no_proxy`)

## Enterprise Usage

For large organizations or high-volume CI/CD environments, we recommend **mirroring** the data sources internally to avoid rate limiting or external dependency failures.

### Option 1: Internal Mirror (Recommended)

To avoid rate limiting or external dependency failures, you can host the data sources on an internal server (e.g., Artifactory, S3).

**If using the npm package directly:**
Use the `--offline` flag to disable default remote fetches, and provide your internal mirror URL via the `--url` flag.

**CSV Example:**

```bash
npx worm-sign --offline --url "https://internal.example.com/compromised-packages.csv" --data-format csv
```

**JSON Example:**

```bash
npx worm-sign --offline --url "https://internal.example.com/compromised-packages.json" --data-format json
```

**Self-Signed Certificates:**
If your internal server uses a self-signed certificate, use the `--insecure` flag to bypass SSL verification:

```bash
npx worm-sign --offline --insecure --url "https://internal.example.com/compromised-packages.json" --data-format json
```

**If maintaining a fork:**
Update the `sources/*.json` files in your repository to point to your internal URLs. This allows you to distribute a pre-configured version of the scanner to your team.

### Option 2: Offline Mode

If you prefer to rely solely on the bundled local CSVs (which are updated with each package release), you can disable remote fetching:

```bash
npx worm-sign --offline
```

This will only scan against the local `.csv` files found in the `sources/` directory.


---


## Command Line Options Reference

| Option                   | Description                                        | Default |
| ------------------------ | -------------------------------------------------- | ------- |
| `-f, --fetch`            | Fetch the latest compromised packages from the API | `false` |
| `-u, --url <url>`        | Custom API URL to fetch compromised packages from  | -       |
| `--data-format <format>` | Data format for custom URL (`json`, `csv`)         | `json`  |
| `-p, --path <path>`      | Path to the project to scan                        | `.`     |
| `--format <format>`      | Output format (`text`, `sarif`)                    | `text`  |
| `--no-cache`             | Disable caching of API responses                   | `false` |
| `--install-hook`         | Install a pre-commit hook to run worm-sign         | `false` |
| `--dry-run`              | Run scan but always exit with 0 (useful for CI)    | `false` |
| `--offline`              | Disable network requests (implies `--no-fetch`)    | `false` |
| `--insecure`             | Disable SSL certificate verification               | `false` |
| `--debug`                | Enable debug logging                               | `false` |

### Advanced Examples

**Scan a specific directory:**

```bash
worm-sign --path ./projects/my-app
```

**Run in CI (Dry Run):**
Use `--dry-run` to see what would be found without failing the build (exit code 0).

```bash
worm-sign --dry-run
```

**Debug Mode:**
Enable verbose logging to troubleshoot issues.

```bash
worm-sign --debug
```
---

## Acknowledgements

Threat intelligence is aggregated from the security research community, including:

**TanStack Attack (Wave 4):**
- [Snyk — TanStack npm Packages Compromised](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)

**Axios Attack:**
- [Socket.dev — Axios Compromise Analysis](https://socket.dev/blog/axios-npm-package-compromised)
- [Snyk — Axios Supply Chain Attack](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [Huntress — Axios Supply Chain Compromise](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package)
- [StepSecurity — Axios RAT Analysis](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Aikido Security — Axios Compromised](https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat)

**Shai-Hulud:**
- [DataDog Security Labs](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Socket.dev](https://socket.dev/blog/shai-hulud-strikes-again-v2)
- [GitGuardian](https://blog.gitguardian.com/shai-hulud-2/)
- [Wiz](https://www.wiz.io/blog/shai-hulud-strikes-again)
- [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect)
- [Phylum](https://blog.phylum.io/)
- [Aikido Security](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
