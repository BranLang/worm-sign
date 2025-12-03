# Worm Sign 🪱🚫

[![CI Status](https://github.com/BranLang/worm-sign/actions/workflows/ci.yml/badge.svg)](https://github.com/BranLang/worm-sign/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/worm-sign.svg)](https://badge.fury.io/js/worm-sign)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm provenance](https://img.shields.io/badge/provenance-verified-green)](https://docs.npmjs.com/generating-provenance-statements)

> "We have wormsign the likes of which even God has never seen."

**Worm Sign** is a specialized scanner designed to detect and block npm packages compromised by the **Shai Hulud** malware campaign. It scans your project's `package.json` and lockfiles against a curated list of **1,717 known compromised packages**.

## Features

- **Safe Static Analysis**: Uses `@npmcli/arborist` to inspect the dependency tree without executing any lifecycle scripts, neutralizing the malware's "Dead Man's Switch".
- **Detects Shai Hulud**: Identifies **1,717** packages known to be compromised by the Shai Hulud malware.
- **Hash-Based Detection**: Detects compromised packages by their integrity hash (SHA-1/SHA-512), catching variants even if they are renamed or version-spoofed.
- **Lockfile Required**: Scans `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`. **A lockfile is required for analysis.**
- **API Integration**: Fetches the latest banned list from a remote API (customizable).
- **Smart Caching**: Caches API responses locally for 1 hour to improve performance.
- **Heuristic Analysis**: Scans `package.json` scripts for suspicious patterns (e.g., `curl | bash`, `rm -rf`, reverse shells, obfuscated code).
- **Entropy Analysis**: Detects high-entropy files (potential obfuscated malware payloads) > 5MB.
- **Behavioral Detection**: Identifies destructive commands (`shred`, `del`) and known C2 signatures.
- **SARIF Output**: Generates SARIF reports for integration with GitHub Security.
- **CI/CD Ready**: Easily integrates into GitHub Actions or other CI pipelines.

## Shai-Hulud 2.0 Detection

Worm Sign includes advanced detection logic specifically for the **Shai-Hulud 2.0** campaign:

- **File Entropy**: Analyzes large files (>5MB) for high entropy, a common indicator of packed/obfuscated malware payloads (e.g., `bun_environment.js`).
- **Destructive Commands**: Flags scripts containing system-wiping commands like `shred -uvz -n 1` (Linux/macOS) and `del /F /Q /S "%USERPROFILE%*"` (Windows).
- **Installation Vectors**: Detects specific installation patterns used by the malware, such as `irm bun.sh/install.ps1|iex` (PowerShell Bun install).
- **C2 Signatures**: Scans for known Command & Control signatures like `"Sha1-Hulud: The Second Coming"`.

## Safety & Trust

### 🛡️ "Dead Man's Switch" Neutralization
Shai-Hulud 2.0 contains a retaliatory wiper that triggers if analysis is detected or network calls fail. **Worm Sign** neutralizes this by using **Safe Static Analysis**. It parses your lockfile directly (using `Arborist.loadVirtual()`) to build an in-memory dependency graph. It **never** runs `npm install` or executes `preinstall`/`postinstall` scripts during scanning, ensuring the malware is never given a chance to execute.

### 🔍 Transparency & Signatures
To ensure full transparency, **Worm Sign** stores all malware signatures (filenames, patterns) in plain text within the source code. We explicitly avoid obfuscation techniques to distinguish this security tool from the malware it detects. You can inspect the signatures in `src/generated/signatures.ts`.

### 🔐 Trusted Publishing
This package is published with **npm provenance**. You can verify the build attestation on the npm registry to confirm that the package you are installing was built from this specific GitHub repository and has not been tampered with.

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

The bundled data sources aggregate findings from various security research teams and community projects, including:

- [DataDog Security Labs](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Aikido Security](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)
- [Socket.dev](https://socket.dev/blog/shai-hulud-strikes-again-v2)
- [GitGuardian](https://blog.gitguardian.com/shai-hulud-2/)
- [Wiz](https://www.wiz.io/blog/shai-hulud-strikes-again)
- [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect)
- [Phylum](https://blog.phylum.io/)
- [Truesec](https://www.truesec.com/hub/blog)
- [IBM X-Force](https://www.ibm.com/x-force)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
