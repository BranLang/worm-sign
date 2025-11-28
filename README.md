# Worm Sign 🪱🚫

> "We have wormsign the likes of which even God has never seen."

**Worm Sign** is a specialized scanner designed to detect and block npm packages compromised by the **Shai Hulud** malware campaign. It scans your project's `package.json` and lockfiles against a list of known banned packages.

## Features
- **Detects Shai Hulud**: Identifies packages known to be compromised by the Shai Hulud malware.
- **Hash-Based Detection**: Detects compromised packages by their integrity hash (SHA-1/SHA-512), catching variants even if they are renamed or version-spoofed.
- **Lockfile Support**: Scans `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`.
- **API Integration**: Fetches the latest banned list from a remote API (customizable).
- **Smart Caching**: Caches API responses locally for 1 hour to improve performance.
- **Heuristic Analysis**: Scans `package.json` scripts for suspicious patterns (e.g., `curl | bash`, `rm -rf`, reverse shells, obfuscated code).
- **SARIF Output**: Generates SARIF reports for integration with GitHub Security.
- **CI/CD Ready**: Easily integrates into GitHub Actions or other CI pipelines.


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

## Enterprise Usage

For large organizations or high-volume CI/CD environments, we recommend **mirroring** the data sources internally to avoid rate limiting or external dependency failures.

### Option 1: Internal Mirror (Recommended)
1. Host the `.csv` files on an internal server (e.g., Artifactory, S3).
2. Update the `sources/*.json` files in your fork/repo to point to your internal URLs.

### Option 2: Offline Mode
If you prefer to rely solely on the bundled local CSVs (which are updated with each package release), you can disable remote fetching:

```bash
npx worm-sign --offline
```

This will only scan against the local `.csv` files found in the `sources/` directory.

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

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

