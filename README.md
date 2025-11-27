# Worm Sign 🪱🚫

> "We have wormsign the likes of which even God has never seen."

**Worm Sign** is a specialized scanner designed to detect and block npm packages compromised by the **Shai Hulud** malware campaign. It scans your project's `package.json` and lockfiles against a list of known banned packages.

## Features
- **Detects Shai Hulud**: Identifies packages known to be compromised by the Shai Hulud malware.
- **Premium CLI**: Beautiful, table-based output with Dune-themed visuals.
- **Lockfile Support**: Scans `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`.
- **API Integration**: Fetches the latest banned list from a remote API (customizable).
- **Smart Caching**: Caches API responses locally for 1 hour to improve performance.
- **Heuristic Analysis**: Scans `package.json` scripts for suspicious patterns (e.g., `curl | bash`, base64).
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
Fetch the latest list of vulnerable packages from the default source (IBM internal API).
```bash
worm-sign --fetch
```

### Select Data Source
You can specify the data source using the `--source` flag. Available sources:
- `ibm` (default): IBM internal JSON API (requires VPN).
- `koi`: Koi Security live CSV feed (public).

```bash
worm-sign --fetch --source koi
```

### Custom Data Source
You can also fetch from a custom URL. You must specify the data format (`json` or `csv`).

**JSON Format:**
Expects an object with a `packages` array: `{ "packages": [ { "name": "pkg", "version": "1.0.0" } ] }`.
```bash
worm-sign --fetch --url "https://example.com/vulns.json" --data-format json
```

**CSV Format:**
Expects a CSV with `name` and `version` columns (headers are ignored if they don't look like package names, but standard format is `name,version`).
```bash
worm-sign --fetch --url "https://example.com/vulns.csv" --data-format csv
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
  run: npx worm-sign --fetch --format sarif
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

