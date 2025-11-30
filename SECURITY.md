# Security Policy

## Supported Versions

We prioritize security updates for the latest major version.

| Version | Supported          | Notes                                  |
| ------- | ------------------ | -------------------------------------- |
| 3.x.x   | :white_check_mark: | Current Release (Safe Static Analysis) |
| < 3.0.0 | :x:                | Deprecated (Unsafe Dynamic Analysis)   |

## Reporting a Vulnerability

We take the security of `worm-sign` seriously. If you discover a vulnerability, especially one that could compromise the safety of the scanner itself (e.g., bypassing the "Dead Man's Switch" protection), please report it immediately.

### How to Report

Please **DO NOT** open a public issue on GitHub for sensitive security vulnerabilities.

1.  Email the maintainers directly at [security@example.com](mailto:security@example.com) (replace with actual email if available, or use GitHub Security Advisories if enabled).
2.  Include a proof of concept (PoC) if possible.
3.  We will acknowledge your report within 48 hours.

### Scope

We are particularly interested in:
*   Bypasses of the static analysis engine (Arborist integration).
*   Methods to trigger code execution during a scan.
*   Leaks of the obfuscated signatures (Vial protocol weaknesses).

### False Positives

If `worm-sign` incorrectly flags a safe package, please open a standard GitHub Issue with the tag `false-positive`. This helps us improve our heuristics.
