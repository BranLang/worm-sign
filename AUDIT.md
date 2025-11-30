# Audit Report: Worm Sign

## Executive Summary
The `worm-sign` tool is a robust security scanner with a solid foundation. It effectively uses safe static analysis (`@npmcli/arborist`) to detect malicious packages without executing them, which is a critical feature for this type of tool.

However, during the audit, we identified two key areas for improvement:
1.  **Security**: Vulnerability to DNS Rebinding attacks (SSRF).
2.  **Performance**: High memory usage when scanning large files for entropy.

Both issues have been addressed and patched.

## Findings & Improvements

### 1. SSRF Protection (DNS Rebinding)
**Severity**: Medium
**Issue**: The original `validateUrl` function checked if a hostname resolved to a private IP, but the subsequent `https.get` request performed a *new* DNS lookup. This time-of-check to time-of-use (TOCTOU) gap allowed an attacker to change the DNS record between the check and the connection, potentially tricking the scanner into connecting to an internal service (SSRF).
**Fix**:
-   Updated `validateUrl` to return the resolved IP address.
-   Modified `fetchFromApi` to connect directly to this resolved IP while setting the `Host` header and SNI to the original hostname. This pins the connection to the validated IP, eliminating the race condition.

### 2. Memory Optimization (Streaming Entropy)
**Severity**: Low (Performance)
**Issue**: The scanner used `fs.readFileSync` to load files into memory before calculating entropy. For large files (>5MB), this could cause spikes in memory usage, especially if multiple large files were scanned concurrently or in a constrained CI environment.
**Fix**:
-   Implemented a streaming `EntropyCalculator` class.
-   Refactored `scanProject` to use `fs.createReadStream`.
-   The scanner now calculates SHA-256 hashes and entropy (for large files) in a single pass over the file stream, significantly reducing memory footprint.

## Code Quality & Architecture
-   **Strengths**:
    -   Use of `Arborist` for safe scanning.
    -   Runtime signature decryption (Vial protocol) adds a layer of defense against static analysis.
    -   Modular structure (`analysis`, `heuristics`, `utils`).
-   **Recommendations**:
    -   **Error Handling**: Some error messages could be more specific.
    -   **Tests**: Maintain high coverage. The current test suite is comprehensive.

## Verification
-   **Tests**: All existing tests (CLI, README commands) passed after the changes.
-   **Manual**: Verified that the tool still correctly scans the local project.
