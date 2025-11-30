# Enterprise Deployment Playbook

This guide provides recommendations for deploying Worm Sign in enterprise environments, focusing on CI/CD integration, internal mirroring, and policy enforcement.

## CI/CD Integration

### GitHub Actions

Add a workflow file `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  worm-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Worm Sign
        run: npx worm-sign@latest --fetch --format sarif > worm-sign-results.sarif
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: worm-sign-results.sarif
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
worm-sign:
  stage: test
  image: node:18
  script:
    - npx worm-sign@latest --fetch
  allow_failure: true
```

## Internal Mirroring

To avoid rate limits and reliance on external services, we recommend mirroring the threat intelligence data internally.

1.  **Fetch Data**: Create a cron job to fetch the CSV/JSON files from the [Network Requirements](../README.md#network-requirements) endpoints.
2.  **Host Internally**: Host these files on an internal static file server or artifact registry (e.g., Artifactory, S3).
3.  **Configure Worm Sign**: Point Worm Sign to your internal mirror using `.wormsignrc`:

```json
{
  "allowedSources": ["internal-mirror"],
  "offline": false
}
```

And run with:
```bash
worm-sign --url https://internal.example.com/threat-intel.json --data-format json
```

## Policy Enforcement

Use `.wormsignrc` to enforce security policies across your organization.

### Example: Strict Mode

```json
{
  "offline": true,
  "severityThreshold": "medium",
  "suppressedRules": []
}
```

### Example: Legacy Project (Lenient)

```json
{
  "severityThreshold": "high",
  "suppressedRules": ["network-request"]
}
```
