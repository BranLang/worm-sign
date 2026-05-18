import { MALWARE_PATTERNS, KNOWN_BAD_GIT_REFS } from './generated/signatures';
import { isHighEntropy } from './heuristics/entropy';

/**
 * Analyzes package scripts for suspicious patterns and high entropy.
 */
interface PackageJson {
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  bundleDependencies?: string[] | Record<string, string>;
  binary?: {
    host?: string;
    remote_path?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

// Hosts commonly used by legitimate native-module distributors via node-pre-gyp
// or prebuild-install. A binary.host outside this set is not necessarily
// malicious, but is worth a manual review — it bypasses lockfile integrity
// (the binary is fetched at install time, not from the npm tarball).
const LEGIT_BINARY_HOSTS = [
  /(^|\.)github\.com$/i,
  /(^|\.)githubusercontent\.com$/i,
  /(^|\.)npmjs\.(com|org)$/i,
  /(^|\.)nodejs\.org$/i,
  /(^|\.)jsdelivr\.net$/i,
  /(^|\.)unpkg\.com$/i,
  /(^|\.)cloudfront\.net$/i, // many vendors host on cloudfront subdomains
  /(^|\.)amazonaws\.com$/i, // S3 buckets are very common for prebuilts
  /(^|\.)mapbox\.com$/i,
  /(^|\.)microsoft\.com$/i,
];

import { Finding, Severity } from './types';
import { WormSignConfig } from './config';

export function analyzeScripts(pkgJson: PackageJson, config?: WormSignConfig): Finding[] {
  const findings: Finding[] = [];
  const scripts = pkgJson.scripts || {};
  const suppressed = new Set(config?.suppressedRules || []);

  // Map of regex patterns to labels
  const PATTERNS = [
    {
      // Only flag curl/wget when a URL follows on the same line — avoids
      // matching `curl --version` / `wget --help` / docs strings.
      regex: /\b(curl|wget)\b[^\n]*\bhttps?:\/\//i,
      label: 'Network request to URL via curl/wget',
      id: 'network-request',
      severity: 'medium',
    },
    { regex: /\|\s*bash\b/, label: 'Pipe to bash', id: 'pipe-to-bash', severity: 'high' },
    {
      // Require `=` padding and 80+ chars. The previous {60,}={0,2} matched
      // long hashes / JWTs / build IDs / npm integrity strings, producing
      // noisy false positives in legit build scripts.
      regex: /[A-Za-z0-9+/]{80,}={1,2}\b/,
      label: 'Potential Base64 encoded string',
      id: 'base64-string',
      severity: 'medium',
    },
    {
      regex: /\\x[0-9a-fA-F]{2}/,
      label: 'Hex escape sequence (obfuscation)',
      id: 'hex-obfuscation',
      severity: 'high',
    },
    { regex: /eval\s*\(/, label: 'Use of eval()', id: 'eval-usage', severity: 'high' },
    {
      regex: /\brm\s+(-rf|-fr)\b/,
      label: 'Destructive command (rm -rf)',
      id: 'destructive-rm',
      severity: 'high',
    },
    {
      regex: /\bnc\b[^\n]*-e\s+/,
      label: 'Netcat reverse shell',
      id: 'netcat-shell',
      severity: 'critical',
    },
    {
      // Require a following quoted expression so we don't match harmless
      // `node -e` flag mentions in help text or `bash -c` followed by nothing.
      regex: /\b(python3?|perl|ruby|node|sh|bash)\s+-[ce]\s+["'`]/,
      label: 'Inline code execution',
      id: 'inline-exec',
      severity: 'medium',
    },
    {
      // Public-IP literal. Excludes RFC1918 (10/8, 172.16/12, 192.168/16),
      // loopback (127/8), link-local (169.254/16), multicast (224-239),
      // CGNAT (100.64/10), RFC5737 docs (192.0.2/24, 198.51.100/24,
      // 203.0.113/24), and 255.x. Lookarounds also exclude `-` adjacency
      // so semver-in-identifier patterns (`build-1.2.3.4-rc`) are skipped.
      regex:
        /(?<![\d.-])(?!10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|22[4-9]\.|23\d\.|255\.)(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})(?![\d.-])/,
      label: 'Public IP address literal in script',
      id: 'ip-address',
      severity: 'medium',
    },
    {
      regex: /\bexecSync\s*\([^)]*nohup/,
      label: 'Background process execution via execSync+nohup (RAT dropper pattern)',
      id: 'execsync-nohup',
      severity: 'critical',
    },
    {
      regex: /\bfs\.unlink[^(]*\([^)]*setup\.(js|ts)/,
      label: 'Self-deleting dropper script',
      id: 'self-deleting-script',
      severity: 'critical',
    },
    {
      regex: /\birm\b[^\n]*\|\s*iex\b/i,
      label: 'PowerShell remote execution (irm|iex)',
      id: 'powershell-remote-exec',
      severity: 'critical',
    },
    {
      // Old pattern matched any lowercase `xor` substring — flagged
      // function names like `xorBuffer`, `xorshift`, harmless RNGs.
      // Restrict to the actual deobfuscation idiom.
      regex: /String\.fromCharCode\s*\(\s*[^)]*\^\s*\d+/,
      label: 'XOR-based string obfuscation',
      id: 'xor-obfuscation',
      severity: 'high',
    },
  ] as const;

  for (const [name, script] of Object.entries(scripts) as [string, string][]) {
    // 1. Check for high entropy (obfuscation)
    if (isHighEntropy(script)) {
      const ruleId = 'high-entropy';
      if (!suppressed.has(ruleId)) {
        findings.push({
          message: `Suspicious script detected in '${name}': High Entropy (Potential Obfuscated Payload)`,
          severity: 'high',
          ruleId,
          file: 'package.json',
        });
      }
    }

    // 2. Check for generic suspicious patterns
    for (const pattern of PATTERNS) {
      if (pattern.regex.test(script)) {
        if (!suppressed.has(pattern.id)) {
          findings.push({
            message: `Suspicious script detected in '${name}': ${pattern.label}`,
            severity: pattern.severity as Severity,
            ruleId: pattern.id,
            file: 'package.json',
          });
        }
      }
    }

    // 3. Check for specific signatures (Shai-Hulud specific)
    for (const signature of MALWARE_PATTERNS) {
      if (script.includes(signature)) {
        const ruleId = 'known-signature';
        if (!suppressed.has(ruleId)) {
          findings.push({
            message: `Suspicious script detected in '${name}': Known Malware Signature Match`,
            severity: 'critical',
            ruleId,
            file: 'package.json',
          });
        }
      }
    }
  }

  return findings;
}

const DEP_SECTIONS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
  'bundleDependencies',
] as const;

/**
 * Analyzes package.json manifest fields (dependencies, optionalDependencies, etc.)
 * for tampering patterns used by supply-chain worms — particularly the TanStack
 * wave 4 attack, which smuggles its payload via an optionalDependencies entry
 * pointing at an orphan git commit rather than via lifecycle scripts.
 */
export function analyzeManifest(pkgJson: PackageJson, config?: WormSignConfig): Finding[] {
  const findings: Finding[] = [];
  const suppressed = new Set(config?.suppressedRules || []);

  for (const section of DEP_SECTIONS) {
    const deps = pkgJson[section];
    if (!deps || Array.isArray(deps)) continue;
    for (const [depName, depSpec] of Object.entries(deps as Record<string, string>)) {
      if (typeof depSpec !== 'string') continue;

      // 1. Exact known-bad git refs (TanStack wave 4 orphan commit)
      for (const badRef of KNOWN_BAD_GIT_REFS) {
        if (depSpec.includes(badRef)) {
          const ruleId = 'malicious-git-ref';
          if (!suppressed.has(ruleId)) {
            findings.push({
              message: `Malicious git ref in ${section}.${depName}: pinned to known-bad commit '${badRef}' (TanStack wave 4 / GHSA-g7cv-rxg3-hmpx)`,
              severity: 'critical',
              ruleId,
              file: 'package.json',
            });
          }
        }
      }

      // 2. The exact phantom dep name used by the TanStack worm
      if (depName === '@tanstack/setup' && section === 'optionalDependencies') {
        const ruleId = 'tanstack-setup-phantom-dep';
        if (!suppressed.has(ruleId)) {
          findings.push({
            message: `Phantom dependency '@tanstack/setup' in optionalDependencies — TanStack wave 4 (GHSA-g7cv-rxg3-hmpx) installation vector`,
            severity: 'critical',
            ruleId,
            file: 'package.json',
          });
        }
      }

      // 3. Generic suspicious git: refs pinning a 40-char commit on a 3rd-party namespace
      //    inside optionalDependencies — a common worm-installation pattern.
      if (
        section === 'optionalDependencies' &&
        /^(github:|git\+|git:)/i.test(depSpec) &&
        /[#@][a-f0-9]{40}\b/.test(depSpec)
      ) {
        const ruleId = 'commit-pinned-optional-dep';
        if (!suppressed.has(ruleId)) {
          findings.push({
            message: `Suspicious commit-pinned git dependency in optionalDependencies.${depName}: '${depSpec}' (review carefully — this pattern is used by supply-chain worms)`,
            severity: 'high',
            ruleId,
            file: 'package.json',
          });
        }
      }
    }
  }

  // 4. binary.host check: native-module packages fetch a prebuilt binary at
  //    install time. The binary is NOT covered by the lockfile integrity hash,
  //    so attacker control of `binary.host` (or `remote_path`) is a direct
  //    code-exec channel during `npm install`. Flag if the host isn't one of
  //    the common legit hosts.
  const binaryHost = pkgJson.binary?.host;
  if (typeof binaryHost === 'string' && binaryHost.length > 0) {
    let parsedHost: string | null = null;
    try {
      parsedHost = new URL(binaryHost).hostname;
    } catch {
      // Not a valid URL — flag, since the field is misformed in a way that
      // could break tooling assumptions.
    }
    const isLegit =
      parsedHost !== null && LEGIT_BINARY_HOSTS.some((re) => re.test(parsedHost));
    if (!isLegit) {
      const ruleId = 'binary-host-unknown';
      if (!suppressed.has(ruleId)) {
        findings.push({
          message: `package.json binary.host points to a non-standard host '${binaryHost}' — install-time binary fetch bypasses lockfile integrity; verify the host is trusted`,
          severity: 'medium',
          ruleId,
          file: 'package.json',
        });
      }
    }
  }

  return findings;
}
