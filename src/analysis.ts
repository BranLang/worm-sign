import { MALWARE_PATTERNS } from './generated/signatures';
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
  [key: string]: unknown;
}

import { Finding, Severity } from './types';
import { WormSignConfig } from './config';

export function analyzeScripts(pkgJson: PackageJson, config?: WormSignConfig): Finding[] {
  const findings: Finding[] = [];
  const scripts = pkgJson.scripts || {};
  const suppressed = new Set(config?.suppressedRules || []);

  // Map of regex patterns to labels
  const PATTERNS = [
    {
      regex: /(curl|wget)\s+/,
      label: 'Network request (curl/wget)',
      id: 'network-request',
      severity: 'medium',
    },
    { regex: /\|\s*bash/, label: 'Pipe to bash', id: 'pipe-to-bash', severity: 'high' },
    {
      regex: /[A-Za-z0-9+/]{60,}={0,2}/,
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
      regex: /rm\s+(-rf|-fr)\s+[\s\S]*/,
      label: 'Destructive command (rm -rf)',
      id: 'destructive-rm',
      severity: 'high',
    },
    {
      regex: /nc\s+.*-e\s+/,
      label: 'Netcat reverse shell',
      id: 'netcat-shell',
      severity: 'critical',
    },
    {
      regex: /(python|perl|ruby|node|sh|bash)\s+-[ce]\s+/,
      label: 'Inline code execution',
      id: 'inline-exec',
      severity: 'medium',
    },
    {
      regex: /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/,
      label: 'IP address detected',
      id: 'ip-address',
      severity: 'medium',
    },
    {
      regex: /execSync\s*\(.*nohup/,
      label: 'Background process execution via execSync+nohup (RAT dropper pattern)',
      id: 'execsync-nohup',
      severity: 'critical',
    },
    {
      regex: /fs\.unlink.*setup\.(js|ts)/,
      label: 'Self-deleting dropper script',
      id: 'self-deleting-script',
      severity: 'critical',
    },
    {
      regex: /irm\s+.*\|.*iex/,
      label: 'PowerShell remote execution (irm|iex)',
      id: 'powershell-remote-exec',
      severity: 'critical',
    },
    {
      regex: /xor|XOR.*cipher|String\.fromCharCode\s*\(\s*.*\^\s*\d+/,
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

// Known-malicious git refs used by supply-chain worms to smuggle payloads via
// `optionalDependencies` / `dependencies`. The TanStack wave 4 (May 2026) attack
// pinned this orphan commit on `tanstack/router` to deliver router_init.js.
const KNOWN_BAD_GIT_REFS = [
  '79ac49eedf774dd4b0cfa308722bc463cfe5885c',
  '79ac49eedf', // truncated form commonly used in package.json
];

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

  return findings;
}
