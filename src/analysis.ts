import { MALWARE_PATTERNS } from './generated/signatures';
import { isHighEntropy } from './heuristics/entropy';

/**
 * Analyzes package scripts for suspicious patterns and high entropy.
 */
interface PackageJson {
  scripts?: Record<string, string>;
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
