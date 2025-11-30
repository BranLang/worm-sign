import { MALWARE_PATTERNS } from './generated/signatures';
import { isHighEntropy } from './heuristics/entropy';

/**
 * Analyzes package scripts for suspicious patterns and high entropy.
 */
interface PackageJson {
  scripts?: Record<string, string>;
  [key: string]: unknown;
}

export function analyzeScripts(pkgJson: PackageJson): string[] {
  const warnings: string[] = [];
  const scripts = pkgJson.scripts || {};

  // Map of regex patterns to labels
  const PATTERNS = [
    { regex: /(curl|wget)\s+/, label: 'Network request (curl/wget)' },
    { regex: /\|\s*bash/, label: 'Pipe to bash' },
    { regex: /[A-Za-z0-9+/]{60,}={0,2}/, label: 'Potential Base64 encoded string' },
    { regex: /\\x[0-9a-fA-F]{2}/, label: 'Hex escape sequence (obfuscation)' },
    { regex: /eval\s*\(/, label: 'Use of eval()' },
    { regex: /rm\s+(-rf|-fr)\s+[\s\S]*/, label: 'Destructive command (rm -rf)' },
    { regex: /nc\s+.*-e\s+/, label: 'Netcat reverse shell' },
    { regex: /(python|perl|ruby|node|sh|bash)\s+-[ce]\s+/, label: 'Inline code execution' },
    { regex: /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/, label: 'IP address detected' },
  ];

  for (const [name, script] of Object.entries(scripts) as [string, string][]) {
    // 1. Check for high entropy (obfuscation)
    if (isHighEntropy(script)) {
      warnings.push(
        `Suspicious script detected in '${name}': High Entropy (Potential Obfuscated Payload)`,
      );
    }

    // 2. Check for generic suspicious patterns
    for (const pattern of PATTERNS) {
      if (pattern.regex.test(script)) {
        warnings.push(`Suspicious script detected in '${name}': ${pattern.label}`);
      }
    }

    // 3. Check for specific signatures (Shai-Hulud specific)
    for (const signature of MALWARE_PATTERNS) {
      if (script.includes(signature)) {
        warnings.push(`Suspicious script detected in '${name}': Known Malware Signature Match`);
      }
    }
  }

  return warnings;
}
