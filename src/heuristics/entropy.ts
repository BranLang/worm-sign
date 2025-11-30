import { Readable } from 'stream';
/**
 * Shannon Entropy Analysis
 *
 * This module calculates the Shannon entropy of strings to detect
 * high-entropy content, which is often indicative of packed or
 * obfuscated malware payloads (e.g. bun_environment.js).
 */

export class EntropyCalculator {
  private frequencies: Record<number, number> = {};
  private totalBytes = 0;

  update(chunk: Buffer | string): void {
    const len = chunk.length;
    this.totalBytes += len;
    for (let i = 0; i < len; i++) {
      const byte = typeof chunk === 'string' ? chunk.charCodeAt(i) : chunk[i];
      this.frequencies[byte] = (this.frequencies[byte] || 0) + 1;
    }
  }

  digest(): number {
    if (this.totalBytes === 0) return 0;
    let entropy = 0;
    for (const count of Object.values(this.frequencies)) {
      const p = count / this.totalBytes;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}

/**
 * Calculates the Shannon entropy of a string.
 * Formula: H(X) = - sum(P(xi) * log2(P(xi)))
 *
 * @param str The input string
 * @returns The entropy value (typically between 0 and 8)
 */
export function calculateEntropy(input: string | Buffer): number {
  const calculator = new EntropyCalculator();
  calculator.update(input);
  return calculator.digest();
}

/**
 * Calculates entropy from a readable stream.
 */
export function calculateEntropyStream(stream: Readable): Promise<number> {
  return new Promise((resolve, reject) => {
    const calculator = new EntropyCalculator();
    stream.on('data', (chunk) => calculator.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(calculator.digest()));
  });
}

/**
 * Checks if a string has suspiciously high entropy.
 *
 * @param str The string to check
 * @param threshold The threshold (default 5.2 based on research)
 * @returns True if entropy exceeds threshold
 */
export function isHighEntropy(str: string, threshold = 5.2): boolean {
  // Short strings can have artificially high or low entropy and are less likely to be packed payloads
  if (str.length < 50) {
    return false;
  }
  return calculateEntropy(str) > threshold;
}
