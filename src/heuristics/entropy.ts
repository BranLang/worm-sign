/**
 * Shannon Entropy Analysis
 *
 * This module calculates the Shannon entropy of strings to detect
 * high-entropy content, which is often indicative of packed or
 * obfuscated malware payloads (e.g. bun_environment.js).
 */

/**
 * Calculates the Shannon entropy of a string.
 * Formula: H(X) = - sum(P(xi) * log2(P(xi)))
 *
 * @param str The input string
 * @returns The entropy value (typically between 0 and 8)
 */
export function calculateEntropy(input: string | Buffer): number {
    if (!input || input.length === 0) {
        return 0;
    }

    const frequencies: Record<number, number> = {};
    const len = input.length;

    for (let i = 0; i < len; i++) {
        const byte = typeof input === 'string' ? input.charCodeAt(i) : input[i];
        frequencies[byte] = (frequencies[byte] || 0) + 1;
    }

    let entropy = 0;

    for (const count of Object.values(frequencies)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }

    return entropy;
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
