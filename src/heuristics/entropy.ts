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
export function calculateEntropy(str: string): number {
    if (!str || str.length === 0) {
        return 0;
    }

    const frequencies: Record<string, number> = {};
    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;

    for (const char in frequencies) {
        const p = frequencies[char] / len;
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
