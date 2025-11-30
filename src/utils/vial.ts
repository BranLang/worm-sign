/**
 * The "Vial" Protocol
 *
 * This module handles the runtime decryption of obfuscated signatures.
 * It uses a simple XOR cipher to prevent static analysis tools (AV/EDR)
 * from flagging the scanner itself as malware because it contains
 * malicious strings (e.g. "Shai-Hulud", "setup_bun.js").
 */

// The static key used for encryption/decryption.
// This matches the key in scripts/encrypt-signatures.ts
const CIPHER_KEY = 0x5f;

/**
 * Decrypts a buffer of XOR-encoded bytes back into a string.
 * @param encodedBytes The array of bytes to decrypt
 * @returns The decrypted string
 */
export function decrypt(encodedBytes: number[]): string {
  return encodedBytes
    .map((byte) => byte ^ CIPHER_KEY)
    .map((byte) => String.fromCharCode(byte))
    .join('');
}

/**
 * Helper to decrypt a list of signatures.
 * @param encodedSignatures Array of byte arrays
 * @returns Array of decrypted strings
 */
export function decryptAll(encodedSignatures: number[][]): string[] {
  return encodedSignatures.map(decrypt);
}
