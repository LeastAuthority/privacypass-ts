import { randomBytes, createHash } from 'crypto';

/**
 * Commits to the input by hashing it concatenated with a random blinding factor.
 * @param input - The input bytes to commit to.
 * @returns An object containing the commitment (SHA-256 hash) and the blinding factor.
 */
export function commit(input: Uint8Array): { commitment: Uint8Array; blinding_factor: Uint8Array } {
    // the input is expected to have exactly 32 bytes
    const EXPECTED_INPUT_LENGTH = 32;
    if (input.length !== EXPECTED_INPUT_LENGTH) {
        throw new Error('input must be exactly 32 bytes');
    }
    const BLINDING_FACTOR_LENGTH = 32;
    const blinding_factor = randomBytes(BLINDING_FACTOR_LENGTH);
    const data = new Uint8Array(EXPECTED_INPUT_LENGTH + BLINDING_FACTOR_LENGTH);
    data.set(input, 0);
    data.set(blinding_factor, EXPECTED_INPUT_LENGTH);
    const hash = createHash('sha256').update(new Uint8Array(data)).digest();
    return {
        commitment: new Uint8Array(hash),
        blinding_factor: new Uint8Array(blinding_factor)
    };
}