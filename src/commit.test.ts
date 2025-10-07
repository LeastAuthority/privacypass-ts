import { describe, expect, test } from 'vitest';
import { commit } from './commit';
import { randomBytes, createHash } from 'crypto';

describe('commit', () => {
    test('returns correct commitment and blinding factor for valid input', () => {
        // Arrange
        const input = new Uint8Array(32);
        for (let i = 0; i < 32; i++) input[i] = i;

        const { commitment, blinding_factor } = commit(input);

        const data = new Uint8Array(64);
        data.set(input, 0);
        data.set(blinding_factor, 32);
        const expectedCommitment = createHash('sha256').update(data).digest();
        expect(commitment).toEqual(new Uint8Array(expectedCommitment));
    });

    test('throws error if input is not 32 bytes', () => {
        expect(() => commit(new Uint8Array(31))).toThrow('input must be exactly 32 bytes');
        expect(() => commit(new Uint8Array(33))).toThrow('input must be exactly 32 bytes');
    });

    test('blinding factor is random for different calls', () => {
        const input = randomBytes(32);
        const result1 = commit(input);
        const result2 = commit(input);
        expect(result1.blinding_factor).not.toEqual(result2.blinding_factor);
        expect(result1.commitment).not.toEqual(result2.commitment);
    });
});
