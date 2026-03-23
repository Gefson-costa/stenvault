/**
 * deriveThumbnailKeyFromMaster Tests (Phase 7.2)
 *
 * Tests the HKDF-based thumbnail key derivation from Master Key.
 * Verifies: determinism, uniqueness per fileId, correct key usages,
 * and stability of HKDF parameters (salt, info prefix).
 */

import { describe, it, expect, beforeAll, vi } from 'vitest';
import { deriveThumbnailKeyFromMaster } from './useMasterKey';

// Create a test HKDF key (deriveThumbnailKeyFromMaster now accepts HKDF CryptoKey directly)
async function createTestMasterKey(seed: Uint8Array): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        'raw',
        seed as BufferSource,
        'HKDF',
        false,
        ['deriveKey', 'deriveBits']
    );
}

describe('deriveThumbnailKeyFromMaster', () => {
    let masterKey: CryptoKey;
    const masterKeyBytes = new Uint8Array(32);

    beforeAll(async () => {
        // Fill with deterministic test data
        for (let i = 0; i < 32; i++) masterKeyBytes[i] = i;
        masterKey = await createTestMasterKey(masterKeyBytes);
    });

    it('should return a CryptoKey', async () => {
        const key = await deriveThumbnailKeyFromMaster(masterKey, '1');
        expect(key).toBeInstanceOf(CryptoKey);
    });

    it('should return an AES-GCM key', async () => {
        const key = await deriveThumbnailKeyFromMaster(masterKey, '1');
        expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    });

    it('should return a key with encrypt and decrypt usages', async () => {
        const key = await deriveThumbnailKeyFromMaster(masterKey, '1');
        expect(key.usages).toContain('encrypt');
        expect(key.usages).toContain('decrypt');
        expect(key.usages).toHaveLength(2);
    });

    it('should return a non-extractable key', async () => {
        const key = await deriveThumbnailKeyFromMaster(masterKey, '1');
        expect(key.extractable).toBe(false);
    });

    it('should produce deterministic output for same inputs', async () => {
        // Need fresh master key for each call since bytes are zeroed
        const mk1 = await createTestMasterKey(new Uint8Array(masterKeyBytes));
        const mk2 = await createTestMasterKey(new Uint8Array(masterKeyBytes));

        const key1 = await deriveThumbnailKeyFromMaster(mk1, '42');
        const key2 = await deriveThumbnailKeyFromMaster(mk2, '42');

        // Keys are not extractable, but we can test by encrypting same data
        const testData = new Uint8Array([1, 2, 3, 4, 5]);
        const iv = new Uint8Array(12); // all zeros for deterministic test

        const encrypted1 = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key1,
            testData
        );
        const encrypted2 = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key2,
            testData
        );

        // Same master key + same fileId → same derived key → same ciphertext
        expect(new Uint8Array(encrypted1)).toEqual(new Uint8Array(encrypted2));
    });

    it('should produce different keys for different fileIds', async () => {
        const mk1 = await createTestMasterKey(new Uint8Array(masterKeyBytes));
        const mk2 = await createTestMasterKey(new Uint8Array(masterKeyBytes));

        const key1 = await deriveThumbnailKeyFromMaster(mk1, '1');
        const key2 = await deriveThumbnailKeyFromMaster(mk2, '2');

        const testData = new Uint8Array([1, 2, 3, 4, 5]);
        const iv = new Uint8Array(12);

        const encrypted1 = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key1,
            testData
        );
        const encrypted2 = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key2,
            testData
        );

        // Different fileId → different derived key → different ciphertext
        expect(new Uint8Array(encrypted1)).not.toEqual(new Uint8Array(encrypted2));
    });

    it('should produce different keys for different master keys', async () => {
        const bytes1 = new Uint8Array(32);
        const bytes2 = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            bytes1[i] = i;
            bytes2[i] = 255 - i;
        }

        const mk1 = await createTestMasterKey(bytes1);
        const mk2 = await createTestMasterKey(bytes2);

        const key1 = await deriveThumbnailKeyFromMaster(mk1, '1');
        const key2 = await deriveThumbnailKeyFromMaster(mk2, '1');

        const testData = new Uint8Array([1, 2, 3, 4, 5]);
        const iv = new Uint8Array(12);

        const encrypted1 = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key1,
            testData
        );
        const encrypted2 = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key2,
            testData
        );

        // Different master key → different derived key → different ciphertext
        expect(new Uint8Array(encrypted1)).not.toEqual(new Uint8Array(encrypted2));
    });

    it('should handle numeric string fileIds', async () => {
        const mk = await createTestMasterKey(new Uint8Array(masterKeyBytes));
        const key = await deriveThumbnailKeyFromMaster(mk, '12345');
        expect(key).toBeInstanceOf(CryptoKey);
    });

    it('should handle empty string fileId', async () => {
        const mk = await createTestMasterKey(new Uint8Array(masterKeyBytes));
        const key = await deriveThumbnailKeyFromMaster(mk, '');
        expect(key).toBeInstanceOf(CryptoKey);
    });

    it('should produce a key that can encrypt and decrypt data', async () => {
        const mk = await createTestMasterKey(new Uint8Array(masterKeyBytes));
        const thumbnailKey = await deriveThumbnailKeyFromMaster(mk, '99');

        const plaintext = new Uint8Array([10, 20, 30, 40, 50]);
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            thumbnailKey,
            plaintext
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            thumbnailKey,
            ciphertext
        );

        expect(new Uint8Array(decrypted)).toEqual(plaintext);
    });

    it('should accept non-extractable HKDF key (no raw byte export needed)', async () => {
        // With Fix V1a, deriveThumbnailKeyFromMaster takes HKDF CryptoKey directly
        // and never calls exportKey on the master key — no raw bytes to zero
        const freshBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) freshBytes[i] = i + 100;
        const freshMk = await createTestMasterKey(freshBytes);

        const exportSpy = vi.spyOn(crypto.subtle, 'exportKey');

        await deriveThumbnailKeyFromMaster(freshMk, '1');

        // exportKey should NOT be called on the master key
        expect(exportSpy).not.toHaveBeenCalled();
        exportSpy.mockRestore();
    });
});
