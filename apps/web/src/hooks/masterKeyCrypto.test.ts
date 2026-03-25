/**
 * Master Key Crypto Tests
 *
 * Tests all pure crypto exports from masterKeyCrypto.ts using real WebCrypto APIs.
 * Argon2 provider is mocked since hash-wasm requires WASM initialization.
 *
 * Tests:
 * - encryptLargeSecretKey / decryptLargeSecretKey roundtrip
 * - deriveArgon2Key
 * - unwrapMasterKey
 * - deriveFileKeyFromMaster
 * - deriveFilenameKeyFromMaster
 * - deriveFingerprintKeyFromMaster
 * - deriveThumbnailKeyFromMaster
 *
 * @module masterKeyCrypto.test
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============ Mocks ============

const mockDeriveKey = vi.fn();

vi.mock('@/lib/platform/webArgon2Provider', () => ({
    getArgon2Provider: () => ({
        deriveKey: (...args: unknown[]) => mockDeriveKey(...args),
    }),
}));

vi.mock('@/lib/platform', () => ({
    base64ToArrayBuffer: (base64: string): ArrayBuffer => {
        const raw = atob(base64);
        const bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) {
            bytes[i] = raw.charCodeAt(i);
        }
        return bytes.buffer;
    },
    toArrayBuffer: (data: Uint8Array): ArrayBuffer => {
        const buf = new ArrayBuffer(data.byteLength);
        new Uint8Array(buf).set(data);
        return buf;
    },
}));

// Import AFTER mocks
import {
    encryptLargeSecretKey,
    decryptLargeSecretKey,
    deriveArgon2Key,
    unwrapMasterKey,
    createMasterKeyBundle,
    wrapSecretWithMK,
    unwrapSecretWithMK,
    deriveFileKeyFromMaster,
    deriveFilenameKeyFromMaster,
    deriveFoldernameKeyFromMaster,
    deriveFingerprintKeyFromMaster,
    deriveThumbnailKeyFromMaster,
} from './masterKeyCrypto';

// ============ Helpers ============

async function generateMasterKeyBytes(length = 32): Promise<Uint8Array> {
    return crypto.getRandomValues(new Uint8Array(length));
}

async function generateAesGcmKey(extractable = true): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        extractable,
        ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
}

async function generateAesKwKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
        { name: 'AES-KW', length: 256 },
        true,
        ['wrapKey', 'unwrapKey']
    );
}

/** Generate an HKDF key from random bytes (for derive* function tests) */
async function generateHkdfKey(): Promise<CryptoKey> {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    return crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey', 'deriveBits']);
}

async function exportKeyRaw(key: CryptoKey): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

// Compare two CryptoKeys by raw bytes (only for extractable keys)
async function keysEqual(a: CryptoKey, b: CryptoKey): Promise<boolean> {
    const aBytes = await exportKeyRaw(a);
    const bBytes = await exportKeyRaw(b);
    if (aBytes.length !== bBytes.length) return false;
    return aBytes.every((byte, i) => byte === bBytes[i]);
}

// Get fingerprint for non-extractable key by encrypting known data
const TEST_DATA = new TextEncoder().encode('masterKeyCrypto test vector');
const FIXED_IV = new Uint8Array(12);

async function keyFingerprint(key: CryptoKey): Promise<string> {
    // For HMAC keys, sign instead of encrypt
    if (key.algorithm.name === 'HMAC') {
        const sig = await crypto.subtle.sign('HMAC', key, TEST_DATA);
        return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: FIXED_IV },
        key,
        TEST_DATA
    );
    return Array.from(new Uint8Array(ct)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============ Tests ============

describe('masterKeyCrypto', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    // ==================== encryptLargeSecretKey / decryptLargeSecretKey ====================

    describe('encryptLargeSecretKey / decryptLargeSecretKey', () => {
        it('should roundtrip a 32-byte key', async () => {
            const masterKey = await generateMasterKeyBytes(32);
            const secretKey = crypto.getRandomValues(new Uint8Array(32));

            const encrypted = await encryptLargeSecretKey(secretKey, masterKey);
            const decrypted = await decryptLargeSecretKey(encrypted, masterKey);

            expect(decrypted).toEqual(secretKey);
        });

        it('should roundtrip a 2400-byte key (ML-KEM-768 secret key size)', async () => {
            const masterKey = await generateMasterKeyBytes(32);
            const secretKey = crypto.getRandomValues(new Uint8Array(2400));

            const encrypted = await encryptLargeSecretKey(secretKey, masterKey);
            const decrypted = await decryptLargeSecretKey(encrypted, masterKey);

            expect(decrypted.length).toBe(2400);
            expect(decrypted).toEqual(secretKey);
        });

        it('should produce output in format [12B IV][ciphertext + 16B tag]', async () => {
            const masterKey = await generateMasterKeyBytes(32);
            const secretKey = crypto.getRandomValues(new Uint8Array(64));

            const encrypted = await encryptLargeSecretKey(secretKey, masterKey);

            // IV (12) + ciphertext (64) + GCM tag (16) = 92
            expect(encrypted.length).toBe(12 + 64 + 16);
            // First 12 bytes are the IV
            const iv = encrypted.slice(0, 12);
            expect(iv.length).toBe(12);
        });

        it('should fail to decrypt with wrong master key', async () => {
            const masterKey1 = await generateMasterKeyBytes(32);
            const masterKey2 = await generateMasterKeyBytes(32);
            const secretKey = crypto.getRandomValues(new Uint8Array(32));

            const encrypted = await encryptLargeSecretKey(secretKey, masterKey1);

            await expect(decryptLargeSecretKey(encrypted, masterKey2)).rejects.toThrow();
        });

        it('should produce different ciphertext for same plaintext (random IV)', async () => {
            const masterKey = await generateMasterKeyBytes(32);
            const secretKey = crypto.getRandomValues(new Uint8Array(32));

            const enc1 = await encryptLargeSecretKey(secretKey, masterKey);
            const enc2 = await encryptLargeSecretKey(secretKey, masterKey);

            // IVs should differ (random)
            const iv1 = enc1.slice(0, 12);
            const iv2 = enc2.slice(0, 12);
            expect(iv1).not.toEqual(iv2);
        });

        it('should handle empty data (0-byte key)', async () => {
            const masterKey = await generateMasterKeyBytes(32);
            const secretKey = new Uint8Array(0);

            const encrypted = await encryptLargeSecretKey(secretKey, masterKey);
            // IV (12) + empty ciphertext (0) + tag (16) = 28
            expect(encrypted.length).toBe(28);

            const decrypted = await decryptLargeSecretKey(encrypted, masterKey);
            expect(decrypted.length).toBe(0);
        });
    });

    // ==================== deriveArgon2Key ====================

    describe('deriveArgon2Key', () => {
        it('should return AES-KW CryptoKey from Argon2 output', async () => {
            const fakeKek = crypto.getRandomValues(new Uint8Array(32));
            mockDeriveKey.mockResolvedValueOnce({ key: fakeKek });

            const salt = crypto.getRandomValues(new Uint8Array(16));
            const params = { type: 'argon2id' as const, memoryCost: 47104, timeCost: 1, parallelism: 1, hashLength: 32 };

            const key = await deriveArgon2Key('test-password', salt, params);

            expect(key).toBeDefined();
            expect(key.algorithm.name).toBe('AES-KW');
            expect(key.usages).toContain('wrapKey');
            expect(key.usages).toContain('unwrapKey');
        });

        it('should pass password and params to Argon2 provider', async () => {
            const fakeKek = crypto.getRandomValues(new Uint8Array(32));
            mockDeriveKey.mockResolvedValueOnce({ key: fakeKek });

            const salt = crypto.getRandomValues(new Uint8Array(16));
            const params = { type: 'argon2id' as const, memoryCost: 47104, timeCost: 1, parallelism: 1, hashLength: 32 };

            await deriveArgon2Key('my-password', salt, params);

            expect(mockDeriveKey).toHaveBeenCalledWith('my-password', salt, params);
        });

        it('should produce non-extractable key (XSS cannot exportKey)', async () => {
            const fakeKek = crypto.getRandomValues(new Uint8Array(32));
            mockDeriveKey.mockResolvedValueOnce({ key: fakeKek });

            const salt = crypto.getRandomValues(new Uint8Array(16));
            const params = { type: 'argon2id' as const, memoryCost: 47104, timeCost: 1, parallelism: 1, hashLength: 32 };

            const key = await deriveArgon2Key('password', salt, params);

            expect(key.extractable).toBe(false);
        });
    });

    // ==================== unwrapMasterKey ====================

    describe('unwrapMasterKey', () => {
        it('should unwrap and return a MasterKeyBundle with 3 non-extractable keys', async () => {
            const kek = await generateAesKwKey();
            const masterKey = await generateAesGcmKey(true);

            // Wrap the master key
            const wrapped = await crypto.subtle.wrapKey('raw', masterKey, kek, 'AES-KW');
            const wrappedB64 = btoa(String.fromCharCode(...new Uint8Array(wrapped)));

            // Unwrap it
            const result = await unwrapMasterKey(wrappedB64, kek);

            expect(result.bundle).toBeDefined();
            expect(result.bundle.hkdf.algorithm.name).toBe('HKDF');
            expect(result.bundle.aesGcm.algorithm.name).toBe('AES-GCM');
            expect(result.bundle.aesKw.algorithm.name).toBe('AES-KW');
            // All keys should be non-extractable
            expect(result.bundle.hkdf.extractable).toBe(false);
            expect(result.bundle.aesGcm.extractable).toBe(false);
            expect(result.bundle.aesKw.extractable).toBe(false);
            // No device wrap requested
            expect(result.deviceWrapped).toBeUndefined();
        });

        it('should return deviceWrapped when deviceKek is provided', async () => {
            const kek = await generateAesKwKey();
            const deviceKek = await generateAesKwKey();
            const masterKey = await generateAesGcmKey(true);

            const wrapped = await crypto.subtle.wrapKey('raw', masterKey, kek, 'AES-KW');
            const wrappedB64 = btoa(String.fromCharCode(...new Uint8Array(wrapped)));

            const result = await unwrapMasterKey(wrappedB64, kek, deviceKek);

            expect(result.bundle).toBeDefined();
            expect(result.deviceWrapped).toBeDefined();
            expect(result.deviceWrapped!.byteLength).toBe(40); // AES-KW adds 8 bytes
        });

        it('should fail with wrong KEK', async () => {
            const kek1 = await generateAesKwKey();
            const kek2 = await generateAesKwKey();
            const masterKey = await generateAesGcmKey(true);

            const wrapped = await crypto.subtle.wrapKey('raw', masterKey, kek1, 'AES-KW');
            const wrappedB64 = btoa(String.fromCharCode(...new Uint8Array(wrapped)));

            await expect(unwrapMasterKey(wrappedB64, kek2)).rejects.toThrow();
        });
    });

    // ==================== createMasterKeyBundle ====================

    describe('createMasterKeyBundle', () => {
        it('should create 3 non-extractable CryptoKeys from raw bytes', async () => {
            const rawBytes = crypto.getRandomValues(new Uint8Array(32));
            const bundle = await createMasterKeyBundle(rawBytes);

            expect(bundle.hkdf.algorithm.name).toBe('HKDF');
            expect(bundle.aesGcm.algorithm.name).toBe('AES-GCM');
            expect(bundle.aesKw.algorithm.name).toBe('AES-KW');
            expect(bundle.hkdf.extractable).toBe(false);
            expect(bundle.aesGcm.extractable).toBe(false);
            expect(bundle.aesKw.extractable).toBe(false);
        });

        it('should zero the input bytes after import', async () => {
            const rawBytes = crypto.getRandomValues(new Uint8Array(32));
            await createMasterKeyBundle(rawBytes);

            expect(rawBytes.every(b => b === 0)).toBe(true);
        });
    });

    // ==================== wrapSecretWithMK / unwrapSecretWithMK ====================

    describe('wrapSecretWithMK / unwrapSecretWithMK', () => {
        it('should roundtrip a 32-byte secret', async () => {
            const rawBytes = crypto.getRandomValues(new Uint8Array(32));
            const rawCopy = new Uint8Array(rawBytes);
            const bundle = await createMasterKeyBundle(rawBytes);

            const secret = crypto.getRandomValues(new Uint8Array(32));
            const wrapped = await wrapSecretWithMK(secret, bundle.aesKw);
            expect(wrapped.length).toBe(40); // AES-KW adds 8 bytes

            const unwrapped = await unwrapSecretWithMK(wrapped, bundle.aesKw);
            expect(unwrapped).toEqual(secret);
        });
    });

    // ==================== deriveFileKeyFromMaster ====================

    describe('deriveFileKeyFromMaster', () => {
        it('should derive deterministic key (same input -> same key)', async () => {
            const masterKey = await generateHkdfKey();
            const fileId = 'file-123';
            const timestamp = 1700000000;

            const key1 = await deriveFileKeyFromMaster(masterKey, fileId, timestamp);
            const key2 = await deriveFileKeyFromMaster(masterKey, fileId, timestamp);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).toBe(fp2);
        });

        it('should derive different key for different fileId', async () => {
            const masterKey = await generateHkdfKey();
            const timestamp = 1700000000;

            const key1 = await deriveFileKeyFromMaster(masterKey, 'file-1', timestamp);
            const key2 = await deriveFileKeyFromMaster(masterKey, 'file-2', timestamp);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).not.toBe(fp2);
        });

        it('should derive different key for different timestamp', async () => {
            const masterKey = await generateHkdfKey();
            const fileId = 'file-123';

            const key1 = await deriveFileKeyFromMaster(masterKey, fileId, 1700000000);
            const key2 = await deriveFileKeyFromMaster(masterKey, fileId, 1700000001);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).not.toBe(fp2);
        });

        it('should derive different key for different master key', async () => {
            const masterKey1 = await generateHkdfKey();
            const masterKey2 = await generateHkdfKey();
            const fileId = 'file-123';
            const timestamp = 1700000000;

            const key1 = await deriveFileKeyFromMaster(masterKey1, fileId, timestamp);
            const key2 = await deriveFileKeyFromMaster(masterKey2, fileId, timestamp);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).not.toBe(fp2);
        });

        it('should return AES-GCM key with encrypt/decrypt usages', async () => {
            const masterKey = await generateHkdfKey();

            const key = await deriveFileKeyFromMaster(masterKey, 'file-1', 1700000000);

            expect(key.algorithm.name).toBe('AES-GCM');
            expect(key.usages).toContain('encrypt');
            expect(key.usages).toContain('decrypt');
            expect(key.extractable).toBe(false);
        });
    });

    // ==================== deriveFilenameKeyFromMaster ====================

    describe('deriveFilenameKeyFromMaster', () => {
        it('should return AES-GCM key', async () => {
            const masterKey = await generateHkdfKey();

            const key = await deriveFilenameKeyFromMaster(masterKey);

            expect(key.algorithm.name).toBe('AES-GCM');
            expect(key.usages).toContain('encrypt');
            expect(key.usages).toContain('decrypt');
        });

        it('should derive deterministic key (same master key -> same filename key)', async () => {
            const masterKey = await generateHkdfKey();

            const key1 = await deriveFilenameKeyFromMaster(masterKey);
            const key2 = await deriveFilenameKeyFromMaster(masterKey);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).toBe(fp2);
        });

        it('should derive different key for different master key', async () => {
            const masterKey1 = await generateHkdfKey();
            const masterKey2 = await generateHkdfKey();

            const key1 = await deriveFilenameKeyFromMaster(masterKey1);
            const key2 = await deriveFilenameKeyFromMaster(masterKey2);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).not.toBe(fp2);
        });

        it('should be non-extractable', async () => {
            const masterKey = await generateHkdfKey();
            const key = await deriveFilenameKeyFromMaster(masterKey);
            expect(key.extractable).toBe(false);
        });
    });

    // ==================== deriveFoldernameKeyFromMaster ====================

    describe('deriveFoldernameKeyFromMaster', () => {
        it('should return AES-GCM key', async () => {
            const masterKey = await generateHkdfKey();

            const key = await deriveFoldernameKeyFromMaster(masterKey);

            expect(key.algorithm.name).toBe('AES-GCM');
            expect(key.usages).toContain('encrypt');
            expect(key.usages).toContain('decrypt');
        });

        it('should derive deterministic key (same master key -> same foldername key)', async () => {
            const masterKey = await generateHkdfKey();

            const key1 = await deriveFoldernameKeyFromMaster(masterKey);
            const key2 = await deriveFoldernameKeyFromMaster(masterKey);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).toBe(fp2);
        });

        it('should derive different key for different master key', async () => {
            const masterKey1 = await generateHkdfKey();
            const masterKey2 = await generateHkdfKey();

            const key1 = await deriveFoldernameKeyFromMaster(masterKey1);
            const key2 = await deriveFoldernameKeyFromMaster(masterKey2);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).not.toBe(fp2);
        });

        it('should be non-extractable', async () => {
            const masterKey = await generateHkdfKey();
            const key = await deriveFoldernameKeyFromMaster(masterKey);
            expect(key.extractable).toBe(false);
        });

        it('should derive different key than filename key (different HKDF salt/info)', async () => {
            const masterKey = await generateHkdfKey();

            const foldernameKey = await deriveFoldernameKeyFromMaster(masterKey);
            const filenameKey = await deriveFilenameKeyFromMaster(masterKey);

            const fp1 = await keyFingerprint(foldernameKey);
            const fp2 = await keyFingerprint(filenameKey);
            expect(fp1).not.toBe(fp2);
        });
    });

    // ==================== deriveFingerprintKeyFromMaster ====================

    describe('deriveFingerprintKeyFromMaster', () => {
        it('should return HMAC key', async () => {
            const masterKey = await generateHkdfKey();

            const key = await deriveFingerprintKeyFromMaster(masterKey);

            expect(key.algorithm.name).toBe('HMAC');
            expect(key.usages).toContain('sign');
        });

        it('should derive deterministic key', async () => {
            const masterKey = await generateHkdfKey();

            const key1 = await deriveFingerprintKeyFromMaster(masterKey);
            const key2 = await deriveFingerprintKeyFromMaster(masterKey);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).toBe(fp2);
        });

        it('should derive different key for different master key', async () => {
            const masterKey1 = await generateHkdfKey();
            const masterKey2 = await generateHkdfKey();

            const key1 = await deriveFingerprintKeyFromMaster(masterKey1);
            const key2 = await deriveFingerprintKeyFromMaster(masterKey2);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).not.toBe(fp2);
        });

        it('should be non-extractable', async () => {
            const masterKey = await generateHkdfKey();
            const key = await deriveFingerprintKeyFromMaster(masterKey);
            expect(key.extractable).toBe(false);
        });
    });

    // ==================== deriveThumbnailKeyFromMaster ====================

    describe('deriveThumbnailKeyFromMaster', () => {
        it('should return AES-GCM key', async () => {
            const masterKey = await generateHkdfKey();

            const key = await deriveThumbnailKeyFromMaster(masterKey, 'file-1');

            expect(key.algorithm.name).toBe('AES-GCM');
            expect(key.usages).toContain('encrypt');
            expect(key.usages).toContain('decrypt');
        });

        it('should be file-specific (different fileId -> different key)', async () => {
            const masterKey = await generateHkdfKey();

            const key1 = await deriveThumbnailKeyFromMaster(masterKey, 'file-1');
            const key2 = await deriveThumbnailKeyFromMaster(masterKey, 'file-2');

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).not.toBe(fp2);
        });

        it('should derive deterministic key (same inputs -> same key)', async () => {
            const masterKey = await generateHkdfKey();
            const fileId = 'file-42';

            const key1 = await deriveThumbnailKeyFromMaster(masterKey, fileId);
            const key2 = await deriveThumbnailKeyFromMaster(masterKey, fileId);

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).toBe(fp2);
        });

        it('should derive different key for different master key', async () => {
            const masterKey1 = await generateHkdfKey();
            const masterKey2 = await generateHkdfKey();

            const key1 = await deriveThumbnailKeyFromMaster(masterKey1, 'file-1');
            const key2 = await deriveThumbnailKeyFromMaster(masterKey2, 'file-1');

            const fp1 = await keyFingerprint(key1);
            const fp2 = await keyFingerprint(key2);
            expect(fp1).not.toBe(fp2);
        });

        it('should be non-extractable', async () => {
            const masterKey = await generateHkdfKey();
            const key = await deriveThumbnailKeyFromMaster(masterKey, 'file-1');
            expect(key.extractable).toBe(false);
        });
    });
});
