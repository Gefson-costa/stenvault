/**
 * Organization Master Key Crypto Tests
 *
 * Tests the pure cryptographic functions for org key operations
 * using real WebCrypto APIs (available in Vitest node environment).
 *
 * Tests:
 * - OMK wrap/unwrap roundtrip with personal MK (AES-KW)
 * - HKDF key derivation produces deterministic keys
 * - Org-scoped key derivation is isolated from other orgs
 *
 * Note: HKDF-derived keys have extractable=false, so we compare them
 * by encrypting test data with a fixed IV and checking ciphertext equality.
 */

import { describe, it, expect } from 'vitest';
import {
  unwrapOMKWithPersonalMK,
  wrapOMKWithPersonalMK,
  deriveOrgFileKey,
  deriveOrgFilenameKey,
  deriveOrgThumbnailKey,
  deriveOrgFileKeyWithBytes,
} from './orgMasterKeyCrypto';

// Helper to generate a 32-byte AES-GCM key (extractable for wrap/unwrap tests)
async function generateTestKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

// Helper to generate an AES-KW key (used as personal MK KEK in tests)
async function generateAesKwKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-KW', length: 256 },
    true,
    ['wrapKey', 'unwrapKey']
  );
}

// Helper to compare two CryptoKeys by raw bytes (only works for extractable keys)
async function keysEqual(a: CryptoKey, b: CryptoKey): Promise<boolean> {
  const aBytes = new Uint8Array(await crypto.subtle.exportKey('raw', a));
  const bBytes = new Uint8Array(await crypto.subtle.exportKey('raw', b));
  if (aBytes.length !== bBytes.length) return false;
  return aBytes.every((byte, i) => byte === bBytes[i]);
}

// Helper to get a fingerprint of a non-extractable key by encrypting known data
const TEST_DATA = new TextEncoder().encode('orgMasterKeyCrypto test vector');
const FIXED_IV = new Uint8Array(12); // all zeros, deterministic for comparison

async function keyFingerprint(key: CryptoKey): Promise<string> {
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: FIXED_IV },
    key,
    TEST_DATA
  );
  return Array.from(new Uint8Array(ct)).map(b => b.toString(16).padStart(2, '0')).join('');
}

describe('orgMasterKeyCrypto', () => {
  describe('OMK Wrap/Unwrap (AES-KW)', () => {
    it('should roundtrip wrap and unwrap an OMK with personal MK (AES-KW)', async () => {
      const personalMK = await generateAesKwKey();
      const omk = await generateTestKey();

      const wrappedB64 = await wrapOMKWithPersonalMK(omk, personalMK);
      expect(typeof wrappedB64).toBe('string');
      expect(wrappedB64.length).toBeGreaterThan(0);

      const unwrapped = await unwrapOMKWithPersonalMK(wrappedB64, personalMK);
      expect(unwrapped).toBeDefined();
      expect(await keysEqual(omk, unwrapped)).toBe(true);
    });

    it('should roundtrip wrap and unwrap an OMK with MasterKeyBundle', async () => {
      const aesKw = await generateAesKwKey();
      const bundle = { aesKw };
      const omk = await generateTestKey();

      const wrappedB64 = await wrapOMKWithPersonalMK(omk, bundle);
      const unwrapped = await unwrapOMKWithPersonalMK(wrappedB64, bundle);
      expect(await keysEqual(omk, unwrapped)).toBe(true);
    });

    it('should fail to unwrap with wrong personal MK', async () => {
      const personalMK1 = await generateAesKwKey();
      const personalMK2 = await generateAesKwKey();
      const omk = await generateTestKey();

      const wrappedB64 = await wrapOMKWithPersonalMK(omk, personalMK1);
      await expect(unwrapOMKWithPersonalMK(wrappedB64, personalMK2)).rejects.toThrow();
    });

    it('should produce different wrapped output for different OMKs', async () => {
      const personalMK = await generateAesKwKey();
      const omk1 = await generateTestKey();
      const omk2 = await generateTestKey();

      const wrapped1 = await wrapOMKWithPersonalMK(omk1, personalMK);
      const wrapped2 = await wrapOMKWithPersonalMK(omk2, personalMK);
      expect(wrapped1).not.toBe(wrapped2);
    });
  });

  describe('HKDF Key Derivation (Org-Scoped)', () => {
    it('should derive a file key from OMK', async () => {
      const omk = await generateTestKey();
      const key = await deriveOrgFileKey(omk, 1, 'file-abc', Date.now());

      expect(key).toBeDefined();
      expect(key.type).toBe('secret');
      expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    });

    it('should derive deterministic file keys for same inputs', async () => {
      const omk = await generateTestKey();
      const ts = 1700000000;

      const key1 = await deriveOrgFileKey(omk, 1, 'file-123', ts);
      const key2 = await deriveOrgFileKey(omk, 1, 'file-123', ts);

      expect(await keyFingerprint(key1)).toBe(await keyFingerprint(key2));
    });

    it('should derive different keys for different fileIds', async () => {
      const omk = await generateTestKey();
      const ts = 1700000000;

      const key1 = await deriveOrgFileKey(omk, 1, 'file-aaa', ts);
      const key2 = await deriveOrgFileKey(omk, 1, 'file-bbb', ts);

      expect(await keyFingerprint(key1)).not.toBe(await keyFingerprint(key2));
    });

    it('should derive different keys for different orgIds', async () => {
      const omk = await generateTestKey();
      const ts = 1700000000;

      const key1 = await deriveOrgFileKey(omk, 1, 'file-abc', ts);
      const key2 = await deriveOrgFileKey(omk, 2, 'file-abc', ts);

      expect(await keyFingerprint(key1)).not.toBe(await keyFingerprint(key2));
    });

    it('should derive a filename key from OMK', async () => {
      const omk = await generateTestKey();
      const key = await deriveOrgFilenameKey(omk, 1);

      expect(key).toBeDefined();
      expect(key.type).toBe('secret');
    });

    it('should derive same filename key for same org', async () => {
      const omk = await generateTestKey();

      const key1 = await deriveOrgFilenameKey(omk, 42);
      const key2 = await deriveOrgFilenameKey(omk, 42);

      expect(await keyFingerprint(key1)).toBe(await keyFingerprint(key2));
    });

    it('should derive different filename keys for different orgs', async () => {
      const omk = await generateTestKey();

      const key1 = await deriveOrgFilenameKey(omk, 1);
      const key2 = await deriveOrgFilenameKey(omk, 2);

      expect(await keyFingerprint(key1)).not.toBe(await keyFingerprint(key2));
    });

    it('should derive a thumbnail key from OMK', async () => {
      const omk = await generateTestKey();
      const key = await deriveOrgThumbnailKey(omk, 1, 'file-xyz');

      expect(key).toBeDefined();
      expect(key.type).toBe('secret');
    });

    it('should derive file key with bytes and provide zeroing', async () => {
      const omk = await generateTestKey();
      const result = await deriveOrgFileKeyWithBytes(omk, 1, 'file-abc', Date.now());

      expect(result.key).toBeDefined();
      expect(result.keyBytes).toBeInstanceOf(Uint8Array);
      expect(result.keyBytes.length).toBe(32);
      expect(typeof result.zeroBytes).toBe('function');

      // Verify bytes are non-zero before zeroing
      expect(result.keyBytes.some(b => b !== 0)).toBe(true);

      // Zero should clear the bytes
      result.zeroBytes();
      expect(result.keyBytes.every(b => b === 0)).toBe(true);
    });

    it('should derive different keys for file vs filename vs thumbnail', async () => {
      const omk = await generateTestKey();

      const fileKey = await deriveOrgFileKey(omk, 1, 'file-abc', 1700000000);
      const filenameKey = await deriveOrgFilenameKey(omk, 1);
      const thumbKey = await deriveOrgThumbnailKey(omk, 1, 'file-abc');

      const fpFile = await keyFingerprint(fileKey);
      const fpFilename = await keyFingerprint(filenameKey);
      const fpThumb = await keyFingerprint(thumbKey);

      // All three derivation paths should produce different keys
      expect(fpFile).not.toBe(fpFilename);
      expect(fpFile).not.toBe(fpThumb);
      expect(fpFilename).not.toBe(fpThumb);
    });
  });
});
