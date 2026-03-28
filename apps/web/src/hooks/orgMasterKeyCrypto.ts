/**
 * Organization Master Key Crypto Helpers
 *
 * Pure cryptographic functions for org key operations.
 * No React hooks or state — used by useOrgMasterKey hook.
 *
 * Operations:
 * - OMK unwrap/wrap with personal Master Key (AES-KW)
 * - OMK decapsulation from hybrid-encrypted distribution
 * - HKDF key derivation with org-scoped info strings
 *
 * Info string convention (prevents collision with personal keys):
 *   Personal: stenvault:file:${id}:${ts}
 *   Org:      stenvault:org:${orgId}:file:${id}:${ts}
 */

import { base64ToArrayBuffer, arrayBufferToBase64, toArrayBuffer } from '@/lib/platform';
import { getHybridKemProvider } from '@/lib/platform/webHybridKemProvider';
import type { HybridSecretKey, HybridCiphertext } from '@stenvault/shared/platform/crypto';
import type { DerivedFileKeyWithBytes } from './masterKeyCrypto';

// Re-export for consumers
export type { DerivedFileKeyWithBytes };

// ============ OMK Wrap/Unwrap (AES-KW) ============

/**
 * Unwrap an OMK using the user's personal Master Key as KEK.
 * Used when wrapMethod=aes-kw (member already confirmed their key).
 */
export async function unwrapOMKWithPersonalMK(
  wrappedOMKB64: string,
  personalMK: CryptoKey | { aesKw: CryptoKey }
): Promise<CryptoKey> {
  const wrappedKey = base64ToArrayBuffer(wrappedOMKB64);

  // Use non-extractable AES-KW key from bundle, or legacy CryptoKey
  const kek = 'aesKw' in personalMK ? personalMK.aesKw : personalMK;

  try {
    return await crypto.subtle.unwrapKey(
      'raw',
      wrappedKey,
      kek,
      'AES-KW',
      { name: 'AES-GCM', length: 256 },
      true, // extractable for HKDF derivation (OMK needs export for org key derivation)
      ['wrapKey', 'unwrapKey']
    );
  } catch {
    throw new Error('Failed to unwrap organization key: personal vault may be locked or key corrupted');
  }
}

/**
 * Wrap an OMK with the user's personal Master Key (AES-KW).
 * Returns Base64-encoded wrapped key for server storage.
 */
export async function wrapOMKWithPersonalMK(
  omk: CryptoKey,
  personalMK: CryptoKey | { aesKw: CryptoKey }
): Promise<string> {
  const kek = 'aesKw' in personalMK ? personalMK.aesKw : personalMK;
  const wrapped = await crypto.subtle.wrapKey('raw', omk, kek, 'AES-KW');
  return arrayBufferToBase64(wrapped);
}

// ============ Hybrid Decapsulation ============

export interface HybridDistributionData {
  omkEncrypted: string;
  distributionIv: string;
  distributionX25519Public: string;
  distributionMlkemCiphertext: string;
}

/**
 * Decapsulate an OMK from a hybrid-encrypted distribution.
 *
 * Flow:
 *   1. X25519 ECDH(own secret, sender's ephemeral public) -> classical secret
 *   2. ML-KEM-768 decapsulate(ciphertext, own PQ secret) -> PQ secret
 *   3. HKDF(classical || pq) -> hybrid KEK (32 bytes)
 *   4. AES-GCM decrypt(omkEncrypted, hybrid KEK, distributionIv) -> raw OMK
 */
export async function decapsulateOMK(
  distribution: HybridDistributionData,
  hybridSecretKey: HybridSecretKey
): Promise<CryptoKey> {
  const hybridKem = getHybridKemProvider();

  // Reconstruct ciphertext from distribution metadata
  const ciphertext: HybridCiphertext = {
    classical: new Uint8Array(base64ToArrayBuffer(distribution.distributionX25519Public)),
    postQuantum: new Uint8Array(base64ToArrayBuffer(distribution.distributionMlkemCiphertext)),
  };

  // Decapsulate -> hybrid KEK (32 bytes)
  const hybridKEK = await hybridKem.decapsulate(ciphertext, hybridSecretKey);

  // AES-GCM decrypt the OMK
  const iv = new Uint8Array(base64ToArrayBuffer(distribution.distributionIv));
  const encryptedOMK = new Uint8Array(base64ToArrayBuffer(distribution.omkEncrypted));

  const kek = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(hybridKEK),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  hybridKEK.fill(0);

  const omkBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    kek,
    toArrayBuffer(encryptedOMK)
  );

  // Import raw OMK as CryptoKey, then zero raw bytes
  try {
    return await crypto.subtle.importKey(
      'raw',
      omkBytes,
      { name: 'AES-GCM', length: 256 },
      true, // extractable for HKDF derivation and AES-KW re-wrap
      ['wrapKey', 'unwrapKey']
    );
  } finally {
    new Uint8Array(omkBytes).fill(0);
  }
}

// ============ HKDF Key Derivation (Org-Scoped) ============

/**
 * Internal: export OMK bytes and import as HKDF key material.
 * Zeroes the intermediate raw bytes after import.
 */
async function importOMKAsHKDF(omk: CryptoKey, usages: KeyUsage[] = ['deriveKey']): Promise<CryptoKey> {
  const omkBytes = await crypto.subtle.exportKey('raw', omk);
  const hkdfKey = await crypto.subtle.importKey('raw', omkBytes, 'HKDF', false, usages);
  new Uint8Array(omkBytes).fill(0);
  return hkdfKey;
}

/**
 * Derive a unique file encryption key from the OMK using HKDF.
 * Info: stenvault:org:${orgId}:file:${fileId}:${timestamp}
 * Salt: stenvault-org-file-key-v1
 */
export async function deriveOrgFileKey(
  omk: CryptoKey,
  orgId: number,
  fileId: string,
  timestamp: number
): Promise<CryptoKey> {
  const hkdfKey = await importOMKAsHKDF(omk);
  const encoder = new TextEncoder();

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode('stenvault-org-file-key-v1'),
      info: encoder.encode(`stenvault:org:${orgId}:file:${fileId}:${timestamp}`),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Derive org file key AND raw bytes for Web Worker transfer.
 * SECURITY: Caller MUST call zeroBytes() after Worker postMessage!
 */
export async function deriveOrgFileKeyWithBytes(
  omk: CryptoKey,
  orgId: number,
  fileId: string,
  timestamp: number
): Promise<DerivedFileKeyWithBytes> {
  const hkdfKey = await importOMKAsHKDF(omk, ['deriveKey', 'deriveBits']);
  const encoder = new TextEncoder();

  const params = {
    name: 'HKDF',
    hash: 'SHA-256',
    salt: encoder.encode('stenvault-org-file-key-v1'),
    info: encoder.encode(`stenvault:org:${orgId}:file:${fileId}:${timestamp}`),
  };

  const derivedBits = await crypto.subtle.deriveBits(params, hkdfKey, 256);
  const keyBytes = new Uint8Array(derivedBits);

  const key = await crypto.subtle.importKey(
    'raw',
    derivedBits,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return { key, keyBytes, zeroBytes: () => keyBytes.fill(0) };
}

/**
 * Derive filename encryption key from OMK using HKDF.
 * Same key for all filenames within an org.
 * Info: stenvault:org:${orgId}:filename:v1
 * Salt: stenvault-org-filename-key-v1
 */
export async function deriveOrgFilenameKey(
  omk: CryptoKey,
  orgId: number
): Promise<CryptoKey> {
  const hkdfKey = await importOMKAsHKDF(omk);
  const encoder = new TextEncoder();

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode('stenvault-org-filename-key-v1'),
      info: encoder.encode(`stenvault:org:${orgId}:filename:v1`),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Derive folder name encryption key from OMK using HKDF.
 * Same key for all folder names within an org.
 * Info: stenvault:org:${orgId}:foldername:v1
 * Salt: stenvault-org-foldername-key-v1
 */
export async function deriveOrgFoldernameKey(
  omk: CryptoKey,
  orgId: number
): Promise<CryptoKey> {
  const hkdfKey = await importOMKAsHKDF(omk);
  const encoder = new TextEncoder();

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode('stenvault-org-foldername-key-v1'),
      info: encoder.encode(`stenvault:org:${orgId}:foldername:v1`),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Derive thumbnail encryption key from OMK using HKDF.
 * Unique per file within the org.
 * Info: stenvault:org:${orgId}:thumbnail:v1:${fileId}
 * Salt: stenvault-org-thumbnail-key-v1
 */
export async function deriveOrgThumbnailKey(
  omk: CryptoKey,
  orgId: number,
  fileId: string
): Promise<CryptoKey> {
  const hkdfKey = await importOMKAsHKDF(omk);
  const encoder = new TextEncoder();

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode('stenvault-org-thumbnail-key-v1'),
      info: encoder.encode(`stenvault:org:${orgId}:thumbnail:v1:${fileId}`),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ============ Base64url Helpers (invite key fragments) ============

export function base64urlEncode(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ============ Invite Key Wrapping (AES-KW) ============

/**
 * Generate a random invite key and AES-KW wrap the OMK with it.
 * Returns the wrapped blob (base64) and the invite key (base64url for URL fragment).
 */
export async function wrapOMKForInvite(
  omk: CryptoKey,
): Promise<{ omkWrappedForInvite: string; inviteKeyFragment: string }> {
  const inviteKeyRaw = crypto.getRandomValues(new Uint8Array(32));

  const inviteKey = await crypto.subtle.importKey(
    'raw', inviteKeyRaw as BufferSource, { name: 'AES-KW', length: 256 }, false, ['wrapKey'],
  );

  const wrappedBuf = await crypto.subtle.wrapKey('raw', omk, inviteKey, 'AES-KW');
  const omkWrappedForInvite = arrayBufferToBase64(wrappedBuf);
  const inviteKeyFragment = base64urlEncode(inviteKeyRaw);

  inviteKeyRaw.fill(0);

  return { omkWrappedForInvite, inviteKeyFragment };
}

/**
 * Unwrap an OMK from an invite blob using the invite key from the URL fragment.
 * Returns the raw OMK as an extractable CryptoKey (for re-wrapping with personal MK).
 */
export async function unwrapOMKFromInvite(
  omkWrappedForInviteB64: string,
  inviteKeyFragmentB64url: string,
): Promise<CryptoKey> {
  const inviteKeyRaw = base64urlDecode(inviteKeyFragmentB64url);
  if (inviteKeyRaw.byteLength !== 32) {
    throw new Error(`Invalid invite key length: expected 32 bytes, got ${inviteKeyRaw.byteLength}`);
  }

  const inviteKey = await crypto.subtle.importKey(
    'raw', inviteKeyRaw as BufferSource, { name: 'AES-KW', length: 256 }, false, ['unwrapKey'],
  );
  inviteKeyRaw.fill(0);

  const wrappedBuf = base64ToArrayBuffer(omkWrappedForInviteB64);

  return crypto.subtle.unwrapKey(
    'raw', wrappedBuf, inviteKey, 'AES-KW',
    { name: 'AES-GCM', length: 256 },
    true, // extractable for re-wrap with personal MK
    ['wrapKey', 'unwrapKey'],
  );
}
