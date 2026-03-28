/**
 * Organization Vault Setup
 *
 * Pure functions for initializing org encryption (OMK + hybrid keypair).
 * Called once by the org owner after org creation.
 *
 * Flow:
 *   1. Generate random 32-byte OMK
 *   2. Generate org hybrid keypair (X25519 + ML-KEM-768)
 *   3. Wrap hybrid secrets with OMK (X25519: AES-KW, ML-KEM: AES-256-GCM)
 *   4. Wrap OMK with owner's personal MK (AES-KW)
 *   5. POST to orgKeys.setup
 */

import { arrayBufferToBase64, toArrayBuffer } from '@/lib/platform';
import { wrapSecretWithMK, encryptLargeSecretKey } from '@/hooks/masterKeyCrypto';
import { wrapOMKWithPersonalMK } from '@/hooks/orgMasterKeyCrypto';
import { getHybridKemProvider } from '@/lib/platform/webHybridKemProvider';
import type { MasterKeyBundle } from '@/hooks/masterKeyCrypto';

interface OrgSetupInput {
  organizationId: number;
  omkWrappedForOwner: string;
  hybridKeyPair: {
    x25519PublicKey: string;
    x25519SecretKeyEncrypted: string;
    mlkem768PublicKey: string;
    mlkem768SecretKeyEncrypted: string;
    mlkem768SecretKeyIv: string;
    fingerprint?: string;
  };
}

/**
 * SHA-256 fingerprint of concatenated public keys (first 16 bytes, hex).
 */
async function generateKeyFingerprint(classicalPub: Uint8Array, pqPub: Uint8Array): Promise<string> {
  const data = new Uint8Array(classicalPub.length + pqPub.length);
  data.set(classicalPub, 0);
  data.set(pqPub, classicalPub.length);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash).slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

function toBase64(bytes: Uint8Array): string {
  return arrayBufferToBase64(toArrayBuffer(bytes));
}

/**
 * Initialize org vault encryption. Generates OMK, hybrid keypair,
 * wraps everything, and calls the backend setup mutation.
 *
 * @throws if hybrid KEM is unavailable or any crypto operation fails
 */
export async function initializeOrgVault(
  orgId: number,
  personalMKBundle: MasterKeyBundle,
  setupMutate: (input: OrgSetupInput) => Promise<unknown>,
): Promise<void> {
  const omkRaw = crypto.getRandomValues(new Uint8Array(32));

  try {
    // Import OMK as AES-KW for wrapping X25519 secret (32 bytes)
    const omkAesKw = await crypto.subtle.importKey(
      'raw', omkRaw.buffer, 'AES-KW', false, ['wrapKey'],
    );

    // Import OMK as AES-GCM for encrypting ML-KEM secret (2400 bytes)
    const omkAesGcm = await crypto.subtle.importKey(
      'raw', omkRaw.buffer, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
    );

    // Extractable version for AES-KW wrapping with personal MK
    const omkExtractable = await crypto.subtle.importKey(
      'raw', omkRaw.buffer, { name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey'],
    );

    // Generate org hybrid keypair (X25519 + ML-KEM-768)
    const hybridKem = getHybridKemProvider();
    if (!(await hybridKem.isAvailable())) {
      throw new Error('Post-quantum cryptography (ML-KEM-768) is not available. Please try again in a moment.');
    }
    const { publicKey, secretKey } = await hybridKem.generateKeyPair();

    let x25519Wrapped: Uint8Array;
    let mlkemIv: Uint8Array;
    let mlkemCiphertext: Uint8Array;
    try {
      // Wrap X25519 secret (32 bytes) with OMK via AES-KW
      x25519Wrapped = await wrapSecretWithMK(secretKey.classical, omkAesKw);

      // Encrypt ML-KEM secret (2400 bytes) with OMK via AES-256-GCM
      // encryptLargeSecretKey returns [12-byte IV][ciphertext+tag]
      const mlkemEncryptedFull = await encryptLargeSecretKey(secretKey.postQuantum, omkAesGcm);
      mlkemIv = mlkemEncryptedFull.slice(0, 12);
      mlkemCiphertext = mlkemEncryptedFull.slice(12);
    } finally {
      // Zero secret key material even if wrapping/encryption threw
      secretKey.classical.fill(0);
      secretKey.postQuantum.fill(0);
    }

    // Wrap OMK with owner's personal MK via AES-KW
    const omkWrapped = await wrapOMKWithPersonalMK(omkExtractable, personalMKBundle);

    // Generate fingerprint for the org hybrid keypair
    const fingerprint = await generateKeyFingerprint(publicKey.classical, publicKey.postQuantum);

    // Call backend setup
    await setupMutate({
      organizationId: orgId,
      omkWrappedForOwner: omkWrapped,
      hybridKeyPair: {
        x25519PublicKey: toBase64(publicKey.classical),
        x25519SecretKeyEncrypted: toBase64(x25519Wrapped),
        mlkem768PublicKey: toBase64(publicKey.postQuantum),
        mlkem768SecretKeyEncrypted: toBase64(mlkemCiphertext),
        mlkem768SecretKeyIv: toBase64(mlkemIv),
        fingerprint,
      },
    });
  } finally {
    omkRaw.fill(0);
  }
}
