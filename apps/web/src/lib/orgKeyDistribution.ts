/**
 * Organization Key Distribution
 *
 * Hybrid-encapsulates the OMK for a target member using their public key.
 * This is the inverse of decapsulateOMK in orgMasterKeyCrypto.ts.
 *
 * Flow:
 *   1. hybridKem.encapsulate(memberPublicKey) → { ciphertext, sharedSecret }
 *   2. AES-GCM encrypt(raw OMK, sharedSecret, random IV)
 *   3. Return encrypted OMK + distribution metadata for server storage
 */

import { base64ToArrayBuffer, arrayBufferToBase64, toArrayBuffer } from '@/lib/platform';
import { getHybridKemProvider } from '@/lib/platform/webHybridKemProvider';
import type { HybridPublicKey } from '@stenvault/shared/platform/crypto';

export interface DistributionPayload {
  omkEncrypted: string;
  distributionIv: string;
  distributionX25519Public: string;
  distributionMlkemCiphertext: string;
}

/**
 * Hybrid-encapsulate the OMK for a target member.
 *
 * @param omk - The org master key (extractable CryptoKey)
 * @param memberPublicKey - Target member's hybrid public key (X25519 + ML-KEM-768)
 * @returns Distribution payload ready for orgKeys.wrapOMKForMember
 */
export async function encapsulateOMKForMember(
  omk: CryptoKey,
  memberPublicKey: { x25519PublicKey: string; mlkem768PublicKey: string },
): Promise<DistributionPayload> {
  const hybridKem = getHybridKemProvider();

  // Reconstruct member's hybrid public key from base64
  const recipientPubKey: HybridPublicKey = {
    classical: new Uint8Array(base64ToArrayBuffer(memberPublicKey.x25519PublicKey)),
    postQuantum: new Uint8Array(base64ToArrayBuffer(memberPublicKey.mlkem768PublicKey)),
  };

  // Hybrid encapsulate → ephemeral ECDH + ML-KEM encapsulate → HKDF → 32-byte shared secret
  const { ciphertext, sharedSecret } = await hybridKem.encapsulate(recipientPubKey);
  let omkBytes: ArrayBuffer | null = null;

  try {
    // Import shared secret as AES-GCM key for encrypting OMK
    const kek = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(sharedSecret),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt'],
    );
    sharedSecret.fill(0);

    // Export raw OMK bytes
    omkBytes = await crypto.subtle.exportKey('raw', omk);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // AES-GCM encrypt the raw OMK with the hybrid KEK
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      kek,
      omkBytes,
    );
    new Uint8Array(omkBytes).fill(0);
    omkBytes = null;

    return {
      omkEncrypted: arrayBufferToBase64(encrypted),
      distributionIv: arrayBufferToBase64(toArrayBuffer(iv)),
      distributionX25519Public: arrayBufferToBase64(toArrayBuffer(ciphertext.classical)),
      distributionMlkemCiphertext: arrayBufferToBase64(toArrayBuffer(ciphertext.postQuantum)),
    };
  } finally {
    sharedSecret.fill(0); // Idempotent re-zero in case importKey threw before line 54
    if (omkBytes) new Uint8Array(omkBytes).fill(0);
  }
}
