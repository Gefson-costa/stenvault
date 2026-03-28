/**
 * Organization Key Rotation
 *
 * Generates a new OMK + hybrid keypair and re-encapsulates for all
 * remaining members. Called after member removal to ensure forward secrecy.
 */

import { arrayBufferToBase64, toArrayBuffer } from '@/lib/platform';
import { wrapSecretWithMK, encryptLargeSecretKey } from '@/hooks/masterKeyCrypto';
import { getHybridKemProvider } from '@/lib/platform/webHybridKemProvider';
import { encapsulateOMKForMember } from './orgKeyDistribution';

interface MemberPublicKey {
  userId: number;
  x25519PublicKey: string;
  mlkem768PublicKey: string;
}

interface RotationPayload {
  organizationId: number;
  memberKeys: {
    userId: number;
    omkEncrypted: string;
    distributionIv: string;
    distributionX25519Public: string;
    distributionMlkemCiphertext: string;
  }[];
  newHybridKeyPair: {
    x25519PublicKey: string;
    x25519SecretKeyEncrypted: string;
    mlkem768PublicKey: string;
    mlkem768SecretKeyEncrypted: string;
    mlkem768SecretKeyIv: string;
    fingerprint?: string;
  };
  rotationReason?: string;
}

function toBase64(bytes: Uint8Array): string {
  return arrayBufferToBase64(toArrayBuffer(bytes));
}

async function generateKeyFingerprint(classicalPub: Uint8Array, pqPub: Uint8Array): Promise<string> {
  const data = new Uint8Array(classicalPub.length + pqPub.length);
  data.set(classicalPub, 0);
  data.set(pqPub, classicalPub.length);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash).slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate a new OMK + hybrid keypair and encapsulate for all remaining members.
 *
 * @param orgId - Organization ID
 * @param memberPublicKeys - Remaining members' hybrid public keys
 * @param reason - Why rotation happened (e.g., "member_removed: user@email.com")
 * @returns Payload ready for orgKeys.rotateOMK
 */
export async function buildRotationPayload(
  orgId: number,
  memberPublicKeys: MemberPublicKey[],
  reason?: string,
): Promise<RotationPayload> {
  if (memberPublicKeys.length === 0) {
    throw new Error('Cannot rotate OMK: no members with public keys. At least one member must have a hybrid keypair.');
  }
  for (const member of memberPublicKeys) {
    if (!member.x25519PublicKey || !member.mlkem768PublicKey) {
      throw new Error(`Member ${member.userId} has incomplete hybrid public key data.`);
    }
  }

  const omkRaw = crypto.getRandomValues(new Uint8Array(32));

  try {
    // Import new OMK with different algorithms
    const omkAesKw = await crypto.subtle.importKey('raw', omkRaw.buffer, 'AES-KW', false, ['wrapKey']);
    const omkAesGcm = await crypto.subtle.importKey('raw', omkRaw.buffer, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);

    // Extractable version for encapsulation (needs export)
    const omkExtractable = await crypto.subtle.importKey(
      'raw', omkRaw.buffer, { name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey'],
    );

    // Generate new org hybrid keypair
    const hybridKem = getHybridKemProvider();
    if (!(await hybridKem.isAvailable())) {
      throw new Error('Post-quantum cryptography (ML-KEM-768) is not available');
    }
    const { publicKey, secretKey } = await hybridKem.generateKeyPair();

    let x25519Wrapped: Uint8Array;
    let mlkemIv: Uint8Array;
    let mlkemCiphertext: Uint8Array;
    try {
      // Wrap new hybrid secrets with new OMK
      x25519Wrapped = await wrapSecretWithMK(secretKey.classical, omkAesKw);
      const mlkemEncryptedFull = await encryptLargeSecretKey(secretKey.postQuantum, omkAesGcm);
      mlkemIv = mlkemEncryptedFull.slice(0, 12);
      mlkemCiphertext = mlkemEncryptedFull.slice(12);
    } finally {
      secretKey.classical.fill(0);
      secretKey.postQuantum.fill(0);
    }

    const fingerprint = await generateKeyFingerprint(publicKey.classical, publicKey.postQuantum);

    // Encapsulate new OMK for each remaining member
    const memberKeys = await Promise.all(
      memberPublicKeys.map(async (member) => {
        const distribution = await encapsulateOMKForMember(omkExtractable, member);
        return {
          userId: member.userId,
          ...distribution,
        };
      }),
    );

    return {
      organizationId: orgId,
      memberKeys,
      newHybridKeyPair: {
        x25519PublicKey: toBase64(publicKey.classical),
        x25519SecretKeyEncrypted: toBase64(x25519Wrapped),
        mlkem768PublicKey: toBase64(publicKey.postQuantum),
        mlkem768SecretKeyEncrypted: toBase64(mlkemCiphertext),
        mlkem768SecretKeyIv: toBase64(mlkemIv),
        fingerprint,
      },
      rotationReason: reason,
    };
  } finally {
    omkRaw.fill(0);
  }
}
