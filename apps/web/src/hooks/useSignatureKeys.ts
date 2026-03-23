/**
 * useSignatureKeys Hook (Phase 3.4 Sovereign)
 *
 * Provides access to user's hybrid signature key pair for signing files.
 * Manages key generation, retrieval, and decryption of secret keys.
 *
 * Features:
 * - Check if user has signature keys
 * - Fetch user's public key (cached)
 * - Get decrypted secret key on-demand for signing
 * - Handle key generation flow
 */

import { useCallback, useMemo } from 'react';
import { trpc } from '@/lib/trpc';
import { toast } from 'sonner';
import { base64ToArrayBuffer, arrayBufferToBase64, toArrayBuffer } from '@/lib/platform';
import { encryptLargeSecretKey, decryptLargeSecretKey } from '@/hooks/masterKeyCrypto';
import type { MasterKeyBundle } from '@/hooks/masterKeyCrypto';
import { getHybridSignatureProvider } from '@/lib/platform/webHybridSignatureProvider';
import type {
  HybridSignaturePublicKey,
  HybridSignatureSecretKey,
} from '@stenvault/shared/platform/crypto';

async function generateKeyFingerprint(classicalPub: Uint8Array, pqPub: Uint8Array): Promise<string> {
  const data = new Uint8Array(classicalPub.length + pqPub.length);
  data.set(classicalPub, 0);
  data.set(pqPub, classicalPub.length);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash).slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============ Types ============

export interface SignatureKeyInfo {
  /** Whether the user has an active signature key pair */
  hasKeyPair: boolean;
  /** User's public key (if available) */
  publicKey: HybridSignaturePublicKey | null;
  /** Key fingerprint */
  fingerprint: string | null;
  /** Key version (for rotation tracking) */
  keyVersion: number | null;
  /** User ID of the key owner */
  userId: number | null;
}

export interface KeyHistoryEntry {
  id: number;
  keyVersion: number;
  algorithm: string;
  isActive: boolean;
  fingerprint: string | null;
  createdAt: string;
}

export interface UseSignatureKeysReturn {
  /** Signature key information */
  keyInfo: SignatureKeyInfo;
  /** Whether key data is loading */
  isLoading: boolean;
  /** Whether hybrid signatures are available on this platform */
  isAvailable: boolean | null;
  /** Generate and store a new key pair */
  generateKeyPair: (masterKey: CryptoKey | MasterKeyBundle) => Promise<boolean>;
  /** Get decrypted secret key for signing */
  getSecretKey: (masterKey: CryptoKey | MasterKeyBundle) => Promise<HybridSignatureSecretKey>;
  /** Whether a mutation is in progress */
  isPending: boolean;
  /** Refetch key info */
  refetch: () => Promise<void>;
  /** Key version history */
  keyHistory: KeyHistoryEntry[] | undefined;
  /** Whether key history is loading */
  isLoadingHistory: boolean;
}

// ============ Helper Functions ============
// Key encryption uses AES-256-GCM via encryptLargeSecretKey/decryptLargeSecretKey
// from masterKeyCrypto.ts (same proven pattern as ML-KEM-768).
// The old AES-KW approach was broken: WebCrypto importKey('raw', ..., 'AES-GCM')
// rejects keys that aren't exactly 16/24/32 bytes (Ed25519=64B, ML-DSA-65=4032B).

// ============ Hook ============

/**
 * Hook for managing user's hybrid signature keys
 */
export function useSignatureKeys(): UseSignatureKeysReturn {
  const utils = trpc.useUtils();

  // Check platform availability
  const signatureProvider = useMemo(() => getHybridSignatureProvider(), []);

  // Check if user has a key pair
  const {
    data: hasKeyPairData,
    isLoading: isLoadingHasKeyPair,
    refetch: refetchHasKeyPair,
  } = trpc.hybridSignature.hasKeyPair.useQuery(undefined, {
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
  });

  // Get user's public key (if they have one)
  const {
    data: publicKeyData,
    isLoading: isLoadingPublicKey,
    refetch: refetchPublicKey,
  } = trpc.hybridSignature.getPublicKey.useQuery(undefined, {
    enabled: hasKeyPairData?.hasKeyPair === true,
    staleTime: 10 * 60 * 1000, // Cache for 10 minutes
  });

  // List all key pair versions (for history view)
  const {
    data: keyHistory,
    isLoading: isLoadingHistory,
  } = trpc.hybridSignature.listKeyPairs.useQuery(undefined, {
    enabled: hasKeyPairData?.hasKeyPair === true,
    staleTime: 5 * 60 * 1000,
  });

  // Generate key pair mutation


  // Store key pair mutation
  const storeMutation = trpc.hybridSignature.storeKeyPair.useMutation({
    onSuccess: () => {
      toast.success('Signature keys generated successfully');
      refetchHasKeyPair();
      refetchPublicKey();
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to store signature keys');
    },
  });

  // Compute key info
  const keyInfo = useMemo((): SignatureKeyInfo => {
    if (!hasKeyPairData?.hasKeyPair || !publicKeyData) {
      return {
        hasKeyPair: false,
        publicKey: null,
        fingerprint: null,
        keyVersion: null,
        userId: null,
      };
    }

    // Convert base64 public keys to Uint8Array
    const publicKey: HybridSignaturePublicKey = {
      classical: new Uint8Array(base64ToArrayBuffer(publicKeyData.ed25519PublicKey)),
      postQuantum: new Uint8Array(base64ToArrayBuffer(publicKeyData.mldsa65PublicKey)),
    };

    return {
      hasKeyPair: true,
      publicKey,
      fingerprint: publicKeyData.fingerprint,
      keyVersion: publicKeyData.keyVersion,
      userId: publicKeyData.userId,
    };
  }, [hasKeyPairData, publicKeyData]);

  // Generate and store a new key pair
  const generateKeyPair = useCallback(
    async (masterKey: CryptoKey | MasterKeyBundle): Promise<boolean> => {
      try {
        const aesGcm = masterKey instanceof CryptoKey ? masterKey : masterKey.aesGcm;

        // Check if hybrid signatures are available
        const available = await signatureProvider.isAvailable();
        if (!available) {
          toast.error('Hybrid signatures are not available on this platform');
          return false;
        }

        // Generate key pair client-side (keys never leave browser)
        const keyPair = await signatureProvider.generateKeyPair();
        const publicKey = {
          classical: arrayBufferToBase64(toArrayBuffer(keyPair.publicKey.classical)),
          postQuantum: arrayBufferToBase64(toArrayBuffer(keyPair.publicKey.postQuantum)),
        };
        const fingerprint = await generateKeyFingerprint(keyPair.publicKey.classical, keyPair.publicKey.postQuantum);

        // Encrypt secret keys with non-extractable AES-GCM key
        const ed25519Encrypted = await encryptLargeSecretKey(keyPair.secretKey.classical, aesGcm);
        const mldsa65Encrypted = await encryptLargeSecretKey(keyPair.secretKey.postQuantum, aesGcm);

        // Store encrypted keys
        await storeMutation.mutateAsync({
          ed25519PublicKey: publicKey.classical,
          ed25519SecretKeyEncrypted: arrayBufferToBase64(toArrayBuffer(ed25519Encrypted)),
          mldsa65PublicKey: publicKey.postQuantum,
          mldsa65SecretKeyEncrypted: arrayBufferToBase64(toArrayBuffer(mldsa65Encrypted)),
          fingerprint,
        });

        return true;
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to generate signature keys';
        toast.error(message);
        return false;
      }
    },
    [signatureProvider, storeMutation]
  );

  // Get decrypted secret key for signing
  const getSecretKey = useCallback(
    async (masterKey: CryptoKey | MasterKeyBundle): Promise<HybridSignatureSecretKey> => {
      try {
        const aesGcm = masterKey instanceof CryptoKey ? masterKey : masterKey.aesGcm;

        // Fetch encrypted secret keys from server
        const { ed25519SecretKeyEncrypted, mldsa65SecretKeyEncrypted } =
          await utils.hybridSignature.getSecretKey.fetch({});

        // Decrypt with non-extractable AES-GCM key
        const ed25519SecretKey = await decryptLargeSecretKey(
          new Uint8Array(base64ToArrayBuffer(ed25519SecretKeyEncrypted)),
          aesGcm
        );
        const mldsa65SecretKey = await decryptLargeSecretKey(
          new Uint8Array(base64ToArrayBuffer(mldsa65SecretKeyEncrypted)),
          aesGcm
        );

        return {
          classical: ed25519SecretKey,
          postQuantum: mldsa65SecretKey,
        };
      } catch (error) {
        // Log error for debugging
        console.error('[useSignatureKeys] Failed to get secret key:', error);

        // Provide user-friendly error messages
        if (error instanceof Error) {
          if (error.message.includes('unwrap') || error.message.includes('decrypt')) {
            throw new Error('Failed to unlock signing keys. Please check your password.');
          }
          if (error.message.includes('network') || error.message.includes('fetch')) {
            throw new Error('Network error while fetching signing keys. Please try again.');
          }
          if (error.message.includes('not found') || error.message.includes('No active')) {
            throw new Error('Signing keys not found. Please generate keys in Settings.');
          }
        }

        // Re-throw with generic message if unrecognized
        throw new Error('Failed to retrieve signing keys. Please try again.');
      }
    },
    [utils]
  );

  // Refetch all key data
  const refetch = useCallback(async () => {
    await refetchHasKeyPair();
    await refetchPublicKey();
  }, [refetchHasKeyPair, refetchPublicKey]);

  return {
    keyInfo,
    isLoading: isLoadingHasKeyPair || isLoadingPublicKey,
    isAvailable: null, // Will be checked asynchronously when needed
    generateKeyPair,
    getSecretKey,
    isPending: storeMutation.isPending,
    refetch,
    keyHistory: keyHistory as KeyHistoryEntry[] | undefined,
    isLoadingHistory,
  };
}

/**
 * Hook for getting another user's public key (for verification)
 */
export function useUserSignaturePublicKey(userId: number | null) {
  const { data, isLoading, refetch } = trpc.hybridSignature.getPublicKeyByUserId.useQuery(
    { userId: userId! },
    {
      enabled: userId !== null,
      staleTime: 10 * 60 * 1000, // Cache for 10 minutes
    }
  );

  const publicKey = useMemo((): HybridSignaturePublicKey | null => {
    if (!data) return null;

    return {
      classical: new Uint8Array(base64ToArrayBuffer(data.ed25519PublicKey)),
      postQuantum: new Uint8Array(base64ToArrayBuffer(data.mldsa65PublicKey)),
    };
  }, [data]);

  return {
    publicKey,
    fingerprint: data?.fingerprint ?? null,
    keyVersion: data?.keyVersion ?? null,
    isLoading,
    refetch,
  };
}
