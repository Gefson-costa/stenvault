/**
 * useMasterKey Hook
 *
 * Provides master key derivation for signing and encryption operations.
 * Derives KEK from password using Argon2id, then unwraps the master key.
 *
 * Features:
 * - Hybrid keypair generation during setup (X25519 + ML-KEM-768)
 * - Functions to fetch and unwrap hybrid secret keys
 * - Session-level caching (key survives re-renders, not page refresh)
 * - Configurable timeout (default: 15 minutes)
 * - Automatic cache invalidation
 *
 * Architecture:
 * Password → Argon2id → KEK → AES-KW Unwrap → Master Key
 */

import { useCallback, useState, useMemo, useSyncExternalStore } from 'react';
import { trpc } from '@/lib/trpc';
import { toast } from 'sonner';
import { useAuth } from '@/_core/hooks/useAuth';
import { getHybridKemProvider } from '@/lib/platform/webHybridKemProvider';
import { getHybridSignatureProvider } from '@/lib/platform/webHybridSignatureProvider';
import { base64ToArrayBuffer, arrayBufferToBase64 } from '@/lib/platform';
import { generateRecoveryCodes } from '@/lib/recoveryCodeUtils';
import { clearThumbnailCache } from '@/hooks/useThumbnailDecryption';
import { clearAllOrgKeyCaches } from '@/hooks/useOrgMasterKey';
import { debugLog, debugError } from '@/lib/debugLogger';
import { getHasActiveOperations } from '@/stores/operationStore';
import { loadUES, deriveDeviceKEK as deriveDeviceKEKFromUES, getStoredFingerprintHash } from '@/lib/uesManager';
import {
  toArrayBuffer,
  encryptLargeSecretKey,
  decryptLargeSecretKey,
  deriveArgon2Key,
  unwrapMasterKey,
  createMasterKeyBundle,
  wrapSecretWithMK,
  unwrapSecretWithMK,
  deriveFileKeyFromMaster,
  deriveFileKeyWithBytesFromMaster,
  deriveFilenameKeyFromMaster,
  deriveFoldernameKeyFromMaster,
  deriveFingerprintKeyFromMaster,
  deriveThumbnailKeyFromMaster,
} from './masterKeyCrypto';
import type { MasterKeyBundle } from './masterKeyCrypto';
import type { HybridSecretKey, HybridPublicKey } from '@stenvault/shared/platform/crypto';
import { ARGON2_PARAMS, type Argon2Params } from '@stenvault/shared/platform/crypto';

// Re-export types and functions used by external consumers
export { deriveThumbnailKeyFromMaster } from './masterKeyCrypto';
export type { DerivedFileKeyWithBytes, MasterKeyBundle } from './masterKeyCrypto';
import type { DerivedFileKeyWithBytes } from './masterKeyCrypto';

// ============ Session Cache (Module-level Singleton) ============

/** Default cache timeout: 30 minutes (aligned with access token TTL) */
const DEFAULT_CACHE_TIMEOUT_MS = 30 * 60 * 1000;
/** Re-check interval during deferral */
const DEFERRAL_CHECK_MS = 10_000;

interface MasterKeyCache {
  bundle: MasterKeyBundle;
  derivedAt: number;
  userId: number;
}

/** In-memory cache - survives re-renders, cleared on page refresh (secure) */
let masterKeyCache: MasterKeyCache | null = null;

/** Timer that fires when cache expires to trigger reactive state update */
let cacheExpirationTimer: ReturnType<typeof setTimeout> | null = null;

/** Timer that warns user 2 minutes before cache expiry */
let cacheWarningTimer: ReturnType<typeof setTimeout> | null = null;

/** Cache for unwrapped hybrid secret keys (Phase 2 NEW_DAY) */
interface HybridSecretKeyCache {
  secretKey: HybridSecretKey;
  cachedAt: number;
  userId: number;
}
let hybridSecretKeyCache: HybridSecretKeyCache | null = null;

// ============ Cache Reactivity (useSyncExternalStore) ============
// Module-level subscription so React re-renders when cache changes

let cacheVersion = 0;
const cacheListeners = new Set<() => void>();

function notifyCacheChange(): void {
  cacheVersion++;
  cacheListeners.forEach((listener) => listener());
}

function subscribeToCacheChanges(listener: () => void): () => void {
  cacheListeners.add(listener);
  return () => {
    cacheListeners.delete(listener);
  };
}

function getCacheVersion(): number {
  return cacheVersion;
}

/**
 * Check if cached master key is valid
 */
function isCacheValid(userId: number, timeoutMs: number = DEFAULT_CACHE_TIMEOUT_MS): boolean {
  if (!masterKeyCache) return false;
  if (masterKeyCache.userId !== userId) return false;

  const age = Date.now() - masterKeyCache.derivedAt;
  return age < timeoutMs;
}

/**
 * Get cached master key bundle if valid
 */
function getCachedMasterKey(userId: number, timeoutMs?: number): MasterKeyBundle | null {
  if (isCacheValid(userId, timeoutMs)) {
    return masterKeyCache!.bundle;
  }
  // Clear expired/invalid cache (including timer and hybrid keys)
  if (masterKeyCache) {
    clearMasterKeyCache();
  }
  return null;
}

/**
 * Cache master key bundle and schedule expiration notification
 */
function cacheMasterKey(bundle: MasterKeyBundle, userId: number): void {
  masterKeyCache = {
    bundle,
    derivedAt: Date.now(),
    userId,
  };

  // Clear any existing timers
  if (cacheExpirationTimer) {
    clearTimeout(cacheExpirationTimer);
  }
  if (cacheWarningTimer) {
    clearTimeout(cacheWarningTimer);
    cacheWarningTimer = null;
  }

  // Schedule warning 2 minutes before expiry
  cacheWarningTimer = setTimeout(() => {
    cacheWarningTimer = null;
    if (getHasActiveOperations()) {
      toast.info('Vault lock deferred — uploads/downloads in progress', { id: 'vault-lock-warning' });
    } else {
      toast.warning('Your vault will lock in 2 minutes — save any open work', { id: 'vault-lock-warning' });
    }
  }, DEFAULT_CACHE_TIMEOUT_MS - 120_000);

  // Schedule reactive notification when cache expires
  // This ensures isUnlocked transitions to false automatically
  // Uses a named function to allow self-rescheduling during active operations
  cacheExpirationTimer = setTimeout(function onCacheExpiry() {
    cacheExpirationTimer = null;
    if (!masterKeyCache) return;

    const ageMs = Date.now() - masterKeyCache.derivedAt;

    // Defer indefinitely while operations are active (upload, download, preview).
    // The MK is needed to encrypt/decrypt — killing it mid-operation causes data loss.
    // Hard cap removed: operations drive the lifetime, not an arbitrary clock.
    if (getHasActiveOperations()) {
      debugLog('[MK]', `Cache expiry deferred — operations in progress (age ${Math.round(ageMs / 1000)}s)`);
      cacheExpirationTimer = setTimeout(onCacheExpiry, DEFERRAL_CHECK_MS);
      return;
    }

    masterKeyCache = null;
    // Zero hybrid secret key bytes before clearing
    if (hybridSecretKeyCache?.secretKey) {
      if (hybridSecretKeyCache.secretKey.classical instanceof Uint8Array) {
        hybridSecretKeyCache.secretKey.classical.fill(0);
      }
      if (hybridSecretKeyCache.secretKey.postQuantum instanceof Uint8Array) {
        hybridSecretKeyCache.secretKey.postQuantum.fill(0);
      }
    }
    hybridSecretKeyCache = null;
    clearThumbnailCache();
    clearAllOrgKeyCaches();
    notifyCacheChange();
  }, DEFAULT_CACHE_TIMEOUT_MS);

  notifyCacheChange();
}

/**
 * Clear master key cache (and hybrid secret key cache)
 */
export function clearMasterKeyCache(): void {
  masterKeyCache = null;
  // Zero hybrid secret key bytes before clearing
  if (hybridSecretKeyCache?.secretKey) {
    if (hybridSecretKeyCache.secretKey.classical instanceof Uint8Array) {
      hybridSecretKeyCache.secretKey.classical.fill(0);
    }
    if (hybridSecretKeyCache.secretKey.postQuantum instanceof Uint8Array) {
      hybridSecretKeyCache.secretKey.postQuantum.fill(0);
    }
  }
  hybridSecretKeyCache = null;

  // Clear timers since we're clearing manually
  if (cacheExpirationTimer) {
    clearTimeout(cacheExpirationTimer);
    cacheExpirationTimer = null;
  }
  if (cacheWarningTimer) {
    clearTimeout(cacheWarningTimer);
    cacheWarningTimer = null;
  }

  clearThumbnailCache(); // Revoke decrypted thumbnails on vault lock
  clearAllOrgKeyCaches(); // Clear all org vault caches on personal vault lock
  notifyCacheChange();
}

// ============ Device-Wrapped Master Key (UES Fast-Path) ============
// Stored in IndexedDB (not localStorage) so structured data stays in a
// dedicated key store. The Device-KEK that wraps this key is non-extractable,
// meaning XSS cannot exportKey() the raw KEK bytes.

const IDB_NAME = 'stenvault_keystore';
const IDB_STORE = 'device_keys';
const IDB_VERSION = 1;
const DEVICE_MK_KEY = 'device_mk_v2';

interface DeviceWrappedMK {
  /** Master Key wrapped with Device-KEK (Base64) */
  wrappedKey: string;
  /** User ID this key belongs to */
  userId: number;
  /** Device fingerprint hash at wrap time (invalidates if device changes) */
  deviceFingerprint: string;
  /** Timestamp of when this was created */
  createdAt: number;
}

/** Open (or create) the IndexedDB key store */
function openKeyStore(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(IDB_STORE)) {
        req.result.createObjectStore(IDB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Store device-wrapped master key in IndexedDB for fast future unlocks.
 * The key is wrapped with Device-KEK (password + UES), safe to persist.
 */
async function storeDeviceWrappedMK(wrappedKeyB64: string, userId: number, fingerprint: string): Promise<void> {
  const data: DeviceWrappedMK = {
    wrappedKey: wrappedKeyB64,
    userId,
    deviceFingerprint: fingerprint,
    createdAt: Date.now(),
  };
  try {
    const db = await openKeyStore();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).put(data, DEVICE_MK_KEY);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  } catch (err) {
    debugError('[WARN]', 'Failed to store device-wrapped MK in IndexedDB', err);
  }
}

/**
 * Load device-wrapped master key from IndexedDB.
 * Returns null if not found, wrong user, or device fingerprint changed.
 */
async function loadDeviceWrappedMK(userId: number): Promise<DeviceWrappedMK | null> {
  try {
    const db = await openKeyStore();
    const data = await new Promise<DeviceWrappedMK | undefined>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readonly');
      const req = tx.objectStore(IDB_STORE).get(DEVICE_MK_KEY);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => db.close();
    });
    if (!data) return null;
    if (data.userId !== userId) return null;
    // Check device fingerprint hasn't changed
    const currentFingerprint = getStoredFingerprintHash();
    if (currentFingerprint && data.deviceFingerprint !== currentFingerprint) {
      debugLog('[MK]', 'Device fingerprint changed, clearing stale device-wrapped key');
      clearDeviceWrappedMK();
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

/**
 * Clear device-wrapped master key from IndexedDB.
 * Fire-and-forget — callers do not need to await.
 */
export function clearDeviceWrappedMK(): void {
  openKeyStore()
    .then(db => new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).delete(DEVICE_MK_KEY);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    }))
    .catch(() => {}); // Non-critical cleanup
}

// ============ Shared Helpers ============

/**
 * Generate a key fingerprint from concatenated public keys (SHA-256, first 16 bytes hex).
 * Used for both KEM and Signature keypairs.
 */
async function generateKeyFingerprint(classicalPub: Uint8Array, pqPub: Uint8Array): Promise<string> {
  const data = new Uint8Array(classicalPub.length + pqPub.length);
  data.set(classicalPub, 0);
  data.set(pqPub, classicalPub.length);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash).slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============ Types ============

export interface MasterKeyConfig {
  isConfigured: boolean;
  kdfAlgorithm: 'argon2id' | null;
  salt: string | null;
  argon2Params: Argon2Params | null;
  masterKeyEncrypted: string | null;
  masterKeyVersion: number | null;
  passwordHint: string | null;
}

export interface UseMasterKeyReturn {
  /** Encryption config from server */
  config: MasterKeyConfig | null;
  /** Whether config is loading */
  isLoading: boolean;
  /** Whether vault is unlocked (Master Key is cached and valid) */
  isUnlocked: boolean;
  /** Whether Master Key is configured on server */
  isConfigured: boolean;
  /** Derive master key from password (caches result for session) */
  deriveMasterKey: (password: string) => Promise<MasterKeyBundle>;
  /** Derive unique file key from Master Key using HKDF (for encryption v3) */
  deriveFileKey: (fileId: string, timestamp: number) => Promise<CryptoKey>;
  /**
   * Derive file key WITH raw bytes for Web Worker decryption (Phase 7.1)
   * SECURITY: Caller MUST call zeroBytes() immediately after Worker postMessage!
   */
  deriveFileKeyWithBytes: (fileId: string, timestamp: number) => Promise<DerivedFileKeyWithBytes>;
  /** Derive key for filename encryption (Phase 5 Zero-Knowledge) */
  deriveFilenameKey: () => Promise<CryptoKey>;
  /** Derive key for folder name encryption (Phase C Zero-Knowledge) */
  deriveFoldernameKey: () => Promise<CryptoKey>;
  /** Derive key for thumbnail encryption (Phase 7.2) */
  deriveThumbnailKey: (fileId: string) => Promise<CryptoKey>;
  /** Derive HMAC key for content fingerprinting (quantum-safe duplicate detection) */
  deriveFingerprintKey: () => Promise<CryptoKey>;
  /** Setup Master Key for new users (Phase 1.2 NEW_DAY) */
  setupMasterKey: (password: string, passwordHint?: string) => Promise<{
    success: boolean;
    recoveryCodesPlain: string[];
  }>;
  /** Get cached master key bundle without password (returns null if not cached or expired) */
  getCachedKey: () => MasterKeyBundle | null;
  /** Check if master key is cached and valid */
  isCached: boolean;
  /** Clear the cached master key (locks the vault) */
  clearCache: () => void;
  /** Whether derivation is in progress */
  isDerivingKey: boolean;
  /** Error message if derivation failed */
  error: string | null;
  /** Refetch config from server */
  refetchConfig: () => void;
  // ===== Phase 2 NEW_DAY: Hybrid KEM =====
  /** Whether user has a hybrid keypair configured */
  hasHybridKeyPair: boolean;
  /** Get user's hybrid public key for encryption (fetches from server, throws if unavailable) */
  getHybridPublicKey: () => Promise<HybridPublicKey>;
  /** Get unlocked hybrid secret key for decryption (unwraps with Master Key) */
  getUnlockedHybridSecretKey: () => Promise<HybridSecretKey | null>;
}

// ============ Hook ============

/**
 * Hook for deriving master key from password
 *
 * Features:
 * - Session-level caching (survives re-renders, cleared on page refresh)
 * - Automatic cache expiration (default: 15 minutes)
 * - Per-user cache isolation
 *
 * @returns Master key derivation utilities
 */
export function useMasterKey(): UseMasterKeyReturn {
  const [isDerivingKey, setIsDerivingKey] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { user } = useAuth();

  // Subscribe to module-level cache changes for reactive isUnlocked/isCached
  const currentCacheVersion = useSyncExternalStore(subscribeToCacheChanges, getCacheVersion);

  // Fetch encryption config from server
  const { data: config, isLoading, refetch } = trpc.encryption.getEncryptionConfig.useQuery(undefined, {
    enabled: !!user?.id,
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
  });

  // tRPC utils for imperative queries (Phase 2 NEW_DAY)
  const trpcUtils = trpc.useUtils();

  // Check if cache is valid for current user
  const isCached = useMemo(() => {
    if (!user?.id) return false;
    return isCacheValid(user.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id, currentCacheVersion]);

  // Get cached key bundle for current user
  const getCachedKey = useCallback((): MasterKeyBundle | null => {
    if (!user?.id) return null;
    return getCachedMasterKey(user.id);
  }, [user?.id]);

  // Clear cache
  const clearCache = useCallback(() => {
    clearMasterKeyCache();
  }, []);

  // Mutations (declared before deriveMasterKey which uses them)
  const setupMasterKeyMutation = trpc.encryption.setupMasterKey.useMutation();

  // Phase 2 NEW_DAY: Hybrid KEM (declared before deriveMasterKey for migration)
  const storeHybridKeyPairMutation = trpc.hybridKem.storeKeyPair.useMutation();
  const { data: hasKeyPairData, refetch: refetchHasKeyPair } = trpc.hybridKem.hasKeyPair.useQuery(
    undefined,
    { enabled: !!user?.id, staleTime: 5 * 60 * 1000 }
  );

  // Phase 3.4: Hybrid Signature (ML-DSA-65 + Ed25519) — auto-generate like KEM
  const storeSignatureKeyPairMutation = trpc.hybridSignature.storeKeyPair.useMutation();
  const generateSignatureKeyPairMutation = trpc.hybridSignature.generateKeyPair.useMutation();
  const { data: hasSignatureKeyPairData, refetch: refetchHasSignatureKeyPair } = trpc.hybridSignature.hasKeyPair.useQuery(
    undefined,
    { enabled: !!user?.id, staleTime: 5 * 60 * 1000 }
  );

  // Derive master key from password (with caching)
  // Phase 3 UES: Dual-KEK logic - tries fast-path (Device-KEK with UES) first
  const deriveMasterKey = useCallback(
    async (password: string): Promise<MasterKeyBundle> => {
      if (import.meta.env.DEV) console.warn('[MK] deriveMasterKey called', { configLoaded: !!config, isConfigured: config?.isConfigured });
      debugLog('[MK]', 'deriveMasterKey called', { userId: user?.id, configLoaded: !!config, isConfigured: config?.isConfigured });

      if (!user?.id) {
        throw new Error('User not authenticated');
      }

      // Check cache first
      const cachedBundle = getCachedMasterKey(user.id);
      if (cachedBundle) {
        debugLog('[MK]', 'Using cached master key');
        return cachedBundle;
      }

      if (!config?.isConfigured) {
        throw new Error('Encryption not configured. Please check your connection and try again.');
      }

      if (!config.salt) {
        throw new Error('Missing encryption salt. Please refresh the page.');
      }

      // Guard: Web Crypto API requires a secure context (HTTPS or localhost)
      if (!globalThis.crypto?.subtle) {
        const ctx = typeof window !== 'undefined'
          ? `URL: ${window.location.href}, isSecureContext: ${window.isSecureContext}`
          : 'non-browser context';
        throw new Error(
          `Web Crypto API is not available (crypto.subtle is undefined). ` +
          `This requires HTTPS or localhost. ${ctx}`
        );
      }

      setIsDerivingKey(true);
      setError(null);

      try {
        const saltBytes = new Uint8Array(base64ToArrayBuffer(config.salt));
        if (import.meta.env.DEV) console.warn('[MK] Config:', {
          kdf: config.kdfAlgorithm,
          hasMKE: !!config.masterKeyEncrypted,
          saltLen: config.salt?.length,
        });
        debugLog('[MK]', 'Config loaded', {
          kdfAlgorithm: config.kdfAlgorithm,
          hasArgon2Params: !!config.argon2Params,
          hasMasterKeyEncrypted: !!config.masterKeyEncrypted,
        });

        // Guard: masterKeyEncrypted must exist (no legacy users without key wrapping)
        if (!config.masterKeyEncrypted) {
          throw new Error('Invalid encryption configuration: master key not found. Please re-setup your Master Key.');
        }

        // === NORMAL PATH: masterKeyEncrypted is set ===
        if (import.meta.env.DEV) console.warn('[MK] NORMAL PATH: unwrapping masterKeyEncrypted');
        let bundle: MasterKeyBundle | undefined;
        let uesDataForRewrap: { ues: Uint8Array; fingerprintHash: string } | null = null;

        // Phase 3 UES: Try fast-path with Device-KEK + locally wrapped key
        try {
          const uesData = await loadUES();
          if (uesData) {
            uesDataForRewrap = uesData;
            const deviceMK = await loadDeviceWrappedMK(user.id);
            if (deviceMK) {
              debugLog('[FAST]', 'Trying UES fast-path (Device-KEK + local wrapped key)');
              const deviceKek = await deriveDeviceKEKFromUES(password, uesData.ues, saltBytes);
              try {
                const result = await unwrapMasterKey(deviceMK.wrappedKey, deviceKek);
                bundle = result.bundle;
                debugLog('[OK]', 'Fast-path unlock successful (~100ms)');
              } catch {
                // Wrong password or stale local key - clear it and fall through
                debugLog('[WARN]', 'Fast-path unwrap failed, clearing stale local key');
                clearDeviceWrappedMK();
              }
            } else {
              debugLog('[MK]', 'UES available but no local device-wrapped key yet');
            }
          }
        } catch (uesError) {
          debugLog('[WARN]', 'UES fast-path unavailable:', uesError);
        }

        // Slow-path: Base-KEK from server
        if (!bundle) {
          if (import.meta.env.DEV) console.warn('[MK] SLOW PATH: deriving Base-KEK');
          debugLog('[SLOW]', 'Using slow-path (Base-KEK)');
          if (!config.argon2Params) {
            throw new Error('Invalid encryption configuration: missing Argon2id params');
          }
          debugLog('[MK]', 'Deriving KEK with Argon2id...');
          const kek = await deriveArgon2Key(password, saltBytes, config.argon2Params as Argon2Params);
          debugLog('[OK]', 'Argon2id derivation complete');

          // Unwrap master key with Base-KEK, optionally re-wrap for device fast-path
          debugLog('[MK]', 'Unwrapping master key with Base-KEK...');
          let deviceKekForRewrap: CryptoKey | undefined;
          if (uesDataForRewrap) {
            try {
              deviceKekForRewrap = await deriveDeviceKEKFromUES(password, uesDataForRewrap.ues, saltBytes);
            } catch {
              debugError('[WARN]', 'Failed to derive Device-KEK for re-wrap (non-fatal)');
            }
          }

          const result = await unwrapMasterKey(config.masterKeyEncrypted, kek, deviceKekForRewrap);
          bundle = result.bundle;
          debugLog('[OK]', 'Slow-path unlock successful');

          // Store device-wrapped key for fast future unlocks
          if (result.deviceWrapped && uesDataForRewrap) {
            try {
              debugLog('[MK]', 'Storing device-wrapped key for fast-path...');
              await storeDeviceWrappedMK(
                arrayBufferToBase64(result.deviceWrapped),
                user.id,
                uesDataForRewrap.fingerprintHash
              );
              debugLog('[OK]', 'Device-wrapped key stored - next unlock will be fast (~100ms)');
            } catch (storeErr) {
              debugError('[WARN]', 'Failed to store device-wrapped key (non-fatal)', storeErr);
            }
          }
        }

        // Cache non-extractable bundle for session
        cacheMasterKey(bundle, user.id);
        debugLog('[OK]', 'Master key derived, unwrapped, and cached (non-extractable)');

        // ===== Phase 2 Migration: Generate hybrid keypair if missing =====
        // Non-blocking: if WASM fails, vault unlock still succeeds — V4 uploads will fail gracefully
        if (!hasKeyPairData?.hasKeyPair) {
          (async () => {
            try {
              console.warn('[MK] Starting hybrid keypair migration...');
              const hybridKem = getHybridKemProvider();
              const isAvailable = await hybridKem.isAvailable();
              console.warn('[MK] Hybrid KEM available:', isAvailable);
              if (!isAvailable) {
                console.warn('[MK] ML-KEM-768 WASM not available — skipping keypair generation, will retry next login');
                return;
              }

              debugLog('[CRYPTO]', 'Migrating: generating hybrid keypairs (X25519 + ML-KEM-768)');
              const { publicKey, secretKey } = await hybridKem.generateKeyPair();

              // Wrap X25519 secret (32 bytes) with AES-KW, encrypt ML-KEM secret (2400 bytes) with AES-GCM
              // Uses non-extractable CryptoKeys from bundle — no raw MK bytes needed
              const x25519WrappedBytes = await wrapSecretWithMK(secretKey.classical, bundle.aesKw);
              const mlkemEncrypted = await encryptLargeSecretKey(secretKey.postQuantum, bundle.aesGcm);

              // Generate fingerprint
              const fingerprint = await generateKeyFingerprint(publicKey.classical, publicKey.postQuantum);

              // Store on server
              await storeHybridKeyPairMutation.mutateAsync({
                x25519PublicKey: arrayBufferToBase64(toArrayBuffer(publicKey.classical)),
                x25519SecretKeyEncrypted: arrayBufferToBase64(toArrayBuffer(x25519WrappedBytes)),
                mlkem768PublicKey: arrayBufferToBase64(toArrayBuffer(publicKey.postQuantum)),
                mlkem768SecretKeyEncrypted: arrayBufferToBase64(toArrayBuffer(mlkemEncrypted)),
                fingerprint,
              });

              await refetchHasKeyPair();
              console.warn('[MK] Hybrid keypairs generated (migration) - v4 encryption now available');
              debugLog('[CRYPTO]', 'Hybrid keypairs generated (migration)', { fingerprint });
            } catch (kemMigrationErr) {
              // Non-fatal: will retry on next login. V4 uploads will fail gracefully.
              console.warn('[MK] Hybrid keypair migration FAILED:', kemMigrationErr);
              debugError('[CRYPTO]', 'Hybrid keypair migration failed (will retry next login)', kemMigrationErr);
            }
          })();
        }

        // ===== Phase 3.4 Migration: Generate hybrid signature keypair if missing =====
        // Non-blocking: fire-and-forget to avoid slowing unlock
        if (!hasSignatureKeyPairData?.hasKeyPair) {
          (async () => {
            try {
              console.warn('[MK] Starting hybrid signature keypair migration...');

              // Try client-side generation first (keys never leave browser)
              const signatureProvider = getHybridSignatureProvider();
              const isAvailable = await signatureProvider.isAvailable();

              let sigPublicKey: { classical: Uint8Array; postQuantum: Uint8Array };
              let sigSecretKey: { classical: Uint8Array; postQuantum: Uint8Array };
              let sigFingerprint: string;

              if (isAvailable) {
                // Client-side: more secure, keys never transit network
                if (import.meta.env.DEV) console.warn('[MK] Generating signature keypairs client-side');
                const keyPair = await signatureProvider.generateKeyPair();
                sigPublicKey = keyPair.publicKey;
                sigSecretKey = keyPair.secretKey;
                sigFingerprint = await generateKeyFingerprint(sigPublicKey.classical, sigPublicKey.postQuantum);
              } else {
                // ML-DSA-65 WASM not available — generate Ed25519 only (native WebCrypto)
                // ML-DSA-65 will be generated when WASM loads in a future session
                if (import.meta.env.DEV) console.warn('[MK] ML-DSA-65 WASM unavailable, generating Ed25519-only client-side');
                const ed25519Key = await crypto.subtle.generateKey(
                  { name: 'Ed25519' } as any, true, ['sign', 'verify']
                );
                const ed25519Pub = new Uint8Array(await crypto.subtle.exportKey('raw', ed25519Key.publicKey));
                const ed25519Priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', ed25519Key.privateKey));
                sigPublicKey = { classical: ed25519Pub, postQuantum: new Uint8Array(0) };
                sigSecretKey = { classical: ed25519Priv, postQuantum: new Uint8Array(0) };
                sigFingerprint = await generateKeyFingerprint(sigPublicKey.classical, sigPublicKey.postQuantum);
              }

              // Encrypt both secret keys with Master Key's AES-GCM CryptoKey (non-extractable)
              const ed25519Encrypted = await encryptLargeSecretKey(sigSecretKey.classical, bundle.aesGcm);
              const mldsa65Encrypted = await encryptLargeSecretKey(sigSecretKey.postQuantum, bundle.aesGcm);
              sigSecretKey.classical.fill(0);
              sigSecretKey.postQuantum.fill(0);

              // Store on server
              await storeSignatureKeyPairMutation.mutateAsync({
                ed25519PublicKey: arrayBufferToBase64(toArrayBuffer(sigPublicKey.classical)),
                ed25519SecretKeyEncrypted: arrayBufferToBase64(toArrayBuffer(ed25519Encrypted)),
                mldsa65PublicKey: arrayBufferToBase64(toArrayBuffer(sigPublicKey.postQuantum)),
                mldsa65SecretKeyEncrypted: arrayBufferToBase64(toArrayBuffer(mldsa65Encrypted)),
                fingerprint: sigFingerprint,
              });

              await refetchHasSignatureKeyPair();
              if (import.meta.env.DEV) console.warn('[MK] Hybrid signature keypairs generated (migration)');
              debugLog('[CRYPTO]', 'Hybrid signature keypairs generated (migration)', { fingerprint: sigFingerprint });
            } catch (sigMigrationErr) {
              // Non-fatal: will retry on next login
              if (import.meta.env.DEV) console.warn('[MK] Hybrid signature keypair migration FAILED:', sigMigrationErr);
              debugError('[CRYPTO]', 'Signature keypair migration failed (will retry next login)', sigMigrationErr);
            }
          })();
        }

        return bundle;
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to derive master key';
        if (import.meta.env.DEV) console.error('[MK] deriveMasterKey FAILED:', message);
        debugError('[ERR]', 'deriveMasterKey failed', err);
        setError(message);
        throw err;
      } finally {
        setIsDerivingKey(false);
      }
    },
    [config, user?.id, refetch, hasKeyPairData?.hasKeyPair, storeHybridKeyPairMutation, refetchHasKeyPair, hasSignatureKeyPairData?.hasKeyPair, storeSignatureKeyPairMutation, generateSignatureKeyPairMutation, refetchHasSignatureKeyPair]
  );

  // Derive file key from Master Key using HKDF (for encryption v3)
  const deriveFileKey = useCallback(
    async (fileId: string, timestamp: number): Promise<CryptoKey> => {
      if (!user?.id) throw new Error('User not authenticated');
      const bundle = getCachedMasterKey(user.id);
      if (!bundle) throw new Error('Vault is locked. Please unlock with your Master Password first.');
      return deriveFileKeyFromMaster(bundle.hkdf, fileId, timestamp);
    },
    [user?.id]
  );

  // Derive file key WITH raw bytes for Web Worker (Phase 7.1)
  const deriveFileKeyWithBytes = useCallback(
    async (fileId: string, timestamp: number): Promise<DerivedFileKeyWithBytes> => {
      if (!user?.id) throw new Error('User not authenticated');
      const bundle = getCachedMasterKey(user.id);
      if (!bundle) throw new Error('Vault is locked. Please unlock with your Master Password first.');
      return deriveFileKeyWithBytesFromMaster(bundle.hkdf, fileId, timestamp);
    },
    [user?.id]
  );

  // Derive filename key from Master Key using HKDF (for Phase 5 Zero-Knowledge)
  const deriveFilenameKey = useCallback(
    async (): Promise<CryptoKey> => {
      if (!user?.id) throw new Error('User not authenticated');
      const bundle = getCachedMasterKey(user.id);
      if (!bundle) throw new Error('Vault is locked. Please unlock with your Master Password first.');
      return deriveFilenameKeyFromMaster(bundle.hkdf);
    },
    [user?.id]
  );

  // Derive foldername key from Master Key using HKDF (Phase C Zero-Knowledge)
  const deriveFoldernameKey = useCallback(
    async (): Promise<CryptoKey> => {
      if (!user?.id) throw new Error('User not authenticated');
      const bundle = getCachedMasterKey(user.id);
      if (!bundle) throw new Error('Vault is locked. Please unlock with your Master Password first.');
      return deriveFoldernameKeyFromMaster(bundle.hkdf);
    },
    [user?.id]
  );

  // Derive thumbnail key from Master Key using HKDF (Phase 7.2)
  const deriveThumbnailKey = useCallback(
    async (fileId: string): Promise<CryptoKey> => {
      if (!user?.id) throw new Error('User not authenticated');
      const bundle = getCachedMasterKey(user.id);
      if (!bundle) throw new Error('Vault is locked. Please unlock with your Master Password first.');
      return deriveThumbnailKeyFromMaster(bundle.hkdf, fileId);
    },
    [user?.id]
  );

  // Derive fingerprint key from Master Key using HKDF (for quantum-safe duplicate detection)
  const deriveFingerprintKey = useCallback(
    async (): Promise<CryptoKey> => {
      if (!user?.id) throw new Error('User not authenticated');
      const bundle = getCachedMasterKey(user.id);
      if (!bundle) throw new Error('Vault is locked. Please unlock with your Master Password first.');
      return deriveFingerprintKeyFromMaster(bundle.hkdf);
    },
    [user?.id]
  );

  // Setup Master Key for new users (Phase 1.2 NEW_DAY)
  const setupMasterKey = useCallback(
    async (password: string, passwordHint?: string): Promise<{ success: boolean; recoveryCodesPlain: string[] }> => {
      if (!user?.id) {
        throw new Error('User not authenticated');
      }

      if (config?.isConfigured) {
        throw new Error('Master Key is already configured');
      }

      setIsDerivingKey(true);
      setError(null);

      try {
        // 1. Generate random salt (32 bytes = 256 bits)
        const salt = crypto.getRandomValues(new Uint8Array(32));
        const saltBase64 = btoa(String.fromCharCode(...salt));

        // 2. Generate 10 recovery codes (8 alphanumeric chars each)
        const recoveryCodesPlain = generateRecoveryCodes();

        // 3. Derive KEK from password using Argon2id (OWASP 2024)
        const argon2Params: Argon2Params = {
          type: ARGON2_PARAMS.type,
          memoryCost: ARGON2_PARAMS.memoryCost,
          timeCost: ARGON2_PARAMS.timeCost,
          parallelism: ARGON2_PARAMS.parallelism,
          hashLength: ARGON2_PARAMS.hashLength,
        };
        const kek = await deriveArgon2Key(password, salt, argon2Params);

        // 5. Generate real Master Key (random 32 bytes), wrap with KEK, create non-extractable bundle
        const masterKeyRaw = crypto.getRandomValues(new Uint8Array(32));

        // Import as extractable temporarily for wrapping with KEK
        const tempKey = await crypto.subtle.importKey(
          'raw', toArrayBuffer(masterKeyRaw),
          { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );
        const wrappedMasterKey = await crypto.subtle.wrapKey('raw', tempKey, kek, 'AES-KW');
        const masterKeyEncryptedB64 = arrayBufferToBase64(wrappedMasterKey);

        // Create non-extractable bundle (zeros masterKeyRaw)
        const bundle = await createMasterKeyBundle(masterKeyRaw);

        // 6. Send to backend (including wrapped Master Key + Argon2 params)
        await setupMasterKeyMutation.mutateAsync({
          pbkdf2Salt: saltBase64,
          recoveryCodes: recoveryCodesPlain,
          masterKeyEncrypted: masterKeyEncryptedB64,
          passwordHint: passwordHint || undefined,
          argon2Params: { ...argon2Params, type: 'argon2id' as const },
        });

        // 9. Refresh config
        await refetch();

        // 10. Cache non-extractable bundle
        cacheMasterKey(bundle, user.id);

        // ===== Phase 2 NEW_DAY: Generate and store Hybrid Keypairs (MANDATORY) =====
        debugLog('[CRYPTO]', 'Generating hybrid keypairs (X25519 + ML-KEM-768)');

        const hybridKem = getHybridKemProvider();

        // V4 hybrid encryption is mandatory — fail if WASM not available
        const isHybridAvailable = await hybridKem.isAvailable();
        if (!isHybridAvailable) {
          const err = new Error('Hybrid KEM (ML-KEM-768) WASM not available. V4 encryption requires quantum-safe keys.');
          (err as any).code = 'HYBRID_KEM_UNAVAILABLE';
          throw err;
        }

        // Generate hybrid keypair
        const { publicKey, secretKey } = await hybridKem.generateKeyPair();

        // Wrap/encrypt with non-extractable bundle keys — no raw MK bytes needed
        const x25519WrappedBytes = await wrapSecretWithMK(secretKey.classical, bundle.aesKw);
        const mlkemEncrypted = await encryptLargeSecretKey(secretKey.postQuantum, bundle.aesGcm);

        // Generate fingerprint
        const fingerprint = await generateKeyFingerprint(publicKey.classical, publicKey.postQuantum);

        // Store on server
        await storeHybridKeyPairMutation.mutateAsync({
          x25519PublicKey: arrayBufferToBase64(toArrayBuffer(publicKey.classical)),
          x25519SecretKeyEncrypted: arrayBufferToBase64(toArrayBuffer(x25519WrappedBytes)),
          mlkem768PublicKey: arrayBufferToBase64(toArrayBuffer(publicKey.postQuantum)),
          mlkem768SecretKeyEncrypted: arrayBufferToBase64(toArrayBuffer(mlkemEncrypted)),
          fingerprint,
        });

        debugLog('[CRYPTO]', 'Hybrid keypairs generated and stored', { fingerprint });
        await refetchHasKeyPair();

        // ===== Phase 3.4: Generate and store Hybrid Signature Keypairs =====
        try {
          debugLog('[CRYPTO]', 'Generating hybrid signature keypairs (Ed25519 + ML-DSA-65)');

          const signatureProvider = getHybridSignatureProvider();
          const isSignatureAvailable = await signatureProvider.isAvailable();

          let sigPublicKey: { classical: Uint8Array; postQuantum: Uint8Array };
          let sigSecretKey: { classical: Uint8Array; postQuantum: Uint8Array };
          let sigFingerprint: string;

          if (isSignatureAvailable) {
            const keyPair = await signatureProvider.generateKeyPair();
            sigPublicKey = keyPair.publicKey;
            sigSecretKey = keyPair.secretKey;
            sigFingerprint = await generateKeyFingerprint(sigPublicKey.classical, sigPublicKey.postQuantum);
          } else {
            debugLog('[CRYPTO]', 'ML-DSA-65 WASM unavailable, generating Ed25519-only client-side');
            const ed25519Key = await crypto.subtle.generateKey(
              { name: 'Ed25519' } as any, true, ['sign', 'verify']
            );
            const ed25519Pub = new Uint8Array(await crypto.subtle.exportKey('raw', ed25519Key.publicKey));
            const ed25519Priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', ed25519Key.privateKey));
            sigPublicKey = { classical: ed25519Pub, postQuantum: new Uint8Array(0) };
            sigSecretKey = { classical: ed25519Priv, postQuantum: new Uint8Array(0) };
            sigFingerprint = await generateKeyFingerprint(sigPublicKey.classical, sigPublicKey.postQuantum);
          }

          // Encrypt with non-extractable AES-GCM key
          const ed25519Encrypted = await encryptLargeSecretKey(sigSecretKey.classical, bundle.aesGcm);
          const mldsa65Encrypted = await encryptLargeSecretKey(sigSecretKey.postQuantum, bundle.aesGcm);
          sigSecretKey.classical.fill(0);
          sigSecretKey.postQuantum.fill(0);

          await storeSignatureKeyPairMutation.mutateAsync({
            ed25519PublicKey: arrayBufferToBase64(toArrayBuffer(sigPublicKey.classical)),
            ed25519SecretKeyEncrypted: arrayBufferToBase64(toArrayBuffer(ed25519Encrypted)),
            mldsa65PublicKey: arrayBufferToBase64(toArrayBuffer(sigPublicKey.postQuantum)),
            mldsa65SecretKeyEncrypted: arrayBufferToBase64(toArrayBuffer(mldsa65Encrypted)),
            fingerprint: sigFingerprint,
          });

          debugLog('[CRYPTO]', 'Hybrid signature keypairs generated and stored', { fingerprint: sigFingerprint });
          await refetchHasSignatureKeyPair();
        } catch (sigErr) {
          debugError('[CRYPTO]', 'Failed to generate signature keypairs (non-fatal)', sigErr);
        }

        toast.success('Master Key configured successfully!');

        return {
          success: true,
          recoveryCodesPlain,
        };
      } catch (err) {
        const code = (err as any)?.code;
        const message = err instanceof Error ? err.message : 'Failed to setup Master Key';
        setError(message);
        if (code !== 'HYBRID_KEM_UNAVAILABLE') {
          toast.error('Failed to setup Master Key', { description: message });
        }
        throw err;
      } finally {
        setIsDerivingKey(false);
      }
    },
    [config?.isConfigured, user?.id, setupMasterKeyMutation, refetch, storeHybridKeyPairMutation, refetchHasKeyPair, storeSignatureKeyPairMutation, generateSignatureKeyPairMutation, refetchHasSignatureKeyPair]
  );

  // Computed: is the vault unlocked (Master Key cached and valid)?
  const isUnlocked = useMemo(() => {
    if (!user?.id) return false;
    if (!config?.isConfigured) return false;
    return isCacheValid(user.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id, config?.isConfigured, currentCacheVersion]);

  // Computed: is Master Key configured on server?
  const isConfigured = useMemo(() => {
    return config?.isConfigured ?? false;
  }, [config?.isConfigured]);

  // ===== Phase 2 NEW_DAY: Hybrid Key Access Functions =====

  // Computed: does user have a hybrid keypair?
  const hasHybridKeyPair = useMemo(() => {
    return hasKeyPairData?.hasKeyPair ?? false;
  }, [hasKeyPairData?.hasKeyPair]);

  // Get user's hybrid public key for encryption (required for V4 uploads)
  const getHybridPublicKey = useCallback(async (): Promise<HybridPublicKey> => {
    if (!user?.id) throw new Error('User not authenticated — cannot fetch hybrid public key');

    const publicKeyResponse = await trpcUtils.hybridKem.getPublicKey.fetch();

    if (!publicKeyResponse) {
      throw new Error('No hybrid public key found. V4 encryption requires quantum-safe keys to be set up.');
    }

    // Convert from base64 to Uint8Array
    return {
      classical: new Uint8Array(base64ToArrayBuffer(publicKeyResponse.x25519PublicKey)),
      postQuantum: new Uint8Array(base64ToArrayBuffer(publicKeyResponse.mlkem768PublicKey)),
    };
  }, [user?.id, trpcUtils]);

  // Get unlocked hybrid secret key for decryption (unwraps with Master Key)
  const getUnlockedHybridSecretKey = useCallback(async (): Promise<HybridSecretKey | null> => {
    if (!user?.id) return null;

    // Check cache first
    if (hybridSecretKeyCache &&
      hybridSecretKeyCache.userId === user.id &&
      Date.now() - hybridSecretKeyCache.cachedAt < DEFAULT_CACHE_TIMEOUT_MS) {
      return hybridSecretKeyCache.secretKey;
    }

    // Get cached master key bundle - must be unlocked
    const bundle = getCachedMasterKey(user.id);
    if (!bundle) {
      debugError('[CRYPTO]', 'Vault is locked, cannot get hybrid secret key');
      return null;
    }

    try {
      const secretKeyResponse = await trpcUtils.hybridKem.getSecretKey.fetch({});

      if (!secretKeyResponse) {
        debugLog('[CRYPTO]', 'No hybrid secret key found for user');
        return null;
      }

      // Unwrap X25519 secret (AES-KW) and decrypt ML-KEM secret (AES-GCM)
      // Uses non-extractable CryptoKeys from bundle — no raw MK bytes needed
      const x25519SecretWrapped = new Uint8Array(base64ToArrayBuffer(secretKeyResponse.x25519SecretKeyEncrypted));
      const mlkemSecretEncrypted = new Uint8Array(base64ToArrayBuffer(secretKeyResponse.mlkem768SecretKeyEncrypted));

      const x25519Secret = await unwrapSecretWithMK(x25519SecretWrapped, bundle.aesKw);
      const mlkemDecrypted = await decryptLargeSecretKey(mlkemSecretEncrypted, bundle.aesGcm);

      const secretKey: HybridSecretKey = {
        classical: x25519Secret,
        postQuantum: mlkemDecrypted,
      };

      // Cache for session
      hybridSecretKeyCache = {
        secretKey,
        cachedAt: Date.now(),
        userId: user.id,
      };

      debugLog('[CRYPTO]', 'Hybrid secret key unwrapped and cached');
      return secretKey;
    } catch (err) {
      debugError('[CRYPTO]', 'Failed to get hybrid secret key', err);
      return null;
    }
  }, [user?.id, trpcUtils]);

  return {
    config: (config as MasterKeyConfig | undefined) ?? null,
    isLoading,
    isUnlocked,
    isConfigured,
    deriveMasterKey,
    deriveFileKey,
    deriveFileKeyWithBytes, // Phase 7.1 Web Worker decryption
    deriveFilenameKey, // Phase 5 Zero-Knowledge
    deriveFoldernameKey, // Phase C Zero-Knowledge
    deriveThumbnailKey, // Phase 7.2 Encrypted Thumbnails
    deriveFingerprintKey, // Quantum-safe duplicate detection
    setupMasterKey,
    getCachedKey,
    isCached,
    clearCache,
    isDerivingKey,
    error,
    refetchConfig: refetch,
    // Phase 2 NEW_DAY: Hybrid KEM
    hasHybridKeyPair,
    getHybridPublicKey,
    getUnlockedHybridSecretKey,
  };
}

