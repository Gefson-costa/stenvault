/**
 * useThumbnailDecryption Hook (Phase 7.2)
 *
 * Provides decryption and caching of encrypted thumbnails for display.
 * Fetches encrypted thumbnails from R2, decrypts with Master Key, and
 * caches blob URLs in memory for performance.
 *
 * @module useThumbnailDecryption
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useMasterKey } from './useMasterKey';
import { useOrgMasterKey } from './useOrgMasterKey';
import { decryptThumbnailFromUrl } from '@/lib/fileCrypto';
import { debugLog, debugWarn } from '@/lib/debugLogger';

// ===== MODULE-LEVEL CACHE =====
// Cache decrypted thumbnail blob URLs in memory
// Key: fileId, Value: { blobUrl, createdAt }
interface CacheEntry {
    blobUrl: string;
    createdAt: number;
}

export const thumbnailCache = new Map<number, CacheEntry>();
export const CACHE_MAX_SIZE = 100; // Maximum cached thumbnails
export const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

/**
 * Clean up expired cache entries
 */
export function cleanupCache(): void {
    const now = Date.now();
    const expiredKeys: number[] = [];

    thumbnailCache.forEach((entry, key) => {
        if (now - entry.createdAt > CACHE_TTL_MS) {
            URL.revokeObjectURL(entry.blobUrl);
            expiredKeys.push(key);
        }
    });

    expiredKeys.forEach((key) => thumbnailCache.delete(key));
}

/**
 * Add entry to cache, evicting oldest if needed
 */
export function addToCache(fileId: number, blobUrl: string): void {
    // Clean up expired entries first
    cleanupCache();

    // Evict oldest if at capacity
    if (thumbnailCache.size >= CACHE_MAX_SIZE) {
        let oldestKey: number | null = null;
        let oldestTime = Infinity;

        thumbnailCache.forEach((entry, key) => {
            if (entry.createdAt < oldestTime) {
                oldestTime = entry.createdAt;
                oldestKey = key;
            }
        });

        if (oldestKey !== null) {
            const oldEntry = thumbnailCache.get(oldestKey);
            if (oldEntry) URL.revokeObjectURL(oldEntry.blobUrl);
            thumbnailCache.delete(oldestKey);
        }
    }

    thumbnailCache.set(fileId, {
        blobUrl,
        createdAt: Date.now(),
    });
}

/**
 * Get cached thumbnail if available
 */
export function getCached(fileId: number): string | null {
    const entry = thumbnailCache.get(fileId);
    if (!entry) return null;

    // Check if expired
    if (Date.now() - entry.createdAt > CACHE_TTL_MS) {
        URL.revokeObjectURL(entry.blobUrl);
        thumbnailCache.delete(fileId);
        return null;
    }

    return entry.blobUrl;
}

// ===== TYPES =====

export interface ThumbnailDecryptionState {
    /** Decrypted thumbnail blob URL (or null if not ready) */
    url: string | null;
    /** Whether decryption is in progress */
    isLoading: boolean;
    /** Error message if decryption failed */
    error: string | null;
}

export interface UseThumbnailDecryptionParams {
    /** File ID for cache key and key derivation */
    fileId: number;
    /** URL to fetch encrypted thumbnail from R2 */
    thumbnailUrl: string | null;
    /** IV used for thumbnail encryption */
    thumbnailIv: string | null;
    /** Override fileId for HKDF key derivation (for duplicated files that share the original's thumbnail key) */
    keyDerivationFileId?: number;
    /** Organization ID — if set, derives thumbnail key from OMK instead of personal MK */
    organizationId?: number | null;
    /** Whether to auto-fetch on mount */
    autoFetch?: boolean;
}

export interface UseThumbnailDecryptionReturn extends ThumbnailDecryptionState {
    /** Manually trigger decryption */
    decrypt: () => Promise<void>;
    /** Clear cached thumbnail */
    clear: () => void;
}

/**
 * Hook for decrypting and displaying encrypted thumbnails
 *
 * @example
 * ```tsx
 * const { url, isLoading, error } = useThumbnailDecryption({
 *   fileId: file.id,
 *   thumbnailUrl: file.thumbnailUrl,
 *   thumbnailIv: file.thumbnailIv,
 * });
 *
 * if (isLoading) return <Skeleton />;
 * if (url) return <img src={url} alt="thumbnail" />;
 * return <FallbackIcon />;
 * ```
 */
export function useThumbnailDecryption({
    fileId,
    thumbnailUrl,
    thumbnailIv,
    keyDerivationFileId,
    organizationId,
    autoFetch = true,
}: UseThumbnailDecryptionParams): UseThumbnailDecryptionReturn {
    const [url, setUrl] = useState<string | null>(() => getCached(fileId));
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const { deriveThumbnailKey, isUnlocked } = useMasterKey();
    const { deriveOrgThumbnailKey, unlockOrgVault, isOrgUnlocked } = useOrgMasterKey();
    const decryptionInProgress = useRef(false);

    const decrypt = useCallback(async () => {
        // Check if we have all required data
        if (!thumbnailUrl || !thumbnailIv) {
            return;
        }

        // Check cache first
        const cached = getCached(fileId);
        if (cached) {
            setUrl(cached);
            return;
        }

        // Check if decryption already in progress
        if (decryptionInProgress.current) {
            return;
        }

        // Vault must be unlocked
        if (!isUnlocked) {
            setError('Vault is locked');
            return;
        }

        decryptionInProgress.current = true;
        setIsLoading(true);
        setError(null);

        try {
            // Derive thumbnail key — org key if org file, personal key otherwise
            const derivationId = (keyDerivationFileId ?? fileId).toString();
            let thumbnailKey: CryptoKey;
            if (organizationId) {
                await unlockOrgVault(organizationId);
                thumbnailKey = await deriveOrgThumbnailKey(organizationId, derivationId);
            } else {
                thumbnailKey = await deriveThumbnailKey(derivationId);
            }

            // Fetch and decrypt thumbnail
            const decryptedBlob = await decryptThumbnailFromUrl(
                thumbnailUrl,
                thumbnailKey,
                thumbnailIv
            );

            // Create blob URL
            const blobUrl = URL.createObjectURL(decryptedBlob);

            // Cache and set
            addToCache(fileId, blobUrl);
            setUrl(blobUrl);

            debugLog('🖼️', 'Thumbnail decrypted and cached', { fileId });
        } catch (err) {
            const message = err instanceof Error ? err.message : 'Decryption failed';
            setError(message);
            debugWarn('🖼️', 'Thumbnail decryption failed', { fileId, error: message });
        } finally {
            setIsLoading(false);
            decryptionInProgress.current = false;
        }
    }, [fileId, thumbnailUrl, thumbnailIv, keyDerivationFileId, organizationId, isUnlocked, deriveThumbnailKey, deriveOrgThumbnailKey, unlockOrgVault]);

    const clear = useCallback(() => {
        const cached = getCached(fileId);
        if (cached) {
            URL.revokeObjectURL(cached);
            thumbnailCache.delete(fileId);
        }
        setUrl(null);
        setError(null);
    }, [fileId]);

    // Auto-fetch on mount or when dependencies change
    useEffect(() => {
        if (autoFetch && thumbnailUrl && thumbnailIv && isUnlocked && !url && !isLoading && !error) {
            decrypt();
        }
    }, [autoFetch, thumbnailUrl, thumbnailIv, isUnlocked, url, isLoading, error, decrypt]);

    // Note: Don't revoke cached blob URLs on unmount - they're shared via module-level cache.
    // Cache cleanup happens via clearThumbnailCache() when vault is locked.

    return {
        url,
        isLoading,
        error,
        decrypt,
        clear,
    };
}

/**
 * Clear all cached thumbnails
 * Call this when user locks vault or logs out
 */
export function clearThumbnailCache(): void {
    thumbnailCache.forEach((entry) => {
        URL.revokeObjectURL(entry.blobUrl);
    });
    thumbnailCache.clear();
    debugLog('🖼️', 'Thumbnail cache cleared');
}
