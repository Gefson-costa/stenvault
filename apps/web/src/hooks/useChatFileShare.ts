/**
 * Chat File Share Hook
 *
 * Hook for sharing vault files in chat with E2E encryption.
 * Handles the complete flow:
 * 1. Get recipient's hybrid public key (X25519 + ML-KEM-768)
 * 2. Get file's encryption key
 * 3. Re-encrypt file key for recipient using hybrid KEM
 * 4. Create share via API
 *
 * @module hooks/useChatFileShare
 */

import { useCallback, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { trpc } from "@/lib/trpc";
import { useMasterKey } from "./useMasterKey";
import { useCryptoStore } from "@/stores/cryptoStore";
import {
    reEncryptFileKeyForPeer,
    generateKeyFingerprint,
} from "@/lib/chatFileCrypto";
import { extractV4FileKey } from "@/lib/hybridFileCrypto";
import { base64ToArrayBuffer, deserializeHybridPublicKey } from "@/lib/platform";
import type { HybridPublicKeySerialized } from "@/lib/platform";
import { getSecureItem } from "@/lib/secureStorage";
import { toast } from "sonner";
import { debugLog } from "@/lib/debugLogger";

// Storage key prefix for file encryption keys
const FILE_KEY_STORAGE_PREFIX = "file:key:";

export interface ShareFileOptions {
    fileId: number;
    recipientUserId: number;
    permission?: "view" | "download";
    expiresIn?: "1h" | "24h" | "7d" | "30d" | "never";
    maxDownloads?: number;
    messageContent?: string;
}

export interface ShareFileResult {
    shareId: number;
    messageId: number;
}

/**
 * Hook for sharing vault files in chat
 */
export function useChatFileShare() {
    const queryClient = useQueryClient();
    const { hasHybridKeyPair, isUnlocked, getUnlockedHybridSecretKey } = useMasterKey();
    const { getCachedHybridPublicKey } = useCryptoStore();
    const [isSharing, setIsSharing] = useState(false);
    const utils = trpc.useUtils();

    // tRPC mutation for creating the share
    const shareFileMutation = trpc.chatFileShare.shareFileToChat.useMutation({
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["chatFileShare", "listMyShares"] });
            queryClient.invalidateQueries({ queryKey: ["chatFileShare", "getShareStats"] });
        },
    });

    /**
     * Get file's encryption key from secure storage
     */
    const getFileEncryptionKey = useCallback(
        async (fileId: number): Promise<ArrayBuffer | null> => {
            const keyBase64 = await getSecureItem(
                `${FILE_KEY_STORAGE_PREFIX}${fileId}`
            );

            if (!keyBase64) {
                console.warn(`No encryption key found for file ${fileId}`);
                return null;
            }

            if (typeof keyBase64 !== "string" || keyBase64.length === 0) {
                throw new Error(`Invalid key format for file ${fileId}: key must be a non-empty string`);
            }

            const base64Regex = /^[A-Za-z0-9+/\-_]*={0,2}$/;
            if (!base64Regex.test(keyBase64)) {
                throw new Error(`Corrupt key data for file ${fileId}: invalid base64 encoding`);
            }

            let keyBytes: ArrayBuffer;
            try {
                keyBytes = base64ToArrayBuffer(keyBase64);
            } catch (error) {
                const msg = error instanceof Error ? error.message : "unknown error";
                throw new Error(`Failed to decode key for file ${fileId}: ${msg}`);
            }

            const AES_256_KEY_LENGTH = 32;
            if (keyBytes.byteLength !== AES_256_KEY_LENGTH) {
                throw new Error(
                    `Invalid key length for file ${fileId}: expected ${AES_256_KEY_LENGTH} bytes, got ${keyBytes.byteLength}`
                );
            }

            return keyBytes;
        },
        []
    );

    /**
     * Share a vault file in chat
     */
    const shareFile = useCallback(
        async (options: ShareFileOptions): Promise<ShareFileResult> => {
            const {
                fileId,
                recipientUserId,
                permission = "download",
                expiresIn,
                maxDownloads,
                messageContent,
            } = options;

            setIsSharing(true);

            try {
                // 1. Check if we have hybrid keys and vault is unlocked
                if (!hasHybridKeyPair || !isUnlocked) {
                    throw new Error("Vault must be unlocked with hybrid keys to share files.");
                }

                // 2. Get recipient's hybrid public key
                let cachedKey = getCachedHybridPublicKey(recipientUserId);
                if (!cachedKey) {
                    // Fetch from server
                    const result = await utils.chat.getPeerHybridPublicKey.fetch({
                        userId: recipientUserId,
                    });
                    if (!result?.hybridPublicKey) {
                        throw new Error("Recipient has not set up encryption yet");
                    }
                    cachedKey = {
                        x25519PublicKey: result.hybridPublicKey.x25519PublicKey,
                        mlkem768PublicKey: result.hybridPublicKey.mlkem768PublicKey,
                        keyVersion: result.hybridPublicKey.keyVersion,
                    };
                }

                const recipientHybridPubKey = deserializeHybridPublicKey({
                    classical: cachedKey.x25519PublicKey,
                    postQuantum: cachedKey.mlkem768PublicKey,
                    algorithm: 'x25519-ml-kem-768',
                } as HybridPublicKeySerialized);

                // 3. Get file's encryption key
                // Priority: secure storage → V4 CVEF header extraction
                let fileKeyBytes = await getFileEncryptionKey(fileId);
                let zeroExtractedKey: (() => void) | null = null;

                if (!fileKeyBytes) {
                    debugLog('[ChatFileShare]', `Key not in storage for file ${fileId}, extracting from CVEF header`);

                    const hybridSecretKey = await getUnlockedHybridSecretKey();
                    if (!hybridSecretKey) {
                        throw new Error('Hybrid keys not available. Please unlock your vault and try again.');
                    }

                    const { url: presignedUrl } = await utils.files.getDownloadUrl.fetch({ fileId });
                    const extracted = await extractV4FileKey(presignedUrl, hybridSecretKey);
                    fileKeyBytes = extracted.fileKeyBytes.buffer.slice(
                        extracted.fileKeyBytes.byteOffset,
                        extracted.fileKeyBytes.byteOffset + extracted.fileKeyBytes.byteLength,
                    ) as ArrayBuffer;
                    zeroExtractedKey = extracted.zeroBytes;
                    debugLog('[ChatFileShare]', `Extracted V4 file key for file ${fileId}`);
                }

                // 4. Re-encrypt file key for recipient using hybrid KEM
                const reEncryptedKey = await reEncryptFileKeyForPeer(
                    fileKeyBytes,
                    recipientHybridPubKey
                );

                // 5. Generate recipient's key fingerprint for tracking
                const recipientKeyFingerprint = await generateKeyFingerprint(
                    cachedKey.x25519PublicKey,
                    cachedKey.mlkem768PublicKey
                );

                // 6. Create share via API
                const result = await shareFileMutation.mutateAsync({
                    fileId,
                    recipientUserId,
                    encryptedFileKey: reEncryptedKey.encryptedFileKey,
                    keyIv: reEncryptedKey.iv,
                    keyDerivationSalt: reEncryptedKey.salt,
                    kemCiphertext: reEncryptedKey.kemCiphertext,
                    recipientKeyFingerprint,
                    permission,
                    expiresIn,
                    maxDownloads,
                    messageContent,
                });

                // Zero extracted key bytes after re-encryption
                if (zeroExtractedKey) zeroExtractedKey();

                toast.success("File shared successfully!");

                return {
                    shareId: result.shareId,
                    messageId: result.messageId,
                };
            } catch (error) {
                const message =
                    error instanceof Error ? error.message : "Failed to share file";
                toast.error(message);
                throw error;
            } finally {
                setIsSharing(false);
            }
        },
        [hasHybridKeyPair, isUnlocked, getCachedHybridPublicKey, getFileEncryptionKey, getUnlockedHybridSecretKey, shareFileMutation, utils]
    );

    /**
     * List files I've shared
     */
    const useMyShares = (options?: {
        limit?: number;
        offset?: number;
        status?: "active" | "revoked" | "expired" | "all";
    }) => {
        return trpc.chatFileShare.listMyShares.useQuery(options ?? {});
    };

    /**
     * List files shared with me
     */
    const useSharedWithMe = (options?: {
        limit?: number;
        offset?: number;
        status?: "active" | "revoked" | "expired" | "all";
    }) => {
        return trpc.chatFileShare.listSharedWithMe.useQuery(options ?? {});
    };

    /**
     * Revoke a share
     */
    const revokeMutation = trpc.chatFileShare.revokeShare.useMutation({
        onSuccess: (_data, variables) => {
            queryClient.invalidateQueries({
                queryKey: ["chatFileShare", "getShareDetails", variables.shareId],
            });
            queryClient.invalidateQueries({ queryKey: ["chatFileShare", "listMyShares"] });
            queryClient.invalidateQueries({ queryKey: ["chatFileShare", "getShareStats"] });
            toast.success("Share revoked");
        },
        onError: (error) => {
            toast.error(error.message || "Failed to revoke share");
        },
    });

    /**
     * Get share statistics
     */
    const useShareStats = () => {
        return trpc.chatFileShare.getShareStats.useQuery();
    };

    return {
        // State
        isSharing,
        hasKeys: hasHybridKeyPair,

        // Actions
        shareFile,
        revokeShare: revokeMutation.mutateAsync,

        // Queries
        useMyShares,
        useSharedWithMe,
        useShareStats,

        // Loading states
        isRevoking: revokeMutation.isPending,
    };
}
