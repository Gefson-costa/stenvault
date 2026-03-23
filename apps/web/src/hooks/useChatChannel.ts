/**
 * useChatChannel — SVCP (StenVault Channel Protocol) Channel Management
 *
 * Manages per-conversation shared secrets so BOTH sender and recipient
 * can decrypt all messages. Eliminates per-message KEM overhead and
 * the volatile sentPlaintextCache.
 *
 * Flow:
 * 1. Initiator: encapsulate(peerHybridPubKey) → sharedSecret
 *    → HKDF("svcp-v1") → channelSecret → wrap with master key → store
 * 2. Responder: decapsulate(kemCiphertext, myHybridSecretKey) → sharedSecret
 *    → HKDF("svcp-v1") → channelSecret → wrap with master key → store
 * 3. Both: unwrap channelSecret from server → use for message encrypt/decrypt
 *
 * @module useChatChannel
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { useMasterKey } from "@/hooks/useMasterKey";
import { useCryptoStore } from "@/stores/cryptoStore";
import {
    arrayBufferToBase64,
    base64ToArrayBuffer,
    getHybridKemProvider,
    serializeHybridCiphertext,
    deserializeHybridCiphertext,
    deserializeHybridPublicKey,
} from "@/lib/platform";
import type { HybridPublicKeySerialized } from "@/lib/platform";
import { unwrapSecretWithMK, wrapSecretWithMK } from "@/hooks/masterKeyCrypto";
import { SVCP_CHANNEL_INFO } from "@/hooks/useE2ECrypto";

export type ChannelStatus = "none" | "pending" | "active";

// Module-level cache for channel secrets (survives re-renders, not page refresh)
const channelSecretCache = new Map<string, { key: CryptoKey; version: number; cachedAt: number }>();
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes

function getCacheKey(myId: number, peerId: number): string {
    return `${Math.min(myId, peerId)}-${Math.max(myId, peerId)}`;
}

/**
 * Derive the 32-byte SVCP channel secret from the raw KEM shared secret.
 * Uses HKDF-SHA256 → deriveBits to get raw bytes (not a non-extractable CryptoKey).
 */
async function deriveChannelSecret(
    rawSharedSecret: Uint8Array,
    salt: Uint8Array
): Promise<Uint8Array> {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        rawSharedSecret.buffer as ArrayBuffer,
        "HKDF",
        false,
        ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: salt.buffer as ArrayBuffer,
            info: new TextEncoder().encode(SVCP_CHANNEL_INFO),
        },
        keyMaterial,
        256 // 32 bytes
    );

    return new Uint8Array(bits);
}

/**
 * Import raw channel secret bytes as a CryptoKey (AES-GCM, extractable)
 */
async function importChannelKey(raw: Uint8Array): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "raw",
        raw.buffer as ArrayBuffer,
        { name: "AES-GCM" },
        true, // extractable — needed for per-message HKDF
        ["encrypt", "decrypt"]
    );
}

export function useChatChannel(peerUserId: number) {
    const [channelStatus, setChannelStatus] = useState<ChannelStatus>("none");
    const [channelKeyVersion, setChannelKeyVersion] = useState(1);
    const [channelSecret, setChannelSecret] = useState<CryptoKey | null>(null);
    const [isSettingUp, setIsSettingUp] = useState(false);
    const completingRef = useRef(false);

    const { user } = useAuth();
    const { isUnlocked, getUnlockedHybridSecretKey, getCachedKey } = useMasterKey();
    const { getCachedHybridPublicKey } = useCryptoStore();

    // Fetch channel status
    const { data: statusData, refetch: refetchStatus } = trpc.chat.getChannelStatus.useQuery(
        { peerUserId },
        { enabled: !!peerUserId && isUnlocked }
    );

    // Fetch channel secret data (only when active or pending-responder)
    const { data: secretData, refetch: refetchSecret } = trpc.chat.getChannelSecret.useQuery(
        { peerUserId },
        { enabled: !!peerUserId && isUnlocked && statusData !== undefined }
    );

    const initiateMutation = trpc.chat.initiateChannel.useMutation();
    const completeMutation = trpc.chat.completeChannel.useMutation();

    // Update status from server data
    useEffect(() => {
        if (statusData === null || statusData === undefined) {
            setChannelStatus("none");
            return;
        }
        setChannelStatus(statusData.status === "active" ? "active" : "pending");
        setChannelKeyVersion(statusData.keyVersion);
    }, [statusData]);

    // Unwrap and cache channel secret when active
    useEffect(() => {
        if (!secretData || !isUnlocked || !peerUserId || !user?.id) return;

        // If active and we have a wrapped secret, unwrap it
        if (secretData.status === "active" && secretData.wrappedSecret) {
            const cacheKey = getCacheKey(user.id, peerUserId);
            const cached = channelSecretCache.get(cacheKey);
            if (cached && cached.version === secretData.keyVersion &&
                Date.now() - cached.cachedAt < CACHE_TTL_MS) {
                setChannelSecret(cached.key);
                return;
            }

            (async () => {
                try {
                    const bundle = getCachedKey();
                    if (!bundle) return;

                    const wrappedBytes = new Uint8Array(
                        base64ToArrayBuffer(secretData.wrappedSecret!)
                    );

                    // Unwrap channel secret using non-extractable AES-KW key
                    const channelSecretBytes = await unwrapSecretWithMK(wrappedBytes, bundle.aesKw);
                    const cryptoKey = await importChannelKey(channelSecretBytes);

                    // Cache
                    channelSecretCache.set(cacheKey, {
                        key: cryptoKey,
                        version: secretData.keyVersion,
                        cachedAt: Date.now(),
                    });
                    setChannelSecret(cryptoKey);

                    // Zero sensitive bytes
                    channelSecretBytes.fill(0);
                } catch (err) {
                    console.warn("[SVCP] Failed to unwrap channel secret:", err);
                }
            })();
        }
    }, [secretData, isUnlocked, peerUserId, user?.id, getCachedKey]);

    // Auto-complete channel if pending and we're the responder
    useEffect(() => {
        if (!secretData || secretData.status !== "pending" || !isUnlocked) return;
        if (!secretData.kemCiphertext || !secretData.agreementSalt) return;
        if (completingRef.current) return;

        completingRef.current = true;

        (async () => {
            try {
                const hybridSecretKey = await getUnlockedHybridSecretKey();
                if (!hybridSecretKey) {
                    completingRef.current = false;
                    return;
                }

                const masterKey = getCachedKey();
                if (!masterKey) {
                    completingRef.current = false;
                    return;
                }

                const provider = getHybridKemProvider();

                // Deserialize the KEM ciphertext
                const hybridCiphertext = deserializeHybridCiphertext(
                    JSON.parse(secretData.kemCiphertext!)
                );

                // Decapsulate to get the same shared secret
                const rawSharedSecret = await provider.decapsulate(
                    hybridCiphertext,
                    hybridSecretKey
                );

                // Derive channel secret via HKDF
                const saltBytes = new Uint8Array(
                    base64ToArrayBuffer(secretData.agreementSalt!)
                );
                const channelSecretBytes = await deriveChannelSecret(rawSharedSecret, saltBytes);

                // Wrap channel secret with non-extractable AES-KW key
                const wrappedKey = await wrapSecretWithMK(channelSecretBytes, masterKey.aesKw);

                // Store on server
                await completeMutation.mutateAsync({
                    peerUserId,
                    wrappedSecret: arrayBufferToBase64(wrappedKey.buffer as ArrayBuffer),
                });

                // Cache the channel secret locally
                const cryptoKey = await importChannelKey(channelSecretBytes);
                if (user?.id) {
                    channelSecretCache.set(getCacheKey(user.id, peerUserId), {
                        key: cryptoKey,
                        version: secretData.keyVersion,
                        cachedAt: Date.now(),
                    });
                }
                setChannelSecret(cryptoKey);
                setChannelStatus("active");

                // Zero sensitive bytes
                channelSecretBytes.fill(0);
                rawSharedSecret.fill(0);

                // Refresh server data
                refetchStatus();
                refetchSecret();
            } catch (err) {
                console.warn("[SVCP] Failed to complete channel:", err);
            } finally {
                completingRef.current = false;
            }
        })();
    }, [secretData, isUnlocked, peerUserId, user?.id, getUnlockedHybridSecretKey, getCachedKey,
        completeMutation, refetchStatus, refetchSecret]);

    /**
     * Initiate a new channel (called before first message send)
     */
    const initiateChannel = useCallback(async (): Promise<CryptoKey | null> => {
        if (channelSecret) {
            return channelSecret;
        }

        // Channel exists on server but secret hasn't been unwrapped yet — wait for it
        // instead of re-creating (which would destroy the old secret and orphan messages).
        if (channelStatus !== "none") {
            const { data } = await refetchSecret();
            if (data?.status === "active" && data.wrappedSecret) {
                try {
                    const mk = getCachedKey();
                    if (mk) {
                        const wrappedBytes = new Uint8Array(base64ToArrayBuffer(data.wrappedSecret));
                        const csBytes = await unwrapSecretWithMK(wrappedBytes, mk.aesKw);
                        const key = await importChannelKey(csBytes);
                        if (user?.id) {
                            channelSecretCache.set(getCacheKey(user.id, peerUserId), {
                                key, version: data.keyVersion, cachedAt: Date.now(),
                            });
                        }
                        setChannelSecret(key);
                        csBytes.fill(0);
                        return key;
                    }
                } catch (err) {
                    console.warn("[SVCP] Unwrap during initiateChannel failed, will re-create:", err);
                }
            }
        }

        setIsSettingUp(true);

        try {
            // Get peer's hybrid public key
            const cachedKey = getCachedHybridPublicKey(peerUserId);
            if (!cachedKey) {
                throw new Error("Peer's encryption key not available");
            }

            const masterKey = getCachedKey();
            if (!masterKey) {
                throw new Error("Vault must be unlocked");
            }

            // Deserialize peer's public key
            const peerHybridPubKey = deserializeHybridPublicKey({
                classical: cachedKey.x25519PublicKey,
                postQuantum: cachedKey.mlkem768PublicKey,
                algorithm: "x25519-ml-kem-768",
            } as HybridPublicKeySerialized);

            const provider = getHybridKemProvider();

            // Encapsulate → shared secret + ciphertext
            const { ciphertext: hybridCiphertext, sharedSecret: rawSharedSecret } =
                await provider.encapsulate(peerHybridPubKey);

            // Generate salt and derive channel secret
            const salt = crypto.getRandomValues(new Uint8Array(32));
            const channelSecretBytes = await deriveChannelSecret(rawSharedSecret, salt);

            // Wrap channel secret with non-extractable AES-KW key
            const keyVersion = 1;
            const wrappedKey = await wrapSecretWithMK(channelSecretBytes, masterKey.aesKw);

            // Serialize HybridCiphertext for storage
            const serializedCiphertext = serializeHybridCiphertext(hybridCiphertext);

            // Store on server
            // initiatorX25519Public is embedded in the HybridCiphertext (classical part)
            // so we pass an empty string — the responder gets it from kemCiphertext
            await initiateMutation.mutateAsync({
                peerUserId,
                kemCiphertext: JSON.stringify(serializedCiphertext),
                salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
                initiatorX25519Public: arrayBufferToBase64(hybridCiphertext.classical.buffer as ArrayBuffer),
                wrappedSecret: arrayBufferToBase64(wrappedKey.buffer as ArrayBuffer),
                keyVersion,
            });

            // Cache locally
            const cryptoKey = await importChannelKey(channelSecretBytes);
            if (user?.id) {
                channelSecretCache.set(getCacheKey(user.id, peerUserId), {
                    key: cryptoKey,
                    version: keyVersion,
                    cachedAt: Date.now(),
                });
            }
            setChannelSecret(cryptoKey);
            setChannelStatus("pending");
            setChannelKeyVersion(keyVersion);

            // Zero sensitive bytes
            channelSecretBytes.fill(0);
            rawSharedSecret.fill(0);

            // Refresh server data
            refetchStatus();
            refetchSecret();

            return cryptoKey;
        } catch (err) {
            console.warn("[SVCP] Failed to initiate channel:", err);
            return null;
        } finally {
            setIsSettingUp(false);
        }
    }, [channelStatus, channelSecret, peerUserId, user?.id, getCachedHybridPublicKey, getCachedKey,
        initiateMutation, refetchStatus, refetchSecret]);

    const isChannelReady = channelStatus === "active" && channelSecret !== null;

    return {
        channelSecret,
        channelStatus,
        channelKeyVersion,
        isChannelReady,
        isSettingUp,
        initiateChannel,
    };
}
