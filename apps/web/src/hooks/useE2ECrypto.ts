/**
 * E2E Encryption Hook — Hybrid Post-Quantum (X25519 + ML-KEM-768)
 *
 * Uses the existing HybridKemProvider for key encapsulation and
 * HKDF-SHA256 + AES-256-GCM for message encryption/decryption.
 *
 * No local key storage — sender encapsulates to recipient's hybrid public key,
 * recipient decapsulates with their hybrid secret key (from useMasterKey).
 *
 * @module useE2ECrypto
 */

import { useCallback } from "react";
import {
    arrayBufferToBase64,
    base64ToArrayBuffer,
    getHybridKemProvider,
    serializeHybridCiphertext,
    deserializeHybridCiphertext,
} from "@/lib/platform";
import type {
    HybridPublicKey,
    HybridSecretKey,
    HybridCiphertextSerialized,
} from "@/lib/platform";

// ===== CONSTANTS =====
const CHAT_HKDF_INFO = "chat-hybrid-v1";
const SVCP_MSG_INFO = "svcp-msg-v1";
const SVCP_CHANNEL_INFO = "svcp-v1";
const AES_KEY_LENGTH = 256;
const IV_LENGTH = 12;
const SALT_LENGTH = 32;

/**
 * Derive AES-256-GCM key from hybrid shared secret using HKDF-SHA256
 */
async function deriveAESKeyFromSharedSecret(
    sharedSecret: Uint8Array,
    salt: Uint8Array,
    info: string = CHAT_HKDF_INFO
): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        sharedSecret.buffer as ArrayBuffer,
        "HKDF",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: salt.buffer as ArrayBuffer,
            info: new TextEncoder().encode(info),
        },
        keyMaterial,
        { name: "AES-GCM", length: AES_KEY_LENGTH },
        false,
        ["encrypt", "decrypt"]
    );
}

/**
 * E2E Encryption Hook — Hybrid Post-Quantum
 */
export function useE2ECrypto() {
    /**
     * Encrypt a message for a recipient using hybrid KEM
     *
     * Flow:
     * 1. Encapsulate to recipient's hybrid public key → {kemCiphertext, sharedSecret}
     * 2. HKDF(sharedSecret, salt, "chat-hybrid-v1") → AES-256-GCM key
     * 3. AES-GCM encrypt(message) → {ciphertext, iv}
     * 4. Return {ciphertext, iv, salt, kemCiphertext}
     */
    const encryptMessage = useCallback(
        async (
            message: string,
            recipientHybridPublicKey: HybridPublicKey
        ): Promise<{
            ciphertext: string;
            iv: string;
            salt: string;
            kemCiphertext: string;
        }> => {
            const provider = getHybridKemProvider();

            // 1. Encapsulate → shared secret + ciphertext
            const { ciphertext: hybridCiphertext, sharedSecret } =
                await provider.encapsulate(recipientHybridPublicKey);

            // 2. Derive AES-GCM key
            const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
            const aesKey = await deriveAESKeyFromSharedSecret(sharedSecret, salt);

            // 3. Encrypt message
            const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
            const encodedText = new TextEncoder().encode(message);
            const encrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                aesKey,
                encodedText.buffer as ArrayBuffer
            );

            // 4. Serialize and return
            const serializedCiphertext = serializeHybridCiphertext(hybridCiphertext);

            return {
                ciphertext: arrayBufferToBase64(encrypted),
                iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
                salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
                kemCiphertext: JSON.stringify(serializedCiphertext),
            };
        },
        []
    );

    /**
     * Decrypt a message using our hybrid secret key
     *
     * Flow:
     * 1. Deserialize kemCiphertext
     * 2. Decapsulate(kemCiphertext, mySecretKey) → sharedSecret
     * 3. HKDF(sharedSecret, salt, "chat-hybrid-v1") → AES-256-GCM key
     * 4. AES-GCM decrypt → plaintext
     */
    const decryptMessage = useCallback(
        async (
            ciphertext: string,
            iv: string,
            salt: string,
            kemCiphertextStr: string,
            myHybridSecretKey: HybridSecretKey
        ): Promise<string> => {
            const provider = getHybridKemProvider();

            // 1. Deserialize KEM ciphertext
            const serialized: HybridCiphertextSerialized = JSON.parse(kemCiphertextStr);
            const hybridCiphertext = deserializeHybridCiphertext(serialized);

            // 2. Decapsulate → shared secret
            const sharedSecret = await provider.decapsulate(hybridCiphertext, myHybridSecretKey);

            // 3. Derive same AES-GCM key
            const saltBytes = new Uint8Array(base64ToArrayBuffer(salt));
            const aesKey = await deriveAESKeyFromSharedSecret(sharedSecret, saltBytes);

            // 4. Decrypt
            const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
            if (ivBytes.length !== IV_LENGTH) {
                throw new Error(`Invalid IV length: expected ${IV_LENGTH} bytes, got ${ivBytes.length}`);
            }

            const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
            if (ciphertextBuffer.byteLength === 0) {
                throw new Error("Empty ciphertext");
            }

            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: ivBytes },
                aesKey,
                ciphertextBuffer
            );

            return new TextDecoder().decode(decrypted);
        },
        []
    );

    /**
     * Encrypt a message using a pre-established SVCP channel secret
     *
     * Flow:
     * 1. Random 32-byte salt
     * 2. HKDF(channelSecret, salt, "svcp-msg-v1") → per-message AES key
     * 3. AES-256-GCM encrypt → {ciphertext, iv, salt}
     *
     * No KEM ciphertext needed — both parties share the channel secret.
     */
    const encryptChannelMessage = useCallback(
        async (
            message: string,
            channelSecret: CryptoKey
        ): Promise<{ ciphertext: string; iv: string; salt: string }> => {
            // Export channel secret raw bytes for HKDF
            const secretBytes = new Uint8Array(
                await crypto.subtle.exportKey("raw", channelSecret)
            );

            const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
            const msgKey = await deriveAESKeyFromSharedSecret(
                secretBytes, salt, SVCP_MSG_INFO
            );

            const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
            const encoded = new TextEncoder().encode(message);
            const encrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                msgKey,
                encoded.buffer as ArrayBuffer
            );

            return {
                ciphertext: arrayBufferToBase64(encrypted),
                iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
                salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
            };
        },
        []
    );

    /**
     * Decrypt a message using a pre-established SVCP channel secret
     *
     * Both sender and recipient use the same path — no isOwn check needed.
     */
    const decryptChannelMessage = useCallback(
        async (
            ciphertext: string,
            iv: string,
            salt: string,
            channelSecret: CryptoKey
        ): Promise<string> => {
            const secretBytes = new Uint8Array(
                await crypto.subtle.exportKey("raw", channelSecret)
            );

            const saltBytes = new Uint8Array(base64ToArrayBuffer(salt));
            const msgKey = await deriveAESKeyFromSharedSecret(
                secretBytes, saltBytes, SVCP_MSG_INFO
            );

            const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
            if (ivBytes.length !== IV_LENGTH) {
                throw new Error(`Invalid IV length: expected ${IV_LENGTH}, got ${ivBytes.length}`);
            }

            const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
            if (ciphertextBuffer.byteLength === 0) {
                throw new Error("Empty ciphertext");
            }

            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: ivBytes },
                msgKey,
                ciphertextBuffer
            );

            return new TextDecoder().decode(decrypted);
        },
        []
    );

    return {
        encryptMessage,
        decryptMessage,
        encryptChannelMessage,
        decryptChannelMessage,
    };
}

// Re-export utilities for backward compatibility
export { arrayBufferToBase64, base64ToArrayBuffer };

// Export SVCP derivation helper for useChatChannel
export { deriveAESKeyFromSharedSecret, SVCP_CHANNEL_INFO, SVCP_MSG_INFO };
