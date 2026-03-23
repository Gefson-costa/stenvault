/**
 * UES Manager (Phase 3.1 UES)
 *
 * Manages User Entropy Seed - a device-specific secret used to bind
 * the Master Key to a specific device for enhanced security.
 *
 * Architecture:
 * - UES is generated from device entropy + random bytes
 * - Stored encrypted in localStorage (encrypted with device-derived key)
 * - Combined with password to derive Device-KEK (fast unlock path)
 * - Server stores encrypted copy for recovery scenarios
 *
 * Security:
 * - UES never leaves device in plaintext
 * - Device key derived from fingerprint (changes if browser changes)
 * - Automatic re-keying if device fingerprint changes
 *
 * @module uesManager
 */

import { collectDeviceEntropy, getDeviceFingerprintHash } from './deviceEntropy';
import { debugLog, debugError } from '@/lib/debugLogger';
import { arrayBufferToBase64, toArrayBuffer, base64ToUint8Array } from '@/lib/platform';
import { getArgon2Provider } from '@/lib/platform';

// ============ Constants ============

const UES_STORAGE_KEY = 'stenvault_ues_v1';
const UES_VERSION = 1;

// ============ Types ============

export interface UESConfig {
    /** Encrypted UES (Base64) */
    encryptedSeed: string;
    /** IV used for encryption (Base64) */
    iv: string;
    /** SHA-256 hash of device fingerprint at creation time */
    deviceFingerprint: string;
    /** UES version for future migrations */
    version: number;
    /** When UES was created */
    createdAt: number;
}

export interface UESExport {
    /** UES encrypted with Master Key (for server storage/recovery) */
    uesEncrypted: string;
    /** IV for decrypting UES */
    uesIv: string;
    /** Device fingerprint hash */
    deviceFingerprint: string;
}

// ============ Internal Functions ============

/**
 * Derive encryption key from device fingerprint
 * This key is used to encrypt UES in localStorage
 */
async function deriveDeviceKey(fingerprintHash: string): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(fingerprintHash),
        'HKDF',
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: encoder.encode('stenvault-device-key-v1'),
            info: encoder.encode('local-storage-encryption'),
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

// ============ Public API ============

/**
 * Check if UES exists in localStorage
 */
export function hasUES(): boolean {
    try {
        const stored = localStorage.getItem(UES_STORAGE_KEY);
        return stored !== null;
    } catch {
        return false;
    }
}

/**
 * Generate new UES and store encrypted in localStorage
 *
 * @returns The raw UES (256-bit) for immediate use
 */
export async function generateAndStoreUES(): Promise<{
    ues: Uint8Array;
    fingerprintHash: string;
}> {
    debugLog('[CRYPTO]', 'Generating new UES...');

    try {
        // Collect device entropy (includes fingerprint and random bytes)
        const { entropy, fingerprintHash } = await collectDeviceEntropy();

        // Derive device key for local encryption
        const deviceKey = await deriveDeviceKey(fingerprintHash);

        // Encrypt UES with device key
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedSeed = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: toArrayBuffer(iv) },
            deviceKey,
            toArrayBuffer(entropy)
        );

        // Store in localStorage
        const config: UESConfig = {
            encryptedSeed: arrayBufferToBase64(encryptedSeed),
            iv: arrayBufferToBase64(toArrayBuffer(iv)),
            deviceFingerprint: fingerprintHash,
            version: UES_VERSION,
            createdAt: Date.now(),
        };

        localStorage.setItem(UES_STORAGE_KEY, JSON.stringify(config));

        debugLog('[CRYPTO]', 'UES generated and stored', {
            fingerprintPrefix: fingerprintHash.substring(0, 16) + '...',
        });

        return { ues: entropy, fingerprintHash };
    } catch (error) {
        debugError('[CRYPTO]', 'Failed to generate UES', error);
        throw new Error('Failed to generate UES');
    }
}

/**
 * Load and decrypt UES from localStorage
 *
 * @returns The raw UES (256-bit) or null if not found or fingerprint changed
 */
export async function loadUES(): Promise<{
    ues: Uint8Array;
    fingerprintHash: string;
} | null> {
    try {
        const stored = localStorage.getItem(UES_STORAGE_KEY);
        if (!stored) {
            debugLog('[CRYPTO]', 'No UES found in localStorage');
            return null;
        }

        const config: UESConfig = JSON.parse(stored);

        // Check version for future migrations
        if (config.version !== UES_VERSION) {
            debugLog('[CRYPTO]', 'UES version mismatch, regeneration required', {
                stored: config.version,
                expected: UES_VERSION,
            });
            return null;
        }

        // Get current device fingerprint
        const currentFingerprint = await getDeviceFingerprintHash();

        // Check if fingerprint matches (device hasn't changed)
        if (config.deviceFingerprint !== currentFingerprint) {
            debugLog('[CRYPTO]', 'Device fingerprint changed, UES invalid', {
                storedPrefix: config.deviceFingerprint.substring(0, 16) + '...',
                currentPrefix: currentFingerprint.substring(0, 16) + '...',
            });
            return null;
        }

        // Derive device key
        const deviceKey = await deriveDeviceKey(currentFingerprint);

        // Decrypt UES
        const iv = base64ToUint8Array(config.iv);
        const encryptedSeed = base64ToUint8Array(config.encryptedSeed);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: toArrayBuffer(iv) },
            deviceKey,
            toArrayBuffer(encryptedSeed)
        );

        debugLog('[CRYPTO]', 'UES loaded successfully');
        return {
            ues: new Uint8Array(decrypted),
            fingerprintHash: currentFingerprint,
        };
    } catch (error) {
        debugError('[CRYPTO]', 'Failed to load UES', error);
        return null;
    }
}

/**
 * Clear UES from localStorage (used on logout or device removal)
 */
export function clearUES(): void {
    try {
        localStorage.removeItem(UES_STORAGE_KEY);
        debugLog('[CRYPTO]', 'UES cleared from localStorage');
    } catch (error) {
        debugError('[CRYPTO]', 'Failed to clear UES', error);
    }
}

/**
 * Export UES encrypted with Master Key (for server storage)
 * This allows recovery of UES on the same device if localStorage is cleared
 *
 * @param ues Raw UES bytes
 * @param masterKey User's Master Key (CryptoKey)
 * @returns Encrypted UES data for server storage
 */
export async function exportUESForServer(
    ues: Uint8Array,
    masterKey: CryptoKey | { aesGcm: CryptoKey }
): Promise<UESExport> {
    try {
        const fingerprintHash = await getDeviceFingerprintHash();

        // Use non-extractable AES-GCM key directly (MasterKeyBundle) or legacy CryptoKey
        let encryptionKey: CryptoKey;
        if ('aesGcm' in masterKey) {
            encryptionKey = masterKey.aesGcm;
        } else {
            // Legacy path: CryptoKey passed directly — assume it's AES-GCM capable
            encryptionKey = masterKey;
        }

        // Encrypt UES
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: toArrayBuffer(iv) },
            encryptionKey,
            toArrayBuffer(ues)
        );

        return {
            uesEncrypted: arrayBufferToBase64(encrypted),
            uesIv: arrayBufferToBase64(toArrayBuffer(iv)),
            deviceFingerprint: fingerprintHash,
        };
    } catch (error) {
        debugError('[CRYPTO]', 'Failed to export UES for server', error);
        throw new Error('Failed to export UES');
    }
}

/**
 * Import UES from server (for recovery scenarios)
 * Decrypts server-stored UES and saves locally
 *
 * @param serverData Encrypted UES from server
 * @param masterKey User's Master Key
 * @returns The raw UES bytes
 */
export async function importUESFromServer(
    serverData: { uesEncrypted: string; uesIv: string },
    masterKey: CryptoKey | { aesGcm: CryptoKey }
): Promise<Uint8Array> {
    try {
        // Use non-extractable AES-GCM key directly
        let decryptionKey: CryptoKey;
        if ('aesGcm' in masterKey) {
            decryptionKey = masterKey.aesGcm;
        } else {
            decryptionKey = masterKey;
        }

        let ues: Uint8Array;
        {
            // Decrypt UES
            const iv = base64ToUint8Array(serverData.uesIv);
            const encrypted = base64ToUint8Array(serverData.uesEncrypted);

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: toArrayBuffer(iv) },
                decryptionKey,
                toArrayBuffer(encrypted)
            );

            ues = new Uint8Array(decrypted);
        }

        // Store locally
        const fingerprintHash = await getDeviceFingerprintHash();
        const deviceKey = await deriveDeviceKey(fingerprintHash);

        const localIv = crypto.getRandomValues(new Uint8Array(12));
        const localEncrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: toArrayBuffer(localIv) },
            deviceKey,
            toArrayBuffer(ues)
        );

        const config: UESConfig = {
            encryptedSeed: arrayBufferToBase64(localEncrypted),
            iv: arrayBufferToBase64(toArrayBuffer(localIv)),
            deviceFingerprint: fingerprintHash,
            version: UES_VERSION,
            createdAt: Date.now(),
        };

        localStorage.setItem(UES_STORAGE_KEY, JSON.stringify(config));

        debugLog('[CRYPTO]', 'UES imported from server and stored locally');
        return ues;
    } catch (error) {
        debugError('[CRYPTO]', 'Failed to import UES from server', error);
        throw new Error('Failed to import UES');
    }
}

/**
 * Get the stored device fingerprint hash (without loading/decrypting UES)
 */
export function getStoredFingerprintHash(): string | null {
    try {
        const stored = localStorage.getItem(UES_STORAGE_KEY);
        if (!stored) return null;

        const config: UESConfig = JSON.parse(stored);
        return config.deviceFingerprint;
    } catch {
        return null;
    }
}

/**
 * Argon2id parameters for the UES fast-path.
 * Lighter than slow-path (16 MiB vs 46 MiB) since UES adds 256 bits of entropy,
 * but still memory-hard for GPU/ASIC resistance.
 * Target: ~150ms on modern hardware.
 */
const FAST_PATH_ARGON2_PARAMS = {
    type: 'argon2id' as const,
    memoryCost: 16384, // 16 MiB
    timeCost: 1,
    parallelism: 1,
    hashLength: 32,
};

/**
 * Derive Device-KEK from password and UES using Argon2id
 * This is the fast-path key derivation (uses lighter Argon2id params since UES adds 256-bit entropy)
 *
 * @param password User's Master Password
 * @param ues User Entropy Seed (256-bit)
 * @param salt Salt from server
 * @returns CryptoKey for unwrapping Master Key
 */
export async function deriveDeviceKEK(
    password: string,
    ues: Uint8Array,
    salt: Uint8Array
): Promise<CryptoKey> {
    // Combine password and UES as the Argon2 "password" input
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);

    // Create combined material: password || UES
    const combined = new Uint8Array(passwordBytes.length + ues.length);
    combined.set(passwordBytes, 0);
    combined.set(ues, passwordBytes.length);

    // Encode combined bytes as base64 for the string-typed Argon2 provider
    // (preserves all byte values losslessly; .slice() ensures a clean ArrayBuffer
    // even if the Uint8Array were ever a subarray view with byteOffset > 0)
    const combinedPassword = arrayBufferToBase64(combined.buffer.slice(combined.byteOffset, combined.byteOffset + combined.byteLength));

    // Derive raw key bytes via Argon2id (memory-hard, GPU/ASIC resistant)
    const argon2 = getArgon2Provider();
    const result = await argon2.deriveKey(combinedPassword, salt, FAST_PATH_ARGON2_PARAMS);

    try {
        return await crypto.subtle.importKey(
            'raw',
            toArrayBuffer(result.key),
            { name: 'AES-KW', length: 256 },
            false, // non-extractable: XSS cannot exportKey() the raw bytes
            ['wrapKey', 'unwrapKey']
        );
    } finally {
        // Zero raw key bytes — CryptoKey now holds the material
        if (result.key instanceof Uint8Array) {
            result.key.fill(0);
        }
    }
}
