/**
 * Web Hybrid KEM Provider
 *
 * Browser implementation of hybrid post-quantum key encapsulation using:
 * - X25519: Web Crypto API (native)
 * - ML-KEM-768: @openforge-sh/liboqs (WASM)
 *
 * Architecture:
 * ```
 * Encapsulation:
 *   1. Generate ephemeral X25519 key pair
 *   2. ECDH with recipient's X25519 public key → classical shared secret
 *   3. ML-KEM-768 encapsulate to recipient's PQ public key → PQ shared secret
 *   4. HKDF-SHA256(classical || pq) → hybrid KEK
 *
 * Decapsulation:
 *   1. X25519 ECDH with sender's ephemeral public key → classical shared secret
 *   2. ML-KEM-768 decapsulate → PQ shared secret
 *   3. HKDF-SHA256(classical || pq) → hybrid KEK
 * ```
 *
 * Fallback: If ML-KEM-768 WASM is not available, operations will fail
 * and the client should use server-side hybrid KEM instead.
 */

import type {
  HybridKemProvider,
  HybridKeyPair,
  HybridPublicKey,
  HybridSecretKey,
  HybridCiphertext,
  HybridEncapsulationResult,
} from '@stenvault/shared/platform/crypto';
import {
  HYBRID_KEM_SIZES,
  HYBRID_KEM_ALGORITHMS,
  HYBRID_KEM_HKDF_INFO,
  HYBRID_KEM_HKDF_SALT,
  validateHybridPublicKey,
  validateHybridSecretKey,
  validateHybridCiphertext,
} from '@stenvault/shared/platform/crypto';
import { toArrayBuffer } from '@stenvault/shared/platform/crypto';
import { PQCWorkerClient } from '../pqcWorkerClient';

// ============ Environment Detection ============

/**
 * Returns true when PQC operations should use liboqs directly (not via PQC Worker).
 * Direct usage when: already inside a Web Worker, or Worker API unavailable (tests/SSR).
 * PQC Worker delegation only on main browser thread where Worker API exists.
 */
function shouldUseDirectLiboqs(): boolean {
  // Worker API not available (Node.js / Vitest / SSR) → use liboqs directly
  if (typeof Worker === 'undefined') return true;
  // Already inside a Web Worker (e.g. fileEncryptor.worker) → already isolated
  if (typeof window === 'undefined' && typeof self !== 'undefined' && typeof self.postMessage === 'function') return true;
  // Main browser thread → delegate to PQC Worker
  return false;
}

// ============ Dynamic Import Types ============

/**
 * Type for the dynamically loaded ML-KEM-768 module
 */
interface MLKEM768Module {
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
}

// ============ Module-level State ============

// Cache the factory function (dynamic import), NOT the WASM instance.
// Each operation creates a fresh instance and calls destroy() when done,
// so WASM memory holding PQC key material is freed immediately.
let createMLKEM768Fn: (() => Promise<MLKEM768Module>) | null = null;
let mlkem768LoadAttempted = false;

/**
 * Load the ML-KEM-768 factory. The factory is cached; instances are not.
 */
async function getMLKEM768Factory(): Promise<(() => Promise<MLKEM768Module>) | null> {
  if (mlkem768LoadAttempted) {
    return createMLKEM768Fn;
  }

  mlkem768LoadAttempted = true;

  try {
    const { createMLKEM768 } = await import('@openforge-sh/liboqs');
    createMLKEM768Fn = () => createMLKEM768() as unknown as Promise<MLKEM768Module>;
    console.warn('[WebHybridKemProvider] ML-KEM-768 WASM factory loaded');
    return createMLKEM768Fn;
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.warn('[WebHybridKemProvider] ML-KEM-768 WASM not available:', msg);
    return null;
  }
}

// ============ Singleton ============

let hybridKemProviderInstance: WebHybridKemProvider | null = null;

/**
 * Get the singleton Hybrid KEM provider instance
 */
export function getHybridKemProvider(): HybridKemProvider {
  if (!hybridKemProviderInstance) {
    hybridKemProviderInstance = new WebHybridKemProvider();
  }
  return hybridKemProviderInstance;
}

/**
 * Create a new Hybrid KEM provider instance (for testing)
 */
export function createHybridKemProvider(): HybridKemProvider {
  return new WebHybridKemProvider();
}

// ============ Implementation ============

export class WebHybridKemProvider implements HybridKemProvider {
  readonly algorithmId = HYBRID_KEM_ALGORITHMS.X25519_MLKEM768;
  readonly algorithm = 'x25519-ml-kem-768' as const;

  /**
   * Check if hybrid KEM (both X25519 and ML-KEM-768) is available
   */
  async isAvailable(): Promise<boolean> {
    const [x25519Available, mlkemAvailable] = await Promise.all([
      this.isClassicalOnlyAvailable(),
      this.isMLKEM768Available(),
    ]);
    return x25519Available && mlkemAvailable;
  }

  /**
   * Check if only classical (X25519) is available
   */
  async isClassicalOnlyAvailable(): Promise<boolean> {
    try {
      if (typeof crypto === 'undefined' || !crypto.subtle) {
        return false;
      }

      // Try to generate an X25519 key pair
      const keyPair = await crypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveKey', 'deriveBits']
      );

      return keyPair !== null;
    } catch {
      return false;
    }
  }

  /**
   * Check if ML-KEM-768 WASM is available
   */
  private async isMLKEM768Available(): Promise<boolean> {
    const factory = await getMLKEM768Factory();
    return factory !== null;
  }

  /**
   * Generate a hybrid key pair (X25519 + ML-KEM-768)
   */
  async generateKeyPair(): Promise<HybridKeyPair> {
    // Generate X25519 key pair
    const x25519KeyPair = await this.generateX25519KeyPair();

    // Generate ML-KEM-768 key pair
    const mlkem768KeyPair = await this.generateMLKEM768KeyPair();

    return {
      publicKey: {
        classical: x25519KeyPair.publicKey,
        postQuantum: mlkem768KeyPair.publicKey,
      },
      secretKey: {
        classical: x25519KeyPair.secretKey,
        postQuantum: mlkem768KeyPair.secretKey,
      },
    };
  }

  /**
   * Encapsulate a shared secret to a recipient's hybrid public key
   */
  async encapsulate(publicKey: HybridPublicKey): Promise<HybridEncapsulationResult> {
    validateHybridPublicKey(publicKey);

    // Generate ephemeral X25519 key pair for ECDH
    const ephemeralX25519 = await this.generateX25519KeyPair();

    // Perform X25519 ECDH to get classical shared secret
    const classicalSecret = await this.x25519ECDH(
      ephemeralX25519.secretKey,
      publicKey.classical
    );

    // Zero ephemeral private key — no longer needed after ECDH
    ephemeralX25519.secretKey.fill(0);

    // Perform ML-KEM-768 encapsulation
    const { ciphertext: pqCiphertext, sharedSecret: pqSecret } =
      await this.mlkem768Encapsulate(publicKey.postQuantum);

    // Combine secrets via HKDF
    const hybridKEK = await this.deriveHybridKEK(classicalSecret, pqSecret);

    return {
      ciphertext: {
        classical: ephemeralX25519.publicKey,
        postQuantum: pqCiphertext,
      },
      sharedSecret: hybridKEK,
    };
  }

  /**
   * Decapsulate a shared secret using our hybrid secret key
   */
  async decapsulate(
    ciphertext: HybridCiphertext,
    secretKey: HybridSecretKey
  ): Promise<Uint8Array> {
    validateHybridCiphertext(ciphertext);
    validateHybridSecretKey(secretKey);

    // Perform X25519 ECDH with sender's ephemeral public key
    const classicalSecret = await this.x25519ECDH(
      secretKey.classical,
      ciphertext.classical
    );

    // Perform ML-KEM-768 decapsulation
    const pqSecret = await this.mlkem768Decapsulate(
      ciphertext.postQuantum,
      secretKey.postQuantum
    );

    // Combine secrets via HKDF
    return this.deriveHybridKEK(classicalSecret, pqSecret);
  }

  /**
   * Derive hybrid KEK from combined secrets using HKDF-SHA256
   */
  async deriveHybridKEK(
    classicalSecret: Uint8Array,
    postQuantumSecret: Uint8Array
  ): Promise<Uint8Array> {
    // Concatenate both secrets as IKM (Input Keying Material)
    const ikm = new Uint8Array(classicalSecret.length + postQuantumSecret.length);
    ikm.set(classicalSecret, 0);
    ikm.set(postQuantumSecret, classicalSecret.length);

    // Import IKM as HKDF key
    const ikmKey = await crypto.subtle.importKey(
      'raw',
      ikm,
      { name: 'HKDF' },
      false,
      ['deriveBits']
    );

    // Derive 256-bit (32-byte) key using HKDF-SHA256
    const info = new TextEncoder().encode(HYBRID_KEM_HKDF_INFO);
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: HYBRID_KEM_HKDF_SALT,
        info,
      },
      ikmKey,
      256 // 32 bytes
    );

    // Zero sensitive key material after HKDF import
    ikm.fill(0);
    classicalSecret.fill(0);
    postQuantumSecret.fill(0);

    return new Uint8Array(derivedBits);
  }

  // ============ X25519 Methods ============

  /**
   * Generate X25519 key pair
   */
  private async generateX25519KeyPair(): Promise<{
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }> {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveKey', 'deriveBits']
    ) as CryptoKeyPair;

    // Export public key as raw bytes
    const publicKeyBuffer = await crypto.subtle.exportKey(
      'raw',
      keyPair.publicKey
    );

    // Export private key as PKCS8 and extract raw bytes
    const privateKeyPkcs8 = await crypto.subtle.exportKey(
      'pkcs8',
      keyPair.privateKey
    );

    // PKCS8 format for X25519 has the raw key at offset 16 (32 bytes)
    const secretKey = new Uint8Array(privateKeyPkcs8).slice(16, 48);

    return {
      publicKey: new Uint8Array(publicKeyBuffer),
      secretKey,
    };
  }

  /**
   * Perform X25519 ECDH to derive shared secret
   */
  private async x25519ECDH(
    privateKeyRaw: Uint8Array,
    peerPublicKeyRaw: Uint8Array
  ): Promise<Uint8Array> {
    // Import private key from raw bytes
    // We need to wrap it in PKCS8 format for importKey
    const pkcs8Header = new Uint8Array([
      0x30, 0x2e, // SEQUENCE, 46 bytes
      0x02, 0x01, 0x00, // INTEGER 0 (version)
      0x30, 0x05, // SEQUENCE, 5 bytes
      0x06, 0x03, 0x2b, 0x65, 0x6e, // OID 1.3.101.110 (X25519)
      0x04, 0x22, // OCTET STRING, 34 bytes
      0x04, 0x20, // OCTET STRING, 32 bytes (the key)
    ]);

    const pkcs8Key = new Uint8Array(pkcs8Header.length + privateKeyRaw.length);
    pkcs8Key.set(pkcs8Header, 0);
    pkcs8Key.set(privateKeyRaw, pkcs8Header.length);

    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      toArrayBuffer(pkcs8Key),
      { name: 'X25519' },
      false,
      ['deriveBits']
    );

    // Import peer's public key
    const peerPublicKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(peerPublicKeyRaw),
      { name: 'X25519' },
      false,
      []
    );

    // Derive shared secret
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'X25519',
        public: peerPublicKey,
      },
      privateKey,
      256 // 32 bytes
    );

    return new Uint8Array(sharedSecret);
  }

  // ============ ML-KEM-768 Methods ============

  /**
   * Generate ML-KEM-768 key pair
   */
  private async generateMLKEM768KeyPair(): Promise<{
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }> {
    // Main browser thread → delegate to PQC Worker (WASM memory isolation)
    if (!shouldUseDirectLiboqs()) {
      return PQCWorkerClient.getInstance().mlkem768GenerateKeyPair();
    }

    // Already in worker context → use liboqs directly (already isolated)
    const factory = await getMLKEM768Factory();
    if (!factory) {
      throw new Error(
        'ML-KEM-768 WASM not available. Install @openforge-sh/liboqs or use server-side hybrid KEM.'
      );
    }

    const instance = await factory();
    try {
      const { publicKey, secretKey } = instance.generateKeyPair();

      if (publicKey.length !== HYBRID_KEM_SIZES.MLKEM768_PUBLIC_KEY) {
        throw new Error(
          `Invalid ML-KEM-768 public key size: expected ${HYBRID_KEM_SIZES.MLKEM768_PUBLIC_KEY}, got ${publicKey.length}`
        );
      }
      if (secretKey.length !== HYBRID_KEM_SIZES.MLKEM768_SECRET_KEY) {
        throw new Error(
          `Invalid ML-KEM-768 secret key size: expected ${HYBRID_KEM_SIZES.MLKEM768_SECRET_KEY}, got ${secretKey.length}`
        );
      }

      return { publicKey, secretKey };
    } finally {
      instance.destroy();
    }
  }

  /**
   * Perform ML-KEM-768 encapsulation
   */
  private async mlkem768Encapsulate(publicKey: Uint8Array): Promise<{
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
  }> {
    // Main browser thread → delegate to PQC Worker (WASM memory isolation)
    if (!shouldUseDirectLiboqs()) {
      return PQCWorkerClient.getInstance().mlkem768Encapsulate(publicKey);
    }

    // Already in worker context → use liboqs directly
    const factory = await getMLKEM768Factory();
    if (!factory) {
      throw new Error(
        'ML-KEM-768 WASM not available. Install @openforge-sh/liboqs or use server-side hybrid KEM.'
      );
    }

    const instance = await factory();
    try {
      const { ciphertext, sharedSecret } = instance.encapsulate(publicKey);

      if (ciphertext.length !== HYBRID_KEM_SIZES.MLKEM768_CIPHERTEXT) {
        throw new Error(
          `Invalid ML-KEM-768 ciphertext size: expected ${HYBRID_KEM_SIZES.MLKEM768_CIPHERTEXT}, got ${ciphertext.length}`
        );
      }
      if (sharedSecret.length !== HYBRID_KEM_SIZES.MLKEM768_SHARED_SECRET) {
        throw new Error(
          `Invalid ML-KEM-768 shared secret size: expected ${HYBRID_KEM_SIZES.MLKEM768_SHARED_SECRET}, got ${sharedSecret.length}`
        );
      }

      return { ciphertext, sharedSecret };
    } finally {
      instance.destroy();
    }
  }

  /**
   * Perform ML-KEM-768 decapsulation
   */
  private async mlkem768Decapsulate(
    ciphertext: Uint8Array,
    secretKey: Uint8Array
  ): Promise<Uint8Array> {
    // Main browser thread → delegate to PQC Worker (WASM memory isolation)
    if (!shouldUseDirectLiboqs()) {
      return PQCWorkerClient.getInstance().mlkem768Decapsulate(ciphertext, secretKey);
    }

    // Already in worker context → use liboqs directly
    const factory = await getMLKEM768Factory();
    if (!factory) {
      throw new Error(
        'ML-KEM-768 WASM not available. Install @openforge-sh/liboqs or use server-side hybrid KEM.'
      );
    }

    const instance = await factory();
    try {
      const sharedSecret = instance.decapsulate(ciphertext, secretKey);

      if (sharedSecret.length !== HYBRID_KEM_SIZES.MLKEM768_SHARED_SECRET) {
        throw new Error(
          `Invalid ML-KEM-768 shared secret size: expected ${HYBRID_KEM_SIZES.MLKEM768_SHARED_SECRET}, got ${sharedSecret.length}`
        );
      }

      return sharedSecret;
    } finally {
      instance.destroy();
    }
  }
}
