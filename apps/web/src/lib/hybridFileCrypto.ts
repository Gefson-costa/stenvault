/**
 * Hybrid Post-Quantum File Encryption
 *
 * Provides hybrid encryption for files using X25519 + ML-KEM-768.
 * This module wraps the existing file encryption with hybrid KEM key wrapping.
 *
 * Architecture:
 * ```
 * File Key (FK) - 32 bytes (random per file)
 *         ↓
 * ┌───────┴───────┐
 * │               │
 * X25519-ECDH   ML-KEM-768
 * │               │
 * └───────┬───────┘
 *         ↓
 *     HKDF-SHA256 → Hybrid KEK
 *         ↓
 *     AES-KW Wrap → Wrapped File Key
 *         ↓
 *     CVEF v1.4 Metadata (AAD-protected, container v2)
 * ```
 *
 * The file content is still encrypted with AES-256-GCM, but the file key
 * is protected with hybrid post-quantum encryption instead of password-derived keys.
 * In v1.4, the entire CVEF header is authenticated as AAD.
 *
 * @module hybridFileCrypto
 */

import { getHybridKemProvider } from '@/lib/platform/webHybridKemProvider';
import { getKeyWrapProvider } from '@/lib/platform/webKeyWrapProvider';
import { STREAMING } from '@/lib/constants';
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  toArrayBuffer,
  deriveChunkIV,
  CRYPTO_CONSTANTS,
} from '@stenvault/shared/platform/crypto';
import type {
  HybridPublicKey,
  HybridSecretKey,
  HybridCiphertext,
  HybridSignaturePublicKey,
  HybridSignatureSecretKey,
} from '@stenvault/shared/platform/crypto';
import {
  createCVEFMetadataV1_4,
  createCVEFHeader,
  parseCVEFHeader,
  isCVEFMetadataV1_2,
  isCVEFMetadataV1_3,
  isCVEFMetadataV1_4,
  hasValidSignatureMetadata,
  type CVEFMetadataV1_4,
  type CVEFMetadata,
  type CVEFPqcParamsV1_2,
  type CVEFSignatureMetadata,
} from '@stenvault/shared/platform/crypto';
import { parseCVEFHeaderFromStream } from './streamingDecrypt';
import { FileCorruptedError } from './errors/cryptoErrors';

// ============ Constants (from shared CRYPTO_CONSTANTS) ============

const FILE_KEY_SIZE = CRYPTO_CONSTANTS.AES_KEY_LENGTH_BYTES;
const IV_SIZE = CRYPTO_CONSTANTS.GCM_IV_LENGTH;
const CHUNK_SIZE = CRYPTO_CONSTANTS.STREAMING_CHUNK_SIZE;

// ============ Types ============

export interface SigningOptions {
  secretKey: HybridSignatureSecretKey;
  fingerprint: string;
  keyVersion: number;
}

export interface HybridEncryptionOptions {
  /** User's hybrid public key for encryption */
  publicKey: HybridPublicKey;
  /** Progress callback */
  onProgress?: (progress: EncryptionProgress) => void;
  /** Optional signing — sign at encrypt time (v1.4 two-block header) */
  signing?: SigningOptions;
}

export interface HybridDecryptionOptions {
  /** User's hybrid secret key for decryption */
  secretKey: HybridSecretKey;
  /** Progress callback */
  onProgress?: (progress: EncryptionProgress) => void;
  /** Signer's public key — if provided and file is signed, signature is verified */
  signerPublicKey?: HybridSignaturePublicKey;
}

export interface EncryptionProgress {
  bytesProcessed: number;
  totalBytes: number;
  percentage: number;
}

export interface HybridEncryptionResult {
  /** Encrypted file blob (CVEF header + ciphertext) */
  blob: Blob;
  /** CVEF v1.4 metadata (core block) */
  metadata: CVEFMetadataV1_4;
  /** Signature metadata from second header block (if signed) */
  signatureMetadata?: CVEFSignatureMetadata;
  /** Original file size */
  originalSize: number;
}

// ============ Helper Functions ============

/**
 * Convert any typed array to a fresh Uint8Array with clean ArrayBuffer.
 * Returns a Uint8Array that TypeScript knows is backed by ArrayBuffer (not SharedArrayBuffer).
 */
function toCleanUint8Array(data: Uint8Array): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(data.length);
  const result = new Uint8Array(buffer);
  result.set(data);
  return result;
}

/**
 * Generate a random file encryption key
 */
function generateFileKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(FILE_KEY_SIZE));
}

/**
 * Generate a random IV for AES-GCM
 */
function generateIV(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(IV_SIZE));
}

/**
 * Import raw key bytes as CryptoKey for AES-GCM
 */
async function importFileKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    toArrayBuffer(keyBytes),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Compute SHA-256 hash of data
 */
async function sha256(data: Uint8Array | ArrayBuffer): Promise<Uint8Array> {
  const buf = data instanceof ArrayBuffer ? data : toArrayBuffer(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buf);
  return new Uint8Array(hashBuffer);
}

// Re-export deriveChunkIV from shared package (imported above from @/lib/platform)
export { deriveChunkIV };

// ============ Signing Helper ============

/**
 * Sign coreMetadataBytes at encrypt time using hybrid signature provider.
 * Returns CVEFSignatureMetadata for the second header block.
 */
async function signCoreMetadata(
  coreMetadataBytes: Uint8Array,
  signing: NonNullable<HybridEncryptionOptions['signing']>,
): Promise<CVEFSignatureMetadata> {
  const { getHybridSignatureProvider } = await import('@/lib/platform/webHybridSignatureProvider');
  const signatureProvider = getHybridSignatureProvider();

  const hash = await sha256(coreMetadataBytes);
  const signature = await signatureProvider.sign(hash, signing.secretKey, 'FILE');

  return {
    signatureAlgorithm: 'ed25519-ml-dsa-65',
    classicalSignature: arrayBufferToBase64(toArrayBuffer(signature.classical)),
    pqSignature: arrayBufferToBase64(toArrayBuffer(signature.postQuantum)),
    signingContext: 'FILE',
    signedAt: signature.signedAt,
    signerFingerprint: signing.fingerprint,
    signerKeyVersion: signing.keyVersion,
  };
}

// ============ Integrity Manifest ============

/**
 * Derive an HMAC-SHA-256 key from the raw file key for chunk integrity manifest.
 * Must be called before the file key is zeroed.
 */
export async function deriveManifestHmacKey(fileKey: Uint8Array): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey('raw', toArrayBuffer(fileKey), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('stenvault-integrity-manifest-v1'),
      info: new TextEncoder().encode('stenvault:integrity-manifest:v1'),
    },
    hkdfKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify'],
  );
}

/**
 * Verify chunk integrity manifest block.
 *
 * Decrypts the manifest ciphertext with AES-GCM using the chunk IV at index `chunkCount`,
 * extracts the stored HMAC-SHA-256 + chunk count, and verifies against the accumulated
 * SHA-256 hashes of each encrypted chunk's ciphertext.
 *
 * @throws Error('File integrity verification failed') on any mismatch
 */
export async function verifyChunkManifest(
  manifestCiphertext: Uint8Array,
  fileKey: CryptoKey,
  hmacKey: CryptoKey,
  baseIv: Uint8Array,
  chunkCount: number,
  chunkHashes: ArrayBuffer[],
  headerBytes?: Uint8Array,
): Promise<void> {
  const manifestIv = deriveChunkIV(baseIv, chunkCount);
  const aadParam = headerBytes ? { additionalData: toArrayBuffer(headerBytes) } : {};
  let manifestPlaintext: ArrayBuffer;
  try {
    manifestPlaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toCleanUint8Array(manifestIv), ...aadParam },
      fileKey,
      toArrayBuffer(manifestCiphertext),
    );
  } catch {
    throw new FileCorruptedError('File integrity verification failed — manifest decryption error');
  }

  const manifestBytes = new Uint8Array(manifestPlaintext);

  // v1.4 manifest: HMAC(32B) + count(4B) + SHA-256(headerBytes)(32B) = 68 bytes
  // v1.2/v1.3 manifest: HMAC(32B) + count(4B) = 36 bytes
  const expectedSize = headerBytes ? 68 : 36;
  if (manifestBytes.byteLength !== expectedSize) {
    throw new FileCorruptedError('File integrity verification failed — unexpected manifest size');
  }

  // Extract stored HMAC (32 bytes) + chunk count (4 bytes big-endian)
  const storedHMAC = manifestBytes.slice(0, 32);
  const storedCount = new DataView(manifestPlaintext, 32, 4).getUint32(0, false);

  if (storedCount !== chunkCount) {
    throw new Error('File integrity verification failed');
  }

  // Rebuild manifestData: chunkCount(4B BE) || hash_0 || ... || hash_{N-1} [|| SHA-256(headerBytes)]
  const hashesSize = chunkHashes.length * 32;
  const headerHashSize = headerBytes ? 32 : 0;
  const manifestData = new Uint8Array(4 + hashesSize + headerHashSize);
  new DataView(manifestData.buffer).setUint32(0, chunkCount, false);
  let offset = 4;
  for (const hash of chunkHashes) {
    manifestData.set(new Uint8Array(hash), offset);
    offset += 32;
  }

  // v1.4: include SHA-256(headerBytes) in manifest HMAC input
  if (headerBytes) {
    const headerHash = await sha256(headerBytes);
    manifestData.set(headerHash, offset);

    // Also verify the stored header hash matches (constant-time comparison)
    const storedHeaderHash = manifestBytes.slice(36, 68);
    let headerHashMatch = true;
    for (let i = 0; i < 32; i++) {
      if (storedHeaderHash[i] !== headerHash[i]) headerHashMatch = false;
    }
    if (!headerHashMatch) {
      throw new Error('File integrity verification failed — header hash mismatch');
    }
  }

  const valid = await crypto.subtle.verify(
    'HMAC', hmacKey, toArrayBuffer(storedHMAC), toArrayBuffer(manifestData),
  );
  if (!valid) {
    throw new Error('File integrity verification failed');
  }
}

// ============ Hybrid Encryption ============

/**
 * Build PQC params and v1.4 core metadata (shared between single-pass and streaming)
 */
function buildPqcParams(
  ciphertext: HybridCiphertext,
  wrappedKey: Uint8Array,
): CVEFPqcParamsV1_2 {
  return {
    kemAlgorithm: 'x25519-ml-kem-768',
    classicalCiphertext: arrayBufferToBase64(toArrayBuffer(ciphertext.classical)),
    pqCiphertext: arrayBufferToBase64(toArrayBuffer(ciphertext.postQuantum)),
    wrappedFileKey: arrayBufferToBase64(toArrayBuffer(wrappedKey)),
  };
}

/**
 * Encrypt a file using hybrid post-quantum encryption (CVEF v1.4)
 *
 * Flow:
 * 1. Generate random file key (FK)
 * 2. Hybrid encapsulate to recipient's public key → get shared secret
 * 3. Wrap file key with hybrid KEK using AES-KW
 * 4. Build v1.4 coreMetadata → serialize → coreMetadataBytes
 * 5. If signing: sign SHA-256(coreMetadataBytes) → signatureMetadata
 * 6. Build two-block header → headerBytes (= AAD)
 * 7. AES-GCM encrypt with AAD = headerBytes
 */
export async function encryptFileHybrid(
  file: File,
  options: HybridEncryptionOptions
): Promise<HybridEncryptionResult> {
  const { publicKey, onProgress, signing } = options;

  // Get providers
  const hybridKem = getHybridKemProvider();
  const keyWrap = getKeyWrapProvider();

  // 1. Generate random file key
  const fileKey = generateFileKey();

  // 2. Hybrid encapsulate
  const { ciphertext, sharedSecret } = await hybridKem.encapsulate(publicKey);
  const hybridKEK = sharedSecret;

  try {
    // 3. Wrap file key
    const { wrappedKey } = await keyWrap.wrap(fileKey, hybridKEK);

    // 4. Build v1.4 core metadata
    const iv = generateIV();
    const pqcParams = buildPqcParams(ciphertext, wrappedKey);

    const metadata = createCVEFMetadataV1_4({
      salt: arrayBufferToBase64(new ArrayBuffer(32)),
      iv: arrayBufferToBase64(toArrayBuffer(iv)),
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 0, timeCost: 0, parallelism: 0 },
      keyWrapAlgorithm: 'aes-kw',
      pqcParams,
    });

    // 5. Sign if requested
    // First create header without signature to get coreMetadataBytes
    const { coreMetadataBytes } = createCVEFHeader(metadata);

    let signatureMetadata: CVEFSignatureMetadata | undefined;
    if (signing) {
      signatureMetadata = await signCoreMetadata(coreMetadataBytes, signing);
    }

    // 6. Build final two-block header (with signature if present)
    const { header, headerBytes } = createCVEFHeader(metadata, signatureMetadata);

    // 7. Encrypt file content with AAD = headerBytes
    const fileKeyHandle = await importFileKey(fileKey);

    const fileData = await file.arrayBuffer();
    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toCleanUint8Array(iv), additionalData: toArrayBuffer(headerBytes) },
      fileKeyHandle,
      fileData
    );

    if (onProgress) {
      onProgress({ bytesProcessed: file.size, totalBytes: file.size, percentage: 100 });
    }

    const blob = new Blob([toArrayBuffer(header), ciphertextBuffer], {
      type: 'application/octet-stream',
    });

    return { blob, metadata, signatureMetadata, originalSize: file.size };
  } finally {
    sharedSecret.fill(0);
    fileKey.fill(0);
  }
}

/**
 * Encrypt a large file using hybrid post-quantum encryption with streaming (CVEF v1.4)
 *
 * Uses chunked encryption for files larger than available memory.
 * AAD = headerBytes for every chunk + manifest. Manifest includes SHA-256(headerBytes).
 */
export async function encryptFileHybridStreaming(
  file: File,
  options: HybridEncryptionOptions
): Promise<HybridEncryptionResult> {
  const { publicKey, onProgress, signing } = options;

  // Get providers
  const hybridKem = getHybridKemProvider();
  const keyWrap = getKeyWrapProvider();

  // 1. Generate random file key
  const fileKey = generateFileKey();

  // 2. Hybrid encapsulate
  const { ciphertext, sharedSecret } = await hybridKem.encapsulate(publicKey);
  const hybridKEK = sharedSecret;

  try {
    // 3. Wrap file key
    const { wrappedKey } = await keyWrap.wrap(fileKey, hybridKEK);

    // 4. Setup encryption
    const baseIv = generateIV();
    const fileKeyHandle = await importFileKey(fileKey);
    const hmacKey = await deriveManifestHmacKey(fileKey);

    // 5. Pre-compute chunk count
    const chunkCount = Math.ceil(file.size / CHUNK_SIZE) || 1;
    const totalBytes = file.size;

    // 6. Build v1.4 metadata
    const pqcParams = buildPqcParams(ciphertext, wrappedKey);

    const metadata = createCVEFMetadataV1_4({
      salt: arrayBufferToBase64(new ArrayBuffer(32)),
      iv: arrayBufferToBase64(toArrayBuffer(baseIv)),
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 0, timeCost: 0, parallelism: 0 },
      keyWrapAlgorithm: 'aes-kw',
      pqcParams,
      chunked: { count: chunkCount, chunkSize: CHUNK_SIZE, ivs: [] },
    });

    // 7. Sign if requested
    const { coreMetadataBytes } = createCVEFHeader(metadata);
    let signatureMetadata: CVEFSignatureMetadata | undefined;
    if (signing) {
      signatureMetadata = await signCoreMetadata(coreMetadataBytes, signing);
    }

    // 8. Build final header (= AAD for all chunks)
    const { header, headerBytes } = createCVEFHeader(metadata, signatureMetadata);
    const aadBuffer = toArrayBuffer(headerBytes);

    // ── Phase 1: Encrypt all chunks ──
    const encryptedParts: BlobPart[] = [];
    const chunkHashesRaw: ArrayBuffer[] = [];

    let offset = 0;
    let chunkIndex = 0;

    while (offset < file.size) {
      const chunkEnd = Math.min(offset + CHUNK_SIZE, file.size);
      const chunk = file.slice(offset, chunkEnd);
      const chunkData = await chunk.arrayBuffer();

      const chunkIv = deriveChunkIV(baseIv, chunkIndex);

      const encryptedChunk = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: toCleanUint8Array(chunkIv), additionalData: aadBuffer },
        fileKeyHandle,
        chunkData,
      );

      chunkHashesRaw.push(await crypto.subtle.digest('SHA-256', encryptedChunk));

      const packet = new Uint8Array(4 + encryptedChunk.byteLength);
      new DataView(packet.buffer).setUint32(0, encryptedChunk.byteLength, false);
      packet.set(new Uint8Array(encryptedChunk), 4);

      encryptedParts.push(packet);
      offset = chunkEnd;
      chunkIndex++;

      if (onProgress) {
        onProgress({
          bytesProcessed: offset,
          totalBytes,
          percentage: Math.round((offset / totalBytes) * 100),
        });
      }
    }

    // ── Phase 2: Build trailing manifest ──

    // v1.4 manifest HMAC input: count(4B BE) || hash_0 || ... || hash_N || SHA-256(headerBytes)
    const headerHash = await sha256(headerBytes);
    const manifestData = new Uint8Array(4 + chunkHashesRaw.length * 32 + 32);
    new DataView(manifestData.buffer).setUint32(0, chunkCount, false);
    let mOffset = 4;
    for (const hash of chunkHashesRaw) {
      manifestData.set(new Uint8Array(hash), mOffset);
      mOffset += 32;
    }
    manifestData.set(headerHash, mOffset);

    const manifestHMAC = await crypto.subtle.sign('HMAC', hmacKey, manifestData);

    // Manifest payload: HMAC(32B) + count(4B BE) + SHA-256(headerBytes)(32B) = 68 bytes
    const manifestPayload = new Uint8Array(68);
    manifestPayload.set(new Uint8Array(manifestHMAC), 0);
    new DataView(manifestPayload.buffer).setUint32(32, chunkCount, false);
    manifestPayload.set(headerHash, 36);

    // Encrypt manifest with AAD
    const manifestIv = deriveChunkIV(baseIv, chunkCount);
    const encryptedManifest = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toCleanUint8Array(manifestIv), additionalData: aadBuffer },
      fileKeyHandle,
      toArrayBuffer(manifestPayload),
    );

    const manifestPacket = new Uint8Array(4 + encryptedManifest.byteLength);
    new DataView(manifestPacket.buffer).setUint32(0, encryptedManifest.byteLength, false);
    manifestPacket.set(new Uint8Array(encryptedManifest), 4);

    const blob = new Blob([toArrayBuffer(header), ...encryptedParts, manifestPacket], {
      type: 'application/octet-stream',
    });

    return { blob, metadata, signatureMetadata, originalSize: file.size };
  } finally {
    sharedSecret.fill(0);
    fileKey.fill(0);
  }
}

// ============ Hybrid Decryption ============

/**
 * Decrypt a hybrid-encrypted file (supports v1.2, v1.3, and v1.4)
 *
 * For v1.4: uses headerBytes as AAD for AES-GCM.
 * For v1.2/v1.3: no AAD (backward compat).
 */
export async function decryptFileHybrid(
  encryptedData: ArrayBuffer,
  options: HybridDecryptionOptions
): Promise<ArrayBuffer> {
  const { secretKey, onProgress } = options;

  // 1. Parse CVEF header
  const dataView = new Uint8Array(encryptedData);
  const { metadata, dataOffset, coreMetadataBytes, signatureMetadata, headerBytes } = parseCVEFHeader(dataView);

  // Verify it's a hybrid file
  if (!isCVEFMetadataV1_2(metadata) && !isCVEFMetadataV1_3(metadata) && !isCVEFMetadataV1_4(metadata)) {
    throw new Error('Not a hybrid-encrypted file (CVEF v1.2/v1.3/v1.4 required)');
  }

  // 1b. Enforce signature verification: if file has a signature, require a public key
  if (isCVEFMetadataV1_4(metadata) && hasValidSignatureMetadata(signatureMetadata) && !options.signerPublicKey) {
    console.warn('[HybridCrypto] CVEF container has valid signature but no signerPublicKey provided — signature verification skipped');
  }

  if (isCVEFMetadataV1_4(metadata) && hasValidSignatureMetadata(signatureMetadata) && options.signerPublicKey) {
    // v1.4: verify SHA-256(coreMetadataBytes) against signature in second block
    const sig = signatureMetadata!;
    const { verifyContentHash } = await import('./signedFileCrypto');
    const hash = await sha256(coreMetadataBytes);
    const signature = {
      classical: new Uint8Array(base64ToArrayBuffer(sig.classicalSignature)),
      postQuantum: new Uint8Array(base64ToArrayBuffer(sig.pqSignature)),
      context: sig.signingContext,
      signedAt: sig.signedAt,
    };
    const result = await verifyContentHash(hash, signature, options.signerPublicKey);
    if (!result.valid) {
      throw new Error(`Signature verification failed: ${result.error || 'invalid signature'}`);
    }
  } else if (isCVEFMetadataV1_3(metadata) && options.signerPublicKey) {
    // v1.3: legacy verification
    const { verifySignedFile } = await import('./signedFileCrypto');
    const blob = new Blob([encryptedData]);
    const result = await verifySignedFile(blob, { publicKey: options.signerPublicKey });
    if (!result.valid) {
      throw new Error(`Signature verification failed: ${result.error || 'invalid signature'}`);
    }
  }

  // Get providers
  const hybridKem = getHybridKemProvider();
  const keyWrap = getKeyWrapProvider();

  // 2. Reconstruct hybrid ciphertext
  const hybridCiphertext: HybridCiphertext = {
    classical: new Uint8Array(base64ToArrayBuffer(metadata.pqcParams.classicalCiphertext)),
    postQuantum: new Uint8Array(base64ToArrayBuffer(metadata.pqcParams.pqCiphertext)),
  };

  // 3. Hybrid decapsulate
  const sharedSecret = await hybridKem.decapsulate(hybridCiphertext, secretKey);
  let fileKey: Uint8Array | undefined;

  try {
    const hybridKEK = sharedSecret;

    // 4. Unwrap file key
    const wrappedFileKey = new Uint8Array(
      base64ToArrayBuffer(metadata.pqcParams.wrappedFileKey)
    );
    const unwrapResult = await keyWrap.unwrap(wrappedFileKey, hybridKEK, 1);
    fileKey = unwrapResult.masterKey;

    // 5. Decrypt file content
    const iv = new Uint8Array(base64ToArrayBuffer(metadata.iv));
    const ciphertextData = dataView.slice(dataOffset);
    const fileKeyHandle = await importFileKey(fileKey);
    const hmacKey = metadata.chunked ? await deriveManifestHmacKey(fileKey) : undefined;

    // Determine AAD: v1.4 uses headerBytes, older versions have no AAD
    const aad = isCVEFMetadataV1_4(metadata) ? headerBytes : undefined;

    let decryptedData: ArrayBuffer;

    if (metadata.chunked) {
      const stream = decryptChunkedToStream(
        ciphertextData,
        fileKeyHandle,
        iv,
        metadata.chunked.count,
        onProgress,
        hmacKey,
        aad,
      );
      const decryptBlob = await new Response(stream).blob();
      decryptedData = await decryptBlob.arrayBuffer();
    } else {
      // Single-pass decryption
      const aadParam = aad ? { additionalData: toArrayBuffer(aad) } : {};
      try {
        decryptedData = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: toCleanUint8Array(iv), ...aadParam },
          fileKeyHandle,
          toArrayBuffer(ciphertextData)
        );
      } catch {
        throw new Error('File decryption failed: invalid key or corrupted data');
      }

      if (onProgress) {
        onProgress({
          bytesProcessed: decryptedData.byteLength,
          totalBytes: decryptedData.byteLength,
          percentage: 100,
        });
      }
    }

    return decryptedData;
  } finally {
    sharedSecret.fill(0);
    if (fileKey) fileKey.fill(0);
  }
}

/**
 * Decrypt chunked data
 */
export async function decryptChunked(
  data: Uint8Array,
  key: CryptoKey,
  baseIv: Uint8Array,
  chunkCount: number,
  onProgress?: (progress: EncryptionProgress) => void,
  hmacKey?: CryptoKey,
  headerBytes?: Uint8Array,
): Promise<ArrayBuffer> {
  const decryptedChunks: ArrayBuffer[] = [];
  const chunkHashes: ArrayBuffer[] = [];
  let offset = 0;
  let bytesDecrypted = 0;
  const aadParam = headerBytes ? { additionalData: toArrayBuffer(headerBytes) } : {};

  for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
    const lengthView = new DataView(data.buffer, data.byteOffset + offset, 4);
    const chunkLength = lengthView.getUint32(0, false);
    offset += 4;

    const encryptedChunk = data.slice(offset, offset + chunkLength);
    offset += chunkLength;

    if (hmacKey) {
      chunkHashes.push(await crypto.subtle.digest('SHA-256', toArrayBuffer(encryptedChunk)));
    }

    const chunkIv = deriveChunkIV(baseIv, chunkIndex);

    let decryptedChunk: ArrayBuffer;
    try {
      decryptedChunk = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: toCleanUint8Array(chunkIv), ...aadParam },
        key,
        toArrayBuffer(encryptedChunk)
      );
    } catch {
      throw new Error(`Chunk ${chunkIndex} decryption failed: invalid key or corrupted data`);
    }

    decryptedChunks.push(decryptedChunk);
    bytesDecrypted += decryptedChunk.byteLength;

    if (onProgress) {
      onProgress({
        bytesProcessed: bytesDecrypted,
        totalBytes: bytesDecrypted,
        percentage: Math.round(((chunkIndex + 1) / chunkCount) * 100),
      });
    }
  }

  // Verify integrity manifest
  if (hmacKey) {
    const manifestLengthView = new DataView(data.buffer, data.byteOffset + offset, 4);
    const manifestLength = manifestLengthView.getUint32(0, false);
    offset += 4;
    const manifestCiphertext = data.slice(offset, offset + manifestLength);
    await verifyChunkManifest(manifestCiphertext, key, hmacKey, baseIv, chunkCount, chunkHashes, headerBytes);
  }

  // Combine decrypted chunks
  const totalLength = decryptedChunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const result = new Uint8Array(totalLength);
  let resultOffset = 0;

  for (const chunk of decryptedChunks) {
    result.set(new Uint8Array(chunk), resultOffset);
    resultOffset += chunk.byteLength;
  }

  return toArrayBuffer(result);
}

/**
 * Streaming variant of decryptChunked — yields a ReadableStream<Uint8Array>
 * instead of accumulating ArrayBuffer[]. Emits chunks immediately after
 * AES-GCM decryption (which authenticates each chunk). Trailing manifest
 * is verified at end as defense-in-depth.
 */
export function decryptChunkedToStream(
  data: Uint8Array,
  key: CryptoKey,
  baseIv: Uint8Array,
  chunkCount: number,
  onProgress?: (progress: EncryptionProgress) => void,
  hmacKey?: CryptoKey,
  headerBytes?: Uint8Array,
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        let offset = 0;
        let bytesDecrypted = 0;
        const chunkHashes: ArrayBuffer[] = [];
        const aadParam = headerBytes ? { additionalData: toArrayBuffer(headerBytes) } : {};

        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
          const lengthView = new DataView(data.buffer, data.byteOffset + offset, 4);
          const chunkLength = lengthView.getUint32(0, false);
          offset += 4;

          const encryptedChunk = data.slice(offset, offset + chunkLength);
          offset += chunkLength;

          if (hmacKey) {
            chunkHashes.push(await crypto.subtle.digest('SHA-256', toArrayBuffer(encryptedChunk)));
          }

          const chunkIv = deriveChunkIV(baseIv, chunkIndex);

          let decryptedChunk: ArrayBuffer;
          try {
            decryptedChunk = await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: toCleanUint8Array(chunkIv), ...aadParam },
              key,
              toArrayBuffer(encryptedChunk)
            );
          } catch {
            throw new Error(`Chunk ${chunkIndex} decryption failed: invalid key or corrupted data`);
          }

          const plaintext = new Uint8Array(decryptedChunk);
          bytesDecrypted += plaintext.byteLength;

          controller.enqueue(plaintext);

          if (onProgress) {
            onProgress({
              bytesProcessed: bytesDecrypted,
              totalBytes: bytesDecrypted,
              percentage: Math.round(((chunkIndex + 1) / chunkCount) * 100),
            });
          }
        }

        // Verify trailing manifest (defense-in-depth)
        if (hmacKey) {
          const manifestLengthView = new DataView(data.buffer, data.byteOffset + offset, 4);
          const manifestLength = manifestLengthView.getUint32(0, false);
          offset += 4;
          const manifestCiphertext = data.slice(offset, offset + manifestLength);
          await verifyChunkManifest(manifestCiphertext, key, hmacKey, baseIv, chunkCount, chunkHashes, headerBytes);
        }

        controller.close();
      } catch (err) {
        controller.error(err);
      }
    },
  });
}

/**
 * Decrypt a hybrid-encrypted file from URL
 */
export async function decryptFileHybridFromUrl(
  url: string,
  options: HybridDecryptionOptions,
  mimeType: string
): Promise<Blob> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch file: ${response.status}`);
  }

  const encryptedData = await response.arrayBuffer();
  const decryptedData = await decryptFileHybrid(encryptedData, options);

  return new Blob([decryptedData], { type: mimeType });
}

// ============ Utility Functions ============

/**
 * Check if encrypted data is in hybrid format (CVEF v1.2, v1.3, or v1.4)
 */
export function isHybridEncrypted(data: ArrayBuffer): boolean {
  try {
    const dataView = new Uint8Array(data);
    const { metadata } = parseCVEFHeader(dataView);
    return isCVEFMetadataV1_2(metadata) || isCVEFMetadataV1_3(metadata) || isCVEFMetadataV1_4(metadata);
  } catch {
    return false;
  }
}

/**
 * Get metadata from encrypted file
 */
export function getEncryptionMetadata(data: ArrayBuffer): CVEFMetadata {
  const dataView = new Uint8Array(data);
  const { metadata } = parseCVEFHeader(dataView);
  return metadata;
}

/**
 * Determine if a file should use streaming encryption
 */
export function shouldUseStreamingEncryption(file: File): boolean {
  return file.size > STREAMING.THRESHOLD_BYTES;
}

/**
 * Encrypt a file with hybrid KEM, automatically choosing streaming for large files
 */
export async function encryptFileHybridAuto(
  file: File,
  options: HybridEncryptionOptions
): Promise<HybridEncryptionResult> {
  if (shouldUseStreamingEncryption(file)) {
    return encryptFileHybridStreaming(file, options);
  }
  return encryptFileHybrid(file, options);
}

// ============ V4 File Key Extraction (for Sharing) ============

export interface ExtractedFileKey {
  /** Raw 32-byte file key */
  fileKeyBytes: Uint8Array;
  /** Zeroes the key bytes in memory */
  zeroBytes: () => void;
}

/**
 * Extract the raw 32-byte file key from a V4 (hybrid) encrypted file.
 *
 * This fetches only the CVEF header from the presigned URL to extract
 * the wrapped file key, then unwraps it using the user's hybrid secret key.
 * The file content itself is NOT decrypted — only the file key is returned.
 *
 * Used by the sharing system to re-wrap the file key for recipients.
 */
export async function extractV4FileKey(
  presignedUrl: string,
  secretKey: HybridSecretKey,
): Promise<ExtractedFileKey> {
  const controller = new AbortController();
  const response = await fetch(presignedUrl, { signal: controller.signal });
  if (!response.ok) {
    throw new Error(`Failed to fetch file header: ${response.status}`);
  }
  if (!response.body) {
    throw new Error('Response body is null — streaming not supported');
  }

  const { metadata } = await parseCVEFHeaderFromStream(response.body);
  controller.abort();

  // Verify it's a hybrid file
  if (!isCVEFMetadataV1_2(metadata) && !isCVEFMetadataV1_3(metadata) && !isCVEFMetadataV1_4(metadata)) {
    throw new Error('Not a V4 hybrid-encrypted file (CVEF v1.2/v1.3/v1.4 required)');
  }

  const hybridKem = getHybridKemProvider();
  const keyWrap = getKeyWrapProvider();

  const hybridCiphertext: HybridCiphertext = {
    classical: new Uint8Array(base64ToArrayBuffer(metadata.pqcParams.classicalCiphertext)),
    postQuantum: new Uint8Array(base64ToArrayBuffer(metadata.pqcParams.pqCiphertext)),
  };

  const sharedSecret = await hybridKem.decapsulate(hybridCiphertext, secretKey);

  const wrappedFileKey = new Uint8Array(
    base64ToArrayBuffer(metadata.pqcParams.wrappedFileKey)
  );
  const { masterKey: fileKey } = await keyWrap.unwrap(wrappedFileKey, sharedSecret, 1);
  sharedSecret.fill(0);

  return {
    fileKeyBytes: fileKey,
    zeroBytes: () => fileKey.fill(0),
  };
}
