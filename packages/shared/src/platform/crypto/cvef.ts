/**
 * Crypto Vault Encrypted File Format (CVEF) v1.0–v1.4
 *
 * This module defines the encrypted file format specification for StenVault.
 *
 * Version history:
 * - v1.0/v1.1: Crypto agility (PBKDF2/Argon2id, key wrapping, PQC readiness)
 * - v1.2: Hybrid PQC (X25519 + ML-KEM-768), chunked with trailing manifest
 * - v1.3: Hybrid digital signatures (Ed25519 + ML-DSA-65) — single-block header
 * - v1.4: AAD-protected metadata + two-block header (container v2)
 *
 * Container v1 (v1.0–v1.3):
 * ```
 * [4 bytes]  Magic Header: "CVEF" (0x43 0x56 0x45 0x46)
 * [1 byte]   Container Version: 1
 * [4 bytes]  Metadata Length (big-endian, unsigned)
 * [N bytes]  Metadata JSON (UTF-8)
 * [rest]     Encrypted Data (chunked or single)
 * ```
 *
 * Container v2 (v1.4):
 * ```
 * [4 bytes]  Magic Header: "CVEF" (0x43 0x56 0x45 0x46)
 * [1 byte]   Container Version: 2
 * [4 bytes]  Core Metadata Length (big-endian, unsigned)
 * [N bytes]  Core Metadata JSON (UTF-8) — signed + used to build AAD
 * [4 bytes]  Signature Metadata Length (big-endian, unsigned) — 0 if unsigned
 * [M bytes]  Signature Metadata JSON (UTF-8) — only signatureParams
 * [rest]     Encrypted Data (AES-GCM with AAD = full header bytes [0..9+N+4+M])
 * ```
 */

// ============ Constants ============

/** CVEF magic header bytes: "CVEF" */
export const CVEF_MAGIC = new Uint8Array([0x43, 0x56, 0x45, 0x46]);

/** Container version 1 (v1.0–v1.3: single metadata block) */
export const CVEF_CONTAINER_V1 = 1;

/** Container version 2 (v1.4: two-block header with AAD) */
export const CVEF_CONTAINER_V2 = 2;

/** @deprecated Use CVEF_CONTAINER_V1 */
export const CVEF_VERSION = CVEF_CONTAINER_V1;

/** Fixed header prefix size: magic (4) + container version (1) + first metadata length (4) */
export const CVEF_HEADER_SIZE = 9;

/** Maximum metadata size (2 MB — metadata is small, chunk hashes go in trailing manifest) */
export const CVEF_MAX_METADATA_SIZE = 2 * 1024 * 1024;

/** Minimum metadata length (must be at least a valid JSON object "{}") */
export const CVEF_MIN_METADATA_SIZE = 2;

// ============ Types ============

/**
 * KDF algorithm identifier
 */
export type CVEFKdfAlgorithm = 'pbkdf2' | 'argon2id';

/**
 * Key wrap algorithm identifier
 */
export type CVEFKeyWrapAlgorithm = 'aes-kw' | 'none';

/**
 * Post-quantum algorithm identifier
 */
export type CVEFPqcAlgorithm = 'ml-kem-768' | 'none';

/**
 * KEM (Key Encapsulation Mechanism) algorithm identifiers
 */
export const CVEF_KEM = {
  /** No KEM (legacy, key derived directly from password) */
  NONE: 0x00,
  /** X25519 + ML-KEM-768 hybrid */
  X25519_MLKEM768: 0x01,
} as const;

/**
 * KEM algorithm type
 */
export type CVEFKemAlgorithm = 'x25519-ml-kem-768' | 'none';

/**
 * Encryption algorithm identifier
 */
export type CVEFEncryptionAlgorithm = 'AES-256-GCM';

/**
 * PBKDF2 parameters (v1.0 compatible)
 */
export interface CVEFPBKDF2Params {
  /** Number of iterations */
  iterations: number;
}

/**
 * Argon2id parameters (v1.1 new)
 */
export interface CVEFArgon2Params {
  /** Memory cost in KiB */
  memoryCost: number;
  /** Time cost (iterations) */
  timeCost: number;
  /** Degree of parallelism */
  parallelism: number;
}

/**
 * Chunked encryption info
 */
export interface CVEFChunkedInfo {
  /** Number of chunks */
  count: number;
  /** Size of each chunk (except last) in bytes */
  chunkSize: number;
  /** Array of IVs for each chunk (Base64) */
  ivs: string[];
}

/**
 * CVEF v1.0 Metadata (legacy format)
 * This is the original format, still supported for reading
 */
export interface CVEFMetadataV1_0 {
  /** Salt used for key derivation (Base64) */
  salt: string;
  /** Initialization vector (Base64) - for non-chunked encryption */
  iv: string;
  /** Algorithm identifier */
  algorithm: CVEFEncryptionAlgorithm;
  /** PBKDF2 iterations used */
  iterations: number;
  /** Chunked encryption info (optional) */
  chunked?: CVEFChunkedInfo;
}

/**
 * CVEF v1.1 Metadata (Sovereign format)
 * Extends v1.0 with crypto agility fields
 */
export interface CVEFMetadataV1_1 extends CVEFMetadataV1_0 {
  /**
   * Metadata version string
   * - undefined or '1.0': Legacy format
   * - '1.1': Sovereign format with new fields
   * - '1.2': Hybrid PQC format
   * - '1.3': Hybrid signature format
   * - '1.4': AAD-protected metadata (container v2)
   */
  version?: '1.0' | '1.1' | '1.2' | '1.3' | '1.4';

  /**
   * KDF algorithm used
   * - 'pbkdf2': Legacy PBKDF2-HMAC-SHA256
   * - 'argon2id': New Argon2id (OWASP 2024)
   * Default: 'pbkdf2' for backward compatibility
   */
  kdfAlgorithm?: CVEFKdfAlgorithm;

  /**
   * KDF-specific parameters
   * Structure depends on kdfAlgorithm
   */
  kdfParams?: CVEFPBKDF2Params | CVEFArgon2Params;

  /**
   * Key wrap algorithm (for master key wrapping)
   * - 'none': Key derived directly from password (legacy)
   * - 'aes-kw': AES Key Wrap (RFC 3394) with master key
   * Default: 'none' for backward compatibility
   */
  keyWrapAlgorithm?: CVEFKeyWrapAlgorithm;

  /**
   * Master key version (when keyWrapAlgorithm is 'aes-kw')
   * Incremented on password change
   */
  masterKeyVersion?: number;

  /**
   * Post-quantum algorithm
   * - 'none': Classical cryptography only
   * - 'ml-kem-768': Hybrid classical + ML-KEM-768
   */
  pqcAlgorithm?: CVEFPqcAlgorithm;

  /**
   * Post-quantum specific parameters (v1.1 reserved format)
   */
  pqcParams?: {
    /** ML-KEM public key (Base64) - for decryption */
    publicKey?: string;
    /** ML-KEM encapsulated key (Base64) */
    encapsulatedKey?: string;
  };
}

/**
 * Post-quantum parameters for CVEF v1.2 (hybrid KEM)
 */
export interface CVEFPqcParamsV1_2 {
  /** KEM algorithm identifier */
  kemAlgorithm: CVEFKemAlgorithm;
  /** X25519 ephemeral public key (Base64, 32 bytes) */
  classicalCiphertext: string;
  /** ML-KEM-768 ciphertext (Base64, 1088 bytes) */
  pqCiphertext: string;
  /** Wrapped file key with hybrid KEK (Base64, 40 bytes) */
  wrappedFileKey: string;
}

/**
 * CVEF v1.2 Metadata (Hybrid PQC format)
 * Extends v1.1 with full hybrid KEM support
 */
export interface CVEFMetadataV1_2 extends Omit<CVEFMetadataV1_1, 'version' | 'pqcParams'> {
  /**
   * Metadata version string - must be '1.2'
   */
  version: '1.2';

  /**
   * Post-quantum algorithm - must be 'ml-kem-768' for v1.2
   */
  pqcAlgorithm: 'ml-kem-768';

  /**
   * Post-quantum parameters (v1.2 format with full hybrid KEM)
   */
  pqcParams: CVEFPqcParamsV1_2;
}

/**
 * Signature algorithm identifier for CVEF v1.3/v1.4
 */
export type CVEFSignatureAlgorithm = 'ed25519-ml-dsa-65' | 'none';

/**
 * Signature context identifier
 */
export type CVEFSignatureContext = 'FILE' | 'TIMESTAMP' | 'SHARE';

/**
 * Base signature parameters (common to all signature types)
 */
interface CVEFSignatureParamsBase {
  /** Signing context (domain separator) */
  signingContext: CVEFSignatureContext;
  /** Timestamp of signing (Unix ms) */
  signedAt: number;
  /** Signer's key fingerprint (for verification) */
  signerFingerprint: string;
  /** Signer's key version at signing time */
  signerKeyVersion: number;
}

/**
 * Signature parameters when no signature is present
 */
interface CVEFSignatureParamsNone extends CVEFSignatureParamsBase {
  /** Signature algorithm */
  signatureAlgorithm: 'none';
}

/**
 * Signature parameters when hybrid signature is present
 */
interface CVEFSignatureParamsHybrid extends CVEFSignatureParamsBase {
  /** Signature algorithm */
  signatureAlgorithm: 'ed25519-ml-dsa-65';
  /** Ed25519 signature (Base64, 64 bytes) */
  classicalSignature: string;
  /** ML-DSA-65 signature (Base64, 3309 bytes) */
  pqSignature: string;
}

/**
 * Signature parameters for CVEF v1.3 (discriminated union)
 *
 * When signatureAlgorithm is 'ed25519-ml-dsa-65', both classicalSignature
 * and pqSignature are required. When 'none', they are not present.
 */
export type CVEFSignatureParamsV1_3 = CVEFSignatureParamsNone | CVEFSignatureParamsHybrid;

/**
 * CVEF v1.3 Metadata (Hybrid Signature format)
 * Extends v1.2 with digital signature support
 *
 * Backward Compatibility:
 * - v1.2 clients can decrypt v1.3 files (signatures are metadata-only)
 * - Signature verification is optional for decryption
 */
export interface CVEFMetadataV1_3 extends Omit<CVEFMetadataV1_2, 'version'> {
  /**
   * Metadata version string - must be '1.3'
   */
  version: '1.3';

  /**
   * Signature parameters (optional - file may not be signed)
   */
  signatureParams?: CVEFSignatureParamsV1_3;
}

/**
 * CVEF v1.4 Core Metadata (AAD-protected, container v2)
 *
 * Same encryption fields as v1.2 but uses container v2 two-block header.
 * Signature parameters are NOT in this metadata — they go in a separate
 * second block so signatures can be computed over coreMetadataBytes before
 * the header is finalized.
 */
export interface CVEFMetadataV1_4 extends Omit<CVEFMetadataV1_2, 'version'> {
  version: '1.4';
}

/**
 * Signature metadata for CVEF v1.4 second header block.
 *
 * This is stored in the separate signature block (container v2).
 * The signature covers SHA-256(coreMetadataBytes) where coreMetadataBytes
 * is the serialized CVEFMetadataV1_4 JSON.
 */
export interface CVEFSignatureMetadata {
  signatureAlgorithm: 'ed25519-ml-dsa-65';
  classicalSignature: string;
  pqSignature: string;
  signingContext: CVEFSignatureContext;
  signedAt: number;
  signerFingerprint: string;
  signerKeyVersion: number;
}

/**
 * Union type for any valid CVEF metadata
 */
export type CVEFMetadata =
  | CVEFMetadataV1_0
  | CVEFMetadataV1_1
  | CVEFMetadataV1_2
  | CVEFMetadataV1_3
  | CVEFMetadataV1_4;

// ============ Parsing Functions ============

/**
 * Check if data starts with CVEF magic header
 */
export function isCVEFFile(data: Uint8Array): boolean {
  if (data.length < CVEF_HEADER_SIZE) {
    return false;
  }
  return (
    data[0] === CVEF_MAGIC[0] &&
    data[1] === CVEF_MAGIC[1] &&
    data[2] === CVEF_MAGIC[2] &&
    data[3] === CVEF_MAGIC[3]
  );
}

/**
 * Result of parsing a CVEF header
 */
export interface CVEFParsedHeader {
  /** Parsed core metadata */
  metadata: CVEFMetadata;
  /** Offset to encrypted data (first byte after header) */
  dataOffset: number;
  /** Raw bytes of the core metadata JSON (for signature verification in v1.4) */
  coreMetadataBytes: Uint8Array;
  /** Parsed signature metadata from second block (v1.4 container v2 only) */
  signatureMetadata?: CVEFSignatureMetadata;
  /** Full header bytes from offset 0 to dataOffset (= AAD for AES-GCM in v1.4) */
  headerBytes: Uint8Array;
}

/**
 * Parse CVEF header and return metadata
 *
 * Supports both container v1 (single block) and v2 (two-block with signature).
 *
 * @param data - File data starting with CVEF header
 * @returns Parsed header with metadata, offsets, and raw bytes for AAD/signature
 */
export function parseCVEFHeader(data: Uint8Array): CVEFParsedHeader {
  if (!isCVEFFile(data)) {
    throw new Error('Not a valid CVEF file: missing magic header');
  }

  const containerVersion = data[4];

  if (containerVersion === CVEF_CONTAINER_V1) {
    return parseCVEFHeaderV1(data);
  } else if (containerVersion === CVEF_CONTAINER_V2) {
    return parseCVEFHeaderV2(data);
  } else {
    throw new Error(`Unsupported CVEF container version: ${containerVersion}`);
  }
}

/**
 * Parse container v1 (single metadata block, v1.0–v1.3)
 */
function parseCVEFHeaderV1(data: Uint8Array): CVEFParsedHeader {
  // Read metadata length (4 bytes, big-endian, unsigned)
  const metadataLength =
    ((data[5]! << 24) | (data[6]! << 16) | (data[7]! << 8) | data[8]!) >>> 0;

  if (metadataLength < CVEF_MIN_METADATA_SIZE) {
    throw new Error(`Metadata too small: ${metadataLength} bytes`);
  }

  if (metadataLength > CVEF_MAX_METADATA_SIZE) {
    throw new Error(`Metadata too large: ${metadataLength} bytes`);
  }

  const dataOffset = CVEF_HEADER_SIZE + metadataLength;

  if (data.length < dataOffset) {
    throw new Error('Truncated CVEF file: metadata incomplete');
  }

  // Parse metadata JSON
  const coreMetadataBytes = data.slice(CVEF_HEADER_SIZE, dataOffset);
  const metadataJson = new TextDecoder().decode(coreMetadataBytes);

  let metadata: CVEFMetadata;
  try {
    metadata = JSON.parse(metadataJson) as CVEFMetadata;
  } catch {
    throw new Error('Invalid CVEF metadata: not valid JSON');
  }

  // Normalize legacy formats
  metadata = normalizeCVEFMetadata(metadata);

  // v1.4 requires container v2 — reject if found in container v1
  if ('version' in metadata && metadata.version === '1.4') {
    throw new Error('CVEF v1.4 metadata requires container v2, but container v1 was found');
  }

  const headerBytes = data.slice(0, dataOffset);

  return {
    metadata,
    dataOffset,
    coreMetadataBytes,
    headerBytes,
  };
}

/**
 * Parse container v2 (two-block header, v1.4)
 *
 * Format:
 * [4B magic] [1B ver=2] [4B coreLen] [N core JSON] [4B sigLen] [M sig JSON] [encrypted data]
 */
function parseCVEFHeaderV2(data: Uint8Array): CVEFParsedHeader {
  // Read core metadata length (4 bytes, big-endian, unsigned)
  const coreMetadataLength =
    ((data[5]! << 24) | (data[6]! << 16) | (data[7]! << 8) | data[8]!) >>> 0;

  if (coreMetadataLength < CVEF_MIN_METADATA_SIZE) {
    throw new Error(`Core metadata too small: ${coreMetadataLength} bytes`);
  }

  if (coreMetadataLength > CVEF_MAX_METADATA_SIZE) {
    throw new Error(`Core metadata too large: ${coreMetadataLength} bytes`);
  }

  const sigLengthOffset = CVEF_HEADER_SIZE + coreMetadataLength;

  if (data.length < sigLengthOffset + 4) {
    throw new Error('Truncated CVEF file: missing signature length field');
  }

  // Read core metadata JSON
  const coreMetadataBytes = data.slice(CVEF_HEADER_SIZE, sigLengthOffset);
  const coreMetadataJson = new TextDecoder().decode(coreMetadataBytes);

  let metadata: CVEFMetadata;
  try {
    metadata = JSON.parse(coreMetadataJson) as CVEFMetadata;
  } catch {
    throw new Error('Invalid CVEF core metadata: not valid JSON');
  }

  // Read signature metadata length (4 bytes, big-endian, unsigned)
  const sigMetadataLength =
    ((data[sigLengthOffset]! << 24) |
      (data[sigLengthOffset + 1]! << 16) |
      (data[sigLengthOffset + 2]! << 8) |
      data[sigLengthOffset + 3]!) >>> 0;

  if (sigMetadataLength > CVEF_MAX_METADATA_SIZE) {
    throw new Error(`Signature metadata too large: ${sigMetadataLength} bytes`);
  }

  const dataOffset = sigLengthOffset + 4 + sigMetadataLength;

  if (data.length < dataOffset) {
    throw new Error('Truncated CVEF file: signature metadata incomplete');
  }

  // Parse signature metadata if present
  let signatureMetadata: CVEFSignatureMetadata | undefined;
  if (sigMetadataLength > 0) {
    const sigMetadataBytes = data.slice(sigLengthOffset + 4, dataOffset);
    const sigMetadataJson = new TextDecoder().decode(sigMetadataBytes);
    let parsed: unknown;
    try {
      parsed = JSON.parse(sigMetadataJson);
    } catch {
      throw new Error('Invalid CVEF signature metadata: not valid JSON');
    }
    signatureMetadata = validateSignatureMetadata(parsed);
    if (!signatureMetadata) {
      throw new Error(
        'Invalid CVEF signature metadata: block present but missing required fields',
      );
    }
  }

  // Normalize (v1.4 should be returned as-is)
  metadata = normalizeCVEFMetadata(metadata);

  const headerBytes = data.slice(0, dataOffset);

  return {
    metadata,
    dataOffset,
    coreMetadataBytes,
    signatureMetadata,
    headerBytes,
  };
}

/**
 * Normalize legacy v1.0 metadata to v1.1 format
 * v1.2, v1.3, and v1.4 metadata are returned as-is
 */
export function normalizeCVEFMetadata(metadata: CVEFMetadata): CVEFMetadata {
  if ('version' in metadata) {
    if (metadata.version === '1.4' || metadata.version === '1.2' || metadata.version === '1.3') {
      // Validate required PQC fields for v1.2/v1.3/v1.4
      const m = metadata as unknown as Record<string, unknown>;
      if (m.pqcAlgorithm !== 'ml-kem-768') {
        throw new Error(`CVEF v${metadata.version} metadata requires pqcAlgorithm 'ml-kem-768'`);
      }
      if (!m.pqcParams || typeof m.pqcParams !== 'object') {
        throw new Error(`CVEF v${metadata.version} metadata missing required pqcParams`);
      }
      const pqc = m.pqcParams as Record<string, unknown>;
      if (!('kemAlgorithm' in pqc)) {
        throw new Error(`CVEF v${metadata.version} metadata missing required pqcParams.kemAlgorithm`);
      }
      if (metadata.version === '1.4') return metadata as CVEFMetadataV1_4;
      if (metadata.version === '1.3') return metadata as CVEFMetadataV1_3;
      return metadata as CVEFMetadataV1_2;
    }
    if (metadata.version === '1.1') return metadata as CVEFMetadataV1_1;
  }

  // Upgrade v1.0 to v1.1 with defaults
  return {
    ...metadata,
    version: '1.0', // Mark as upgraded from 1.0
    kdfAlgorithm: 'pbkdf2',
    kdfParams: {
      iterations: metadata.iterations,
    },
    keyWrapAlgorithm: 'none',
    pqcAlgorithm: 'none',
  } as CVEFMetadataV1_1;
}

/**
 * Check if metadata is v1.2 format (hybrid PQC)
 */
export function isCVEFMetadataV1_2(metadata: CVEFMetadata): metadata is CVEFMetadataV1_2 {
  return (
    'version' in metadata &&
    metadata.version === '1.2' &&
    metadata.pqcAlgorithm === 'ml-kem-768' &&
    !!metadata.pqcParams &&
    'kemAlgorithm' in metadata.pqcParams
  );
}

/**
 * Check if metadata is v1.3 format (hybrid signatures, container v1)
 */
export function isCVEFMetadataV1_3(metadata: CVEFMetadata): metadata is CVEFMetadataV1_3 {
  return 'version' in metadata && metadata.version === '1.3';
}

/**
 * Check if metadata is v1.4 format (AAD-protected, container v2)
 */
export function isCVEFMetadataV1_4(metadata: CVEFMetadata): metadata is CVEFMetadataV1_4 {
  return (
    'version' in metadata &&
    metadata.version === '1.4' &&
    metadata.pqcAlgorithm === 'ml-kem-768' &&
    !!metadata.pqcParams &&
    'kemAlgorithm' in metadata.pqcParams
  );
}

/**
 * Check if metadata has a valid signature.
 * For v1.3: checks signatureParams in metadata.
 * For v1.4: only checks metadata version (signature is in separate block, use signatureMetadata from parsed header).
 */
export function hasValidSignature(metadata: CVEFMetadata): boolean {
  if (isCVEFMetadataV1_3(metadata)) {
    const sigParams = metadata.signatureParams;
    if (!sigParams) return false;
    return (
      sigParams.signatureAlgorithm === 'ed25519-ml-dsa-65' &&
      !!sigParams.classicalSignature &&
      !!sigParams.pqSignature &&
      !!sigParams.signerFingerprint
    );
  }
  // For v1.4, signature validity is checked via signatureMetadata from parseCVEFHeader
  return false;
}

/**
 * Validate parsed JSON is a structurally valid CVEFSignatureMetadata.
 * Returns the typed object if valid, undefined if required fields are missing.
 */
export function validateSignatureMetadata(parsed: unknown): CVEFSignatureMetadata | undefined {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
  const obj = parsed as Record<string, unknown>;

  // Validate types
  if (
    typeof obj.signatureAlgorithm !== 'string' ||
    typeof obj.classicalSignature !== 'string' ||
    typeof obj.pqSignature !== 'string' ||
    typeof obj.signingContext !== 'string' ||
    typeof obj.signedAt !== 'number' ||
    typeof obj.signerFingerprint !== 'string' ||
    typeof obj.signerKeyVersion !== 'number'
  ) {
    return undefined;
  }

  // Validate algorithm value (only known algorithm accepted)
  if (obj.signatureAlgorithm !== 'ed25519-ml-dsa-65') return undefined;

  // Validate signing context value
  if (obj.signingContext !== 'FILE' && obj.signingContext !== 'TIMESTAMP' && obj.signingContext !== 'SHARE') {
    return undefined;
  }

  return obj as unknown as CVEFSignatureMetadata;
}

/**
 * Check if a CVEFSignatureMetadata block has valid signature data
 */
export function hasValidSignatureMetadata(sig: CVEFSignatureMetadata | undefined): boolean {
  if (!sig) return false;
  return (
    sig.signatureAlgorithm === 'ed25519-ml-dsa-65' &&
    !!sig.classicalSignature &&
    !!sig.pqSignature &&
    !!sig.signerFingerprint
  );
}

// ============ Creation Functions ============

/**
 * Result of creating a CVEF header
 */
export interface CVEFHeaderResult {
  /** Complete header bytes to write to file */
  header: Uint8Array;
  /** Core metadata JSON bytes (for signature computation) */
  coreMetadataBytes: Uint8Array;
  /** Full header bytes = AAD for AES-GCM (same as header) */
  headerBytes: Uint8Array;
}

/**
 * Create CVEF header bytes
 *
 * For v1.4 metadata, creates a container v2 two-block header.
 * For older versions, creates a container v1 single-block header.
 *
 * @param metadata - Encryption metadata
 * @param signatureMetadata - Optional signature block (v1.4 only)
 * @returns Header bytes, core metadata bytes, and full header bytes (AAD)
 */
export function createCVEFHeader(
  metadata: CVEFMetadataV1_1 | CVEFMetadataV1_2 | CVEFMetadataV1_3 | CVEFMetadataV1_4,
  signatureMetadata?: CVEFSignatureMetadata,
): CVEFHeaderResult {
  // Serialize core metadata
  const metadataJson = JSON.stringify(metadata);
  const coreMetadataBytes = new TextEncoder().encode(metadataJson);

  if (coreMetadataBytes.length > CVEF_MAX_METADATA_SIZE) {
    throw new Error(`Metadata too large: ${coreMetadataBytes.length} bytes`);
  }

  // v1.4 → container v2 (two-block header)
  if ('version' in metadata && metadata.version === '1.4') {
    const sigBytes = signatureMetadata
      ? new TextEncoder().encode(JSON.stringify(signatureMetadata))
      : new Uint8Array(0);

    if (sigBytes.length > CVEF_MAX_METADATA_SIZE) {
      throw new Error(`Signature metadata too large: ${sigBytes.length} bytes`);
    }

    // Total: magic(4) + ver(1) + coreLen(4) + core(N) + sigLen(4) + sig(M)
    const totalSize = CVEF_HEADER_SIZE + coreMetadataBytes.length + 4 + sigBytes.length;
    const header = new Uint8Array(totalSize);

    // Magic
    header.set(CVEF_MAGIC, 0);

    // Container version 2
    header[4] = CVEF_CONTAINER_V2;

    // Core metadata length (big-endian)
    header[5] = (coreMetadataBytes.length >> 24) & 0xff;
    header[6] = (coreMetadataBytes.length >> 16) & 0xff;
    header[7] = (coreMetadataBytes.length >> 8) & 0xff;
    header[8] = coreMetadataBytes.length & 0xff;

    // Core metadata
    header.set(coreMetadataBytes, CVEF_HEADER_SIZE);

    // Signature metadata length (big-endian)
    const sigLenOffset = CVEF_HEADER_SIZE + coreMetadataBytes.length;
    header[sigLenOffset] = (sigBytes.length >> 24) & 0xff;
    header[sigLenOffset + 1] = (sigBytes.length >> 16) & 0xff;
    header[sigLenOffset + 2] = (sigBytes.length >> 8) & 0xff;
    header[sigLenOffset + 3] = sigBytes.length & 0xff;

    // Signature metadata
    if (sigBytes.length > 0) {
      header.set(sigBytes, sigLenOffset + 4);
    }

    return {
      header,
      coreMetadataBytes,
      headerBytes: header,
    };
  }

  // v1.0–v1.3 → container v1 (single block, backward compat)
  const header = new Uint8Array(CVEF_HEADER_SIZE + coreMetadataBytes.length);

  // Magic
  header.set(CVEF_MAGIC, 0);

  // Container version 1
  header[4] = CVEF_CONTAINER_V1;

  // Metadata length (big-endian)
  header[5] = (coreMetadataBytes.length >> 24) & 0xff;
  header[6] = (coreMetadataBytes.length >> 16) & 0xff;
  header[7] = (coreMetadataBytes.length >> 8) & 0xff;
  header[8] = coreMetadataBytes.length & 0xff;

  // Metadata
  header.set(coreMetadataBytes, CVEF_HEADER_SIZE);

  return {
    header,
    coreMetadataBytes,
    headerBytes: header,
  };
}

/**
 * Create v1.1 metadata for new file encryption (non-hybrid)
 */
export function createCVEFMetadata(options: {
  salt: string;
  iv: string;
  kdfAlgorithm: CVEFKdfAlgorithm;
  kdfParams: CVEFPBKDF2Params | CVEFArgon2Params;
  keyWrapAlgorithm?: CVEFKeyWrapAlgorithm;
  masterKeyVersion?: number;
  chunked?: CVEFChunkedInfo;
}): CVEFMetadataV1_1 {
  const metadata: CVEFMetadataV1_1 = {
    version: '1.1',
    salt: options.salt,
    iv: options.iv,
    algorithm: 'AES-256-GCM',
    iterations:
      options.kdfAlgorithm === 'pbkdf2'
        ? (options.kdfParams as CVEFPBKDF2Params).iterations
        : 0, // Not used for Argon2, but required for v1.0 compat
    kdfAlgorithm: options.kdfAlgorithm,
    kdfParams: options.kdfParams,
    keyWrapAlgorithm: options.keyWrapAlgorithm ?? 'none',
    pqcAlgorithm: 'none',
  };

  if (options.masterKeyVersion !== undefined) {
    metadata.masterKeyVersion = options.masterKeyVersion;
  }

  if (options.chunked) {
    metadata.chunked = options.chunked;
  }

  return metadata;
}

/**
 * Create v1.2 metadata for hybrid PQC file encryption
 */
export function createCVEFMetadataV1_2(options: {
  salt: string;
  iv: string;
  kdfAlgorithm: CVEFKdfAlgorithm;
  kdfParams: CVEFPBKDF2Params | CVEFArgon2Params;
  keyWrapAlgorithm?: CVEFKeyWrapAlgorithm;
  masterKeyVersion?: number;
  pqcParams: CVEFPqcParamsV1_2;
  chunked?: CVEFChunkedInfo;
}): CVEFMetadataV1_2 {
  const metadata: CVEFMetadataV1_2 = {
    version: '1.2',
    salt: options.salt,
    iv: options.iv,
    algorithm: 'AES-256-GCM',
    iterations:
      options.kdfAlgorithm === 'pbkdf2'
        ? (options.kdfParams as CVEFPBKDF2Params).iterations
        : 0,
    kdfAlgorithm: options.kdfAlgorithm,
    kdfParams: options.kdfParams,
    keyWrapAlgorithm: options.keyWrapAlgorithm ?? 'aes-kw',
    pqcAlgorithm: 'ml-kem-768',
    pqcParams: options.pqcParams,
  };

  if (options.masterKeyVersion !== undefined) {
    metadata.masterKeyVersion = options.masterKeyVersion;
  }

  if (options.chunked) {
    metadata.chunked = options.chunked;
  }

  return metadata;
}

/**
 * Create v1.4 core metadata for AAD-protected file encryption (container v2)
 *
 * Signature is NOT embedded in metadata — it goes in the separate signature block.
 */
export function createCVEFMetadataV1_4(options: {
  salt: string;
  iv: string;
  kdfAlgorithm: CVEFKdfAlgorithm;
  kdfParams: CVEFPBKDF2Params | CVEFArgon2Params;
  keyWrapAlgorithm?: CVEFKeyWrapAlgorithm;
  masterKeyVersion?: number;
  pqcParams: CVEFPqcParamsV1_2;
  chunked?: CVEFChunkedInfo;
}): CVEFMetadataV1_4 {
  const metadata: CVEFMetadataV1_4 = {
    version: '1.4',
    salt: options.salt,
    iv: options.iv,
    algorithm: 'AES-256-GCM',
    iterations:
      options.kdfAlgorithm === 'pbkdf2'
        ? (options.kdfParams as CVEFPBKDF2Params).iterations
        : 0,
    kdfAlgorithm: options.kdfAlgorithm,
    kdfParams: options.kdfParams,
    keyWrapAlgorithm: options.keyWrapAlgorithm ?? 'aes-kw',
    pqcAlgorithm: 'ml-kem-768',
    pqcParams: options.pqcParams,
  };

  if (options.masterKeyVersion !== undefined) {
    metadata.masterKeyVersion = options.masterKeyVersion;
  }

  if (options.chunked) {
    metadata.chunked = options.chunked;
  }

  return metadata;
}

// ============ Validation Functions ============

/**
 * Validate CVEF metadata structure
 */
export function validateCVEFMetadata(metadata: unknown): metadata is CVEFMetadata {
  if (typeof metadata !== 'object' || metadata === null) {
    return false;
  }

  const m = metadata as Record<string, unknown>;

  // Required fields
  if (typeof m.salt !== 'string') return false;
  if (typeof m.iv !== 'string') return false;
  if (m.algorithm !== 'AES-256-GCM') return false;
  if (typeof m.iterations !== 'number') return false;

  // Version validation
  if (
    m.version !== undefined &&
    m.version !== '1.0' &&
    m.version !== '1.1' &&
    m.version !== '1.2' &&
    m.version !== '1.3' &&
    m.version !== '1.4'
  ) {
    return false;
  }

  if (m.kdfAlgorithm !== undefined && m.kdfAlgorithm !== 'pbkdf2' && m.kdfAlgorithm !== 'argon2id') {
    return false;
  }

  if (m.keyWrapAlgorithm !== undefined && m.keyWrapAlgorithm !== 'none' && m.keyWrapAlgorithm !== 'aes-kw') {
    return false;
  }

  if (m.pqcAlgorithm !== undefined && m.pqcAlgorithm !== 'none' && m.pqcAlgorithm !== 'ml-kem-768') {
    return false;
  }

  // v1.2 specific validation
  if (m.version === '1.2') {
    if (m.pqcAlgorithm !== 'ml-kem-768') return false;
    if (!m.pqcParams || typeof m.pqcParams !== 'object') return false;

    const pqcParams = m.pqcParams as Record<string, unknown>;
    if (pqcParams.kemAlgorithm !== 'x25519-ml-kem-768' && pqcParams.kemAlgorithm !== 'none') {
      return false;
    }
    if (typeof pqcParams.classicalCiphertext !== 'string') return false;
    if (typeof pqcParams.pqCiphertext !== 'string') return false;
    if (typeof pqcParams.wrappedFileKey !== 'string') return false;
  }

  // v1.3 specific validation (extends v1.2)
  if (m.version === '1.3') {
    // v1.3 must have all v1.2 PQC fields
    if (m.pqcAlgorithm !== 'ml-kem-768') return false;
    if (!m.pqcParams || typeof m.pqcParams !== 'object') return false;

    const pqcParams = m.pqcParams as Record<string, unknown>;
    if (pqcParams.kemAlgorithm !== 'x25519-ml-kem-768' && pqcParams.kemAlgorithm !== 'none') {
      return false;
    }
    if (typeof pqcParams.classicalCiphertext !== 'string') return false;
    if (typeof pqcParams.pqCiphertext !== 'string') return false;
    if (typeof pqcParams.wrappedFileKey !== 'string') return false;

    // Signature params are optional in v1.3
    if (m.signatureParams !== undefined) {
      if (typeof m.signatureParams !== 'object' || m.signatureParams === null) return false;

      const sigParams = m.signatureParams as Record<string, unknown>;
      if (
        sigParams.signatureAlgorithm !== 'none' &&
        sigParams.signatureAlgorithm !== 'ed25519-ml-dsa-65'
      ) {
        return false;
      }
      if (
        sigParams.signingContext !== 'FILE' &&
        sigParams.signingContext !== 'TIMESTAMP' &&
        sigParams.signingContext !== 'SHARE'
      ) {
        return false;
      }
      if (typeof sigParams.signedAt !== 'number') return false;
      if (typeof sigParams.signerFingerprint !== 'string') return false;
      if (typeof sigParams.signerKeyVersion !== 'number') return false;

      // If algorithm is not 'none', signatures must be present
      if (sigParams.signatureAlgorithm === 'ed25519-ml-dsa-65') {
        if (typeof sigParams.classicalSignature !== 'string') return false;
        if (typeof sigParams.pqSignature !== 'string') return false;
      }
    }
  }

  // v1.4 specific validation (same PQC fields as v1.2, no signatureParams)
  if (m.version === '1.4') {
    if (m.pqcAlgorithm !== 'ml-kem-768') return false;
    if (!m.pqcParams || typeof m.pqcParams !== 'object') return false;

    const pqcParams = m.pqcParams as Record<string, unknown>;
    if (pqcParams.kemAlgorithm !== 'x25519-ml-kem-768' && pqcParams.kemAlgorithm !== 'none') {
      return false;
    }
    if (typeof pqcParams.classicalCiphertext !== 'string') return false;
    if (typeof pqcParams.pqCiphertext !== 'string') return false;
    if (typeof pqcParams.wrappedFileKey !== 'string') return false;
  }

  // Chunked validation
  if (m.chunked !== undefined) {
    const c = m.chunked as Record<string, unknown>;
    if (typeof c.count !== 'number') return false;
    if (typeof c.chunkSize !== 'number') return false;
    if (!Array.isArray(c.ivs)) return false;
  }

  return true;
}

/**
 * Get human-readable description of CVEF metadata
 */
export function describeCVEFMetadata(metadata: CVEFMetadata): string {
  const parts: string[] = [];

  const version = 'version' in metadata ? metadata.version : '1.0';
  parts.push(`CVEF v${version ?? '1.0'}`);
  parts.push(`Encryption: ${metadata.algorithm}`);

  const kdfAlgorithm = 'kdfAlgorithm' in metadata ? metadata.kdfAlgorithm : 'pbkdf2';
  parts.push(`KDF: ${kdfAlgorithm ?? 'pbkdf2'}`);

  if (kdfAlgorithm === 'argon2id' && 'kdfParams' in metadata && metadata.kdfParams) {
    const params = metadata.kdfParams as CVEFArgon2Params;
    parts.push(`  Memory: ${Math.round(params.memoryCost / 1024)} MiB`);
    parts.push(`  Iterations: ${params.timeCost}`);
  } else if (kdfAlgorithm === 'pbkdf2' || !kdfAlgorithm) {
    parts.push(`  Iterations: ${metadata.iterations}`);
  }

  const keyWrapAlgorithm = 'keyWrapAlgorithm' in metadata ? metadata.keyWrapAlgorithm : 'none';
  const masterKeyVersion = 'masterKeyVersion' in metadata ? metadata.masterKeyVersion : undefined;
  if (keyWrapAlgorithm === 'aes-kw') {
    parts.push(`Key Wrap: AES-KW (version ${masterKeyVersion})`);
  }

  const pqcAlgorithm = 'pqcAlgorithm' in metadata ? metadata.pqcAlgorithm : 'none';
  if (pqcAlgorithm === 'ml-kem-768') {
    if (isCVEFMetadataV1_2(metadata) || isCVEFMetadataV1_3(metadata) || isCVEFMetadataV1_4(metadata)) {
      parts.push(`PQC: ML-KEM-768 (hybrid X25519 + ML-KEM-768)`);
      parts.push(`  KEM: ${metadata.pqcParams.kemAlgorithm}`);
    } else {
      parts.push(`PQC: ML-KEM-768 (hybrid)`);
    }
  }

  // v1.3 signature info (embedded in metadata)
  if (isCVEFMetadataV1_3(metadata) && metadata.signatureParams) {
    const sig = metadata.signatureParams;
    if (sig.signatureAlgorithm === 'ed25519-ml-dsa-65') {
      parts.push(`Signature: Ed25519 + ML-DSA-65 (hybrid)`);
      parts.push(`  Context: ${sig.signingContext}`);
      parts.push(`  Signed: ${new Date(sig.signedAt).toISOString()}`);
      parts.push(`  Signer: ${sig.signerFingerprint} (v${sig.signerKeyVersion})`);
    } else {
      parts.push(`Signature: none`);
    }
  }

  // v1.4 AAD info
  if (isCVEFMetadataV1_4(metadata)) {
    parts.push(`Container: v2 (AAD-protected header)`);
    parts.push(`Signature: in separate header block (verify via parseCVEFHeader)`);
  }

  if (metadata.chunked) {
    parts.push(`Chunks: ${metadata.chunked.count} x ${metadata.chunked.chunkSize} bytes`);
  }

  return parts.join('\n');
}
