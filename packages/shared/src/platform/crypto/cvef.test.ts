/**
 * Tests for CVEF format (v1.0–v1.3)
 */

import { describe, it, expect } from 'vitest';
import {
  CVEF_MAGIC,
  CVEF_VERSION,
  CVEF_HEADER_SIZE,
  CVEF_CONTAINER_V1,
  CVEF_CONTAINER_V2,
  isCVEFFile,
  parseCVEFHeader,
  normalizeCVEFMetadata,
  createCVEFHeader,
  createCVEFMetadata,
  createCVEFMetadataV1_4,
  validateCVEFMetadata,
  describeCVEFMetadata,
  isCVEFMetadataV1_4,
  hasValidSignatureMetadata,
  validateSignatureMetadata,
  type CVEFMetadataV1_0,
  type CVEFMetadataV1_1,
  type CVEFSignatureMetadata,
} from './cvef';

describe('CVEF Constants', () => {
  it('should have correct magic header', () => {
    expect(CVEF_MAGIC).toEqual(new Uint8Array([0x43, 0x56, 0x45, 0x46]));
    expect(new TextDecoder().decode(CVEF_MAGIC)).toBe('CVEF');
  });

  it('should have version 1', () => {
    expect(CVEF_VERSION).toBe(1);
  });

  it('should have correct header size', () => {
    expect(CVEF_HEADER_SIZE).toBe(9); // magic(4) + version(1) + length(4)
  });
});

describe('isCVEFFile', () => {
  it('should return true for valid CVEF header', () => {
    const data = new Uint8Array([0x43, 0x56, 0x45, 0x46, 0x01, 0, 0, 0, 10]);
    expect(isCVEFFile(data)).toBe(true);
  });

  it('should return false for invalid magic', () => {
    const data = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 10]);
    expect(isCVEFFile(data)).toBe(false);
  });

  it('should return false for too short data', () => {
    const data = new Uint8Array([0x43, 0x56, 0x45]);
    expect(isCVEFFile(data)).toBe(false);
  });

  it('should return false for empty data', () => {
    expect(isCVEFFile(new Uint8Array(0))).toBe(false);
  });
});

describe('createCVEFHeader and parseCVEFHeader', () => {
  it('should round-trip v1.1 metadata', () => {
    const metadata: CVEFMetadataV1_1 = {
      version: '1.1',
      salt: 'dGVzdHNhbHQ=',
      iv: 'dGVzdGl2',
      algorithm: 'AES-256-GCM',
      iterations: 0,
      kdfAlgorithm: 'argon2id',
      kdfParams: {
        memoryCost: 47104,
        timeCost: 1,
        parallelism: 1,
      },
      keyWrapAlgorithm: 'aes-kw',
      masterKeyVersion: 1,
      pqcAlgorithm: 'none',
    };

    const { header } = createCVEFHeader(metadata);
    const parsed = parseCVEFHeader(header);
    const m = parsed.metadata as CVEFMetadataV1_1;

    expect(m.version).toBe('1.1');
    expect(m.salt).toBe(metadata.salt);
    expect(m.iv).toBe(metadata.iv);
    expect(m.kdfAlgorithm).toBe('argon2id');
    expect(m.kdfParams).toEqual(metadata.kdfParams);
    expect(m.keyWrapAlgorithm).toBe('aes-kw');
    expect(m.masterKeyVersion).toBe(1);
    expect(parsed.dataOffset).toBe(header.length);
  });

  it('should round-trip v1.0 compatible metadata', () => {
    const metadata: CVEFMetadataV1_1 = {
      version: '1.0',
      salt: 'dGVzdHNhbHQ=',
      iv: 'dGVzdGl2',
      algorithm: 'AES-256-GCM',
      iterations: 600000,
      kdfAlgorithm: 'pbkdf2',
      kdfParams: { iterations: 600000 },
      keyWrapAlgorithm: 'none',
      pqcAlgorithm: 'none',
    };

    const { header } = createCVEFHeader(metadata);
    const parsed = parseCVEFHeader(header);

    const m = parsed.metadata as CVEFMetadataV1_1;
    expect(m.iterations).toBe(600000);
    expect(m.kdfAlgorithm).toBe('pbkdf2');
    expect(m.keyWrapAlgorithm).toBe('none');
  });

  it('should round-trip chunked metadata', () => {
    const metadata: CVEFMetadataV1_1 = {
      version: '1.1',
      salt: 'dGVzdHNhbHQ=',
      iv: 'dGVzdGl2',
      algorithm: 'AES-256-GCM',
      iterations: 0,
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 47104, timeCost: 1, parallelism: 1 },
      chunked: {
        count: 3,
        chunkSize: 65536,
        ivs: ['aXYx', 'aXYy', 'aXYz'],
      },
    };

    const { header } = createCVEFHeader(metadata);
    const parsed = parseCVEFHeader(header);

    expect(parsed.metadata.chunked).toEqual(metadata.chunked);
  });

  it('should throw on invalid magic', () => {
    const data = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 2, 0x7b, 0x7d]);
    expect(() => parseCVEFHeader(data)).toThrow('missing magic header');
  });

  it('should throw on unsupported container version', () => {
    const data = new Uint8Array([0x43, 0x56, 0x45, 0x46, 0x99, 0, 0, 0, 2, 0x7b, 0x7d]);
    expect(() => parseCVEFHeader(data)).toThrow('Unsupported CVEF container version');
  });

  it('should throw on truncated metadata', () => {
    const data = new Uint8Array([0x43, 0x56, 0x45, 0x46, 0x01, 0, 0, 0, 100]);
    expect(() => parseCVEFHeader(data)).toThrow('metadata incomplete');
  });
});

describe('normalizeCVEFMetadata', () => {
  it('should return v1.1 metadata unchanged', () => {
    const metadata: CVEFMetadataV1_1 = {
      version: '1.1',
      salt: 'test',
      iv: 'test',
      algorithm: 'AES-256-GCM',
      iterations: 0,
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 47104, timeCost: 1, parallelism: 1 },
      keyWrapAlgorithm: 'aes-kw',
      masterKeyVersion: 2,
      pqcAlgorithm: 'none',
    };

    const normalized = normalizeCVEFMetadata(metadata);
    expect(normalized).toEqual(metadata);
  });

  it('should upgrade v1.0 metadata to v1.1 format', () => {
    const legacyMetadata: CVEFMetadataV1_0 = {
      salt: 'legacy-salt',
      iv: 'legacy-iv',
      algorithm: 'AES-256-GCM',
      iterations: 600000,
    };

    const normalized = normalizeCVEFMetadata(legacyMetadata) as CVEFMetadataV1_1;

    expect(normalized.version).toBe('1.0'); // Marked as upgraded
    expect(normalized.kdfAlgorithm).toBe('pbkdf2');
    expect(normalized.kdfParams).toEqual({ iterations: 600000 });
    expect(normalized.keyWrapAlgorithm).toBe('none');
    expect(normalized.pqcAlgorithm).toBe('none');
    expect(normalized.salt).toBe('legacy-salt');
    expect(normalized.iterations).toBe(600000);
  });

  it('should preserve chunked info when upgrading', () => {
    const legacyMetadata: CVEFMetadataV1_0 = {
      salt: 'test',
      iv: 'test',
      algorithm: 'AES-256-GCM',
      iterations: 600000,
      chunked: {
        count: 5,
        chunkSize: 65536,
        ivs: ['a', 'b', 'c', 'd', 'e'],
      },
    };

    const normalized = normalizeCVEFMetadata(legacyMetadata);
    expect(normalized.chunked).toEqual(legacyMetadata.chunked);
  });
});

describe('createCVEFMetadata', () => {
  it('should create v1.1 metadata with PBKDF2', () => {
    const metadata = createCVEFMetadata({
      salt: 'test-salt',
      iv: 'test-iv',
      kdfAlgorithm: 'pbkdf2',
      kdfParams: { iterations: 600000 },
    });

    expect(metadata.version).toBe('1.1');
    expect(metadata.algorithm).toBe('AES-256-GCM');
    expect(metadata.kdfAlgorithm).toBe('pbkdf2');
    expect(metadata.iterations).toBe(600000);
    expect(metadata.keyWrapAlgorithm).toBe('none');
    expect(metadata.pqcAlgorithm).toBe('none');
  });

  it('should create v1.1 metadata with Argon2id', () => {
    const metadata = createCVEFMetadata({
      salt: 'test-salt',
      iv: 'test-iv',
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 47104, timeCost: 1, parallelism: 1 },
    });

    expect(metadata.kdfAlgorithm).toBe('argon2id');
    expect(metadata.kdfParams).toEqual({
      memoryCost: 47104,
      timeCost: 1,
      parallelism: 1,
    });
    expect(metadata.iterations).toBe(0); // Not used for Argon2
  });

  it('should create metadata with key wrapping', () => {
    const metadata = createCVEFMetadata({
      salt: 'test-salt',
      iv: 'test-iv',
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 47104, timeCost: 1, parallelism: 1 },
      keyWrapAlgorithm: 'aes-kw',
      masterKeyVersion: 3,
    });

    expect(metadata.keyWrapAlgorithm).toBe('aes-kw');
    expect(metadata.masterKeyVersion).toBe(3);
  });

  it('should create metadata with chunked info', () => {
    const metadata = createCVEFMetadata({
      salt: 'test-salt',
      iv: 'test-iv',
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 47104, timeCost: 1, parallelism: 1 },
      chunked: {
        count: 10,
        chunkSize: 65536,
        ivs: Array(10).fill('test-iv'),
      },
    });

    expect(metadata.chunked?.count).toBe(10);
    expect(metadata.chunked?.ivs.length).toBe(10);
  });
});

describe('validateCVEFMetadata', () => {
  it('should validate v1.0 metadata', () => {
    const metadata: CVEFMetadataV1_0 = {
      salt: 'test',
      iv: 'test',
      algorithm: 'AES-256-GCM',
      iterations: 600000,
    };
    expect(validateCVEFMetadata(metadata)).toBe(true);
  });

  it('should validate v1.1 metadata', () => {
    const metadata: CVEFMetadataV1_1 = {
      version: '1.1',
      salt: 'test',
      iv: 'test',
      algorithm: 'AES-256-GCM',
      iterations: 0,
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 47104, timeCost: 1, parallelism: 1 },
      keyWrapAlgorithm: 'aes-kw',
      masterKeyVersion: 1,
      pqcAlgorithm: 'none',
    };
    expect(validateCVEFMetadata(metadata)).toBe(true);
  });

  it('should reject null', () => {
    expect(validateCVEFMetadata(null)).toBe(false);
  });

  it('should reject missing salt', () => {
    expect(
      validateCVEFMetadata({
        iv: 'test',
        algorithm: 'AES-256-GCM',
        iterations: 600000,
      })
    ).toBe(false);
  });

  it('should reject invalid algorithm', () => {
    expect(
      validateCVEFMetadata({
        salt: 'test',
        iv: 'test',
        algorithm: 'AES-128-GCM',
        iterations: 600000,
      })
    ).toBe(false);
  });

  it('should reject invalid kdfAlgorithm', () => {
    expect(
      validateCVEFMetadata({
        salt: 'test',
        iv: 'test',
        algorithm: 'AES-256-GCM',
        iterations: 600000,
        kdfAlgorithm: 'bcrypt',
      })
    ).toBe(false);
  });

  it('should reject invalid version', () => {
    expect(
      validateCVEFMetadata({
        salt: 'test',
        iv: 'test',
        algorithm: 'AES-256-GCM',
        iterations: 600000,
        version: '2.0',
      })
    ).toBe(false);
  });
});

describe('describeCVEFMetadata', () => {
  it('should describe v1.0 metadata', () => {
    const description = describeCVEFMetadata({
      salt: 'test',
      iv: 'test',
      algorithm: 'AES-256-GCM',
      iterations: 600000,
    });

    expect(description).toContain('CVEF v1.0');
    expect(description).toContain('AES-256-GCM');
    expect(description).toContain('pbkdf2');
    expect(description).toContain('600000');
  });

  it('should describe v1.1 Argon2id metadata', () => {
    const description = describeCVEFMetadata({
      version: '1.1',
      salt: 'test',
      iv: 'test',
      algorithm: 'AES-256-GCM',
      iterations: 0,
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 47104, timeCost: 1, parallelism: 1 },
      keyWrapAlgorithm: 'aes-kw',
      masterKeyVersion: 2,
    });

    expect(description).toContain('CVEF v1.1');
    expect(description).toContain('argon2id');
    expect(description).toContain('46 MiB'); // 47104 / 1024
    expect(description).toContain('AES-KW');
    expect(description).toContain('version 2');
  });

  it('should describe chunked encryption', () => {
    const description = describeCVEFMetadata({
      version: '1.1',
      salt: 'test',
      iv: 'test',
      algorithm: 'AES-256-GCM',
      iterations: 0,
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 47104, timeCost: 1, parallelism: 1 },
      chunked: { count: 5, chunkSize: 65536, ivs: [] },
    });

    expect(description).toContain('Chunks: 5');
    expect(description).toContain('65536 bytes');
  });
});

// ============ normalizeCVEFMetadata PQC Validation ============

describe('normalizeCVEFMetadata PQC validation', () => {
  it('should throw for v1.2 metadata without pqcAlgorithm ml-kem-768', () => {
    const metadata = {
      version: '1.2',
      salt: 'x', iv: 'x', algorithm: 'AES-256-GCM', iterations: 0,
      pqcAlgorithm: 'none',
      pqcParams: { kemAlgorithm: 'x25519-ml-kem-768', classicalCiphertext: 'x', pqCiphertext: 'x', wrappedFileKey: 'x' },
    };
    expect(() => normalizeCVEFMetadata(metadata as any)).toThrow("requires pqcAlgorithm 'ml-kem-768'");
  });

  it('should throw for v1.4 metadata without pqcParams', () => {
    const metadata = {
      version: '1.4',
      salt: 'x', iv: 'x', algorithm: 'AES-256-GCM', iterations: 0,
      pqcAlgorithm: 'ml-kem-768',
    };
    expect(() => normalizeCVEFMetadata(metadata as any)).toThrow('missing required pqcParams');
  });

  it('should throw for v1.3 metadata without kemAlgorithm in pqcParams', () => {
    const metadata = {
      version: '1.3',
      salt: 'x', iv: 'x', algorithm: 'AES-256-GCM', iterations: 0,
      pqcAlgorithm: 'ml-kem-768',
      pqcParams: { classicalCiphertext: 'x', pqCiphertext: 'x', wrappedFileKey: 'x' },
    };
    expect(() => normalizeCVEFMetadata(metadata as any)).toThrow('missing required pqcParams.kemAlgorithm');
  });
});

// ============ validateSignatureMetadata edge cases ============

describe('validateSignatureMetadata edge cases', () => {
  it('should reject unknown signatureAlgorithm', () => {
    expect(validateSignatureMetadata({
      signatureAlgorithm: 'rsa-4096',
      classicalSignature: 'abc',
      pqSignature: 'def',
      signingContext: 'FILE',
      signedAt: 12345,
      signerFingerprint: 'fp1',
      signerKeyVersion: 1,
    })).toBeUndefined();
  });

  it('should reject unknown signingContext', () => {
    expect(validateSignatureMetadata({
      signatureAlgorithm: 'ed25519-ml-dsa-65',
      classicalSignature: 'abc',
      pqSignature: 'def',
      signingContext: 'UNKNOWN_CONTEXT',
      signedAt: 12345,
      signerFingerprint: 'fp1',
      signerKeyVersion: 1,
    })).toBeUndefined();
  });

  it('should reject array input', () => {
    expect(validateSignatureMetadata([1, 2, 3])).toBeUndefined();
  });

  it('should reject when signerKeyVersion is not a number', () => {
    expect(validateSignatureMetadata({
      signatureAlgorithm: 'ed25519-ml-dsa-65',
      classicalSignature: 'abc',
      pqSignature: 'def',
      signingContext: 'FILE',
      signedAt: 12345,
      signerFingerprint: 'fp1',
      signerKeyVersion: '1', // string, not number
    })).toBeUndefined();
  });

  it('should accept TIMESTAMP context', () => {
    const result = validateSignatureMetadata({
      signatureAlgorithm: 'ed25519-ml-dsa-65',
      classicalSignature: 'abc',
      pqSignature: 'def',
      signingContext: 'TIMESTAMP',
      signedAt: 12345,
      signerFingerprint: 'fp1',
      signerKeyVersion: 1,
    });
    expect(result).toBeDefined();
    expect(result!.signingContext).toBe('TIMESTAMP');
  });

  it('should accept SHARE context', () => {
    const result = validateSignatureMetadata({
      signatureAlgorithm: 'ed25519-ml-dsa-65',
      classicalSignature: 'abc',
      pqSignature: 'def',
      signingContext: 'SHARE',
      signedAt: 12345,
      signerFingerprint: 'fp1',
      signerKeyVersion: 1,
    });
    expect(result).toBeDefined();
    expect(result!.signingContext).toBe('SHARE');
  });
});

// ============ v1.4 Container v2 Tests ============

describe('CVEF v1.4 (container v2)', () => {
  const v14Metadata = createCVEFMetadataV1_4({
    salt: 'dGVzdHNhbHQ=',
    iv: 'dGVzdGl2',
    kdfAlgorithm: 'argon2id',
    kdfParams: { memoryCost: 47104, timeCost: 1, parallelism: 1 },
    keyWrapAlgorithm: 'aes-kw',
    pqcParams: {
      kemAlgorithm: 'x25519-ml-kem-768',
      classicalCiphertext: 'dGVzdGNsYXNzaWNhbA==',
      pqCiphertext: 'dGVzdHBx',
      wrappedFileKey: 'dGVzdHdyYXBwZWQ=',
    },
  });

  const mockSignature: CVEFSignatureMetadata = {
    signatureAlgorithm: 'ed25519-ml-dsa-65',
    classicalSignature: 'Y2xhc3NpY2Fs',
    pqSignature: 'cG9zdHF1YW50dW0=',
    signingContext: 'FILE',
    signedAt: Date.now(),
    signerFingerprint: 'abc123',
    signerKeyVersion: 1,
  };

  it('should create container v2 header with correct magic and version', () => {
    const { header } = createCVEFHeader(v14Metadata);

    expect(header[0]).toBe(0x43); // C
    expect(header[1]).toBe(0x56); // V
    expect(header[2]).toBe(0x45); // E
    expect(header[3]).toBe(0x46); // F
    expect(header[4]).toBe(CVEF_CONTAINER_V2); // container v2
  });

  it('should round-trip v1.4 metadata without signature', () => {
    const { header } = createCVEFHeader(v14Metadata);
    const parsed = parseCVEFHeader(header);

    expect(isCVEFMetadataV1_4(parsed.metadata)).toBe(true);
    expect('version' in parsed.metadata && parsed.metadata.version).toBe('1.4');
    expect(parsed.signatureMetadata).toBeUndefined();
    expect(parsed.coreMetadataBytes).toBeDefined();
    expect(parsed.headerBytes).toBeDefined();
    expect(parsed.headerBytes.length).toBe(header.length);
  });

  it('should round-trip v1.4 metadata with signature', () => {
    const { header } = createCVEFHeader(v14Metadata, mockSignature);
    const parsed = parseCVEFHeader(header);

    expect(isCVEFMetadataV1_4(parsed.metadata)).toBe(true);
    expect(parsed.signatureMetadata).toBeDefined();
    expect(parsed.signatureMetadata!.signatureAlgorithm).toBe('ed25519-ml-dsa-65');
    expect(parsed.signatureMetadata!.classicalSignature).toBe(mockSignature.classicalSignature);
    expect(parsed.signatureMetadata!.pqSignature).toBe(mockSignature.pqSignature);
    expect(parsed.signatureMetadata!.signerFingerprint).toBe('abc123');
  });

  it('should include sigLen=0 when no signature is provided', () => {
    const { header } = createCVEFHeader(v14Metadata);
    const metadataJson = JSON.stringify(v14Metadata);
    const metadataLen = new TextEncoder().encode(metadataJson).length;
    const sigLenOffset = CVEF_HEADER_SIZE + metadataLen;

    // sigLen should be 0 (4 bytes big-endian)
    expect(header[sigLenOffset]).toBe(0);
    expect(header[sigLenOffset + 1]).toBe(0);
    expect(header[sigLenOffset + 2]).toBe(0);
    expect(header[sigLenOffset + 3]).toBe(0);
  });

  it('should have dataOffset after signature block', () => {
    const { header: headerNoSig } = createCVEFHeader(v14Metadata);
    const { header: headerWithSig } = createCVEFHeader(v14Metadata, mockSignature);

    const parsedNoSig = parseCVEFHeader(headerNoSig);
    const parsedWithSig = parseCVEFHeader(headerWithSig);

    // With signature should be larger
    expect(parsedWithSig.dataOffset).toBeGreaterThan(parsedNoSig.dataOffset);
    // Both should equal header length
    expect(parsedNoSig.dataOffset).toBe(headerNoSig.length);
    expect(parsedWithSig.dataOffset).toBe(headerWithSig.length);
  });

  it('should have headerBytes equal to full header', () => {
    const { header, headerBytes } = createCVEFHeader(v14Metadata, mockSignature);
    expect(Array.from(headerBytes)).toEqual(Array.from(header));
  });

  it('should validate v1.4 metadata', () => {
    expect(validateCVEFMetadata(v14Metadata)).toBe(true);
  });

  it('should describe v1.4 metadata', () => {
    const description = describeCVEFMetadata(v14Metadata);
    expect(description).toContain('CVEF v1.4');
    expect(description).toContain('Container: v2');
  });

  it('hasValidSignatureMetadata validates correctly', () => {
    expect(hasValidSignatureMetadata(mockSignature)).toBe(true);
    expect(hasValidSignatureMetadata(undefined)).toBe(false);
    expect(hasValidSignatureMetadata({
      ...mockSignature,
      classicalSignature: '',
    })).toBe(false);
  });

  it('validateSignatureMetadata returns typed object for valid input', () => {
    const result = validateSignatureMetadata({
      signatureAlgorithm: 'ed25519-ml-dsa-65',
      classicalSignature: 'abc',
      pqSignature: 'def',
      signingContext: 'FILE',
      signedAt: 12345,
      signerFingerprint: 'fp1',
      signerKeyVersion: 1,
    });
    expect(result).toBeDefined();
    expect(result!.signerFingerprint).toBe('fp1');
  });

  it('validateSignatureMetadata returns undefined for missing fields', () => {
    expect(validateSignatureMetadata({})).toBeUndefined();
    expect(validateSignatureMetadata(null)).toBeUndefined();
    expect(validateSignatureMetadata('not an object')).toBeUndefined();
    expect(validateSignatureMetadata({ signatureAlgorithm: 'ed25519-ml-dsa-65' })).toBeUndefined();
    expect(validateSignatureMetadata({
      signatureAlgorithm: 'ed25519-ml-dsa-65',
      classicalSignature: 'abc',
      pqSignature: 'def',
      signingContext: 'FILE',
      signedAt: 'not a number', // wrong type
      signerFingerprint: 'fp1',
      signerKeyVersion: 1,
    })).toBeUndefined();
  });

  it('isCVEFMetadataV1_4 rejects metadata without PQC params', () => {
    expect(isCVEFMetadataV1_4({ version: '1.4' } as any)).toBe(false);
    expect(isCVEFMetadataV1_4({
      version: '1.4',
      pqcAlgorithm: 'ml-kem-768',
      pqcParams: { kemAlgorithm: 'x25519-ml-kem-768' },
    } as any)).toBe(true);
  });

  it('should throw on truncated v2 signature metadata', () => {
    // Build a v2 header but truncate in the signature block
    const { header } = createCVEFHeader(v14Metadata, mockSignature);
    const truncated = header.slice(0, header.length - 10);
    expect(() => parseCVEFHeader(truncated)).toThrow('signature metadata incomplete');
  });

  it('should throw on truncated v2 missing sigLen field', () => {
    const { header } = createCVEFHeader(v14Metadata);
    // Truncate to just before the sigLen field
    const metadataJson = JSON.stringify(v14Metadata);
    const metadataLen = new TextEncoder().encode(metadataJson).length;
    const truncated = header.slice(0, CVEF_HEADER_SIZE + metadataLen + 2); // only 2 of 4 sigLen bytes
    expect(() => parseCVEFHeader(truncated)).toThrow('missing signature length field');
  });

  it('should reject v1.4 metadata smuggled inside container v1', () => {
    // Manually craft a container v1 header with v1.4 metadata JSON
    const v14Json = JSON.stringify(v14Metadata);
    const metadataBytes = new TextEncoder().encode(v14Json);
    const header = new Uint8Array(CVEF_HEADER_SIZE + metadataBytes.length);
    header.set([0x43, 0x56, 0x45, 0x46], 0); // magic
    header[4] = CVEF_CONTAINER_V1; // container v1!
    header[5] = (metadataBytes.length >> 24) & 0xff;
    header[6] = (metadataBytes.length >> 16) & 0xff;
    header[7] = (metadataBytes.length >> 8) & 0xff;
    header[8] = metadataBytes.length & 0xff;
    header.set(metadataBytes, CVEF_HEADER_SIZE);

    expect(() => parseCVEFHeader(header)).toThrow('v1.4 metadata requires container v2');
  });

  it('should reject invalid signature JSON in container v2', () => {
    // Build v2 header with valid core metadata but garbage signature block
    const coreJson = JSON.stringify(v14Metadata);
    const coreBytes = new TextEncoder().encode(coreJson);
    const garbageSig = new TextEncoder().encode('{invalid json!!!');

    const totalSize = CVEF_HEADER_SIZE + coreBytes.length + 4 + garbageSig.length;
    const header = new Uint8Array(totalSize);
    header.set([0x43, 0x56, 0x45, 0x46], 0);
    header[4] = CVEF_CONTAINER_V2;
    header[5] = (coreBytes.length >> 24) & 0xff;
    header[6] = (coreBytes.length >> 16) & 0xff;
    header[7] = (coreBytes.length >> 8) & 0xff;
    header[8] = coreBytes.length & 0xff;
    header.set(coreBytes, CVEF_HEADER_SIZE);
    const sigLenOffset = CVEF_HEADER_SIZE + coreBytes.length;
    header[sigLenOffset] = (garbageSig.length >> 24) & 0xff;
    header[sigLenOffset + 1] = (garbageSig.length >> 16) & 0xff;
    header[sigLenOffset + 2] = (garbageSig.length >> 8) & 0xff;
    header[sigLenOffset + 3] = garbageSig.length & 0xff;
    header.set(garbageSig, sigLenOffset + 4);

    expect(() => parseCVEFHeader(header)).toThrow('not valid JSON');
  });

  it('should reject structurally invalid signature metadata in container v2', () => {
    // Build v2 header with valid JSON but missing required signature fields
    const coreJson = JSON.stringify(v14Metadata);
    const coreBytes = new TextEncoder().encode(coreJson);
    const incompleteSig = new TextEncoder().encode(JSON.stringify({ signatureAlgorithm: 'ed25519-ml-dsa-65' }));

    const totalSize = CVEF_HEADER_SIZE + coreBytes.length + 4 + incompleteSig.length;
    const header = new Uint8Array(totalSize);
    header.set([0x43, 0x56, 0x45, 0x46], 0);
    header[4] = CVEF_CONTAINER_V2;
    header[5] = (coreBytes.length >> 24) & 0xff;
    header[6] = (coreBytes.length >> 16) & 0xff;
    header[7] = (coreBytes.length >> 8) & 0xff;
    header[8] = coreBytes.length & 0xff;
    header.set(coreBytes, CVEF_HEADER_SIZE);
    const sigLenOffset = CVEF_HEADER_SIZE + coreBytes.length;
    header[sigLenOffset] = (incompleteSig.length >> 24) & 0xff;
    header[sigLenOffset + 1] = (incompleteSig.length >> 16) & 0xff;
    header[sigLenOffset + 2] = (incompleteSig.length >> 8) & 0xff;
    header[sigLenOffset + 3] = incompleteSig.length & 0xff;
    header.set(incompleteSig, sigLenOffset + 4);

    expect(() => parseCVEFHeader(header)).toThrow('missing required fields');
  });

  it('v1.4 with chunked info round-trips', () => {
    const chunkedMetadata = createCVEFMetadataV1_4({
      salt: 'dGVzdHNhbHQ=',
      iv: 'dGVzdGl2',
      kdfAlgorithm: 'argon2id',
      kdfParams: { memoryCost: 47104, timeCost: 1, parallelism: 1 },
      pqcParams: {
        kemAlgorithm: 'x25519-ml-kem-768',
        classicalCiphertext: 'dGVzdGNsYXNzaWNhbA==',
        pqCiphertext: 'dGVzdHBx',
        wrappedFileKey: 'dGVzdHdyYXBwZWQ=',
      },
      chunked: { count: 4, chunkSize: 65536, ivs: [] },
    });

    const { header } = createCVEFHeader(chunkedMetadata);
    const parsed = parseCVEFHeader(header);

    expect(isCVEFMetadataV1_4(parsed.metadata)).toBe(true);
    expect(parsed.metadata.chunked).toBeDefined();
    expect(parsed.metadata.chunked!.count).toBe(4);
  });
});

