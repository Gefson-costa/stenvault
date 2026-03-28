/**
 * Streaming Decrypt Tests
 *
 * Tests the streaming decryption module that processes V4 (CVEF) chunked files
 * without accumulating the entire file in memory.
 *
 * Uses real WebCrypto (Node 20 has crypto.subtle) — no mocks.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  BufferedStreamReader,
  parseCVEFHeaderFromStream,
  decryptV4ChunkedToStream,
} from '../streamingDecrypt';
import {
  encryptFileHybrid,
  encryptFileHybridStreaming,
  deriveManifestHmacKey,
} from '../hybridFileCrypto';
import {
  getHybridKemProvider,
  getKeyWrapProvider,
  base64ToArrayBuffer,
} from '@/lib/platform';
import {
  parseCVEFHeader,
  isCVEFMetadataV1_2,
  isCVEFMetadataV1_4,
} from '@stenvault/shared/platform/crypto';
import type { HybridPublicKey, HybridSecretKey } from '@stenvault/shared/platform/crypto';

// ============ Helpers ============

let testPublicKey: HybridPublicKey;
let testSecretKey: HybridSecretKey;

/** Fill a Uint8Array with random data, respecting the 65536-byte getRandomValues limit */
function fillRandom(arr: Uint8Array): void {
  const LIMIT = 65536;
  for (let offset = 0; offset < arr.byteLength; offset += LIMIT) {
    const end = Math.min(offset + LIMIT, arr.byteLength);
    crypto.getRandomValues(arr.subarray(offset, end));
  }
}

beforeAll(async () => {
  const hybridKem = getHybridKemProvider();
  const keyPair = await hybridKem.generateKeyPair();
  testPublicKey = keyPair.publicKey;
  testSecretKey = keyPair.secretKey;
});

/** Create a File from bytes (clean ArrayBuffer for TypeScript strict mode) */
function createTestFile(data: Uint8Array, name = 'test.bin'): File {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return new File([buf], name, { type: 'application/octet-stream' });
}

/** Collect a ReadableStream into a Uint8Array */
async function collectStream(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
  }

  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

/** Convert a Blob to a ReadableStream */
function blobToStream(blob: Blob): ReadableStream<Uint8Array> {
  // blob.stream() returns ReadableStream in Node 20
  return blob.stream() as unknown as ReadableStream<Uint8Array>;
}

/** Extract file key and optional hmac key from CVEF metadata for decryption */
async function extractFileKey(blob: Blob): Promise<{ fileKey: CryptoKey; hmacKey?: CryptoKey }> {
  const data = new Uint8Array(await blob.arrayBuffer());
  const { metadata } = parseCVEFHeader(data);

  if (!isCVEFMetadataV1_2(metadata) && !isCVEFMetadataV1_4(metadata)) {
    throw new Error('Not a V4 hybrid file');
  }

  const hybridKem = getHybridKemProvider();
  const keyWrap = getKeyWrapProvider();

  const hybridCiphertext = {
    classical: new Uint8Array(base64ToArrayBuffer(metadata.pqcParams.classicalCiphertext)),
    postQuantum: new Uint8Array(base64ToArrayBuffer(metadata.pqcParams.pqCiphertext)),
  };

  const sharedSecret = await hybridKem.decapsulate(hybridCiphertext, testSecretKey);
  const wrappedFileKey = new Uint8Array(base64ToArrayBuffer(metadata.pqcParams.wrappedFileKey));
  const { masterKey: fileKeyBytes } = await keyWrap.unwrap(wrappedFileKey, sharedSecret, 1);

  const hmacKey = metadata.chunked ? await deriveManifestHmacKey(fileKeyBytes) : undefined;

  const fileKey = await crypto.subtle.importKey(
    'raw',
    fileKeyBytes.buffer.slice(fileKeyBytes.byteOffset, fileKeyBytes.byteOffset + fileKeyBytes.byteLength) as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );

  return { fileKey, hmacKey };
}

// ============ BufferedStreamReader Tests ============

describe('BufferedStreamReader', () => {
  it('readExact handles cross-boundary reads', async () => {
    // Create a stream that yields chunks of different sizes
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(data.slice(0, 3));  // [1, 2, 3]
        controller.enqueue(data.slice(3, 7));  // [4, 5, 6, 7]
        controller.enqueue(data.slice(7, 10)); // [8, 9, 10]
        controller.close();
      },
    });

    const reader = new BufferedStreamReader(stream.getReader());

    // Read 5 bytes across the first two chunks
    const first = await reader.readExact(5);
    expect(Array.from(first)).toEqual([1, 2, 3, 4, 5]);

    // Read 3 bytes across the second and third chunks
    const second = await reader.readExact(3);
    expect(Array.from(second)).toEqual([6, 7, 8]);

    // Read remaining 2 bytes
    const third = await reader.readExact(2);
    expect(Array.from(third)).toEqual([9, 10]);
  });

  it('readExact with initial buffer', async () => {
    const initial = new Uint8Array([1, 2, 3]);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([4, 5]));
        controller.close();
      },
    });

    const reader = new BufferedStreamReader(stream.getReader(), initial);
    const result = await reader.readExact(5);
    expect(Array.from(result)).toEqual([1, 2, 3, 4, 5]);
  });

  it('readExact throws on truncated stream', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2]));
        controller.close();
      },
    });

    const reader = new BufferedStreamReader(stream.getReader());
    await expect(reader.readExact(5)).rejects.toThrow('Unexpected end of stream');
  });
});

// ============ parseCVEFHeaderFromStream Tests ============

describe('parseCVEFHeaderFromStream', () => {
  it('correctly parses header from a stream', async () => {
    // Create a V4 chunked encrypted file
    const plaintext = new Uint8Array(200 * 1024); // 200KB → multiple chunks
    fillRandom(plaintext);
    const file = createTestFile(plaintext);

    const { blob } = await encryptFileHybridStreaming(file, { publicKey: testPublicKey });

    // Parse header from stream
    const stream = blobToStream(blob);
    const { metadata, reader } = await parseCVEFHeaderFromStream(stream);

    expect(isCVEFMetadataV1_4(metadata)).toBe(true);
    expect(metadata.chunked).toBeDefined();
    expect(metadata.chunked!.count).toBeGreaterThan(1);
  });
});

// ============ decryptV4ChunkedToStream Tests ============

describe('decryptV4ChunkedToStream', () => {
  it('roundtrip: encrypt streaming → decrypt streaming → matches original', async () => {
    // Create test data larger than one chunk (64KB)
    const plaintext = new Uint8Array(150 * 1024); // 150KB → ~3 chunks at 64KB
    fillRandom(plaintext);
    const file = createTestFile(plaintext);

    // Encrypt with streaming
    const { blob } = await encryptFileHybridStreaming(file, { publicKey: testPublicKey });

    // Extract file key + hmac key for decryption
    const { fileKey, hmacKey } = await extractFileKey(blob);

    // Decrypt as stream
    const encryptedStream = blobToStream(blob);
    const plaintextStream = decryptV4ChunkedToStream(encryptedStream, { fileKey, hmacKey });

    // Collect decrypted output
    const decrypted = await collectStream(plaintextStream);

    // Verify roundtrip
    expect(decrypted.byteLength).toBe(plaintext.byteLength);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });

  it('progress callback fires for each chunk', async () => {
    const plaintext = new Uint8Array(200 * 1024); // ~4 chunks
    fillRandom(plaintext);
    const file = createTestFile(plaintext);

    const { blob } = await encryptFileHybridStreaming(file, { publicKey: testPublicKey });
    const { fileKey, hmacKey } = await extractFileKey(blob);

    const progressCalls: Array<{ chunkIndex: number; chunkCount: number }> = [];

    const encryptedStream = blobToStream(blob);
    const plaintextStream = decryptV4ChunkedToStream(encryptedStream, {
      fileKey,
      hmacKey,
      onProgress: (p) => progressCalls.push({ chunkIndex: p.chunkIndex, chunkCount: p.chunkCount }),
    });

    await collectStream(plaintextStream);

    // Should have one progress call per chunk
    expect(progressCalls.length).toBeGreaterThan(1);
    // First call should be chunk 0
    expect(progressCalls[0]!.chunkIndex).toBe(0);
    // Last call should be the final chunk
    const last = progressCalls[progressCalls.length - 1]!;
    expect(last.chunkIndex).toBe(last.chunkCount - 1);
  });

  it('errors on truncated stream', async () => {
    const plaintext = new Uint8Array(150 * 1024);
    fillRandom(plaintext);
    const file = createTestFile(plaintext);

    const { blob } = await encryptFileHybridStreaming(file, { publicKey: testPublicKey });
    const { fileKey, hmacKey } = await extractFileKey(blob);

    // Create a truncated stream (only first half)
    const fullData = new Uint8Array(await blob.arrayBuffer());
    const truncated = fullData.slice(0, Math.floor(fullData.byteLength / 2));
    const truncatedStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(truncated);
        controller.close();
      },
    });

    const plaintextStream = decryptV4ChunkedToStream(truncatedStream, { fileKey, hmacKey });
    const reader = plaintextStream.getReader();

    // Read until error
    let gotError = false;
    try {
      while (true) {
        const { done } = await reader.read();
        if (done) break;
      }
    } catch {
      gotError = true;
    }

    expect(gotError).toBe(true);
  });

  it('non-chunked V4 fallback: encrypt small → stream-decrypt → matches original', async () => {
    // Small file (< 50MB threshold) → encryptFileHybrid produces non-chunked V4
    const plaintext = new Uint8Array(1024); // 1KB
    fillRandom(plaintext);
    const file = createTestFile(plaintext);

    const { blob } = await encryptFileHybrid(file, { publicKey: testPublicKey });
    const { fileKey } = await extractFileKey(blob);

    // Stream-decrypt the non-chunked V4 file (exercises the fallback path)
    const encryptedStream = blobToStream(blob);
    const plaintextStream = decryptV4ChunkedToStream(encryptedStream, { fileKey });
    const decrypted = await collectStream(plaintextStream);

    expect(decrypted.byteLength).toBe(plaintext.byteLength);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });
});

// ============ Streaming Decrypt with Signed v1.4 (container v2) ============

describe('decryptV4ChunkedToStream with signed v1.4 header', () => {
  it('roundtrip: signed streaming encrypt → streaming decrypt → matches original', async () => {
    const { getHybridSignatureProvider } = await import('@/lib/platform/webHybridSignatureProvider');
    const signatureProvider = getHybridSignatureProvider();
    const sigKeyPair = await signatureProvider.generateKeyPair();

    const plaintext = new Uint8Array(150 * 1024); // 150KB → ~3 chunks
    fillRandom(plaintext);
    const file = createTestFile(plaintext);

    const { blob, signatureMetadata } = await encryptFileHybridStreaming(file, {
      publicKey: testPublicKey,
      signing: {
        secretKey: sigKeyPair.secretKey,
        fingerprint: 'stream-sig-fp',
        keyVersion: 1,
      },
    });

    // Verify signature metadata was produced
    expect(signatureMetadata).toBeDefined();
    expect(signatureMetadata!.signerFingerprint).toBe('stream-sig-fp');

    // Verify container v2 header
    const data = new Uint8Array(await blob.arrayBuffer());
    expect(data[4]).toBe(2); // container v2

    const parsed = parseCVEFHeader(data);
    expect(isCVEFMetadataV1_4(parsed.metadata)).toBe(true);
    expect(parsed.signatureMetadata).toBeDefined();

    // Extract key and stream-decrypt
    const { fileKey, hmacKey } = await extractFileKey(blob);
    const encryptedStream = blobToStream(blob);
    const plaintextStream = decryptV4ChunkedToStream(encryptedStream, { fileKey, hmacKey });
    const decrypted = await collectStream(plaintextStream);

    expect(decrypted.byteLength).toBe(plaintext.byteLength);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });

  it('non-chunked signed v1.4: stream-decrypt roundtrip', async () => {
    const { getHybridSignatureProvider } = await import('@/lib/platform/webHybridSignatureProvider');
    const signatureProvider = getHybridSignatureProvider();
    const sigKeyPair = await signatureProvider.generateKeyPair();

    const plaintext = new Uint8Array(1024); // 1KB → non-chunked
    fillRandom(plaintext);
    const file = createTestFile(plaintext);

    const { blob, signatureMetadata } = await encryptFileHybrid(file, {
      publicKey: testPublicKey,
      signing: {
        secretKey: sigKeyPair.secretKey,
        fingerprint: 'small-sig-fp',
        keyVersion: 2,
      },
    });

    expect(signatureMetadata).toBeDefined();

    const { fileKey } = await extractFileKey(blob);
    const encryptedStream = blobToStream(blob);
    const plaintextStream = decryptV4ChunkedToStream(encryptedStream, { fileKey });
    const decrypted = await collectStream(plaintextStream);

    expect(decrypted.byteLength).toBe(plaintext.byteLength);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });
});

// ============ Streaming Encrypt Blob Output Tests ============

describe('encryptFileHybridStreaming (streaming Blob output)', () => {
  it('roundtrip for multi-chunk file verifies CVEF format correctness', async () => {
    // 200KB → multiple chunks at 64KB
    const plaintext = new Uint8Array(200 * 1024);
    fillRandom(plaintext);
    const file = createTestFile(plaintext);

    const { blob, metadata } = await encryptFileHybridStreaming(file, { publicKey: testPublicKey });

    // Verify metadata — v1.4 with trailing manifest
    expect(isCVEFMetadataV1_4(metadata)).toBe(true);
    expect(metadata.chunked).toBeDefined();
    expect(metadata.chunked!.count).toBe(Math.ceil(file.size / (64 * 1024)));

    // Verify blob is valid by parsing the CVEF header
    const data = new Uint8Array(await blob.arrayBuffer());
    const parsed = parseCVEFHeader(data);
    expect(isCVEFMetadataV1_4(parsed.metadata)).toBe(true);

    // Full roundtrip: stream decrypt
    const { fileKey, hmacKey } = await extractFileKey(blob);
    const encryptedStream = blobToStream(blob);
    const plaintextStream = decryptV4ChunkedToStream(encryptedStream, { fileKey, hmacKey });
    const decrypted = await collectStream(plaintextStream);

    expect(decrypted.byteLength).toBe(plaintext.byteLength);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });

  it('progress callback fires for each chunk during streaming encrypt', async () => {
    const plaintext = new Uint8Array(200 * 1024); // ~4 chunks
    fillRandom(plaintext);
    const file = createTestFile(plaintext);

    const progressCalls: Array<{ bytesProcessed: number; percentage: number }> = [];

    await encryptFileHybridStreaming(file, {
      publicKey: testPublicKey,
      onProgress: (p) => progressCalls.push({
        bytesProcessed: p.bytesProcessed,
        percentage: p.percentage,
      }),
    });

    const expectedChunks = Math.ceil(file.size / (64 * 1024));
    expect(progressCalls.length).toBe(expectedChunks);
    // Last call should be 100%
    expect(progressCalls[progressCalls.length - 1]!.percentage).toBe(100);
    // Last call should have bytesProcessed === file.size
    expect(progressCalls[progressCalls.length - 1]!.bytesProcessed).toBe(file.size);
  });
});
