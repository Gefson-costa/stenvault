/**
 * Crypto Roundtrip Tests
 *
 * Tests that encrypt → decrypt with real WebCrypto (Node 20 has crypto.subtle)
 * and verify data integrity. No mocks — real crypto operations.
 *
 * These tests would have caught:
 * - V3 key derivation mismatches (tempId vs dbId)
 * - Share password roundtrip failures
 * - Link share fragment key encoding issues
 *
 * @module __tests__/cryptoRoundtrip
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
    createPasswordShare,
    decryptPasswordShare,
    createLinkShare,
    decryptLinkShare,
    isLinkShare,
} from '../shareCrypto';
import {
    encryptFilename,
    decryptFilename,
} from '../fileCrypto';
import {
    getHybridKemProvider,
    getKeyWrapProvider,
    arrayBufferToBase64,
    base64ToArrayBuffer,
} from '@/lib/platform';
import {
    encryptFileHybrid,
    decryptFileHybrid,
    encryptFileHybridStreaming,
    isHybridEncrypted,
    getEncryptionMetadata,
    deriveChunkIV,
    deriveManifestHmacKey,
} from '../hybridFileCrypto';
import {
    isCVEFMetadataV1_2,
    isCVEFMetadataV1_4,
    parseCVEFHeader,
} from '@stenvault/shared/platform/crypto';
import { getHybridSignatureProvider } from '@/lib/platform/webHybridSignatureProvider';
import { verifySignedFile, fileHasSignature, getSignatureInfo } from '../signedFileCrypto';

// ============================================================
// Helpers
// ============================================================

/** Generate random bytes — handles >65536 limit of getRandomValues */
function randomBytes(n: number): Uint8Array {
    const result = new Uint8Array(n);
    // crypto.getRandomValues has a 65536-byte limit per call
    for (let offset = 0; offset < n; offset += 65536) {
        const chunk = Math.min(65536, n - offset);
        crypto.getRandomValues(result.subarray(offset, offset + chunk));
    }
    return result;
}

/** Import raw bytes as AES-GCM CryptoKey */
async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        'raw',
        raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
}

/** Create a File-like object usable in Node (has arrayBuffer()) */
function createMockFile(content: Uint8Array, name: string, type = 'application/octet-stream'): File {
    const buf = new ArrayBuffer(content.byteLength);
    new Uint8Array(buf).set(content);
    const blob = new Blob([buf], { type });
    // In Node 20+, Blob has .arrayBuffer() and can be cast
    return Object.assign(blob, { name, lastModified: Date.now() }) as unknown as File;
}

// ============================================================
// 1. Share Crypto Roundtrips
// ============================================================

describe('Share Crypto Roundtrips', () => {
    const fileKeyBytes = randomBytes(32);
    const testFilename = 'secret-document.pdf';

    describe('Password share', () => {
        it('encrypts and decrypts with the same password', async () => {
            const password = 'Str0ngP@ssword!';

            const encrypted = await createPasswordShare(fileKeyBytes, testFilename, password);

            // Verify output shape
            expect(encrypted.encryptedShareKey).toBeTruthy();
            expect(encrypted.shareKeyIv).toBeTruthy();
            expect(encrypted.shareKeySalt).toBeTruthy();
            expect(isLinkShare(encrypted.shareKeySalt)).toBe(false);

            // Decrypt
            const decrypted = await decryptPasswordShare(
                { key: encrypted.encryptedShareKey, iv: encrypted.shareKeyIv, salt: encrypted.shareKeySalt },
                password,
            );

            // Verify bytes match
            expect(decrypted.filename).toBe(testFilename);
            expect(decrypted.fileKeyBytes).toEqual(fileKeyBytes);
        });

        it('fails with wrong password', async () => {
            const password = 'CorrectPassword123!';
            const encrypted = await createPasswordShare(fileKeyBytes, testFilename, password);

            await expect(
                decryptPasswordShare(
                    { key: encrypted.encryptedShareKey, iv: encrypted.shareKeyIv, salt: encrypted.shareKeySalt },
                    'WrongPassword456!',
                ),
            ).rejects.toThrow();
        });

        it('produces different ciphertext for same input (random IV + salt)', async () => {
            const password = 'SamePassword!';
            const enc1 = await createPasswordShare(fileKeyBytes, testFilename, password);
            const enc2 = await createPasswordShare(fileKeyBytes, testFilename, password);

            // Salt and IV should differ → ciphertext should differ
            expect(enc1.shareKeySalt).not.toBe(enc2.shareKeySalt);
            expect(enc1.shareKeyIv).not.toBe(enc2.shareKeyIv);
            expect(enc1.encryptedShareKey).not.toBe(enc2.encryptedShareKey);
        });
    });

    describe('Link share', () => {
        it('encrypts and decrypts with fragment key', async () => {
            const { encrypted, fragmentKey } = await createLinkShare(fileKeyBytes, testFilename);

            // Verify link share sentinel
            expect(isLinkShare(encrypted.shareKeySalt)).toBe(true);
            expect(encrypted.shareKeySalt).toBe('url-fragment');

            // Fragment key should be URL-safe base64
            expect(fragmentKey).toBeTruthy();
            expect(fragmentKey).not.toContain('+');
            expect(fragmentKey).not.toContain('/');
            expect(fragmentKey).not.toContain('=');

            // Decrypt
            const decrypted = await decryptLinkShare(
                { key: encrypted.encryptedShareKey, iv: encrypted.shareKeyIv, salt: encrypted.shareKeySalt },
                fragmentKey,
            );

            expect(decrypted.filename).toBe(testFilename);
            expect(decrypted.fileKeyBytes).toEqual(fileKeyBytes);
        });

        it('fails with wrong fragment key', async () => {
            const { encrypted } = await createLinkShare(fileKeyBytes, testFilename);

            // Create a different fragment key
            const wrongKey = 'dGhpc2lzYXdyb25na2V5aW5iYXNlNjR1cmw'; // different key

            await expect(
                decryptLinkShare(
                    { key: encrypted.encryptedShareKey, iv: encrypted.shareKeyIv, salt: encrypted.shareKeySalt },
                    wrongKey,
                ),
            ).rejects.toThrow();
        });

        it('produces different ciphertext each time (random key)', async () => {
            const result1 = await createLinkShare(fileKeyBytes, testFilename);
            const result2 = await createLinkShare(fileKeyBytes, testFilename);

            expect(result1.fragmentKey).not.toBe(result2.fragmentKey);
            expect(result1.encrypted.encryptedShareKey).not.toBe(result2.encrypted.encryptedShareKey);
        });
    });

    describe('isLinkShare', () => {
        it('returns true for url-fragment sentinel', () => {
            expect(isLinkShare('url-fragment')).toBe(true);
        });

        it('returns false for regular base64 salt', () => {
            expect(isLinkShare('c29tZXJhbmRvbXNhbHQ=')).toBe(false);
        });

        it('returns false for empty string', () => {
            expect(isLinkShare('')).toBe(false);
        });
    });

    describe('Unicode filenames', () => {
        it('roundtrips filenames with emoji and CJK characters', async () => {
            const unicodeName = '📎 契約書.pdf';
            const password = 'TestPassword!';

            const encrypted = await createPasswordShare(fileKeyBytes, unicodeName, password);
            const decrypted = await decryptPasswordShare(
                { key: encrypted.encryptedShareKey, iv: encrypted.shareKeyIv, salt: encrypted.shareKeySalt },
                password,
            );

            expect(decrypted.filename).toBe(unicodeName);
        });
    });
});

// ============================================================
// 2. Filename Encryption Roundtrips
// ============================================================

describe('Filename Encryption Roundtrips', () => {
    let filenameKey: CryptoKey;

    beforeAll(async () => {
        filenameKey = await importAesKey(randomBytes(32));
    });

    it('encrypts and decrypts a simple filename', async () => {
        const filename = 'document.pdf';

        const { encryptedFilename: enc, iv } = await encryptFilename(filename, filenameKey);
        expect(enc).toBeTruthy();
        expect(iv).toBeTruthy();

        const decrypted = await decryptFilename(enc, filenameKey, iv);
        expect(decrypted).toBe(filename);
    });

    it('encrypts and decrypts a Unicode filename', async () => {
        const filename = '日本語のファイル名.xlsx';

        const { encryptedFilename: enc, iv } = await encryptFilename(filename, filenameKey);
        const decrypted = await decryptFilename(enc, filenameKey, iv);

        expect(decrypted).toBe(filename);
    });

    it('encrypts and decrypts a filename with special chars', async () => {
        const filename = 'my file (copy 2) [final] {v3}.tar.gz';

        const { encryptedFilename: enc, iv } = await encryptFilename(filename, filenameKey);
        const decrypted = await decryptFilename(enc, filenameKey, iv);

        expect(decrypted).toBe(filename);
    });

    it('encrypts and decrypts a very long filename', async () => {
        const filename = 'a'.repeat(255) + '.txt';

        const { encryptedFilename: enc, iv } = await encryptFilename(filename, filenameKey);
        const decrypted = await decryptFilename(enc, filenameKey, iv);

        expect(decrypted).toBe(filename);
    });

    it('fails with wrong key', async () => {
        const filename = 'secret.pdf';
        const { encryptedFilename: enc, iv } = await encryptFilename(filename, filenameKey);

        const wrongKey = await importAesKey(randomBytes(32));

        await expect(
            decryptFilename(enc, wrongKey, iv),
        ).rejects.toThrow();
    });

    it('throws for empty filename', async () => {
        await expect(
            encryptFilename('', filenameKey),
        ).rejects.toThrow('Filename is required');
    });

    it('throws for missing IV on decrypt', async () => {
        await expect(
            decryptFilename('somedata', filenameKey, ''),
        ).rejects.toThrow();
    });
});

// ============================================================
// 3. WebCrypto API Sanity
// ============================================================

describe('WebCrypto API Sanity', () => {
    it('getRandomValues returns correct length', () => {
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        expect(bytes).toBeInstanceOf(Uint8Array);
        expect(bytes.length).toBe(32);
    });

    it('getRandomValues returns different values each time', () => {
        const a = crypto.getRandomValues(new Uint8Array(32));
        const b = crypto.getRandomValues(new Uint8Array(32));
        // Technically could be equal, but probability is 1/2^256
        expect(a).not.toEqual(b);
    });

    it('AES-GCM encrypt + decrypt roundtrip', async () => {
        const plaintext = new TextEncoder().encode('Test data for AES roundtrip');
        const key = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            plaintext.buffer as ArrayBuffer,
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext,
        );
        expect(new Uint8Array(decrypted)).toEqual(plaintext);
    });
});

// ============================================================
// 4. V4 Hybrid Encryption Roundtrips (X25519 + ML-KEM-768)
// ============================================================

describe('V4 Hybrid Encryption Roundtrips', () => {
    let hybridKem: ReturnType<typeof getHybridKemProvider>;
    let keyWrap: ReturnType<typeof getKeyWrapProvider>;
    let available: boolean;

    beforeAll(async () => {
        hybridKem = getHybridKemProvider();
        keyWrap = getKeyWrapProvider();
        available = await hybridKem.isAvailable();
    });

    it('ML-KEM-768 WASM is available in Node test environment', async () => {
        expect(available).toBe(true);
    });

    describe('Hybrid KEM provider', () => {
        it('generates key pair with correct sizes', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            // X25519 public key = 32 bytes
            expect(keyPair.publicKey.classical).toBeInstanceOf(Uint8Array);
            expect(keyPair.publicKey.classical.length).toBe(32);

            // ML-KEM-768 public key = 1184 bytes
            expect(keyPair.publicKey.postQuantum).toBeInstanceOf(Uint8Array);
            expect(keyPair.publicKey.postQuantum.length).toBe(1184);

            // X25519 secret key = 32 bytes
            expect(keyPair.secretKey.classical.length).toBe(32);

            // ML-KEM-768 secret key = 2400 bytes
            expect(keyPair.secretKey.postQuantum.length).toBe(2400);
        });

        it('encapsulate + decapsulate produce same shared secret', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            const { ciphertext, sharedSecret: encapSecret } =
                await hybridKem.encapsulate(keyPair.publicKey);

            const decapSecret = await hybridKem.decapsulate(ciphertext, keyPair.secretKey);

            expect(encapSecret).toEqual(decapSecret);
            expect(encapSecret.length).toBe(32); // HKDF output = 32 bytes
        });

        it('different encapsulations produce different shared secrets', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            const result1 = await hybridKem.encapsulate(keyPair.publicKey);
            const result2 = await hybridKem.encapsulate(keyPair.publicKey);

            // Ephemeral X25519 keys are different each time
            expect(result1.ciphertext.classical).not.toEqual(result2.ciphertext.classical);
            expect(result1.sharedSecret).not.toEqual(result2.sharedSecret);
        });

        it('decapsulate fails with wrong secret key', async () => {
            if (!available) return;
            const keyPair1 = await hybridKem.generateKeyPair();
            const keyPair2 = await hybridKem.generateKeyPair();

            const { ciphertext } = await hybridKem.encapsulate(keyPair1.publicKey);

            // Decapsulate with wrong key — should produce different shared secret
            // (ML-KEM decapsulation doesn't throw, it produces implicit rejection)
            const wrongSecret = await hybridKem.decapsulate(ciphertext, keyPair2.secretKey);
            const rightSecret = await hybridKem.decapsulate(ciphertext, keyPair1.secretKey);

            expect(wrongSecret).not.toEqual(rightSecret);
        });
    });

    describe('Key wrap provider', () => {
        it('wrap + unwrap roundtrip', async () => {
            const masterKey = keyWrap.generateMasterKey();
            expect(masterKey.length).toBe(32);

            const kek = randomBytes(32);
            const { wrappedKey } = await keyWrap.wrap(masterKey, kek);

            // AES-KW produces 40 bytes for 32-byte input
            expect(wrappedKey.length).toBe(40);

            const { masterKey: unwrapped } = await keyWrap.unwrap(wrappedKey, kek, 1);
            expect(unwrapped).toEqual(masterKey);
        });

        it('unwrap fails with wrong KEK', async () => {
            const masterKey = keyWrap.generateMasterKey();
            const kek = randomBytes(32);
            const wrongKek = randomBytes(32);

            const { wrappedKey } = await keyWrap.wrap(masterKey, kek);

            await expect(
                keyWrap.unwrap(wrappedKey, wrongKek, 1),
            ).rejects.toThrow();
        });
    });

    describe('Full V4 file encryption', () => {
        it('encrypts and decrypts a small file', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            const plaintext = new TextEncoder().encode('Hello, Quantum-Safe StenVault! 🔐🛡️');
            const file = createMockFile(plaintext, 'quantum.txt', 'text/plain');

            // Encrypt
            const { blob, metadata } = await encryptFileHybrid(file, {
                publicKey: keyPair.publicKey,
            });

            expect(blob.size).toBeGreaterThan(plaintext.byteLength);
            expect(metadata.version).toBe('1.4');
            expect(metadata.pqcAlgorithm).toBe('ml-kem-768');
            expect(metadata.pqcParams.kemAlgorithm).toBe('x25519-ml-kem-768');

            // Decrypt
            const encryptedData = await blob.arrayBuffer();
            const decryptedData = await decryptFileHybrid(encryptedData, {
                secretKey: keyPair.secretKey,
            });

            expect(new Uint8Array(decryptedData)).toEqual(plaintext);
        });

        it('encrypts and decrypts a 1MB file', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            const plaintext = randomBytes(1024 * 1024);
            const file = createMockFile(plaintext, 'big-quantum.bin');

            const { blob } = await encryptFileHybrid(file, {
                publicKey: keyPair.publicKey,
            });

            const decryptedData = await decryptFileHybrid(await blob.arrayBuffer(), {
                secretKey: keyPair.secretKey,
            });

            expect(new Uint8Array(decryptedData)).toEqual(plaintext);
        });

        it('fails with wrong secret key', async () => {
            if (!available) return;
            const keyPair1 = await hybridKem.generateKeyPair();
            const keyPair2 = await hybridKem.generateKeyPair();

            const plaintext = new TextEncoder().encode('Secret quantum data');
            const file = createMockFile(plaintext, 'secret.txt');

            const { blob } = await encryptFileHybrid(file, {
                publicKey: keyPair1.publicKey,
            });

            // Decrypting with wrong key should fail (AES-KW unwrap rejects)
            await expect(
                decryptFileHybrid(await blob.arrayBuffer(), {
                    secretKey: keyPair2.secretKey,
                }),
            ).rejects.toThrow();
        });

        it('produces different ciphertext each time (random FK + ephemeral KEM)', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            const plaintext = new TextEncoder().encode('Same content');
            const file1 = createMockFile(plaintext, 'test.txt');
            const file2 = createMockFile(plaintext, 'test.txt');

            const result1 = await encryptFileHybrid(file1, { publicKey: keyPair.publicKey });
            const result2 = await encryptFileHybrid(file2, { publicKey: keyPair.publicKey });

            // Metadata should differ (different ephemeral keys, different IV)
            expect(result1.metadata.pqcParams.classicalCiphertext)
                .not.toBe(result2.metadata.pqcParams.classicalCiphertext);
            expect(result1.metadata.iv).not.toBe(result2.metadata.iv);
        });
    });

    describe('CVEF header format', () => {
        it('encrypted blob starts with CVEF magic header', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            const plaintext = new TextEncoder().encode('CVEF test');
            const file = createMockFile(plaintext, 'cvef.txt');

            const { blob } = await encryptFileHybrid(file, { publicKey: keyPair.publicKey });
            const data = new Uint8Array(await blob.arrayBuffer());

            // Magic: "CVEF" = 0x43 0x56 0x45 0x46
            expect(data[0]).toBe(0x43);
            expect(data[1]).toBe(0x56);
            expect(data[2]).toBe(0x45);
            expect(data[3]).toBe(0x46);
            // Container version: 2 (v1.4 uses container v2)
            expect(data[4]).toBe(2);
        });

        it('isHybridEncrypted returns true for V4 files', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            const file = createMockFile(new TextEncoder().encode('test'), 'test.txt');
            const { blob } = await encryptFileHybrid(file, { publicKey: keyPair.publicKey });

            expect(isHybridEncrypted(await blob.arrayBuffer())).toBe(true);
        });

        it('isHybridEncrypted returns false for non-CVEF data', () => {
            const randomData = randomBytes(100);
            expect(isHybridEncrypted(randomData.buffer as ArrayBuffer)).toBe(false);
        });

        it('getEncryptionMetadata returns valid V1.4 metadata', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            const file = createMockFile(new TextEncoder().encode('metadata test'), 'test.txt');
            const { blob } = await encryptFileHybrid(file, { publicKey: keyPair.publicKey });

            const metadata = getEncryptionMetadata(await blob.arrayBuffer());
            expect(isCVEFMetadataV1_4(metadata)).toBe(true);

            if (isCVEFMetadataV1_4(metadata)) {
                expect(metadata.algorithm).toBe('AES-256-GCM');
                expect(metadata.pqcParams.wrappedFileKey).toBeTruthy();
                expect(metadata.pqcParams.classicalCiphertext).toBeTruthy();
                expect(metadata.pqcParams.pqCiphertext).toBeTruthy();
            }
        });
    });

    describe('V4 streaming (chunked) encryption', () => {
        it('encrypts and decrypts with streaming path (v1.4 chunked)', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            // Use a small file but force the streaming path
            const plaintext = randomBytes(200 * 1024); // 200KB
            const file = createMockFile(plaintext, 'stream-test.bin');

            // Call streaming encrypt directly (normally only for >100MB)
            const { blob, metadata } = await encryptFileHybridStreaming(file, {
                publicKey: keyPair.publicKey,
            });

            // v1.4 with trailing manifest + AAD
            expect(metadata.version).toBe('1.4');
            expect(isCVEFMetadataV1_4(metadata)).toBe(true);
            expect(metadata.chunked).toBeTruthy();
            expect(metadata.chunked!.count).toBeGreaterThan(0);
            expect(metadata.chunked!.chunkSize).toBe(64 * 1024); // 64KB

            // Decrypt (decryptFileHybrid handles v1.4 chunked with AAD)
            const decryptedData = await decryptFileHybrid(await blob.arrayBuffer(), {
                secretKey: keyPair.secretKey,
            });

            expect(new Uint8Array(decryptedData)).toEqual(plaintext);
        });

        it('chunk IVs are unique per chunk', () => {
            const baseIv = randomBytes(12);
            const iv0 = deriveChunkIV(baseIv, 0);
            const iv1 = deriveChunkIV(baseIv, 1);
            const iv2 = deriveChunkIV(baseIv, 2);

            expect(iv0).not.toEqual(iv1);
            expect(iv1).not.toEqual(iv2);
            expect(iv0.length).toBe(12);
        });

        it('streaming decrypt fails with wrong key', async () => {
            if (!available) return;
            const keyPair1 = await hybridKem.generateKeyPair();
            const keyPair2 = await hybridKem.generateKeyPair();

            const plaintext = randomBytes(200 * 1024);
            const file = createMockFile(plaintext, 'stream-test.bin');

            const { blob } = await encryptFileHybridStreaming(file, {
                publicKey: keyPair1.publicKey,
            });

            await expect(
                decryptFileHybrid(await blob.arrayBuffer(), {
                    secretKey: keyPair2.secretKey,
                }),
            ).rejects.toThrow();
        });
    });

    describe('Progress callback', () => {
        it('reports progress during encryption', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            const plaintext = randomBytes(64 * 1024);
            const file = createMockFile(plaintext, 'progress.bin');

            let lastProgress = 0;
            const { blob } = await encryptFileHybrid(file, {
                publicKey: keyPair.publicKey,
                onProgress: (p) => { lastProgress = p.percentage; },
            });

            expect(lastProgress).toBe(100);
            expect(blob.size).toBeGreaterThan(0);
        });

        it('reports progress during decryption', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();

            const plaintext = randomBytes(64 * 1024);
            const file = createMockFile(plaintext, 'progress.bin');

            const { blob } = await encryptFileHybrid(file, { publicKey: keyPair.publicKey });

            let lastProgress = 0;
            await decryptFileHybrid(await blob.arrayBuffer(), {
                secretKey: keyPair.secretKey,
                onProgress: (p) => { lastProgress = p.percentage; },
            });

            expect(lastProgress).toBe(100);
        });
    });

    describe('Chunk integrity manifest', () => {
        /** Find byte offset where the manifest block starts (after all data chunks) */
        function findChunkEndOffset(data: Uint8Array, dataOffset: number, chunkCount: number): number {
            let offset = dataOffset;
            for (let i = 0; i < chunkCount; i++) {
                const len = new DataView(
                    data.buffer, data.byteOffset + offset, 4,
                ).getUint32(0, false);
                offset += 4 + len;
            }
            return offset;
        }

        /** Replace a same-length string in the CVEF metadata JSON (in-place) */
        function tamperMetadata(data: Uint8Array, search: string, replace: string): Uint8Array {
            if (search.length !== replace.length) throw new Error('Length mismatch');
            const metaLen =
                (data[5]! << 24) | (data[6]! << 16) | (data[7]! << 8) | data[8]!;
            const metaStr = new TextDecoder().decode(data.slice(9, 9 + metaLen));
            const newStr = metaStr.replace(search, replace);
            if (newStr === metaStr) throw new Error(`Search string "${search}" not found in metadata`);
            const result = new Uint8Array(data.length);
            result.set(data);
            result.set(new TextEncoder().encode(newStr), 9);
            return result;
        }

        it('roundtrip: chunked encrypt → decrypt with manifest verification', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();
            const plaintext = randomBytes(200 * 1024); // 200KB → 4 chunks (64KB each)
            const file = createMockFile(plaintext, 'manifest-roundtrip.bin');

            const { blob } = await encryptFileHybridStreaming(file, {
                publicKey: keyPair.publicKey,
            });
            const decrypted = await decryptFileHybrid(await blob.arrayBuffer(), {
                secretKey: keyPair.secretKey,
            });

            expect(new Uint8Array(decrypted)).toEqual(plaintext);
        });

        it('rejects when metadata chunk count is tampered', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();
            const plaintext = randomBytes(200 * 1024); // 4 chunks
            const file = createMockFile(plaintext, 'tamper-count.bin');

            const { blob } = await encryptFileHybridStreaming(file, {
                publicKey: keyPair.publicKey,
            });
            const data = new Uint8Array(await blob.arrayBuffer());

            // Tamper: reduce chunk count from 4 to 3
            const tampered = tamperMetadata(data, '"count":4', '"count":3');

            await expect(
                decryptFileHybrid(tampered.buffer as ArrayBuffer, {
                    secretKey: keyPair.secretKey,
                }),
            ).rejects.toThrow();
        });

        it('rejects when chunk ciphertext is tampered', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();
            const plaintext = randomBytes(200 * 1024);
            const file = createMockFile(plaintext, 'tamper-chunk.bin');

            const { blob } = await encryptFileHybridStreaming(file, {
                publicKey: keyPair.publicKey,
            });
            const data = new Uint8Array(await blob.arrayBuffer());

            const { dataOffset } = parseCVEFHeader(data);

            // Flip a byte in the first chunk's ciphertext (after 4-byte length prefix)
            const tampered = new Uint8Array(data.length);
            tampered.set(data);
            tampered[dataOffset + 4] = tampered[dataOffset + 4]! ^ 0x01;

            await expect(
                decryptFileHybrid(tampered.buffer as ArrayBuffer, {
                    secretKey: keyPair.secretKey,
                }),
            ).rejects.toThrow();
        });

        it('works correctly with single-chunk chunked file', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();
            const plaintext = randomBytes(1024); // 1KB → 1 chunk
            const file = createMockFile(plaintext, 'single-chunk.bin');

            const { blob, metadata } = await encryptFileHybridStreaming(file, {
                publicKey: keyPair.publicKey,
            });

            expect(metadata.chunked!.count).toBe(1);

            const decrypted = await decryptFileHybrid(await blob.arrayBuffer(), {
                secretKey: keyPair.secretKey,
            });
            expect(new Uint8Array(decrypted)).toEqual(plaintext);
        });

        it('detects truncation with adjusted count and stripped chunks', async () => {
            if (!available) return;
            const keyPair = await hybridKem.generateKeyPair();
            const plaintext = randomBytes(200 * 1024); // 4 chunks
            const file = createMockFile(plaintext, 'strip-chunks.bin');

            const { blob } = await encryptFileHybridStreaming(file, {
                publicKey: keyPair.publicKey,
            });
            const data = new Uint8Array(await blob.arrayBuffer());

            const { dataOffset } = parseCVEFHeader(data);
            // Keep only first 3 data chunks (strip chunk 3 + manifest)
            const chunk3Start = findChunkEndOffset(data, dataOffset, 3);
            const truncatedData = data.slice(0, chunk3Start);

            // Tamper metadata to say count=3
            const tampered = tamperMetadata(truncatedData, '"count":4', '"count":3');

            await expect(
                decryptFileHybrid(tampered.buffer as ArrayBuffer, {
                    secretKey: keyPair.secretKey,
                }),
            ).rejects.toThrow();
        });
    });
});

// ============================================================
// 8. Sign-at-Encrypt Integration (v1.4 + Hybrid Signatures)
// ============================================================

describe('Sign-at-Encrypt Integration', () => {
    let hybridKem: ReturnType<typeof getHybridKemProvider>;
    let signatureProvider: ReturnType<typeof getHybridSignatureProvider>;
    let available: boolean;

    beforeAll(async () => {
        hybridKem = getHybridKemProvider();
        signatureProvider = getHybridSignatureProvider();
        available = await hybridKem.isAvailable();
    });

    it('ML-DSA-65 signature provider is available', async () => {
        if (!available) return;
        const sigKeyPair = await signatureProvider.generateKeyPair();
        expect(sigKeyPair.publicKey.classical.length).toBeGreaterThan(0);
        expect(sigKeyPair.publicKey.postQuantum.length).toBeGreaterThan(0);
    });

    it('encrypt with signing produces signed v1.4 file', async () => {
        if (!available) return;
        const kemKeyPair = await hybridKem.generateKeyPair();
        const sigKeyPair = await signatureProvider.generateKeyPair();

        const plaintext = new TextEncoder().encode('Signed file content');
        const file = createMockFile(plaintext, 'signed.txt');

        const { blob, signatureMetadata } = await encryptFileHybrid(file, {
            publicKey: kemKeyPair.publicKey,
            signing: {
                secretKey: sigKeyPair.secretKey,
                fingerprint: 'test-fp-001',
                keyVersion: 1,
            },
        });

        expect(signatureMetadata).toBeDefined();
        expect(signatureMetadata!.signatureAlgorithm).toBe('ed25519-ml-dsa-65');
        expect(signatureMetadata!.signerFingerprint).toBe('test-fp-001');
        expect(signatureMetadata!.signerKeyVersion).toBe(1);
        expect(signatureMetadata!.signingContext).toBe('FILE');
        expect(signatureMetadata!.classicalSignature).toBeTruthy();
        expect(signatureMetadata!.pqSignature).toBeTruthy();

        // Verify the header is container v2
        const data = new Uint8Array(await blob.arrayBuffer());
        expect(data[4]).toBe(2); // container v2
    });

    it('signed file decrypts correctly', async () => {
        if (!available) return;
        const kemKeyPair = await hybridKem.generateKeyPair();
        const sigKeyPair = await signatureProvider.generateKeyPair();

        const plaintext = new TextEncoder().encode('Roundtrip signed content');
        const file = createMockFile(plaintext, 'roundtrip-signed.txt');

        const { blob } = await encryptFileHybrid(file, {
            publicKey: kemKeyPair.publicKey,
            signing: {
                secretKey: sigKeyPair.secretKey,
                fingerprint: 'test-fp-002',
                keyVersion: 1,
            },
        });

        const decrypted = await decryptFileHybrid(await blob.arrayBuffer(), {
            secretKey: kemKeyPair.secretKey,
            signerPublicKey: sigKeyPair.publicKey,
        });

        expect(new Uint8Array(decrypted)).toEqual(plaintext);
    });

    it('signature verifies via verifySignedFile', async () => {
        if (!available) return;
        const kemKeyPair = await hybridKem.generateKeyPair();
        const sigKeyPair = await signatureProvider.generateKeyPair();

        const plaintext = new TextEncoder().encode('Verify me');
        const file = createMockFile(plaintext, 'verify.txt');

        const { blob } = await encryptFileHybrid(file, {
            publicKey: kemKeyPair.publicKey,
            signing: {
                secretKey: sigKeyPair.secretKey,
                fingerprint: 'verify-fp',
                keyVersion: 3,
            },
        });

        const result = await verifySignedFile(blob, {
            publicKey: sigKeyPair.publicKey,
        });

        expect(result.valid).toBe(true);
        expect(result.classicalValid).toBe(true);
        expect(result.postQuantumValid).toBe(true);
        expect(result.signerFingerprint).toBe('verify-fp');
        expect(result.signerKeyVersion).toBe(3);
    });

    it('signature fails with wrong public key', async () => {
        if (!available) return;
        const kemKeyPair = await hybridKem.generateKeyPair();
        const sigKeyPair1 = await signatureProvider.generateKeyPair();
        const sigKeyPair2 = await signatureProvider.generateKeyPair();

        const plaintext = new TextEncoder().encode('Wrong key test');
        const file = createMockFile(plaintext, 'wrong-key.txt');

        const { blob } = await encryptFileHybrid(file, {
            publicKey: kemKeyPair.publicKey,
            signing: {
                secretKey: sigKeyPair1.secretKey,
                fingerprint: 'fp-1',
                keyVersion: 1,
            },
        });

        const result = await verifySignedFile(blob, {
            publicKey: sigKeyPair2.publicKey, // wrong key
        });

        expect(result.valid).toBe(false);
    });

    it('fileHasSignature and getSignatureInfo work for signed files', async () => {
        if (!available) return;
        const kemKeyPair = await hybridKem.generateKeyPair();
        const sigKeyPair = await signatureProvider.generateKeyPair();

        const file = createMockFile(new TextEncoder().encode('info test'), 'info.txt');

        const { blob } = await encryptFileHybrid(file, {
            publicKey: kemKeyPair.publicKey,
            signing: {
                secretKey: sigKeyPair.secretKey,
                fingerprint: 'info-fp',
                keyVersion: 5,
            },
        });

        expect(await fileHasSignature(blob)).toBe(true);

        const info = await getSignatureInfo(blob);
        expect(info).not.toBeNull();
        expect(info!.signerFingerprint).toBe('info-fp');
        expect(info!.signerKeyVersion).toBe(5);
        expect(info!.context).toBe('FILE');
    });

    it('unsigned file reports no signature', async () => {
        if (!available) return;
        const kemKeyPair = await hybridKem.generateKeyPair();

        const file = createMockFile(new TextEncoder().encode('unsigned'), 'unsigned.txt');

        const { blob, signatureMetadata } = await encryptFileHybrid(file, {
            publicKey: kemKeyPair.publicKey,
            // no signing option
        });

        expect(signatureMetadata).toBeUndefined();
        expect(await fileHasSignature(blob)).toBe(false);
        expect(await getSignatureInfo(blob)).toBeNull();
    });

    it('streaming encrypt with signing produces signed file', async () => {
        if (!available) return;
        const kemKeyPair = await hybridKem.generateKeyPair();
        const sigKeyPair = await signatureProvider.generateKeyPair();

        const plaintext = randomBytes(200 * 1024); // 200KB → chunked
        const file = createMockFile(plaintext, 'stream-signed.bin');

        const { blob, signatureMetadata } = await encryptFileHybridStreaming(file, {
            publicKey: kemKeyPair.publicKey,
            signing: {
                secretKey: sigKeyPair.secretKey,
                fingerprint: 'stream-fp',
                keyVersion: 2,
            },
        });

        expect(signatureMetadata).toBeDefined();
        expect(signatureMetadata!.signerFingerprint).toBe('stream-fp');

        // Verify signature
        const result = await verifySignedFile(blob, {
            publicKey: sigKeyPair.publicKey,
        });
        expect(result.valid).toBe(true);

        // Decrypt
        const decrypted = await decryptFileHybrid(await blob.arrayBuffer(), {
            secretKey: kemKeyPair.secretKey,
            signerPublicKey: sigKeyPair.publicKey,
        });
        expect(new Uint8Array(decrypted)).toEqual(plaintext);
    });
});

// ============================================================
// 9. AAD Tampering Detection (v1.4)
// ============================================================

describe('AAD Tampering Detection', () => {
    let hybridKem: ReturnType<typeof getHybridKemProvider>;
    let available: boolean;

    beforeAll(async () => {
        hybridKem = getHybridKemProvider();
        available = await hybridKem.isAvailable();
    });

    it('flipping a byte in header causes decrypt to fail', async () => {
        if (!available) return;
        const keyPair = await hybridKem.generateKeyPair();

        const plaintext = new TextEncoder().encode('AAD tamper test');
        const file = createMockFile(plaintext, 'aad.txt');

        const { blob } = await encryptFileHybrid(file, {
            publicKey: keyPair.publicKey,
        });

        const data = new Uint8Array(await blob.arrayBuffer());
        const tampered = new Uint8Array(data.length);
        tampered.set(data);

        // Flip a byte in the metadata JSON region (after 9-byte fixed header)
        tampered[20]! ^= 0xFF;

        await expect(
            decryptFileHybrid(tampered.buffer as ArrayBuffer, {
                secretKey: keyPair.secretKey,
            }),
        ).rejects.toThrow();
    });

    it('flipping a byte in ciphertext causes decrypt to fail', async () => {
        if (!available) return;
        const keyPair = await hybridKem.generateKeyPair();

        const plaintext = new TextEncoder().encode('Ciphertext tamper test');
        const file = createMockFile(plaintext, 'ct-tamper.txt');

        const { blob } = await encryptFileHybrid(file, {
            publicKey: keyPair.publicKey,
        });

        const data = new Uint8Array(await blob.arrayBuffer());
        const { dataOffset } = parseCVEFHeader(data);

        const tampered = new Uint8Array(data.length);
        tampered.set(data);

        // Flip a byte in the encrypted data region
        tampered[dataOffset + 10]! ^= 0xFF;

        await expect(
            decryptFileHybrid(tampered.buffer as ArrayBuffer, {
                secretKey: keyPair.secretKey,
            }),
        ).rejects.toThrow();
    });

    it('untampered file decrypts successfully (control)', async () => {
        if (!available) return;
        const keyPair = await hybridKem.generateKeyPair();

        const plaintext = new TextEncoder().encode('Control: no tampering');
        const file = createMockFile(plaintext, 'control.txt');

        const { blob } = await encryptFileHybrid(file, {
            publicKey: keyPair.publicKey,
        });

        const decrypted = await decryptFileHybrid(await blob.arrayBuffer(), {
            secretKey: keyPair.secretKey,
        });

        expect(new Uint8Array(decrypted)).toEqual(plaintext);
    });

    it('flipping a byte in the signature block causes decrypt to fail', async () => {
        if (!available) return;
        const keyPair = await hybridKem.generateKeyPair();
        const sigKeyPair = await getHybridSignatureProvider().generateKeyPair();

        const plaintext = new TextEncoder().encode('Sig block tamper test');
        const file = createMockFile(plaintext, 'sig-tamper.txt');

        const { blob } = await encryptFileHybrid(file, {
            publicKey: keyPair.publicKey,
            signing: {
                secretKey: sigKeyPair.secretKey,
                fingerprint: 'tamper-fp',
                keyVersion: 1,
            },
        });

        const data = new Uint8Array(await blob.arrayBuffer());
        const { dataOffset } = parseCVEFHeader(data);

        // The signature block sits between core metadata and encrypted data.
        // Flip a byte near the end of the header (inside the signature block).
        const tampered = new Uint8Array(data.length);
        tampered.set(data);
        // Flip a byte 20 bytes before dataOffset (inside sig block)
        const tamperOffset = dataOffset - 20;
        tampered[tamperOffset]! ^= 0xFF;

        // AAD mismatch: headerBytes at decrypt time differ from encrypt time
        await expect(
            decryptFileHybrid(tampered.buffer as ArrayBuffer, {
                secretKey: keyPair.secretKey,
            }),
        ).rejects.toThrow();
    });

    it('signed v1.4 decrypts without signerPublicKey (AAD still protects integrity)', async () => {
        if (!available) return;
        const keyPair = await hybridKem.generateKeyPair();
        const sigKeyPair = await getHybridSignatureProvider().generateKeyPair();

        const plaintext = new TextEncoder().encode('No signer key test');
        const file = createMockFile(plaintext, 'no-signer.txt');

        const { blob } = await encryptFileHybrid(file, {
            publicKey: keyPair.publicKey,
            signing: {
                secretKey: sigKeyPair.secretKey,
                fingerprint: 'nosigner-fp',
                keyVersion: 1,
            },
        });

        // Decrypt without signerPublicKey — should succeed (AAD integrity holds)
        const decrypted = await decryptFileHybrid(await blob.arrayBuffer(), {
            secretKey: keyPair.secretKey,
            // no signerPublicKey
        });

        expect(new Uint8Array(decrypted)).toEqual(plaintext);
    });
});

// ============================================================
// 10. Chunked Manifest Header Hash Verification (v1.4)
// ============================================================

describe('Chunked Manifest Header Hash Verification', () => {
    let hybridKem: ReturnType<typeof getHybridKemProvider>;
    let available: boolean;

    beforeAll(async () => {
        hybridKem = getHybridKemProvider();
        available = await hybridKem.isAvailable();
    });

    it('manifest rejects when header bytes are tampered in chunked v1.4', async () => {
        if (!available) return;
        const keyPair = await hybridKem.generateKeyPair();

        const plaintext = randomBytes(200 * 1024); // 4 chunks
        const file = createMockFile(plaintext, 'manifest-header-tamper.bin');

        const { blob } = await encryptFileHybridStreaming(file, {
            publicKey: keyPair.publicKey,
        });

        const data = new Uint8Array(await blob.arrayBuffer());

        // Tamper a byte in the core metadata JSON region (byte 15, inside header)
        // This changes the AAD seen at decrypt → each chunk's AES-GCM should fail
        const tampered = new Uint8Array(data.length);
        tampered.set(data);
        tampered[15]! ^= 0x01;

        await expect(
            decryptFileHybrid(tampered.buffer as ArrayBuffer, {
                secretKey: keyPair.secretKey,
            }),
        ).rejects.toThrow();
    });
});
