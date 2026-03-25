/**
 * useMasterKey Hook Tests
 *
 * Tests for core master key management:
 * - Module-level cache (cacheMasterKey, getCachedMasterKey, isCacheValid, clearMasterKeyCache)
 * - deriveMasterKey: fast-path (UES) and slow-path (Base-KEK)
 * - deriveFileKey / deriveFilenameKey / deriveThumbnailKey
 * - setupMasterKey: generates MK, wraps with KEK, stores on server
 * - Error cases: wrong password, missing config, expired cache
 *
 * @module useMasterKey.test
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';

// ============ Module-level Mocks ============

// Mock tRPC
const mockGetEncryptionConfig = {
    data: {
        isConfigured: true,
        kdfAlgorithm: 'argon2id',
        salt: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))),
        argon2Params: { memory: 47104, iterations: 1, parallelism: 1, type: 'argon2id' },
        masterKeyEncrypted: 'base64WrappedKey==',
        masterKeyVersion: 1,
    },
    isLoading: false,
    refetch: vi.fn(),
};

const mockHasKeyPair = {
    data: { hasKeyPair: true },
    refetch: vi.fn(),
};

const mockSetupMasterKeyMutation = {
    mutateAsync: vi.fn().mockResolvedValue({ success: true }),
};
const mockStoreHybridKeyPairMutation = {
    mutateAsync: vi.fn().mockResolvedValue({ success: true }),
};
const mockStoreSignatureKeyPairMutation = {
    mutateAsync: vi.fn().mockResolvedValue({ success: true }),
};
const mockGenerateSignatureKeyPairMutation = {
    mutateAsync: vi.fn().mockResolvedValue({ success: true }),
};
const mockHasSignatureKeyPair = {
    data: { hasKeyPair: true },
    refetch: vi.fn(),
};

vi.mock('@/lib/trpc', () => ({
    trpc: {
        encryption: {
            getEncryptionConfig: {
                useQuery: vi.fn(() => mockGetEncryptionConfig),
            },
            setupMasterKey: {
                useMutation: vi.fn(() => mockSetupMasterKeyMutation),
            },
        },
        hybridKem: {
            storeKeyPair: {
                useMutation: vi.fn(() => mockStoreHybridKeyPairMutation),
            },
            hasKeyPair: {
                useQuery: vi.fn(() => mockHasKeyPair),
            },
        },
        hybridSignature: {
            storeKeyPair: {
                useMutation: vi.fn(() => mockStoreSignatureKeyPairMutation),
            },
            generateKeyPair: {
                useMutation: vi.fn(() => mockGenerateSignatureKeyPairMutation),
            },
            hasKeyPair: {
                useQuery: vi.fn(() => mockHasSignatureKeyPair),
            },
        },
        useUtils: vi.fn(() => ({
            hybridKem: {
                getPublicKey: { fetch: vi.fn().mockResolvedValue(null) },
                getSecretKey: { fetch: vi.fn().mockResolvedValue(null) },
            },
        })),
    },
}));

// Mock useAuth
vi.mock('@/_core/hooks/useAuth', () => ({
    useAuth: vi.fn(() => ({
        user: { id: 1, email: 'test@test.com', role: 'user' },
    })),
}));

// Mock toast
vi.mock('sonner', () => ({
    toast: {
        success: vi.fn(),
        error: vi.fn(),
        warning: vi.fn(),
        info: vi.fn(),
    },
}));

// Mock debug logger
vi.mock('@/lib/debugLogger', () => ({
    debugLog: vi.fn(),
    debugError: vi.fn(),
}));

// Mock thumbnail cache
vi.mock('@/hooks/useThumbnailDecryption', () => ({
    clearThumbnailCache: vi.fn(),
}));

// Mock platform providers
vi.mock('@/lib/platform/webKeyWrapProvider', () => ({
    getKeyWrapProvider: vi.fn(() => ({
        wrap: vi.fn().mockResolvedValue({ wrappedKey: new Uint8Array(40) }),
        unwrap: vi.fn().mockResolvedValue({ masterKey: new Uint8Array(32) }),
    })),
}));

vi.mock('@/lib/platform/webHybridKemProvider', () => ({
    getHybridKemProvider: vi.fn(() => ({
        isAvailable: vi.fn().mockResolvedValue(true),
        generateKeyPair: vi.fn().mockResolvedValue({
            publicKey: { classical: new Uint8Array(32), postQuantum: new Uint8Array(1184) },
            secretKey: { classical: new Uint8Array(32), postQuantum: new Uint8Array(2400) },
        }),
    })),
}));

vi.mock('@/lib/platform/webHybridSignatureProvider', () => ({
    getHybridSignatureProvider: vi.fn(() => ({
        isAvailable: vi.fn().mockResolvedValue(true),
        generateKeyPair: vi.fn().mockResolvedValue({
            publicKey: { classical: new Uint8Array(32), postQuantum: new Uint8Array(1952) },
            secretKey: { classical: new Uint8Array(64), postQuantum: new Uint8Array(4032) },
        }),
    })),
}));

vi.mock('@/hooks/useOrgMasterKey', () => ({
    clearAllOrgKeyCaches: vi.fn(),
}));

vi.mock('@/lib/platform', () => ({
    base64ToArrayBuffer: vi.fn((b64: string) => {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }),
    arrayBufferToBase64: vi.fn((buf: ArrayBuffer) => {
        return btoa(String.fromCharCode(...new Uint8Array(buf)));
    }),
}));

vi.mock('@/lib/recoveryCodeUtils', () => ({
    generateRecoveryCodes: vi.fn(() =>
        Array.from({ length: 10 }, (_, i) => `CODE${i.toString().padStart(4, '0')}`)
    ),
}));

// Mock UES manager
vi.mock('@/lib/uesManager', () => ({
    loadUES: vi.fn().mockResolvedValue(null),
    deriveDeviceKEK: vi.fn(),
    getStoredFingerprintHash: vi.fn().mockReturnValue(null),
}));

// Mock operationStore
const mockGetHasActiveOperations = vi.fn().mockReturnValue(false);
vi.mock('@/stores/operationStore', () => ({
    getHasActiveOperations: (...args: unknown[]) => mockGetHasActiveOperations(...args),
    getLastActiveOperationStartTime: vi.fn(() => null),
}));

// Mock masterKeyCrypto
const mockDeriveArgon2Key = vi.fn();
const mockUnwrapMasterKey = vi.fn();
const mockDeriveFileKeyFromMaster = vi.fn();
const mockDeriveFileKeyWithBytesFromMaster = vi.fn();
const mockDeriveFilenameKeyFromMaster = vi.fn();
const mockDeriveThumbnailKeyFromMaster = vi.fn();

vi.mock('./masterKeyCrypto', () => ({
    toArrayBuffer: vi.fn((data: Uint8Array) => data.buffer),
    encryptLargeSecretKey: vi.fn().mockResolvedValue(new Uint8Array(100)),
    decryptLargeSecretKey: vi.fn().mockResolvedValue(new Uint8Array(2400)),
    createMasterKeyBundle: vi.fn().mockResolvedValue({
        hkdf: { type: 'secret', extractable: false, algorithm: { name: 'HKDF' }, usages: ['deriveKey', 'deriveBits'] },
        aesGcm: { type: 'secret', extractable: false, algorithm: { name: 'AES-GCM', length: 256 }, usages: ['encrypt', 'decrypt'] },
        aesKw: { type: 'secret', extractable: false, algorithm: { name: 'AES-KW', length: 256 }, usages: ['wrapKey', 'unwrapKey'] },
    }),
    wrapSecretWithMK: vi.fn().mockResolvedValue(new Uint8Array(40)),
    unwrapSecretWithMK: vi.fn().mockResolvedValue(new Uint8Array(32)),
    deriveArgon2Key: (...args: unknown[]) => mockDeriveArgon2Key(...args),
    unwrapMasterKey: (...args: unknown[]) => mockUnwrapMasterKey(...args),
    deriveFileKeyFromMaster: (...args: unknown[]) => mockDeriveFileKeyFromMaster(...args),
    deriveFileKeyWithBytesFromMaster: (...args: unknown[]) => mockDeriveFileKeyWithBytesFromMaster(...args),
    deriveFilenameKeyFromMaster: (...args: unknown[]) => mockDeriveFilenameKeyFromMaster(...args),
    deriveThumbnailKeyFromMaster: (...args: unknown[]) => mockDeriveThumbnailKeyFromMaster(...args),
}));

import { useMasterKey, clearMasterKeyCache } from './useMasterKey';

// ============ Test Helpers ============

function createMockCryptoKey(algo = 'AES-GCM', usages = ['encrypt', 'decrypt']): CryptoKey {
    return {
        type: 'secret',
        extractable: false,
        algorithm: { name: algo, length: 256 },
        usages,
    } as unknown as CryptoKey;
}

function createMockBundle() {
    return {
        hkdf: createMockCryptoKey('HKDF', ['deriveKey', 'deriveBits']),
        aesGcm: createMockCryptoKey('AES-GCM', ['encrypt', 'decrypt']),
        aesKw: createMockCryptoKey('AES-KW', ['wrapKey', 'unwrapKey']),
    };
}

// ============ Tests ============

describe('useMasterKey', () => {
    const MOCK_BUNDLE = createMockBundle();
    const MOCK_KEK = createMockCryptoKey('AES-KW', ['wrapKey', 'unwrapKey']);
    const MOCK_FILE_KEY = createMockCryptoKey();
    const MOCK_FILENAME_KEY = createMockCryptoKey();
    const MOCK_THUMB_KEY = createMockCryptoKey();

    beforeEach(() => {
        vi.clearAllMocks();
        clearMasterKeyCache();

        // Setup default mock responses
        mockDeriveArgon2Key.mockResolvedValue(MOCK_KEK);
        mockUnwrapMasterKey.mockResolvedValue({ bundle: MOCK_BUNDLE });
        mockDeriveFileKeyFromMaster.mockResolvedValue(MOCK_FILE_KEY);
        mockDeriveFilenameKeyFromMaster.mockResolvedValue(MOCK_FILENAME_KEY);
        mockDeriveThumbnailKeyFromMaster.mockResolvedValue(MOCK_THUMB_KEY);
        mockDeriveFileKeyWithBytesFromMaster.mockResolvedValue({
            key: MOCK_FILE_KEY,
            keyBytes: new Uint8Array(32),
            zeroBytes: vi.fn(),
        });

        // Reset tRPC config to default configured state
        mockGetEncryptionConfig.data = {
            isConfigured: true,
            kdfAlgorithm: 'argon2id',
            salt: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))),
            argon2Params: { memory: 47104, iterations: 1, parallelism: 1, type: 'argon2id' },
            masterKeyEncrypted: 'base64WrappedKey==',
            masterKeyVersion: 1,
        };
    });

    afterEach(() => {
        clearMasterKeyCache();
    });

    describe('initial state', () => {
        it('reports isConfigured from server config', () => {
            const { result } = renderHook(() => useMasterKey());

            expect(result.current.isConfigured).toBe(true);
        });

        it('reports not unlocked initially', () => {
            const { result } = renderHook(() => useMasterKey());

            expect(result.current.isUnlocked).toBe(false);
            expect(result.current.isCached).toBe(false);
        });

        it('reports not deriving key initially', () => {
            const { result } = renderHook(() => useMasterKey());

            expect(result.current.isDerivingKey).toBe(false);
            expect(result.current.error).toBeNull();
        });

        it('getCachedKey returns null when not derived', () => {
            const { result } = renderHook(() => useMasterKey());

            expect(result.current.getCachedKey()).toBeNull();
        });

        it('reports isConfigured false when not set up', () => {
            mockGetEncryptionConfig.data = {
                isConfigured: false,
                kdfAlgorithm: null as any,
                salt: null as any,
                argon2Params: null as any,
                masterKeyEncrypted: null as any,
                masterKeyVersion: null as any,
            };

            const { result } = renderHook(() => useMasterKey());

            expect(result.current.isConfigured).toBe(false);
        });
    });

    describe('deriveMasterKey', () => {
        it('derives and caches master key successfully', async () => {
            const { result } = renderHook(() => useMasterKey());

            let bundle: any;
            await act(async () => {
                bundle = await result.current.deriveMasterKey('password123');
            });

            expect(bundle).toBe(MOCK_BUNDLE);
            expect(mockDeriveArgon2Key).toHaveBeenCalled();
            expect(mockUnwrapMasterKey).toHaveBeenCalled();
            expect(result.current.isUnlocked).toBe(true);
            expect(result.current.isCached).toBe(true);
        });

        it('returns cached key on subsequent calls', async () => {
            const { result } = renderHook(() => useMasterKey());

            await act(async () => {
                await result.current.deriveMasterKey('password123');
            });

            vi.clearAllMocks();

            let bundle: any;
            await act(async () => {
                bundle = await result.current.deriveMasterKey('password123');
            });

            // Should NOT call derivation again
            expect(mockDeriveArgon2Key).not.toHaveBeenCalled();
            expect(bundle).toBeTruthy();
        });

        it('throws when encryption not configured', async () => {
            mockGetEncryptionConfig.data = {
                isConfigured: false,
                kdfAlgorithm: null as any,
                salt: null as any,
                argon2Params: null as any,
                masterKeyEncrypted: null as any,
                masterKeyVersion: null as any,
            };

            const { result } = renderHook(() => useMasterKey());

            await expect(
                act(async () => {
                    await result.current.deriveMasterKey('password123');
                })
            ).rejects.toThrow('Encryption not configured');
        });

        it('throws when salt is missing', async () => {
            mockGetEncryptionConfig.data = {
                ...mockGetEncryptionConfig.data,
                salt: null as any,
            };

            const { result } = renderHook(() => useMasterKey());

            await expect(
                act(async () => {
                    await result.current.deriveMasterKey('password123');
                })
            ).rejects.toThrow('Missing encryption salt');
        });

        it('throws on derivation failure', async () => {
            mockUnwrapMasterKey.mockRejectedValue(new Error('Wrong password'));
            const { result } = renderHook(() => useMasterKey());

            await expect(
                act(async () => {
                    await result.current.deriveMasterKey('wrong-pass');
                })
            ).rejects.toThrow('Wrong password');

            expect(result.current.isDerivingKey).toBe(false);
        });

        it('throws when masterKeyEncrypted is null (no legacy migration)', async () => {
            mockGetEncryptionConfig.data = {
                ...mockGetEncryptionConfig.data,
                masterKeyEncrypted: null as any,
            };

            const { result } = renderHook(() => useMasterKey());

            await expect(
                act(async () => {
                    await result.current.deriveMasterKey('password123');
                })
            ).rejects.toThrow('master key not found');
        });
    });

    describe('deriveFileKey', () => {
        it('derives file key when vault is unlocked', async () => {
            const { result } = renderHook(() => useMasterKey());

            // First unlock
            await act(async () => {
                await result.current.deriveMasterKey('password123');
            });

            let fileKey: CryptoKey;
            await act(async () => {
                fileKey = await result.current.deriveFileKey('file-123', Date.now());
            });

            expect(fileKey!).toBe(MOCK_FILE_KEY);
            expect(mockDeriveFileKeyFromMaster).toHaveBeenCalledWith(MOCK_BUNDLE.hkdf, 'file-123', expect.any(Number));
        });

        it('throws when vault is locked', async () => {
            const { result } = renderHook(() => useMasterKey());

            await expect(
                act(async () => {
                    await result.current.deriveFileKey('file-123', Date.now());
                })
            ).rejects.toThrow('Vault is locked');
        });
    });

    describe('deriveFileKeyWithBytes', () => {
        it('derives file key with bytes for Worker transfer', async () => {
            const { result } = renderHook(() => useMasterKey());

            await act(async () => {
                await result.current.deriveMasterKey('password123');
            });

            let keyResult: any;
            await act(async () => {
                keyResult = await result.current.deriveFileKeyWithBytes('file-123', Date.now());
            });

            expect(keyResult.key).toBe(MOCK_FILE_KEY);
            expect(keyResult.keyBytes).toBeInstanceOf(Uint8Array);
            expect(typeof keyResult.zeroBytes).toBe('function');
        });
    });

    describe('deriveFilenameKey', () => {
        it('derives filename key when unlocked', async () => {
            const { result } = renderHook(() => useMasterKey());

            await act(async () => {
                await result.current.deriveMasterKey('password123');
            });

            let key: CryptoKey;
            await act(async () => {
                key = await result.current.deriveFilenameKey();
            });

            expect(key!).toBe(MOCK_FILENAME_KEY);
            expect(mockDeriveFilenameKeyFromMaster).toHaveBeenCalledWith(MOCK_BUNDLE.hkdf);
        });

        it('throws when vault is locked', async () => {
            const { result } = renderHook(() => useMasterKey());

            await expect(
                act(async () => {
                    await result.current.deriveFilenameKey();
                })
            ).rejects.toThrow('Vault is locked');
        });
    });

    describe('deriveThumbnailKey', () => {
        it('derives thumbnail key when unlocked', async () => {
            const { result } = renderHook(() => useMasterKey());

            await act(async () => {
                await result.current.deriveMasterKey('password123');
            });

            let key: CryptoKey;
            await act(async () => {
                key = await result.current.deriveThumbnailKey('file-456');
            });

            expect(key!).toBe(MOCK_THUMB_KEY);
            expect(mockDeriveThumbnailKeyFromMaster).toHaveBeenCalledWith(MOCK_BUNDLE.hkdf, 'file-456');
        });
    });

    describe('clearCache', () => {
        it('locks vault and clears cached key', async () => {
            const { result } = renderHook(() => useMasterKey());

            // Unlock first
            await act(async () => {
                await result.current.deriveMasterKey('password123');
            });

            expect(result.current.isUnlocked).toBe(true);

            // Clear cache
            act(() => {
                result.current.clearCache();
            });

            expect(result.current.isUnlocked).toBe(false);
            expect(result.current.isCached).toBe(false);
            expect(result.current.getCachedKey()).toBeNull();
        });
    });

    describe('module-level cache functions', () => {
        it('clearMasterKeyCache exported function works', async () => {
            const { result } = renderHook(() => useMasterKey());

            await act(async () => {
                await result.current.deriveMasterKey('password123');
            });

            expect(result.current.isUnlocked).toBe(true);

            act(() => {
                clearMasterKeyCache();
            });

            expect(result.current.isUnlocked).toBe(false);
        });
    });

    describe('setupMasterKey', () => {
        it('throws when already configured', async () => {
            const { result } = renderHook(() => useMasterKey());

            await expect(
                act(async () => {
                    await result.current.setupMasterKey('newpassword');
                })
            ).rejects.toThrow('Master Key is already configured');
        });

        it('sets up master key and returns recovery codes when not configured', async () => {
            mockGetEncryptionConfig.data = {
                isConfigured: false,
                kdfAlgorithm: null as any,
                salt: null as any,
                argon2Params: null as any,
                masterKeyEncrypted: null as any,
                masterKeyVersion: null as any,
            };

            // Mock crypto.subtle for setup flow
            vi.spyOn(crypto.subtle, 'importKey').mockResolvedValue(MOCK_KEK);
            vi.spyOn(crypto.subtle, 'exportKey').mockResolvedValue(new ArrayBuffer(32));
            vi.spyOn(crypto.subtle, 'deriveBits').mockResolvedValue(new ArrayBuffer(32));
            vi.spyOn(crypto.subtle, 'digest').mockResolvedValue(new ArrayBuffer(32));
            vi.spyOn(crypto.subtle, 'wrapKey').mockResolvedValue(new ArrayBuffer(40));
            mockDeriveArgon2Key.mockResolvedValue(MOCK_KEK);

            const { result } = renderHook(() => useMasterKey());

            let setupResult: { success: boolean; recoveryCodesPlain: string[] };
            await act(async () => {
                setupResult = await result.current.setupMasterKey('newpassword', 'my hint');
            });

            expect(setupResult!.success).toBe(true);
            expect(setupResult!.recoveryCodesPlain).toHaveLength(10);
            expect(mockSetupMasterKeyMutation.mutateAsync).toHaveBeenCalledWith(
                expect.objectContaining({
                    pbkdf2Salt: expect.any(String),
                    recoveryCodes: expect.any(Array),
                    masterKeyEncrypted: expect.any(String),
                    passwordHint: 'my hint',
                })
            );
        });
    });

    describe('hybrid keypair', () => {
        it('reports hasHybridKeyPair from server', () => {
            mockHasKeyPair.data = { hasKeyPair: true };

            const { result } = renderHook(() => useMasterKey());

            expect(result.current.hasHybridKeyPair).toBe(true);
        });

        it('reports no hybrid keypair when not set up', () => {
            mockHasKeyPair.data = { hasKeyPair: false };

            const { result } = renderHook(() => useMasterKey());

            expect(result.current.hasHybridKeyPair).toBe(false);
        });
    });

    describe('cache expiry deferral', () => {
        beforeEach(() => {
            vi.useFakeTimers();
        });

        afterEach(() => {
            vi.useRealTimers();
            mockGetHasActiveOperations.mockReturnValue(false);
        });

        it('defers cache expiry when operations are active', async () => {
            const { result } = renderHook(() => useMasterKey());

            await act(async () => {
                await result.current.deriveMasterKey('password123');
            });

            expect(result.current.isUnlocked).toBe(true);

            // Simulate active operations when timer fires
            mockGetHasActiveOperations.mockReturnValue(true);

            // Advance to 15 minutes (normal expiry time)
            act(() => {
                vi.advanceTimersByTime(15 * 60 * 1000);
            });

            // Cache should still be valid because operations are active
            expect(result.current.isUnlocked).toBe(true);
        });

        it('expires cache normally when no operations are active', async () => {
            const { result } = renderHook(() => useMasterKey());

            await act(async () => {
                await result.current.deriveMasterKey('password123');
            });

            expect(result.current.isUnlocked).toBe(true);

            // No active operations
            mockGetHasActiveOperations.mockReturnValue(false);

            // Advance to 15 minutes
            act(() => {
                vi.advanceTimersByTime(15 * 60 * 1000);
            });

            expect(result.current.isUnlocked).toBe(false);
        });

        it('enforces hard cap at 30 minutes even with active operations', async () => {
            const { result } = renderHook(() => useMasterKey());

            await act(async () => {
                await result.current.deriveMasterKey('password123');
            });

            expect(result.current.isUnlocked).toBe(true);

            // Operations stay active the entire time
            mockGetHasActiveOperations.mockReturnValue(true);

            // Advance to 30 minutes (hard cap)
            act(() => {
                vi.advanceTimersByTime(30 * 60 * 1000);
            });

            expect(result.current.isUnlocked).toBe(false);
        });
    });
});
