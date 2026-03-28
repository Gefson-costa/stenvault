/**
 * useFileDecryption Hook
 *
 * Manages file decryption for encrypted files in the preview modal.
 * V4 (Hybrid PQC) auto-decryption.
 * Also handles signature verification for signed files (Phase 3.4 Sovereign).
 */

import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { toast } from 'sonner';
import { trpc } from '@/lib/trpc';
import { debugLog, debugError, debugWarn } from '@/lib/debugLogger';
import { decryptFileHybrid, extractV4FileKey, deriveManifestHmacKey } from '@/lib/hybridFileCrypto';
import { decryptV4ChunkedToStream } from '@/lib/streamingDecrypt';
import { verifySignedFile } from '@/lib/signedFileCrypto';
import { base64ToArrayBuffer } from '@/lib/platform';
import { useMasterKey } from '@/hooks/useMasterKey';
import { useOrgMasterKey } from '@/hooks/useOrgMasterKey';
import { unwrapOrgHybridSecretKey } from '@/lib/orgHybridCrypto';
import type { DecryptionState, PreviewableFile, SignatureInfo, SignatureVerificationState } from '../types';
import type { HybridSecretKey, HybridSignaturePublicKey } from '@stenvault/shared/platform/crypto';

/** Common extension → MIME type map for when file.mimeType is null or octet-stream */
const EXTENSION_MIME_MAP: Record<string, string> = {
    // Images
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', bmp: 'image/bmp', ico: 'image/x-icon',
    avif: 'image/avif', tiff: 'image/tiff', tif: 'image/tiff',
    // Video
    mp4: 'video/mp4', webm: 'video/webm', ogg: 'video/ogg', ogv: 'video/ogg',
    mov: 'video/quicktime', avi: 'video/x-msvideo', mkv: 'video/x-matroska',
    // Audio
    mp3: 'audio/mpeg', wav: 'audio/wav', flac: 'audio/flac', aac: 'audio/aac',
    oga: 'audio/ogg', m4a: 'audio/mp4', wma: 'audio/x-ms-wma',
    // Documents
    pdf: 'application/pdf', txt: 'text/plain', html: 'text/html',
    css: 'text/css', js: 'text/javascript', json: 'application/json',
    xml: 'application/xml', csv: 'text/csv',
};

/**
 * Get the best available MIME type for a file.
 * Uses file.mimeType if valid, otherwise infers from extension.
 */
export function getEffectiveMimeType(file: PreviewableFile): string {
    // 1. Use stored mimeType if it's a real type (not null/octet-stream)
    if (file.mimeType && file.mimeType !== 'application/octet-stream') {
        return file.mimeType;
    }
    // 2. Try to infer from plaintextExtension (stored separately for zero-knowledge)
    if (file.plaintextExtension) {
        const ext = file.plaintextExtension.toLowerCase().replace('.', '');
        if (EXTENSION_MIME_MAP[ext]) return EXTENSION_MIME_MAP[ext];
    }
    // 3. Try to infer from decryptedFilename or filename
    const name = file.decryptedFilename || file.filename;
    if (name) {
        const dotIdx = name.lastIndexOf('.');
        if (dotIdx !== -1) {
            const ext = name.substring(dotIdx + 1).toLowerCase();
            if (EXTENSION_MIME_MAP[ext]) return EXTENSION_MIME_MAP[ext];
        }
    }
    // 4. Last resort
    return 'application/octet-stream';
}

/**
 * Verify file signature BEFORE decryption (defense-in-depth).
 * Returns true if decryption should proceed, false to block.
 * On infra errors (WASM, network), allows decrypt with warning.
 */
async function verifyBeforeDecrypt(
    encryptedData: ArrayBuffer,
    sigInfo: SignatureInfo,
    pubKeyData: { ed25519PublicKey: string; mldsa65PublicKey: string },
    callbacks: {
        setIsVerifying: (v: boolean) => void;
        setVerificationResult: (r: {
            valid: boolean;
            classicalValid: boolean;
            postQuantumValid: boolean;
            error?: string;
        } | null) => void;
        setError: (e: string) => void;
    },
): Promise<boolean> {
    callbacks.setIsVerifying(true);
    debugLog('✍️', 'Verifying signature BEFORE decryption', {
        signerId: sigInfo.signerId,
        signerFingerprint: sigInfo.signerFingerprint,
    });

    try {
        const encryptedBlob = new Blob([encryptedData]);
        const publicKey: HybridSignaturePublicKey = {
            classical: new Uint8Array(base64ToArrayBuffer(pubKeyData.ed25519PublicKey)),
            postQuantum: new Uint8Array(base64ToArrayBuffer(pubKeyData.mldsa65PublicKey)),
        };

        const result = await verifySignedFile(encryptedBlob, { publicKey });

        callbacks.setVerificationResult({
            valid: result.valid,
            classicalValid: result.classicalValid,
            postQuantumValid: result.postQuantumValid,
            error: result.error,
        });
        callbacks.setIsVerifying(false);

        if (result.valid) {
            toast.success('Signature verified');
            debugLog('✍️', 'Signature verification passed — proceeding to decrypt');
            return true;
        } else {
            // Invalid signature — BLOCK decryption
            const msg = result.error || 'File signature is invalid — decryption blocked';
            callbacks.setError(msg);
            toast.error('Signature verification failed', {
                description: 'The file signature could not be verified. Decryption blocked for security.',
            });
            debugWarn('✍️', 'Signature verification FAILED — blocking decrypt', result);
            return false;
        }
    } catch (verifyError) {
        // Infra error (WASM, parsing) — block decrypt (fail closed)
        debugError('✍️', 'Signature verification infra error', verifyError);
        callbacks.setVerificationResult({
            valid: false,
            classicalValid: false,
            postQuantumValid: false,
            error: verifyError instanceof Error ? verifyError.message : 'Verification failed',
        });
        callbacks.setIsVerifying(false);
        const msg = 'Signature verification encountered an infrastructure error. Decryption blocked for security.';
        callbacks.setError(msg);
        toast.error('Could not verify signature', {
            description: 'Decryption blocked — please try again. If the problem persists, contact support.',
        });
        return false;
    }
}

interface UseFileDecryptionParams {
    file: PreviewableFile | null;
    isOpen: boolean;
    rawUrl: string | undefined;
    encryptionIv: string | undefined;
    encryptionSalt: string | undefined;
    encryptionVersion: number;
    signatureInfo?: SignatureInfo | null;
}

interface UseFileDecryptionReturn {
    state: DecryptionState;
    signatureState: SignatureVerificationState;
    reset: () => void;
}

export function useFileDecryption({
    file,
    isOpen,
    rawUrl,
    encryptionIv,
    encryptionSalt,
    encryptionVersion,
    signatureInfo,
}: UseFileDecryptionParams): UseFileDecryptionReturn {
    const [isDecrypting, setIsDecrypting] = useState(false);
    const [progress, setProgress] = useState(0);
    const [error, setError] = useState<string | null>(null);
    const [decryptedBlobUrl, setDecryptedBlobUrl] = useState<string | null>(null);
    // Ref to track current blob URL for cleanup (avoids stale closure in effects)
    const blobUrlRef = useRef<string | null>(null);
    blobUrlRef.current = decryptedBlobUrl;

    // ===== SIGNATURE VERIFICATION STATE (Phase 3.4 Sovereign) =====
    const [isVerifying, setIsVerifying] = useState(false);
    const [verificationResult, setVerificationResult] = useState<{
        valid: boolean;
        classicalValid: boolean;
        postQuantumValid: boolean;
        error?: string;
    } | null>(null);
    const [decryptionVerified, setDecryptionVerified] = useState(false);

    // Fetch signer's public key if signature info is present
    const { data: signerPublicKeyData, error: signerKeyError } = trpc.hybridSignature.getPublicKeyByUserId.useQuery(
        { userId: signatureInfo?.signerId ?? 0 },
        {
            enabled: !!signatureInfo?.signerId,
            staleTime: 10 * 60 * 1000, // Cache for 10 minutes
        }
    );

    // Gate: don't auto-decrypt until signer key is resolved (loaded or failed)
    // If no signature, or key loaded, or query errored → ready to proceed
    const sigKeyReady = !signatureInfo?.signerId || !!signerPublicKeyData || !!signerKeyError;

    // Compute signature state
    const signatureState = useMemo((): SignatureVerificationState => ({
        hasSignature: !!signatureInfo,
        isVerifying,
        result: verificationResult,
        signerInfo: signatureInfo ?? null,
        decryptionVerified,
    }), [signatureInfo, isVerifying, verificationResult, decryptionVerified]);

    // Reset state when file changes
    useEffect(() => {
        setError(null);
        setIsDecrypting(false);
        setProgress(0);
        setIsVerifying(false);
        setVerificationResult(null);
        setDecryptionVerified(false);

        // Revoke previous blob URL to free memory (using ref for current value)
        if (blobUrlRef.current) {
            URL.revokeObjectURL(blobUrlRef.current);
            setDecryptedBlobUrl(null);
        }
    }, [file?.id]);

    // ===== MASTER KEY & HYBRID AUTO-DECRYPTION =====
    const { isUnlocked, getUnlockedHybridSecretKey } = useMasterKey();
    const { unlockOrgVault } = useOrgMasterKey();
    const trpcUtils = trpc.useUtils();

    // Hybrid decryption handler for v4 files
    // Unsigned V4: pure streaming (~128KB peak). Signed V4: full load for SHA-256 verify.
    const handleHybridDecrypt = useCallback(async () => {
        if (!rawUrl || !file) {
            debugWarn('🔐', 'handleHybridDecrypt called with missing params', {
                rawUrl: !!rawUrl, file: !!file,
            });
            return;
        }

        setIsDecrypting(true);
        setProgress(0);
        setError(null);

        try {
            const isOrgFile = !!file.organizationId;

            let hybridSecretKey: HybridSecretKey;
            if (isOrgFile) {
                debugLog('🔐', `Using V4 Org Hybrid PQC decryption (org=${file.organizationId})`);
                const omk = await unlockOrgVault(file.organizationId!);
                const orgSecretData = await trpcUtils.orgKeys.getOrgHybridSecretKey.fetch({
                    organizationId: file.organizationId!,
                    ...(file.orgKeyVersion ? { keyVersion: file.orgKeyVersion } : {}),
                });
                hybridSecretKey = await unwrapOrgHybridSecretKey(omk, orgSecretData);
            } else {
                debugLog('🔐', 'Using V4 Personal Hybrid PQC decryption');
                const personalKey = await getUnlockedHybridSecretKey();
                if (!personalKey) {
                    throw new Error('Hybrid secret key not available. Please unlock your vault.');
                }
                hybridSecretKey = personalKey;
            }

            const isSigned = !!signatureInfo && !!signerPublicKeyData;

            if (isSigned) {
                // SIGNED V4: Must load full file for SHA-256 signature verification
                const response = await fetch(rawUrl);
                if (!response.ok) {
                    throw new Error(`Failed to fetch file: ${response.status}`);
                }
                const encryptedData = await response.arrayBuffer();

                const allowed = await verifyBeforeDecrypt(encryptedData, signatureInfo, signerPublicKeyData, {
                    setIsVerifying, setVerificationResult, setError,
                });
                if (!allowed) return;

                // Decrypt with streaming internals (decryptFileHybrid uses decryptChunkedToStream)
                const decryptedData = await decryptFileHybrid(encryptedData, {
                    secretKey: hybridSecretKey,
                    onProgress: (p) => setProgress(p.percentage),
                });
                const decryptedBlob = new Blob([decryptedData], { type: getEffectiveMimeType(file) });

                setProgress(100);
                const blobUrl = URL.createObjectURL(decryptedBlob);
                setDecryptedBlobUrl(blobUrl);
                setDecryptionVerified(true);
            } else {
                // UNSIGNED V4: Pure streaming — peak memory ~128KB for chunked files
                // 1. Extract file key from header (8KB Range request)
                const { fileKeyBytes, zeroBytes } = await extractV4FileKey(rawUrl, hybridSecretKey);
                try {
                    const hmacKey = await deriveManifestHmacKey(fileKeyBytes);
                    const fileKey = await crypto.subtle.importKey(
                        'raw',
                        fileKeyBytes.buffer.slice(
                            fileKeyBytes.byteOffset,
                            fileKeyBytes.byteOffset + fileKeyBytes.byteLength,
                        ) as ArrayBuffer,
                        { name: 'AES-GCM', length: 256 },
                        false,
                        ['decrypt'],
                    );

                    // 2. Fetch full file as stream
                    const response = await fetch(rawUrl);
                    if (!response.ok || !response.body) {
                        throw new Error(`Failed to fetch file: ${response.status}`);
                    }

                    // 3. Stream-decrypt (handles chunked + non-chunked V4)
                    const plaintextStream = decryptV4ChunkedToStream(response.body, {
                        fileKey,
                        hmacKey,
                        onProgress: (p) => setProgress(
                            Math.round((p.chunkIndex / Math.max(p.chunkCount, 1)) * 100),
                        ),
                    });

                    // 4. Collect to Blob — browser can back-pressure to disk
                    const rawBlob = await new Response(plaintextStream).blob();
                    const decryptedBlob = new Blob([rawBlob], { type: getEffectiveMimeType(file) });

                    setProgress(100);
                    const blobUrl = URL.createObjectURL(decryptedBlob);
                    setDecryptedBlobUrl(blobUrl);
                    setDecryptionVerified(true);
                } finally {
                    zeroBytes();
                }
            }

            toast.success(isOrgFile ? 'File decrypted with Organization Hybrid PQC' : 'File decrypted with Hybrid PQC');
        } catch (err) {
            debugError('🔐', 'Hybrid decryption failed', err);
            const isIntegrityError = err instanceof Error && err.message.includes('integrity verification failed');
            const isOperationError = err instanceof DOMException && err.name === 'OperationError';
            if (isIntegrityError) {
                setError('File integrity check failed. The file may have been tampered with or corrupted.');
                toast.error('File integrity check failed', {
                    description: 'The file may have been tampered with or corrupted.',
                });
            } else if (isOperationError) {
                setError('Wrong Master Password — try unlocking your vault again.');
                toast.error('Decryption failed', {
                    description: 'Wrong Master Password. Try unlocking again.',
                });
            } else {
                setError(
                    err instanceof Error
                        ? err.message
                        : 'This file may be corrupted or damaged.'
                );
                toast.error('Failed to decrypt file', {
                    description: err instanceof Error ? err.message : 'This file may be corrupted.',
                });
            }
        } finally {
            setIsDecrypting(false);
        }
    }, [rawUrl, file, getUnlockedHybridSecretKey, unlockOrgVault, trpcUtils, signatureInfo, signerPublicKeyData]);

    // Stable refs for auto-decrypt effects — prevents infinite loop from unstable callback identity.
    // getUnlockedHybridSecretKey/trpcUtils recreate on each render, propagating to handleHybridDecrypt.
    // Using refs decouples effect scheduling from callback identity changes.
    const handleHybridDecryptRef = useRef(handleHybridDecrypt);
    handleHybridDecryptRef.current = handleHybridDecrypt;

    // ===== DIAGNOSTIC LOGGING =====
    // Production-visible logging for auto-decrypt decisions
    useEffect(() => {
        if (isOpen && rawUrl && file && !decryptedBlobUrl && !error) {
            console.warn('[Decrypt] Auto-decrypt evaluating:', {
                fileId: file.id,
                encryptionVersion,
                hasIv: !!encryptionIv,
                isUnlocked,
                isDecrypting,
                fileType: file.fileType,
            });
        }
    }, [isOpen, rawUrl, file, encryptionVersion, encryptionIv, isUnlocked, isDecrypting, decryptedBlobUrl, error]);

    // Detect missing encryption metadata for encrypted files
    // Without IV, decryption can never start — surface error instead of infinite spinner
    useEffect(() => {
        if (
            isOpen &&
            encryptionVersion === 4 &&
            rawUrl &&
            !encryptionIv &&
            file &&
            isUnlocked &&
            !decryptedBlobUrl &&
            !isDecrypting &&
            !error
        ) {
            const msg = `Missing encryption IV (version ${encryptionVersion}). This file may need to be re-uploaded.`;
            console.warn('[Decrypt] Missing IV for file', file.id, { encryptionVersion });
            setError(msg);
            toast.error('Cannot decrypt file', {
                description: msg,
            });
        }
    }, [isOpen, encryptionVersion, rawUrl, encryptionIv, file, isUnlocked, decryptedBlobUrl, isDecrypting, error]);

    // Auto-decrypt v4 (hybrid) files with Hybrid Secret Key when vault is unlocked
    // sigKeyReady gates decrypt until signer public key is resolved (or no signature)
    useEffect(() => {
        if (
            isOpen &&
            encryptionVersion === 4 &&
            rawUrl &&
            file &&
            isUnlocked &&
            sigKeyReady &&
            !decryptedBlobUrl &&
            !isDecrypting &&
            !error
        ) {
            console.warn('[Decrypt] Triggering V4 Hybrid PQC decryption for file', file.id);
            handleHybridDecryptRef.current();
        }
    }, [isOpen, encryptionVersion, rawUrl, file, isUnlocked, sigKeyReady, decryptedBlobUrl, isDecrypting, error]);

    // ===== CATCH-ALL: Detect stuck states =====
    // If rawUrl is available, vault is unlocked, but no decrypt started and no error,
    // the user would see an infinite spinner. Surface the issue instead.
    useEffect(() => {
        if (
            isOpen &&
            rawUrl &&
            file &&
            isUnlocked &&
            !decryptedBlobUrl &&
            !isDecrypting &&
            !error &&
            encryptionVersion !== 4
        ) {
            const msg = `Unsupported encryption version (${encryptionVersion}). This file may need to be re-uploaded with the current encryption system.`;
            console.warn('[Decrypt] Unsupported version for file', file.id, { encryptionVersion, encryptionIv });
            setError(msg);
            toast.error('Cannot decrypt file', { description: msg });
        }
    }, [isOpen, rawUrl, file, isUnlocked, decryptedBlobUrl, isDecrypting, error, encryptionVersion, encryptionIv]);

    // ===== CATCH-ALL: Vault locked =====
    // If the modal is open with a URL but vault is not unlocked, inform the user
    useEffect(() => {
        if (
            isOpen &&
            rawUrl &&
            file &&
            !isUnlocked &&
            !decryptedBlobUrl &&
            !isDecrypting &&
            !error
        ) {
            console.warn('[Decrypt] Vault is locked, cannot decrypt file', file.id);
            setError('Your vault is locked. Please unlock it to view this file.');
            toast.error('Vault is locked', {
                description: 'Please unlock your vault to view encrypted files.',
            });
        }
    }, [isOpen, rawUrl, file, isUnlocked, decryptedBlobUrl, isDecrypting, error]);

    // Cleanup blob URL when modal closes (using ref for current value).
    // Delay revocation to allow close animation to complete without flashing broken media.
    useEffect(() => {
        if (!isOpen && blobUrlRef.current) {
            const urlToRevoke = blobUrlRef.current;
            const timer = setTimeout(() => {
                URL.revokeObjectURL(urlToRevoke);
            }, 300);
            setDecryptedBlobUrl(null);
            return () => { clearTimeout(timer); };
        }
        return undefined;
    }, [isOpen]);

    const reset = useCallback(() => {
        setError(null);
        setIsDecrypting(false);
        setProgress(0);
        if (decryptedBlobUrl) {
            URL.revokeObjectURL(decryptedBlobUrl);
            setDecryptedBlobUrl(null);
        }
    }, [decryptedBlobUrl]);

    return {
        state: {
            isDecrypting,
            progress,
            error,
            decryptedBlobUrl,
        },
        signatureState,
        reset,
    };
}
