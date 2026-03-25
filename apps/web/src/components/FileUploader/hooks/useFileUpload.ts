/**
 * useFileUpload Hook
 *
 * Manages file upload logic including:
 * - Client-side encryption (mandatory via Master Key)
 * - Single-file and multipart uploads
 * - Progress tracking
 * - Error handling
 */

import { useState, useCallback, useRef, useEffect } from 'react';
import { trpc } from '@/lib/trpc';
import { toast } from 'sonner';
import { debugLog, debugWarn, debugError } from '@/lib/debugLogger';
import { encryptFilename, encryptThumbnail, decryptFilename } from '@/lib/fileCrypto';
import { encryptFileV4 } from '@/lib/fileEncryptor';
import { computeContentFingerprint } from '@/lib/contentFingerprint';
import {
    shouldUseMultipart,
    performMultipartUpload,
} from '@/lib/multipartUpload';
import { signEncryptedFile } from '@/lib/signedFileCrypto';
import { useMasterKey } from '@/hooks/useMasterKey';
import { useOrgMasterKey } from '@/hooks/useOrgMasterKey';
import { useOrganizationContext } from '@/contexts/OrganizationContext';
import { generateThumbnail, isThumbnailSupported } from '@/lib/thumbnailGenerator';
import type { UploadFile, EncryptedResult, EncryptionState, SignatureParams } from '../types';
import type { HybridSignatureSecretKey } from '@stenvault/shared/platform/crypto';
import type { DuplicateInfo, DuplicateAction } from '../components/DuplicateDialog';
import { getMimeType, isImageFile } from '../utils/mime-types';
import { useOperationStore } from '@/stores/operationStore';
import { STREAMING } from '@/lib/constants';

/** Server-side info tracked per upload for cleanup on cancel */
interface ServerUploadInfo {
    serverFileId: number;
    serverFileKey?: string;
    multipartUploadId?: string;
}

interface SigningContext {
    secretKey: HybridSignatureSecretKey;
    fingerprint: string;
    keyVersion: number;
}

interface UseFileUploadParams {
    folderId?: number | null;
    maxFiles: number;
    maxSize: number;
    onUploadComplete?: () => void;
    /** Signing context (secret key, fingerprint, keyVersion) - passed from parent */
    signingContext?: SigningContext | null;
    /** Show duplicate dialog and return user action (passed from parent component) */
    showDuplicateDialog?: (info: DuplicateInfo) => Promise<DuplicateAction>;
}

interface UseFileUploadReturn {
    // State
    uploadFiles: UploadFile[];
    isDragging: boolean;
    encryptionState: EncryptionState;
    isMultipartUpload: boolean;

    // File operations
    handleFiles: (fileList: FileList) => Promise<void>;
    handleFilesToFolder: (files: File[], targetFolderId: number | null) => Promise<void>;
    removeFile: (id: string) => void;
    retryFile: (id: string) => void;

    // Drag handlers
    handleDragOver: (e: React.DragEvent) => void;
    handleDragLeave: (e: React.DragEvent) => void;
    handleDrop: (e: React.DragEvent) => void;

    // Ref for file input
    fileInputRef: React.RefObject<HTMLInputElement | null>;
}

export function useFileUpload({
    folderId,
    maxFiles,
    maxSize,
    onUploadComplete,
    signingContext,
    showDuplicateDialog,
}: UseFileUploadParams): UseFileUploadReturn {
    // ===== UPLOAD STATE =====
    const [uploadFiles, setUploadFiles] = useState<UploadFile[]>([]);
    const [isDragging, setIsDragging] = useState(false);
    const [isMultipartUpload, setIsMultipartUpload] = useState(false);
    const fileInputRef = useRef<HTMLInputElement>(null);

    // ===== MASTER KEY (Encryption is mandatory) =====
    const { isUnlocked, isConfigured, deriveFilenameKey, deriveFingerprintKey, deriveThumbnailKey, getHybridPublicKey } = useMasterKey();
    const useMasterKeyEncryption = isConfigured && isUnlocked;

    // ===== ORG CONTEXT (Vault Model) =====
    const { currentOrgId } = useOrganizationContext();
    const {
        unlockOrgVault,
        deriveOrgFilenameKey: _deriveOrgFilenameKey,
        deriveOrgThumbnailKey: _deriveOrgThumbnailKey,
        getOrgKeyVersion,
    } = useOrgMasterKey();

    // ===== TRPC =====
    const trpcUtils = trpc.useUtils();
    const { data: multipartConfig } = trpc.files.getMultipartConfig.useQuery();
    const getUploadUrl = trpc.files.getUploadUrl.useMutation();
    const checkDuplicate = trpc.files.checkDuplicate.useMutation();
    const confirmUpload = trpc.files.confirmUpload.useMutation({
        onSuccess: () => {
            trpcUtils.files.list.invalidate();
            trpcUtils.files.getStorageStats.invalidate();
        },
    });
    const cancelUpload = trpc.files.cancelUpload.useMutation({
        onSuccess: () => {
            // Invalidate file list to remove ghost entries after cleanup
            trpcUtils.files.list.invalidate();
            trpcUtils.files.getStorageStats.invalidate();
        },
    });
    const getThumbnailUploadUrl = trpc.files.getThumbnailUploadUrl.useMutation(); // Phase 7.2
    const initiateMultipart = trpc.files.initiateMultipartUpload.useMutation();
    const getPartUrl = trpc.files.getUploadPartUrl.useMutation();
    const completeMultipart = trpc.files.completeMultipartUpload.useMutation({
        onSuccess: () => {
            trpcUtils.files.list.invalidate();
            trpcUtils.files.getStorageStats.invalidate();
        },
    });
    const abortMultipart = trpc.files.abortMultipartUpload.useMutation();

    // ===== SERVER INFO REF (for cleanup on cancel) =====
    // Tracks server-side file info per upload ID so removeFile can roll back quota
    const serverInfoRef = useRef<Map<string, ServerUploadInfo>>(new Map());

    // ===== CLEANUP PREVIEWS ON UNMOUNT =====
    const uploadFilesRef = useRef<UploadFile[]>([]);
    uploadFilesRef.current = uploadFiles;
    useEffect(() => {
        return () => {
            uploadFilesRef.current.forEach(f => {
                if (f.previewUrl) URL.revokeObjectURL(f.previewUrl);
            });
        };
    }, []);

    // ===== CLEANUP SERVER UPLOAD (fire-and-forget) =====
    const cleanupServerUpload = useCallback((uploadId: string) => {
        const info = serverInfoRef.current.get(uploadId);
        if (!info) return;

        serverInfoRef.current.delete(uploadId);

        if (info.multipartUploadId && info.serverFileKey) {
            // Multipart: abort in R2 + delete record + rollback quota
            abortMultipart.mutateAsync({
                fileId: info.serverFileId,
                uploadId: info.multipartUploadId,
                fileKey: info.serverFileKey,
            }).catch((err) => {
                debugWarn('[UPLOAD]', 'Failed to abort multipart on cancel', err);
                // Fallback: try cancelUpload (handles DB + quota even if R2 abort fails)
                cancelUpload.mutateAsync({ fileId: info.serverFileId }).catch(() => {});
            });
        } else {
            // Single upload: delete record + rollback quota + clean R2
            cancelUpload.mutateAsync({ fileId: info.serverFileId }).catch((err) => {
                debugWarn('[UPLOAD]', 'Failed to cancel upload on server', err);
            });
        }
    }, [abortMultipart, cancelUpload]);

    // ===== CONSTANTS =====
    /** Skip fingerprint (duplicate detection) for files larger than 100MB to avoid main-thread freeze */
    const FINGERPRINT_MAX_SIZE = 100 * 1024 * 1024;

    // ===== PROCESS SINGLE UPLOAD =====
    const processUpload = useCallback(async (uploadFile: UploadFile, targetFolderId?: number | null) => {
        const effectiveFolderId = targetFolderId !== undefined ? targetFolderId : folderId;
        const { file, id } = uploadFile;

        // Create AbortController for this upload — allows cancellation at any stage
        const abortController = new AbortController();
        const { signal } = abortController;

        // Validate file size
        if (file.size > maxSize) {
            const errorMsg = `File too large: ${file.name} is ${Math.round(file.size / 1024 / 1024)}MB but max is ${Math.round(maxSize / 1024 / 1024)}MB`;
            debugWarn('[WARN]', 'Size validation failed: ' + errorMsg);
            toast.error(errorMsg);
            setUploadFiles((prev) =>
                prev.map((f) =>
                    f.id === id
                        ? { ...f, status: 'error', error: `File too large (max ${Math.round(maxSize / 1024 / 1024)}MB)` }
                        : f
                )
            );
            return;
        }

        // Vault must be unlocked for upload
        if (!useMasterKeyEncryption) {
            setUploadFiles((prev) =>
                prev.map((f) =>
                    f.id === id
                        ? { ...f, status: 'error', error: 'Vault is locked. Please unlock your vault to upload files.' }
                        : f
                )
            );
            toast.error('Vault is locked. Please unlock your vault to upload files.');
            return;
        }

        // Phase 5 Zero-Knowledge: Encrypted filename data
        let encryptedFilenameData: { encryptedFilename: string; filenameIv: string; plaintextExtension: string } | null = null;

        // Track in global operation store (survives navigation)
        const opId = useOperationStore.getState().addOperation({ id, type: 'upload', filename: file.name, status: 'encrypting', abortController });

        try {
            console.warn('[Upload] Starting upload pipeline for:', file.name, file.size, 'bytes');

            // Set encrypting status (covers prep + file encryption)
            setUploadFiles((prev) =>
                prev.map((f) => (f.id === id ? { ...f, status: 'encrypting' } : f))
            );

            const contentType = getMimeType(file);

            // ===== ORG VAULT: Ensure unlocked if uploading to org =====
            const uploadOrgId = currentOrgId;
            let orgKeyVer: number | undefined;
            if (uploadOrgId) {
                await unlockOrgVault(uploadOrgId);
                orgKeyVer = getOrgKeyVersion(uploadOrgId) ?? undefined;
                debugLog('[ORG]', 'Uploading to org vault', { orgId: uploadOrgId, keyVersion: orgKeyVer });
            }

            // ===== PHASE 5: ENCRYPT FILENAME (Zero-Knowledge) =====
            // Filename encryption is independent of fileId - can happen first
            try {
                const filenameKey = uploadOrgId
                    ? await _deriveOrgFilenameKey(uploadOrgId)
                    : await deriveFilenameKey();
                const { encryptedFilename, iv: filenameIv } = await encryptFilename(file.name, filenameKey);
                const parts = file.name.split('.');
                const extension = parts.length > 1 ? `.${parts.pop()}` : '';

                encryptedFilenameData = {
                    encryptedFilename,
                    filenameIv,
                    plaintextExtension: extension,
                };

                debugLog('[CRYPTO]', 'Filename encrypted', { hasEncrypted: true, extension });
            } catch (filenameErr) {
                toast.error("Failed to encrypt filename. Upload cancelled.");
                throw filenameErr; // re-throw to abort upload
            }

            // Zero-knowledge: Send opaque filename to server (never plaintext)
            const opaqueFilename = `encrypted${encryptedFilenameData?.plaintextExtension || ''}`;

            // ===== QUANTUM-SAFE DUPLICATE DETECTION =====
            // Compute HMAC-SHA-256 fingerprint of plaintext file before encryption.
            // Non-fatal: if fingerprint fails, proceed with upload (dedup is convenience, not a gate).
            // Skip for large files (>100MB) to avoid main-thread freeze from file.arrayBuffer().
            let contentHash: string | undefined;
            if (showDuplicateDialog && !uploadOrgId && file.size < FINGERPRINT_MAX_SIZE) {
                try {
                    const fpKey = await deriveFingerprintKey();
                    contentHash = await computeContentFingerprint(file, fpKey);

                    const dupResult = await checkDuplicate.mutateAsync({
                        contentHash,
                        size: file.size,
                        folderId: effectiveFolderId ?? undefined,
                    });

                    if (dupResult.isDuplicate) {
                        // Decrypt existing filename for display
                        let existingName = '[Encrypted]';
                        if (dupResult.existingEncryptedFilename && dupResult.existingFilenameIv) {
                            try {
                                const fnKey = await deriveFilenameKey();
                                existingName = await decryptFilename(
                                    dupResult.existingEncryptedFilename,
                                    fnKey,
                                    dupResult.existingFilenameIv,
                                );
                            } catch {
                                // Decryption failed — use fallback
                            }
                        }

                        const action = await showDuplicateDialog({
                            newFileName: file.name,
                            newFileSize: file.size,
                            existingFileName: existingName,
                            existingSize: dupResult.existingSize ?? file.size,
                            existingFolderId: dupResult.existingFolderId ?? null,
                            existingCreatedAt: new Date(dupResult.existingCreatedAt ?? Date.now()),
                        });

                        if (action === 'skip') {
                            setUploadFiles((prev) =>
                                prev.map((f) =>
                                    f.id === id ? { ...f, status: 'completed', progress: 100 } : f
                                )
                            );
                            debugLog('[FP]', 'Duplicate skipped by user', { contentHash });
                            return;
                        }
                    }
                } catch (fpError) {
                    debugWarn('[FP]', 'Fingerprint/dedup check failed (non-fatal), proceeding with upload', fpError);
                }
            } else if (file.size >= FINGERPRINT_MAX_SIZE) {
                toast.info('Large file — duplicate check skipped');
            }

            // ===== ESTIMATE ENCRYPTED SIZE =====
            // Rough estimate for quota reservation. Presigned URL doesn't sign ContentLength.
            // confirmUpload corrects to actual R2 size via HeadObject.
            // V4: +~800 bytes (CVEF header) or +~5,200 bytes (CVEF + signature)
            // V4 chunked (>threshold): +5,000 + Math.ceil(size/64KB) * 20 (per-chunk overhead)
            const isStreaming = file.size >= STREAMING.THRESHOLD_BYTES;
            const chunkOverhead = isStreaming
                ? Math.ceil(file.size / 65536) * 20  // 4 bytes length prefix + 16 bytes auth tag per chunk
                : 0;
            const estimatedEncryptedSize = file.size + 6000 + chunkOverhead; // 6KB covers CVEF + signature worst case

            // ===== FETCH HYBRID PUBLIC KEY (V4 mandatory) =====
            // For org files, fetch the org's hybrid public key; for personal, use user's
            console.warn('[Upload] Fetching hybrid public key...');
            let hybridPublicKey: import('@stenvault/shared/platform/crypto').HybridPublicKey;
            if (uploadOrgId) {
                const orgPubKeyData = await trpcUtils.orgKeys.getOrgHybridPublicKey.fetch({ organizationId: uploadOrgId });
                const { toHybridPublicKey } = await import('@/lib/orgHybridCrypto');
                hybridPublicKey = toHybridPublicKey(orgPubKeyData);
            } else {
                hybridPublicKey = await getHybridPublicKey();
            }
            console.warn('[Upload] Hybrid public key obtained', {
                classical: hybridPublicKey.classical.length,
                pq: hybridPublicKey.postQuantum.length,
            });

            // ===== GET FILE ID FROM SERVER (BEFORE encryption) =====
            // This ensures the HKDF info string uses the real database fileId+createdAt
            const multipartThreshold = multipartConfig?.threshold ?? 500 * 1024 * 1024;
            const useMultipart = shouldUseMultipart(estimatedEncryptedSize, multipartThreshold);

            let serverFileId: number;
            let serverCreatedAt: Date;
            let uploadUrl: string | undefined;
            let multipartParams: { uploadId: string; fileKey: string; partSize: number; totalParts: number } | undefined;

            const uploadContentType = 'application/octet-stream';

            if (useMultipart) {
                const result = await initiateMultipart.mutateAsync({
                    filename: opaqueFilename,
                    contentType: uploadContentType,
                    size: estimatedEncryptedSize,
                    folderId: effectiveFolderId,
                    organizationId: uploadOrgId,
                    encryptedFilename: encryptedFilenameData?.encryptedFilename,
                    filenameIv: encryptedFilenameData?.filenameIv,
                    plaintextExtension: encryptedFilenameData?.plaintextExtension,
                    originalMimeType: file.type || undefined,
                });
                serverFileId = result.fileId;
                serverCreatedAt = new Date(result.createdAt);
                multipartParams = {
                    uploadId: result.uploadId,
                    fileKey: result.fileKey,
                    partSize: result.partSize,
                    totalParts: result.totalParts,
                };
            } else {
                const result = await getUploadUrl.mutateAsync({
                    filename: opaqueFilename,
                    contentType: uploadContentType,
                    size: estimatedEncryptedSize,
                    folderId: effectiveFolderId,
                    organizationId: uploadOrgId,
                    encryptedFilename: encryptedFilenameData?.encryptedFilename,
                    filenameIv: encryptedFilenameData?.filenameIv,
                    plaintextExtension: encryptedFilenameData?.plaintextExtension,
                    originalMimeType: file.type || undefined,
                });
                serverFileId = result.fileId;
                serverCreatedAt = new Date(result.createdAt);
                uploadUrl = result.uploadUrl;
            }

            // Track server info for cleanup on cancel
            serverInfoRef.current.set(id, {
                serverFileId,
                serverFileKey: useMultipart ? multipartParams?.fileKey : undefined,
                multipartUploadId: useMultipart ? multipartParams?.uploadId : undefined,
            });

            debugLog('[UPLOAD]', 'Got fileId from server BEFORE encryption', {
                fileId: serverFileId,
                createdAt: serverCreatedAt.toISOString(),
                useMultipart,
            });

            // ===== CLIENT-SIDE ENCRYPTION (using real fileId + createdAt) =====
            let encryptedResult: EncryptedResult | null = null;
            let uploadBlob: Blob = file;
            let uploadSize = file.size;

            setUploadFiles(prev => prev.map(f => f.id === id ? { ...f, status: 'encrypting', progress: 0 } : f));

            try {
                // ===== HYBRID ENCRYPTION (V4 only — PQC mandatory) =====
                console.warn('[Upload] Starting V4 encryption, fileId:', serverFileId, 'size:', file.size);

                const hybridResult = await encryptFileV4(file, hybridPublicKey, {
                    signal,
                    onProgress: (p) => {
                        setUploadFiles(prev => prev.map(f => f.id === id ? { ...f, progress: p.percentage } : f));
                        useOperationStore.getState().updateProgress(opId, { status: 'encrypting', progress: p.percentage });
                    },
                });

                uploadBlob = hybridResult.blob;
                uploadSize = hybridResult.blob.size;

                encryptedResult = {
                    blob: hybridResult.blob,
                    iv: hybridResult.metadata.iv,
                    salt: '', // Not used in hybrid mode
                    version: 4,
                };

                debugLog('[CRYPTO]', 'Hybrid encryption complete', {
                    originalSize: file.size,
                    encryptedSize: uploadSize,
                    version: 4,
                    algorithm: hybridResult.metadata.pqcParams?.kemAlgorithm,
                });
            } catch (encryptError) {
                console.warn('[Upload] Encryption FAILED:', encryptError);
                setUploadFiles((prev) =>
                    prev.map((f) =>
                        f.id === id
                            ? { ...f, status: 'error', error: 'Encryption failed. Please try again.' }
                            : f
                    )
                );
                useOperationStore.getState().failOperation(opId, 'Encryption failed');

                // Clean up server record + rollback quota
                cleanupServerUpload(id);
                return;
            }

            // Encryption done — transition to uploading
            setUploadFiles(prev => prev.map(f => f.id === id ? { ...f, status: 'uploading', progress: 0 } : f));
            useOperationStore.getState().updateProgress(opId, { status: 'uploading', progress: 0 });

            // ===== PHASE 7.2: GENERATE THUMBNAIL (plaintext) =====
            let rawThumbnailBlob: Blob | null = null;

            if (isThumbnailSupported(contentType)) {
                try {
                    debugLog('[THUMB]', 'Generating thumbnail client-side', { mimeType: contentType });
                    const thumbnailResult = await generateThumbnail(file);
                    if (thumbnailResult) {
                        rawThumbnailBlob = thumbnailResult.blob;
                        debugLog('[THUMB]', 'Thumbnail generated', {
                            size: thumbnailResult.size,
                            dimensions: `${thumbnailResult.width}x${thumbnailResult.height}`,
                        });
                    }
                } catch (thumbnailError) {
                    debugWarn('[THUMB]', 'Failed to generate thumbnail, continuing without', thumbnailError);
                }
            }

            // ===== HYBRID SIGNATURE (Phase 3.4 Sovereign) =====
            let signatureParams: SignatureParams | undefined;
            let finalUploadBlob = uploadBlob;

            if (encryptedResult && signingContext) {
                try {
                    debugLog('[SIG]', 'Signing encrypted file', {
                        fingerprint: signingContext.fingerprint,
                        keyVersion: signingContext.keyVersion,
                    });

                    const signedResult = await signEncryptedFile(uploadBlob, {
                        secretKey: signingContext.secretKey,
                        fingerprint: signingContext.fingerprint,
                        keyVersion: signingContext.keyVersion,
                        context: 'FILE',
                    });

                    finalUploadBlob = signedResult.blob;
                    uploadSize = signedResult.blob.size;

                    const sig = signedResult.metadata.signatureParams!;
                    if (sig.signatureAlgorithm === 'ed25519-ml-dsa-65') {
                        signatureParams = {
                            classicalSignature: sig.classicalSignature,
                            pqSignature: sig.pqSignature,
                            signingContext: sig.signingContext,
                            signedAt: sig.signedAt,
                            signerFingerprint: sig.signerFingerprint,
                            signerKeyVersion: sig.signerKeyVersion,
                        };
                    }

                    debugLog('[SIG]', 'File signed successfully', {
                        signedAt: sig.signedAt,
                        originalSize: encryptedResult.blob.size,
                        signedSize: signedResult.blob.size,
                    });
                } catch (signError) {
                    debugWarn('[SIG]', 'Failed to sign file, uploading unsigned', signError);
                    toast.warning('File will be uploaded without signature', {
                        description: signError instanceof Error ? signError.message : 'Signing failed',
                    });
                }
            }

            // ===== THUMBNAIL KEY DERIVATION (org-aware) =====
            const effectiveThumbnailKey = uploadOrgId
                ? (fileId: string) => _deriveOrgThumbnailKey(uploadOrgId, fileId)
                : deriveThumbnailKey;

            // ===== UPLOAD (server call already done, just need to upload blob) =====
            if (useMultipart && multipartParams) {
                await performMultipartUploadFlow({
                    id,
                    file,
                    uploadBlob: finalUploadBlob,
                    uploadSize,
                    encryptedResult,
                    signatureParams,
                    rawThumbnailBlob,
                    serverFileId,
                    multipartParams,
                    setIsMultipartUpload,
                    setUploadFiles,
                    getPartUrl,
                    completeMultipart,
                    abortMultipart,
                    getThumbnailUploadUrl,
                    deriveThumbnailKey: effectiveThumbnailKey,
                    orgKeyVersion: orgKeyVer,
                    contentHash,
                    operationId: opId,
                });
            } else if (uploadUrl) {
                await performSingleUpload({
                    id,
                    file,
                    uploadBlob: finalUploadBlob,
                    uploadSize,
                    uploadContentType,
                    encryptedResult,
                    signatureParams,
                    rawThumbnailBlob,
                    serverFileId,
                    uploadUrl,
                    setUploadFiles,
                    confirmUpload,
                    getThumbnailUploadUrl,
                    deriveThumbnailKey: effectiveThumbnailKey,
                    orgKeyVersion: orgKeyVer,
                    contentHash,
                    operationId: opId,
                    signal,
                });
            }

            // Upload succeeded — clear server info (no cleanup needed)
            serverInfoRef.current.delete(id);
            useOperationStore.getState().completeOperation(opId);
        } catch (error) {
            // Handle cancellation silently — no error toast, just cleanup
            if (error instanceof DOMException && error.name === 'AbortError') {
                setUploadFiles((prev) => prev.filter((f) => f.id !== id));
                cleanupServerUpload(id);
                return;
            }

            const message = error instanceof Error ? error.message : 'Upload failed';
            const msg = message.toLowerCase();
            let hint: string;
            if (msg.includes('network') || msg.includes('fetch') || msg.includes('failed to fetch') || msg.includes('networkerror')) {
                hint = 'Check your connection and try again';
            } else if (msg.includes('401') || msg.includes('403') || msg.includes('unauthorized') || msg.includes('session')) {
                hint = 'Session expired — please reload';
            } else if (msg.includes('quota') || msg.includes('storage')) {
                hint = 'Storage full — free up space or upgrade';
            } else {
                hint = `Failed to upload ${file.name}`;
            }
            setUploadFiles((prev) =>
                prev.map((f) =>
                    f.id === id ? { ...f, status: 'error', error: message } : f
                )
            );
            toast.error(hint);
            useOperationStore.getState().failOperation(opId, message);

            // Clean up server record + rollback quota (if server record was created)
            cleanupServerUpload(id);
        }
    }, [maxSize, multipartConfig, folderId, getUploadUrl, confirmUpload, cleanupServerUpload, initiateMultipart, getPartUrl, completeMultipart, abortMultipart, signingContext, useMasterKeyEncryption, deriveFilenameKey, deriveFingerprintKey, getHybridPublicKey, deriveThumbnailKey, getThumbnailUploadUrl, currentOrgId, unlockOrgVault, getOrgKeyVersion, _deriveOrgFilenameKey, _deriveOrgThumbnailKey, trpcUtils, showDuplicateDialog, checkDuplicate]);

    // ===== HANDLE FILES DROP/SELECT =====
    const handleFiles = useCallback(async (fileList: FileList) => {
        const files = Array.from(fileList);

        debugLog('[FILES]', 'handleFiles called', {
            fileCount: files.length,
            files: files.map(f => ({ name: f.name, size: f.size, sizeMB: Math.round(f.size / 1024 / 1024) })),
            maxSize,
            maxSizeMB: Math.round(maxSize / 1024 / 1024),
        });

        if (files.length > maxFiles) {
            toast.error(`Maximum ${maxFiles} files allowed at once`);
            return;
        }

        const newUploadFiles: UploadFile[] = files.map((file) => {
            const previewUrl = isImageFile(file)
                ? URL.createObjectURL(file)
                : undefined;

            return {
                id: crypto.randomUUID(),
                file,
                progress: 0,
                status: 'pending' as const,
                previewUrl,
            };
        });

        setUploadFiles((prev) => [...prev, ...newUploadFiles]);

        // Process uploads in parallel batches
        const CONCURRENCY = 3;
        for (let i = 0; i < newUploadFiles.length; i += CONCURRENCY) {
            const batch = newUploadFiles.slice(i, i + CONCURRENCY);
            await Promise.all(batch.map(f => processUpload(f)));
        }

        onUploadComplete?.();
    }, [maxFiles, maxSize, onUploadComplete, processUpload]);

    // ===== HANDLE FILES TO SPECIFIC FOLDER (for folder upload) =====
    const handleFilesToFolder = useCallback(async (files: File[], targetFolderId: number | null) => {
        const newUploadFiles: UploadFile[] = files.map((file) => {
            // For folder uploads, use just the filename (last segment) for display
            const displayName = file.name.includes('/') ? file.name.split('/').pop()! : file.name;
            const displayFile = new File([file], displayName, { type: file.type, lastModified: file.lastModified });
            const previewUrl = isImageFile(displayFile) ? URL.createObjectURL(displayFile) : undefined;
            return {
                id: crypto.randomUUID(),
                file: displayFile,
                progress: 0,
                status: 'pending' as const,
                previewUrl,
            };
        });

        setUploadFiles((prev) => [...prev, ...newUploadFiles]);

        const CONCURRENCY = 3;
        for (let i = 0; i < newUploadFiles.length; i += CONCURRENCY) {
            const batch = newUploadFiles.slice(i, i + CONCURRENCY);
            await Promise.all(batch.map(f => processUpload(f, targetFolderId)));
        }
    }, [processUpload]);

    // ===== REMOVE FILE =====
    const removeFile = useCallback((id: string) => {
        // Cancel any in-flight encryption/upload via AbortController
        useOperationStore.getState().cancelOperation(id);

        setUploadFiles((prev) => {
            const fileToRemove = prev.find(f => f.id === id);
            if (fileToRemove?.previewUrl) {
                URL.revokeObjectURL(fileToRemove.previewUrl);
            }
            // Only clean up server-side for non-completed uploads
            if (fileToRemove && fileToRemove.status !== 'completed') {
                cleanupServerUpload(id);
            }
            return prev.filter((f) => f.id !== id);
        });
    }, [cleanupServerUpload]);

    // ===== RETRY FILE =====
    const retryFile = useCallback((id: string) => {
        const fileToRetry = uploadFilesRef.current.find(f => f.id === id && f.status === 'error');
        if (!fileToRetry) return;

        // Reset status and re-process
        setUploadFiles((prev) =>
            prev.map((f) => f.id === id ? { ...f, status: 'pending', progress: 0, error: undefined } : f)
        );
        processUpload({ ...fileToRetry, status: 'pending', progress: 0, error: undefined });
    }, [processUpload]);

    // ===== DRAG HANDLERS =====
    const handleDragOver = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(true);
    }, []);

    const handleDragLeave = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);
    }, []);

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);
        if (e.dataTransfer.files.length > 0) {
            handleFiles(e.dataTransfer.files);
        }
    }, [handleFiles]);

    return {
        uploadFiles,
        isDragging,
        encryptionState: (() => {
            const encrypting = uploadFiles.filter(f => f.status === 'encrypting');
            const avgProgress = encrypting.length > 0
                ? Math.round(encrypting.reduce((sum, f) => sum + f.progress, 0) / encrypting.length)
                : 0;
            return {
                isEncrypting: encrypting.length > 0,
                encryptingCount: encrypting.length,
                totalCount: uploadFiles.length,
                progress: avgProgress,
            };
        })(),
        isMultipartUpload,
        handleFiles,
        handleFilesToFolder,
        removeFile,
        retryFile,
        handleDragOver,
        handleDragLeave,
        handleDrop,
        fileInputRef,
    };
}

// ===== HELPER FUNCTIONS =====

interface PartUrlInput {
    fileId: number;
    uploadId: string;
    fileKey: string;
    partNumber: number;
    partSize: number;
}

interface CompleteMultipartInput {
    fileId: number;
    uploadId: string;
    fileKey: string;
    parts: { partNumber: number; etag: string }[];
    encryptionIv?: string;
    encryptionSalt?: string;
    encryptionVersion?: number;
    orgKeyVersion?: number;
    signatureParams?: SignatureParams;
    thumbnailMetadata?: { thumbnailKey: string; thumbnailIv: string; thumbnailSize: number };
    contentHash?: string;
    fingerprintVersion?: number;
}

interface CompleteMultipartOutput {
    success: boolean;
    fileId: number;
    message: string;
}

interface AbortMultipartInput {
    fileId: number;
    uploadId: string;
    fileKey: string;
}

interface AbortMultipartOutput {
    success: boolean;
    message: string;
}

interface MultipartUploadParams {
    id: string;
    file: File;
    uploadBlob: Blob;
    uploadSize: number;
    encryptedResult: EncryptedResult | null;
    signatureParams?: SignatureParams;
    rawThumbnailBlob?: Blob | null;
    serverFileId: number;
    multipartParams: { uploadId: string; fileKey: string; partSize: number; totalParts: number };
    setIsMultipartUpload: (v: boolean) => void;
    setUploadFiles: React.Dispatch<React.SetStateAction<UploadFile[]>>;
    getPartUrl: { mutateAsync: (p: PartUrlInput) => Promise<{ uploadUrl: string }> };
    completeMultipart: { mutateAsync: (p: CompleteMultipartInput) => Promise<CompleteMultipartOutput> };
    abortMultipart: { mutateAsync: (p: AbortMultipartInput) => Promise<AbortMultipartOutput> };
    getThumbnailUploadUrl: { mutateAsync: (p: { fileId: number; size: number }) => Promise<{ uploadUrl: string; thumbnailKey: string; expiresIn: number }> };
    deriveThumbnailKey: (fileId: string) => Promise<CryptoKey>;
    orgKeyVersion?: number;
    contentHash?: string;
    operationId?: string;
}

async function performMultipartUploadFlow(params: MultipartUploadParams) {
    const {
        id, file, uploadBlob, uploadSize,
        encryptedResult, signatureParams, rawThumbnailBlob,
        serverFileId, multipartParams,
        setIsMultipartUpload, setUploadFiles,
        getPartUrl, completeMultipart, abortMultipart, getThumbnailUploadUrl, deriveThumbnailKey,
        orgKeyVersion, contentHash, operationId,
    } = params;

    const { uploadId, fileKey, partSize, totalParts } = multipartParams;
    const fileId = serverFileId;

    setIsMultipartUpload(true);
    debugLog('[UPLOAD]', 'Using MULTIPART upload for large file', { fileId, uploadSize, totalParts });

    try {
        try {
            const parts = await performMultipartUpload(uploadBlob, {
                partSize,
                getPartUrl: async (partNumber, partSizeBytes) => {
                    const { uploadUrl } = await getPartUrl.mutateAsync({
                        fileId,
                        uploadId,
                        fileKey,
                        partNumber,
                        partSize: partSizeBytes,
                    });
                    return uploadUrl;
                },
                onProgress: (progress) => {
                    setUploadFiles((prev) =>
                        prev.map((f) =>
                            f.id === id ? { ...f, progress: progress.percentage } : f
                        )
                    );
                    if (operationId) {
                        useOperationStore.getState().updateProgress(operationId, { progress: progress.percentage });
                    }
                },
            });

            debugLog('[UPLOAD]', 'All parts uploaded: ' + parts.length);

            // ===== PHASE 7.2: ENCRYPT AND UPLOAD THUMBNAIL (using real fileId) =====
            let thumbnailMetadata: { thumbnailKey: string; thumbnailIv: string; thumbnailSize: number } | undefined;

            if (rawThumbnailBlob) {
                try {
                    // Derive thumbnail key using REAL database fileId (consistent with decryption)
                    const thumbCryptoKey = await deriveThumbnailKey(fileId.toString());
                    const encrypted = await encryptThumbnail(rawThumbnailBlob, thumbCryptoKey);

                    // Get presigned URL for thumbnail upload
                    const { uploadUrl: thumbnailUploadUrl, thumbnailKey } = await getThumbnailUploadUrl.mutateAsync({
                        fileId,
                        size: encrypted.size,
                    });

                    // Upload encrypted thumbnail to R2
                    const thumbnailResponse = await fetch(thumbnailUploadUrl, {
                        method: 'PUT',
                        body: encrypted.encryptedBlob,
                        headers: { 'Content-Type': 'application/octet-stream' },
                    });

                    if (!thumbnailResponse.ok) {
                        throw new Error(`Thumbnail upload failed: ${thumbnailResponse.status}`);
                    }

                    thumbnailMetadata = {
                        thumbnailKey,
                        thumbnailIv: encrypted.iv,
                        thumbnailSize: encrypted.size,
                    };

                    debugLog('[THUMB]', 'Encrypted thumbnail uploaded (multipart)', { fileId, thumbnailKey });
                } catch (thumbnailUploadError) {
                    debugWarn('[THUMB]', 'Failed to upload thumbnail for multipart, continuing without', thumbnailUploadError);
                }
            }

            await completeMultipart.mutateAsync({
                fileId,
                uploadId,
                fileKey,
                parts,
                encryptionIv: encryptedResult?.iv,
                encryptionSalt: encryptedResult?.salt,
                encryptionVersion: encryptedResult?.version,
                orgKeyVersion,
                signatureParams,
                thumbnailMetadata, // Phase 7.2
                contentHash,
                fingerprintVersion: contentHash ? 1 : undefined,
            });

            setUploadFiles((prev) =>
                prev.map((f) =>
                    f.id === id ? { ...f, status: 'completed', progress: 100 } : f
                )
            );

            toast.success(`${file.name} uploaded successfully`);
        } catch (uploadError) {
            debugError('[UPLOAD]', 'Multipart upload failed, aborting', uploadError);
            try {
                await abortMultipart.mutateAsync({ fileId, uploadId, fileKey });
            } catch (abortError) {
                debugError('[UPLOAD]', 'Failed to abort multipart', abortError);
            }
            throw uploadError;
        }
    } finally {
        setIsMultipartUpload(false);
    }
}

interface ConfirmUploadInput {
    fileId: number;
    encryptionIv?: string;
    encryptionSalt?: string;
    encryptionVersion?: number;
    orgKeyVersion?: number;
    signatureParams?: SignatureParams;
    thumbnailMetadata?: { thumbnailKey: string; thumbnailIv: string; thumbnailSize: number };
    contentHash?: string;
    fingerprintVersion?: number;
}

interface ConfirmUploadOutput {
    success: boolean;
    file: {
        id: number;
        filename: string;
        mimeType: string | null;
        size: number;
        createdAt: Date;
    };
}

interface SingleUploadParams {
    id: string;
    file: File;
    uploadBlob: Blob;
    uploadSize: number;
    uploadContentType: string;
    encryptedResult: EncryptedResult | null;
    signatureParams?: SignatureParams;
    rawThumbnailBlob?: Blob | null;
    serverFileId: number;
    uploadUrl: string;
    setUploadFiles: React.Dispatch<React.SetStateAction<UploadFile[]>>;
    confirmUpload: { mutateAsync: (p: ConfirmUploadInput) => Promise<ConfirmUploadOutput> };
    getThumbnailUploadUrl: { mutateAsync: (p: { fileId: number; size: number }) => Promise<{ uploadUrl: string; thumbnailKey: string; expiresIn: number }> };
    deriveThumbnailKey: (fileId: string) => Promise<CryptoKey>;
    orgKeyVersion?: number;
    contentHash?: string;
    operationId?: string;
    signal?: AbortSignal;
}

async function performSingleUpload(params: SingleUploadParams) {
    const {
        id, file, uploadBlob, uploadSize, uploadContentType,
        encryptedResult, signatureParams, rawThumbnailBlob,
        serverFileId, uploadUrl,
        setUploadFiles, confirmUpload, getThumbnailUploadUrl, deriveThumbnailKey,
        orgKeyVersion, contentHash, operationId, signal,
    } = params;

    const fileId = serverFileId;

    debugLog('[UPLOAD]', 'Starting single upload to R2', { fileId, size: uploadSize });

    await new Promise<void>((resolve, reject) => {
        if (signal?.aborted) {
            reject(new DOMException('Aborted', 'AbortError'));
            return;
        }

        const xhr = new XMLHttpRequest();

        // Wire AbortSignal to XHR
        const onAbort = () => {
            xhr.abort();
        };
        signal?.addEventListener('abort', onAbort);

        xhr.upload.addEventListener('progress', (event) => {
            if (event.lengthComputable) {
                const progress = Math.round((event.loaded / event.total) * 100);
                setUploadFiles((prev) =>
                    prev.map((f) => (f.id === id ? { ...f, progress } : f))
                );
                if (operationId) {
                    useOperationStore.getState().updateProgress(operationId, { progress });
                }
            }
        });

        xhr.addEventListener('load', () => {
            signal?.removeEventListener('abort', onAbort);
            debugLog('[UPLOAD]', 'Upload response', { status: xhr.status });
            if (xhr.status >= 200 && xhr.status < 300) {
                resolve();
            } else {
                reject(new Error(`Upload failed: ${xhr.status} - ${xhr.responseText}`));
            }
        });

        xhr.addEventListener('error', (e) => {
            signal?.removeEventListener('abort', onAbort);
            debugError('[UPLOAD]', 'Upload XHR error', e);
            reject(new Error('Upload failed - network error'));
        });

        xhr.addEventListener('abort', () => {
            signal?.removeEventListener('abort', onAbort);
            reject(new DOMException('Aborted', 'AbortError'));
        });

        xhr.open('PUT', uploadUrl);
        xhr.setRequestHeader('Content-Type', uploadContentType);
        xhr.send(uploadBlob);
    });

    // ===== PHASE 7.2: ENCRYPT AND UPLOAD THUMBNAIL (using real fileId) =====
    let thumbnailMetadata: { thumbnailKey: string; thumbnailIv: string; thumbnailSize: number } | undefined;

    if (rawThumbnailBlob) {
        try {
            // Derive thumbnail key using REAL database fileId (consistent with decryption)
            const thumbCryptoKey = await deriveThumbnailKey(fileId.toString());
            const encrypted = await encryptThumbnail(rawThumbnailBlob, thumbCryptoKey);

            // Get presigned URL for thumbnail upload
            const { uploadUrl: thumbnailUploadUrl, thumbnailKey } = await getThumbnailUploadUrl.mutateAsync({
                fileId,
                size: encrypted.size,
            });

            // Upload encrypted thumbnail to R2
            const thumbnailResponse = await fetch(thumbnailUploadUrl, {
                method: 'PUT',
                body: encrypted.encryptedBlob,
                headers: { 'Content-Type': 'application/octet-stream' },
            });

            if (!thumbnailResponse.ok) {
                throw new Error(`Thumbnail upload failed: ${thumbnailResponse.status}`);
            }

            thumbnailMetadata = {
                thumbnailKey,
                thumbnailIv: encrypted.iv,
                thumbnailSize: encrypted.size,
            };

            debugLog('[THUMB]', 'Encrypted thumbnail uploaded', { fileId, thumbnailKey });
        } catch (thumbnailUploadError) {
            debugWarn('[THUMB]', 'Failed to upload thumbnail, continuing without', thumbnailUploadError);
        }
    }

    await confirmUpload.mutateAsync({
        fileId,
        encryptionIv: encryptedResult?.iv,
        encryptionSalt: encryptedResult?.salt,
        encryptionVersion: encryptedResult?.version,
        orgKeyVersion,
        signatureParams,
        thumbnailMetadata, // Phase 7.2
        contentHash,
        fingerprintVersion: contentHash ? 1 : undefined,
    });

    setUploadFiles((prev) =>
        prev.map((f) =>
            f.id === id ? { ...f, status: 'completed', progress: 100 } : f
        )
    );

    toast.success(`${file.name} uploaded successfully`);
}

