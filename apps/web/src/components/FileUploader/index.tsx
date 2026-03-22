/**
 * FileUploader Component
 *
 * Main orchestrator component for file uploads.
 * Composes EncryptionPanel, SigningPanel, DropZone, and UploadProgress.
 *
 * Features:
 * - Drag and drop file uploads
 * - Folder upload (click + drag-and-drop)
 * - Client-side encryption (mandatory via Master Key)
 * - Hybrid digital signatures (Ed25519 + ML-DSA-65) - Phase 3.4 Sovereign
 * - Single-file and multipart uploads
 * - Progress tracking
 * - File size validation
 */

import { useCallback, useEffect, useMemo, useReducer } from 'react';
import { cn } from '@/lib/utils';
import { trpc } from '@/lib/trpc';
import { useFileUpload } from './hooks/useFileUpload';
import { useFolderUpload } from './hooks/useFolderUpload';
import { getSignByDefault } from '@/components/settings/SignatureKeysSection';
import { useSignatureKeys } from '@/hooks/useSignatureKeys';
import { EncryptionPanel } from './components/EncryptionPanel';
import { SigningPanel, type SigningState } from './components/SigningPanel';
import { DropZone } from './components/DropZone';
import { UploadProgress } from './components/UploadProgress';
import { useDuplicateDialog } from './components/DuplicateDialog';
import type { FileUploaderProps } from './types';
import type { HybridSignatureSecretKey } from '@stenvault/shared/platform/crypto';

// ===== SIGNING STATE REDUCER (Phase 3.4 Sovereign) =====

type SigningAction =
    | { type: 'ENABLE' }
    | { type: 'DISABLE' }
    | { type: 'KEYS_READY'; secretKey: HybridSignatureSecretKey; fingerprint: string; keyVersion: number }
    | { type: 'ERROR'; error: string }
    | { type: 'CLEAR_KEYS' };

interface SigningReducerState {
    enabled: boolean;
    keysReady: boolean;
    secretKey: HybridSignatureSecretKey | null;
    fingerprint: string | null;
    keyVersion: number | null;
    error: string | null;
}

const signingInitialState: SigningReducerState = {
    enabled: false,
    keysReady: false,
    secretKey: null,
    fingerprint: null,
    keyVersion: null,
    error: null,
};

function signingReducer(state: SigningReducerState, action: SigningAction): SigningReducerState {
    switch (action.type) {
        case 'ENABLE':
            return { ...state, enabled: true };
        case 'DISABLE':
            return signingInitialState;
        case 'KEYS_READY':
            return { ...state, keysReady: true, secretKey: action.secretKey, fingerprint: action.fingerprint, keyVersion: action.keyVersion, error: null };
        case 'ERROR':
            return { ...state, error: action.error };
        case 'CLEAR_KEYS':
            return { ...state, keysReady: false, secretKey: null, fingerprint: null, keyVersion: null };
    }
}

const FOLDER_UPLOAD_PHASE_LABELS: Record<string, string> = {
    'parsing': 'Analyzing folder structure...',
    'checking-conflicts': 'Checking for conflicts...',
    'creating-folders': 'Creating folders...',
    'uploading-files': 'Uploading files...',
};

export function FileUploader({
    folderId,
    onUploadComplete,
    maxFiles = 10,
    maxSize: propMaxSize,
    className,
    folderUploadMaxFiles,
}: FileUploaderProps) {
    // Fetch user's storage stats including their max file size limit
    const { data: storageStats } = trpc.files.getStorageStats.useQuery();

    // Priority: prop > user's personal limit > default 100MB
    const maxSize = propMaxSize ?? storageStats?.maxFileSize ?? 100 * 1024 * 1024;
    const maxSizeMB = Math.round(maxSize / 1024 / 1024);

    const effectiveFolderMaxFiles = folderUploadMaxFiles ?? storageStats?.folderUploadMaxFiles ?? 100;

    // ===== DUPLICATE DETECTION =====
    const { showDuplicateDialog, DuplicateDialogPortal } = useDuplicateDialog();

    // ===== SIGNING STATE (Phase 3.4 Sovereign) =====
    const [signing, dispatchSigning] = useReducer(signingReducer, signingInitialState);
    const { keyInfo: sigKeyInfo } = useSignatureKeys();

    // Auto-enable signing when "sign by default" is ON and user has keys
    useEffect(() => {
        if (getSignByDefault() && sigKeyInfo.hasKeyPair && !signing.enabled) {
            dispatchSigning({ type: 'ENABLE' });
        }
    }, [sigKeyInfo.hasKeyPair]); // eslint-disable-line react-hooks/exhaustive-deps

    const signingState: SigningState = useMemo(
        () => ({
            enabled: signing.enabled,
            keysReady: signing.keysReady,
            fingerprint: signing.fingerprint,
            keyVersion: signing.keyVersion,
            error: signing.error,
        }),
        [signing.enabled, signing.keysReady, signing.fingerprint, signing.keyVersion, signing.error]
    );

    // Signing context for the upload hook (only when keys are ready)
    const signingContext = useMemo(() => {
        if (!signing.enabled || !signing.keysReady || !signing.secretKey || !signing.fingerprint || !signing.keyVersion) {
            return null;
        }
        return {
            secretKey: signing.secretKey,
            fingerprint: signing.fingerprint,
            keyVersion: signing.keyVersion,
        };
    }, [signing.enabled, signing.keysReady, signing.secretKey, signing.fingerprint, signing.keyVersion]);

    // Handlers for signing state
    const handleSigningEnableChange = useCallback((enabled: boolean) => {
        dispatchSigning(enabled ? { type: 'ENABLE' } : { type: 'DISABLE' });
    }, []);

    const handleSigningKeysReady = useCallback(
        (secretKey: HybridSignatureSecretKey, fingerprint: string, keyVersion: number) => {
            dispatchSigning({ type: 'KEYS_READY', secretKey, fingerprint, keyVersion });
        },
        []
    );

    const handleSigningKeysClear = useCallback(() => {
        dispatchSigning({ type: 'CLEAR_KEYS' });
    }, []);

    // ===== FILE UPLOAD =====
    const {
        uploadFiles,
        isDragging,
        handleFiles,
        handleFilesToFolder,
        removeFile,
        retryFile,
        handleDragOver,
        handleDragLeave,
        handleDrop,
        fileInputRef,
    } = useFileUpload({
        folderId,
        maxFiles,
        maxSize,
        onUploadComplete,
        signingContext,
        showDuplicateDialog,
    });

    // Now create the folder upload hook using handleFilesToFolder
    const {
        processFolderFiles,
        processDroppedFolder,
        isFolderUploading,
        folderUploadPhase,
        folderInputRef,
        FolderConflictDialogPortal,
    } = useFolderUpload({
        folderId,
        folderUploadMaxFiles: effectiveFolderMaxFiles,
        handleFilesToFolder,
    });

    // Wire folder drop detection — detect directories before delegating to handleDrop
    const handleDropWithFolders = useCallback(async (e: React.DragEvent) => {
        e.preventDefault();
        // Always reset drag state immediately (handleDrop does this too, but the folder path bypasses it)
        handleDragLeave(e);

        // Check for directories via webkitGetAsEntry
        if (e.dataTransfer.items) {
            for (let i = 0; i < e.dataTransfer.items.length; i++) {
                const entry = e.dataTransfer.items[i]?.webkitGetAsEntry?.();
                if (entry?.isDirectory) {
                    await processDroppedFolder(e.dataTransfer);
                    return;
                }
            }
        }

        // No directories — delegate to normal file drop (which also resets isDragging)
        if (e.dataTransfer.files.length > 0) {
            handleFiles(e.dataTransfer.files);
        }
    }, [processDroppedFolder, handleFiles, handleDragLeave]);

    const handleClick = () => {
        fileInputRef.current?.click();
    };

    const handleFolderClick = useCallback(() => {
        folderInputRef.current?.click();
    }, [folderInputRef]);

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files.length > 0) {
            handleFiles(e.target.files);
            e.target.value = ''; // Reset input
        }
    };

    const handleFolderChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files.length > 0) {
            processFolderFiles(e.target.files);
            e.target.value = ''; // Reset input
        }
    }, [processFolderFiles]);

    return (
        <div className={cn('space-y-4', className)}>
            {/* Encryption Panel - Always shown (encryption is mandatory) */}
            <EncryptionPanel />

            {/* Signing Panel - Always available since encryption is always on */}
            <SigningPanel
                signingState={signingState}
                onEnableChange={handleSigningEnableChange}
                onKeysReady={handleSigningKeysReady}
                onKeysClear={handleSigningKeysClear}
            />

            {/* Folder Upload Phase Indicator */}
            {isFolderUploading && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground px-1">
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                    {FOLDER_UPLOAD_PHASE_LABELS[folderUploadPhase] ?? 'Processing folder...'}
                </div>
            )}

            {/* Drop Zone */}
            <DropZone
                ref={fileInputRef}
                isDragging={isDragging}
                maxFiles={maxFiles}
                maxSizeMB={maxSizeMB}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDropWithFolders}
                onClick={handleClick}
                onFileChange={handleFileChange}
                onFolderClick={handleFolderClick}
                onFolderChange={handleFolderChange}
                folderInputRef={folderInputRef}
            />

            {/* Upload Progress List */}
            <UploadProgress
                files={uploadFiles}
                onRemove={removeFile}
                onRetry={retryFile}
            />

            {/* Duplicate Detection Dialog */}
            <DuplicateDialogPortal />

            {/* Folder Conflict Dialog */}
            <FolderConflictDialogPortal />
        </div>
    );
}

// Re-export types for convenience
export type { FileUploaderProps, UploadFile } from './types';
