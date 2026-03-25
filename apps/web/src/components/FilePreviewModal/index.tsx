/**
 * FilePreviewModal Component
 *
 * Main orchestrator component for file previews.
 * Supports video, audio, image, and document files with encryption handling.
 * v3 (Master Key) and v4 (Hybrid PQC) files auto-decrypt when vault is unlocked.
 */

import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { trpc } from '@/lib/trpc';
import { useOperationStore } from '@/stores/operationStore';
import { toast } from 'sonner';
import { Loader2, AlertTriangle, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import {
    AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
    AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { formatBytes } from '@stenvault/shared';
import { debugWarn } from '@/lib/debugLogger';
import { useMasterKey } from '@/hooks/useMasterKey';
import { extractV4FileKey } from '@/lib/hybridFileCrypto';
import { decryptV4ChunkedToStream } from '@/lib/streamingDecrypt';
import { streamDownloadToDisk } from '@/lib/platform';
import { useBatchTimestampStatus } from '@/hooks/useTimestamp';

// Hooks
import { useMediaControls } from './hooks/useMediaControls';
import { useFileDecryption, getEffectiveMimeType } from './hooks/useFileDecryption';
import { useImageControls } from './hooks/useImageControls';
import { useFilenameDecryption } from '@/hooks/useFilenameDecryption';

// Components
import { PreviewHeader } from './components/PreviewHeader';
import { VideoPlayer } from './components/VideoPlayer';
import { AudioPlayer } from './components/AudioPlayer';
import { ImageViewer } from './components/ImageViewer';
import { DocumentViewer, UnsupportedFile } from './components/DocumentViewer';
import { MediaControls } from './components/MediaControls';
import { ImageControls } from './components/ImageControls';
import { TimestampProofModal } from '@/components/files/components/TimestampProofModal';

// Types
import type { FilePreviewModalProps } from './types';
import type { FileItem } from '@/components/files/types';

/** Try to infer file type from extension when mimeType is null/octet-stream */
const EXTENSION_TYPE_MAP: Record<string, string> = {
    jpg: 'image', jpeg: 'image', png: 'image', gif: 'image', webp: 'image',
    svg: 'image', bmp: 'image', avif: 'image', tiff: 'image', tif: 'image', ico: 'image',
    mp4: 'video', webm: 'video', ogg: 'video', ogv: 'video', mov: 'video',
    avi: 'video', mkv: 'video',
    mp3: 'audio', wav: 'audio', flac: 'audio', aac: 'audio', oga: 'audio',
    m4a: 'audio', wma: 'audio',
    pdf: 'document', txt: 'document', html: 'document', csv: 'document',
    doc: 'document', docx: 'document', xls: 'document', xlsx: 'document',
};

function inferTypeFromExtension(file: { plaintextExtension?: string | null; decryptedFilename?: string; filename?: string }): string | null {
    // Try plaintextExtension first (zero-knowledge)
    if (file.plaintextExtension) {
        const ext = file.plaintextExtension.toLowerCase().replace('.', '');
        if (EXTENSION_TYPE_MAP[ext]) return EXTENSION_TYPE_MAP[ext];
    }
    // Try decrypted or raw filename
    const name = file.decryptedFilename || file.filename;
    if (name) {
        const dotIdx = name.lastIndexOf('.');
        if (dotIdx !== -1) {
            const ext = name.substring(dotIdx + 1).toLowerCase();
            if (EXTENSION_TYPE_MAP[ext]) return EXTENSION_TYPE_MAP[ext];
        }
    }
    return null;
}

const LARGE_FILE_THRESHOLD = 200 * 1024 * 1024; // 200 MB

export function FilePreviewModal({ file, open, onClose, mode = 'preview' }: FilePreviewModalProps) {
    const containerRef = useRef<HTMLDivElement>(null);

    // ===== LARGE FILE WARNING =====
    const isLargeFile = !!file && file.size > LARGE_FILE_THRESHOLD;
    const [largeFileConfirmed, setLargeFileConfirmed] = useState(false);
    const [showLargeFileWarning, setShowLargeFileWarning] = useState(false);

    // Reset when file changes
    useEffect(() => {
        setLargeFileConfirmed(false);
        setShowLargeFileWarning(false);
    }, [file?.id]);

    // Show warning when opening a large file
    useEffect(() => {
        if (open && isLargeFile && !largeFileConfirmed) {
            setShowLargeFileWarning(true);
        }
    }, [open, file?.id]);

    const canFetchUrl = !isLargeFile || largeFileConfirmed;

    // ===== TRPC QUERIES =====
    // Stream URL for video/audio files
    const { data: streamData, isLoading: streamLoading } = trpc.files.getStreamUrl.useQuery(
        { fileId: file?.id ?? 0 },
        { enabled: !!file && canFetchUrl && (file.fileType === 'video' || file.fileType === 'audio') }
    );

    // Download URL for everything else (images, documents, AND 'other' encrypted files)
    const { data: downloadData, isLoading: downloadLoading } = trpc.files.getDownloadUrl.useQuery(
        { fileId: file?.id ?? 0 },
        { enabled: !!file && canFetchUrl && file.fileType !== 'video' && file.fileType !== 'audio' }
    );

    // ===== ENCRYPTION METADATA =====
    const encryptionIv = streamData?.encryptionIv || downloadData?.encryptionIv;
    const encryptionSalt = streamData?.encryptionSalt || downloadData?.encryptionSalt;
    // Use the actual version from API, default to 3 only as last resort (all new files are V3+)
    const apiVersion = streamData?.encryptionVersion ?? downloadData?.encryptionVersion;
    const encryptionVersion = apiVersion ?? (encryptionIv ? 3 : 1);
    const isUnsupportedVersion = encryptionVersion !== 1 && encryptionVersion !== 3 && encryptionVersion !== 4;
    const rawUrl = streamData?.url || downloadData?.url;

    // Log encryption metadata once when available (not on every re-render)
    const loggedFileIdRef = useRef<number | null>(null);
    useEffect(() => {
        if (rawUrl && file && !streamLoading && !downloadLoading && loggedFileIdRef.current !== file.id) {
            loggedFileIdRef.current = file.id;
            console.warn('[Preview] Encryption metadata:', {
                fileId: file.id,
                apiVersion,
                encryptionVersion,
                hasIv: !!encryptionIv,
                fileType: file.fileType,
                source: streamData ? 'stream' : downloadData ? 'download' : 'none',
            });
        }
    }, [rawUrl, file, streamLoading, downloadLoading, apiVersion, encryptionVersion, encryptionIv, streamData, downloadData]);

    // ===== SIGNATURE INFO (Phase 3.4 Sovereign) =====
    const signatureInfo = downloadData?.signatureInfo ?? null;

    // ===== FILENAME DECRYPTION (Zero-Knowledge) =====
    const { getDisplayName } = useFilenameDecryption();
    // Use decrypted filename for display and download
    const displayFilename = file ? getDisplayName(file as FileItem) : '';

    // ===== TIMESTAMP STATUS =====
    const fileIdArray = file ? [file.id] : [];
    const { getStatus: getTimestampStatus } = useBatchTimestampStatus(fileIdArray);
    const timestampStatus = file ? getTimestampStatus(file.id) : null;
    const [showTimestampModal, setShowTimestampModal] = useState(false);

    // ===== MASTER KEY (for streaming download) =====
    const { getUnlockedHybridSecretKey } = useMasterKey();
    const [isStreamingDownload, setIsStreamingDownload] = useState(false);

    // ===== HOOKS =====
    const mediaControls = useMediaControls();
    const imageControls = useImageControls();
    const decryption = useFileDecryption({
        file,
        isOpen: open,
        rawUrl,
        encryptionIv: encryptionIv ?? undefined,
        encryptionSalt: encryptionSalt ?? undefined,
        encryptionVersion,
        signatureInfo,
    });

    // ===== ACTIVE PREVIEW OPERATION (defers vault lock while viewing) =====
    const opStore = useOperationStore();
    const previewOpIdRef = useRef<string | null>(null);
    useEffect(() => {
        if (open && decryption.state.decryptedBlobUrl && !previewOpIdRef.current) {
            previewOpIdRef.current = opStore.addOperation({
                type: 'preview',
                filename: displayFilename || 'preview',
                status: 'downloading', // any non-terminal status keeps it "active"
            });
        }
        if (!open && previewOpIdRef.current) {
            opStore.removeOperation(previewOpIdRef.current);
            previewOpIdRef.current = null;
        }
        return () => {
            if (previewOpIdRef.current) {
                opStore.removeOperation(previewOpIdRef.current);
                previewOpIdRef.current = null;
            }
        };
    }, [open, !!decryption.state.decryptedBlobUrl]);

    // ===== EFFECTIVE FILE TYPE =====
    // For files stored as 'other' (e.g. existing encrypted files before fix),
    // infer the actual type from mimeType or file extension
    const effectiveFileType = (() => {
        if (file?.fileType !== 'other') {
            return file?.fileType ?? 'other';
        }
        const mime = file?.mimeType;
        // Try MIME type first (if it's a real type)
        if (mime && mime !== 'application/octet-stream') {
            if (mime.startsWith('image/')) return 'image';
            if (mime.startsWith('video/')) return 'video';
            if (mime.startsWith('audio/')) return 'audio';
            if (
                mime.startsWith('application/pdf') ||
                mime.startsWith('application/msword') ||
                mime.startsWith('application/vnd.openxmlformats') ||
                mime.startsWith('application/vnd.ms-') ||
                mime.startsWith('text/')
            ) return 'document';
        }
        // MIME is null or octet-stream - try to infer from file extension
        if (file) {
            const inferred = inferTypeFromExtension(file);
            if (inferred) return inferred;
        }
        return 'other';
    })();

    // ===== EFFECTIVE MIME TYPE =====
    // Infer correct MIME type from extension when stored mimeType is wrong
    const effectiveMimeType = file ? getEffectiveMimeType(file) : undefined;

    // Use decrypted blob URL (all files are encrypted, must decrypt first)
    const mediaUrl = decryption.state.decryptedBlobUrl || null;

    // ===== RESET ON FILE CHANGE =====
    useEffect(() => {
        mediaControls.reset();
        imageControls.reset();
    }, [file?.id]);

    // ===== IMAGE ERROR HANDLER =====
    // Destructure stable setState refs to avoid recreating callback on every render
    const { setError: setImageError } = imageControls;
    const { setLoading: setMediaLoading } = mediaControls;
    const handleImageError = useCallback((message: string) => {
        setImageError(message);
        setMediaLoading(false);
    }, [setImageError, setMediaLoading]);

    // ===== DOWNLOAD HANDLER =====
    const handleDownload = useCallback(async () => {
        if (!file) return;

        try {
            // If already decrypted in memory, use the blob URL directly
            if (decryption.state.decryptedBlobUrl) {
                const link = document.createElement('a');
                link.href = decryption.state.decryptedBlobUrl;
                link.download = displayFilename;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                toast.success('File downloaded successfully');
                return;
            }

            // V4 streaming download: decrypt + stream to disk without accumulating in RAM
            if (encryptionVersion === 4 && rawUrl) {
                setIsStreamingDownload(true);
                try {
                    const secretKey = await getUnlockedHybridSecretKey();
                    if (!secretKey) {
                        toast.error('Please unlock your vault first');
                        return;
                    }

                    // Extract file key from CVEF header (fetches only ~8KB)
                    const { fileKeyBytes, zeroBytes } = await extractV4FileKey(rawUrl, secretKey);
                    const fileKey = await crypto.subtle.importKey(
                        'raw',
                        fileKeyBytes.buffer.slice(fileKeyBytes.byteOffset, fileKeyBytes.byteOffset + fileKeyBytes.byteLength) as ArrayBuffer,
                        { name: 'AES-GCM', length: 256 },
                        false,
                        ['decrypt'],
                    );
                    zeroBytes();

                    // Fetch encrypted file as stream
                    const response = await fetch(rawUrl);
                    if (!response.ok || !response.body) throw new Error(`Download failed: ${response.status}`);

                    // Create decrypted plaintext stream
                    const plaintextStream = decryptV4ChunkedToStream(response.body, { fileKey });

                    // Stream to disk
                    const result = await streamDownloadToDisk(plaintextStream, {
                        filename: displayFilename,
                        totalSize: file.size,
                        mimeType: effectiveMimeType || 'application/octet-stream',
                    });

                    toast.success(`File downloaded (${result.tier})`);
                    return;
                } catch (err) {
                    if (err instanceof DOMException && err.name === 'AbortError') return;
                    throw err;
                } finally {
                    setIsStreamingDownload(false);
                }
            }

            // Not yet decrypted (V3 or V4 non-chunked), show info toast
            toast.info('Waiting for decryption to complete...');
        } catch (err) {
            const message = err instanceof Error ? err.message : 'Unknown error';
            debugWarn('[Preview]', 'Download failed', err);
            toast.error('Failed to download file', {
                description: message.includes('expired')
                    ? 'The download link may have expired. Please close and reopen the preview.'
                    : 'Please check your connection and try again.',
            });
        }
    }, [file, decryption, displayFilename, encryptionVersion, rawUrl, getUnlockedHybridSecretKey, effectiveMimeType]);

    // ===== AUTO-DOWNLOAD MODE =====
    // When opened with mode='download', trigger download as soon as decryption completes
    const autoDownloadTriggeredRef = useRef(false);
    useEffect(() => {
        // Reset when file changes
        autoDownloadTriggeredRef.current = false;
    }, [file?.id]);

    useEffect(() => {
        if (mode !== 'download' || !open || autoDownloadTriggeredRef.current) return;

        // Blob already decrypted — trigger download immediately
        if (decryption.state.decryptedBlobUrl) {
            autoDownloadTriggeredRef.current = true;
            handleDownload().then(() => onClose());
            return;
        }

        // V4 streaming: rawUrl ready, no need to wait for blob decryption
        if (encryptionVersion === 4 && rawUrl && !decryption.state.isDecrypting) {
            autoDownloadTriggeredRef.current = true;
            handleDownload().then(() => onClose());
        }
    }, [mode, open, decryption.state.decryptedBlobUrl, decryption.state.isDecrypting, encryptionVersion, rawUrl, handleDownload, onClose]);

    // ===== EARLY RETURNS =====
    if (!file) return null;

    const isQueryLoading = streamLoading || downloadLoading;
    const showMediaControls = (effectiveFileType === 'video' || effectiveFileType === 'audio');
    const hasDecryptionError = !!decryption.state.error;

    return (
        <Dialog open={open} onOpenChange={(isOpen) => !isOpen && onClose()}>
            <DialogContent
                className="max-w-5xl w-full h-[100dvh] md:h-[90vh] p-0 overflow-hidden rounded-none md:rounded-xl"
                showCloseButton={false}
                aria-describedby={undefined}
            >
                <div ref={containerRef} className="flex flex-col h-full bg-background">
                    {/* Header */}
                    <PreviewHeader
                        filename={displayFilename}
                        signatureState={decryption.signatureState}
                        timestampStatus={timestampStatus}
                        onTimestampClick={() => setShowTimestampModal(true)}
                        onDownload={handleDownload}
                        onClose={onClose}
                    />

                    {/* Content */}
                    <div className="flex-1 flex items-center justify-center overflow-hidden bg-black/90 relative">
                        {/* Unsupported encryption version */}
                        {isUnsupportedVersion && (
                            <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/80 z-20 gap-4">
                                <AlertTriangle className="w-12 h-12 text-red-400" />
                                <p className="text-sm text-red-500 font-medium">Unsupported encryption version: {encryptionVersion}</p>
                                <p className="text-xs text-white/60 mt-1">This file uses an encryption format that is not supported by this client.</p>
                            </div>
                        )}

                        {/* Waiting for API to return URL */}
                        {isQueryLoading && (
                            <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/80 z-20 gap-4">
                                <Loader2 className="w-12 h-12 animate-spin text-white" />
                                <p className="text-white/70">Loading file metadata...</p>
                            </div>
                        )}

                        {/* Decryption in progress */}
                        {!isQueryLoading && !decryption.state.decryptedBlobUrl && !hasDecryptionError && rawUrl && (
                            <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/80 z-20 gap-4">
                                <Loader2 className="w-12 h-12 animate-spin text-white" />
                                <p className="text-white/70">Decrypting file...</p>
                                {decryption.state.progress > 0 && (
                                    <p className="text-white/50 text-sm">{Math.round(decryption.state.progress)}%</p>
                                )}
                            </div>
                        )}

                        {/* Decryption failed */}
                        {hasDecryptionError && (
                            <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/80 z-20 gap-4">
                                <AlertTriangle className="w-12 h-12 text-red-400" />
                                <p className="text-red-400 text-lg font-medium">Decryption failed</p>
                                <p className="text-red-400/80 text-sm text-center max-w-md px-4">{decryption.state.error}</p>
                                <p className="text-white/40 text-xs">{displayFilename}</p>
                                <Button onClick={handleDownload} variant="outline" className="mt-2">
                                    <Download className="w-4 h-4 mr-2" />
                                    Download encrypted file
                                </Button>
                            </div>
                        )}

                        {/* API returned no URL (unexpected) */}
                        {!isQueryLoading && !rawUrl && !hasDecryptionError && (
                            <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/80 z-20 gap-4">
                                <AlertTriangle className="w-12 h-12 text-yellow-400" />
                                <p className="text-yellow-400 text-lg font-medium">Unable to load file</p>
                                <p className="text-white/60 text-sm">The file URL could not be retrieved. Please close and try again.</p>
                            </div>
                        )}

                        {/* Video Player */}
                        {effectiveFileType === 'video' && mediaUrl && (
                            <VideoPlayer
                                ref={mediaControls.videoRef}
                                mediaUrl={mediaUrl}
                                filename={displayFilename}
                                mimeType={effectiveMimeType}
                                state={mediaControls.state}
                                videoContainerRef={mediaControls.videoContainerRef}
                                onLoadedMetadata={mediaControls.handleLoadedMetadata}
                                onTimeUpdate={mediaControls.handleTimeUpdate}
                                onEnded={mediaControls.handleEnded}
                                onError={mediaControls.handleMediaError}
                                onTogglePlay={mediaControls.togglePlay}
                                onToggleFullscreen={mediaControls.toggleFullscreen}
                                onSeek={mediaControls.handleSeek}
                                onDownload={handleDownload}
                                onStalled={() => debugWarn('[Preview]', 'Video stalled: ' + displayFilename)}
                            />
                        )}

                        {/* Audio Player */}
                        {effectiveFileType === 'audio' && mediaUrl && (
                            <AudioPlayer
                                ref={mediaControls.audioRef}
                                mediaUrl={mediaUrl}
                                filename={displayFilename}
                                mimeType={effectiveMimeType}
                                state={mediaControls.state}
                                onLoadedMetadata={mediaControls.handleLoadedMetadata}
                                onTimeUpdate={mediaControls.handleTimeUpdate}
                                onEnded={mediaControls.handleEnded}
                                onError={mediaControls.handleMediaError}
                                onDownload={handleDownload}
                            />
                        )}

                        {/* Image Viewer */}
                        {effectiveFileType === 'image' && mediaUrl && (
                            <ImageViewer
                                mediaUrl={mediaUrl}
                                filename={displayFilename}
                                imageState={imageControls.state}
                                onLoad={() => mediaControls.setLoading(false)}
                                onError={handleImageError}
                                onDownload={handleDownload}
                            />
                        )}

                        {/* Document Viewer */}
                        {effectiveFileType === 'document' && mediaUrl && (
                            <DocumentViewer
                                mediaUrl={mediaUrl}
                                mimeType={file.mimeType ?? undefined}
                                onLoad={() => mediaControls.setLoading(false)}
                                onDownload={handleDownload}
                            />
                        )}

                        {/* Unsupported file type */}
                        {effectiveFileType === 'other' && (
                            <UnsupportedFile onDownload={handleDownload} />
                        )}
                    </div>

                    {/* Media Controls (video/audio) */}
                    {showMediaControls && (
                        <MediaControls
                            state={mediaControls.state}
                            fileType={effectiveFileType}
                            onTogglePlay={mediaControls.togglePlay}
                            onToggleMute={mediaControls.toggleMute}
                            onVolumeChange={mediaControls.handleVolumeChange}
                            onSeek={mediaControls.handleSeek}
                            onSkip={mediaControls.skip}
                            onToggleFullscreen={mediaControls.toggleFullscreen}
                        />
                    )}

                    {/* Image Controls (only show when no error) */}
                    {effectiveFileType === 'image' && !imageControls.state.error && (
                        <ImageControls
                            state={imageControls.state}
                            onZoomIn={imageControls.zoomIn}
                            onZoomOut={imageControls.zoomOut}
                            onRotate={imageControls.rotate}
                        />
                    )}
                </div>

                {/* Timestamp Proof Modal */}
                {file && showTimestampModal && (
                    <TimestampProofModal
                        fileId={file.id}
                        filename={displayFilename}
                        open={showTimestampModal}
                        onClose={() => setShowTimestampModal(false)}
                    />
                )}
            </DialogContent>

            {/* Large file warning */}
            <AlertDialog open={showLargeFileWarning} onOpenChange={setShowLargeFileWarning}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>Large file</AlertDialogTitle>
                        <AlertDialogDescription>
                            This file is {formatBytes(file?.size ?? 0)}. Preview may use significant memory and take a while to decrypt.
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel onClick={() => { setShowLargeFileWarning(false); onClose(); }}>
                            Cancel
                        </AlertDialogCancel>
                        <AlertDialogAction onClick={() => { setLargeFileConfirmed(true); setShowLargeFileWarning(false); }}>
                            Preview Anyway
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </Dialog>
    );
}

// Re-export types for convenience
export type { FilePreviewModalProps } from './types';
