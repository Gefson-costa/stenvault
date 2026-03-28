/**
 * useMobileDrive - Custom hook for MobileDrive state and logic
 * 
 * Extracts all state management and handlers from MobileDrive component
 * to improve maintainability and reduce component size.
 */

import { useState, useCallback, useMemo, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import { useNavigate, useSearchParams } from "react-router-dom";
import { hapticTap, hapticMedium } from "@/lib/haptics";
import { toast } from "sonner";
import { type FileAction, type FileInfo, type FileType } from "../../FileActionSheet";
import { type PreviewableFile, type FileItem } from "@/components/files/types";
import { useFilenameDecryption } from "@/hooks/useFilenameDecryption";
import { useFoldernameDecryption } from "@/hooks/useFoldernameDecryption";
import { useDirectDownload } from "@/hooks/useDirectDownload";
import { useFavoriteToggle } from "@/hooks/useFavoriteToggle";
import type { FolderItem as FolderItemType } from "@/components/files/types";

interface FolderItem {
    id: number;
    name: string;
    parentId: number | null;
}

// FileItem type matching FilePreviewModal expectations
type MobileFileItem = PreviewableFile;

interface BreadcrumbItem {
    id: number | null;
    name: string;
}

interface DeleteDialogState {
    open: boolean;
    type: 'file' | 'folder';
    item: { id: number; name: string } | null;
}

interface RenameDialogState {
    open: boolean;
    type: 'file' | 'folder';
    item: { id: number; name: string } | null;
}

export function useMobileDrive(initialFolderId: number | null = null, organizationId?: number | null) {
    // Current folder state
    const [currentFolderId, setCurrentFolderId] = useState<number | null>(initialFolderId);

    // Action sheet state
    const [selectedFile, setSelectedFile] = useState<FileInfo | null>(null);
    const [actionSheetOpen, setActionSheetOpen] = useState(false);

    // Uploader state
    const [showUploader, setShowUploader] = useState(false);

    // Preview state
    const [previewFile, setPreviewFile] = useState<MobileFileItem | null>(null);
    const [showPreview, setShowPreview] = useState(false);

    // Share state
    const [shareFile, setShareFile] = useState<{ id: number; filename: string; encryptionVersion?: number | null; createdAt?: Date } | null>(null);
    const [showShare, setShowShare] = useState(false);

    // Timestamp state
    const [timestampFile, setTimestampFile] = useState<{ id: number; filename: string } | null>(null);
    const [showTimestamp, setShowTimestamp] = useState(false);

    // Delete state
    const [deleteDialog, setDeleteDialog] = useState<DeleteDialogState>({
        open: false,
        type: 'file',
        item: null,
    });

    // Rename state
    const [renameDialog, setRenameDialog] = useState<RenameDialogState>({
        open: false,
        type: 'file',
        item: null,
    });

    const utils = trpc.useUtils();

    // Favorites
    const { toggleFavorite } = useFavoriteToggle();
    const { download: directDownload } = useDirectDownload();

    // Fetch files (org-aware: passes organizationId when viewing a vault)
    const {
        data: filesData,
        isLoading: filesLoading,
        refetch: refetchFiles,
    } = trpc.files.list.useQuery({
        folderId: currentFolderId,
        ...(organizationId ? { organizationId } : {}),
    });

    // Fetch folders
    const {
        data: foldersData,
        isLoading: foldersLoading,
        refetch: refetchFolders,
    } = trpc.folders.list.useQuery({ parentId: currentFolderId });

    // Fetch all folders for breadcrumb
    const { data: allFolders } = trpc.folders.list.useQuery({});

    // Phase C Zero-Knowledge: Decrypt folder names for mobile display
    const { getDisplayName: getFolderDisplayName, decryptFoldernames } = useFoldernameDecryption();

    useEffect(() => {
        if (foldersData && foldersData.length > 0) {
            decryptFoldernames(foldersData as FolderItemType[]);
        }
    }, [foldersData, decryptFoldernames]);

    // Also decrypt allFolders for breadcrumb
    useEffect(() => {
        if (allFolders && allFolders.length > 0) {
            decryptFoldernames(allFolders as FolderItemType[]);
        }
    }, [allFolders, decryptFoldernames]);

    // Handle URL actions
    const [searchParamsObj] = useSearchParams();
    const searchString = searchParamsObj.toString();
    const setLocation = useNavigate();

    useEffect(() => {
        const params = new URLSearchParams(searchString);
        const action = params.get('action');

        if (action === 'upload') {
            setShowUploader(true);
        }
    }, [searchString]);

    // Mutations with optimistic UX (Golden Rule #6: Local-First)
    // Close dialog immediately on mutate for snappy feedback
    const deleteFile = trpc.files.delete.useMutation({
        onMutate: () => {
            // Close dialog immediately for responsive UX
            setDeleteDialog({ open: false, type: 'file', item: null });
        },
        onSuccess: () => {
            toast.success('File deleted');
            utils.files.list.invalidate();
        },
        onError: (error) => {
            toast.error(error.message);
        },
    });

    const renameFile = trpc.files.rename.useMutation({
        onSuccess: () => {
            toast.success('File renamed');
            utils.files.list.invalidate();
            setRenameDialog({ open: false, type: 'file', item: null });
        },
        onError: (error) => toast.error(error.message),
    });

    const renameFolder = trpc.folders.rename.useMutation({
        onSuccess: () => {
            toast.success('Folder renamed');
            utils.folders.list.invalidate();
            setRenameDialog({ open: false, type: 'folder', item: null });
        },
        onError: (error) => toast.error(error.message),
    });

    const deleteFolder = trpc.folders.delete.useMutation({
        onMutate: () => {
            // Close dialog immediately for responsive UX
            setDeleteDialog({ open: false, type: 'folder', item: null });
        },
        onSuccess: () => {
            toast.success('Folder deleted');
            utils.folders.list.invalidate();
        },
        onError: (error) => {
            toast.error(error.message);
        },
    });

    // Build breadcrumb path
    const getBreadcrumbPath = useCallback((): BreadcrumbItem[] => {
        const path: BreadcrumbItem[] = [{ id: null, name: 'My Drive' }];

        if (!currentFolderId || !allFolders) return path;

        const buildPath = (folderId: number) => {
            const folder = allFolders.find(f => f.id === folderId);
            if (folder) {
                if (folder.parentId) {
                    buildPath(folder.parentId);
                }
                path.push({ id: folder.id, name: getFolderDisplayName(folder as FolderItemType) });
            }
        };

        buildPath(currentFolderId);
        return path;
    }, [allFolders, currentFolderId, getFolderDisplayName]);

    const breadcrumbPath = useMemo(() => getBreadcrumbPath(), [getBreadcrumbPath]);

    // Handlers
    const handleRefresh = useCallback(async () => {
        await Promise.all([refetchFiles(), refetchFolders()]);
    }, [refetchFiles, refetchFolders]);

    const handleFolderClick = useCallback((folderId: number) => {
        hapticTap();
        setCurrentFolderId(folderId);
    }, []);

    const handleFileClick = useCallback((file: MobileFileItem) => {
        hapticTap();
        setPreviewFile(file);
        setShowPreview(true);
    }, []);

    const handleFileLongPress = useCallback((file: FileInfo) => {
        hapticMedium();
        setSelectedFile(file);
        setActionSheetOpen(true);
    }, []);

    const handleFolderLongPress = useCallback((folder: FolderItem) => {
        hapticMedium();
        setSelectedFile({
            id: folder.id,
            name: getFolderDisplayName(folder as FolderItemType),
            type: "folder" as FileType,
            isFolder: true,
        });
        setActionSheetOpen(true);
    }, [getFolderDisplayName]);

    // Download handler — background decrypt + save (no modal)
    const handleDownload = useCallback(async (fileId: number, _filename: string) => {
        const file = filesData?.files.find(f => f.id === fileId);
        if (!file) {
            toast.error('File not found');
            return;
        }
        await directDownload(file as FileItem);
    }, [filesData, directDownload]);

    const handleFileAction = useCallback((action: FileAction, file: FileInfo) => {
        switch (action) {
            case "preview":
                const previewTarget = filesData?.files.find(f => f.id === file.id);
                if (previewTarget) {
                    setPreviewFile(previewTarget as MobileFileItem);
                    setShowPreview(true);
                }
                break;
            case "download":
                handleDownload(file.id, file.name);
                break;
            case "share": {
                const shareTarget = filesData?.files.find(f => f.id === file.id);
                setShareFile({
                    id: file.id,
                    filename: file.name,
                    encryptionVersion: (shareTarget as any)?.encryptionVersion ?? null,
                    createdAt: shareTarget?.createdAt ? new Date(shareTarget.createdAt) : undefined,
                });
                setShowShare(true);
                break;
            }
            case "favorite":
                toggleFavorite(file.id);
                break;
            case "timestamp":
                setTimestampFile({ id: file.id, filename: file.name });
                setShowTimestamp(true);
                break;
            case "rename":
                setRenameDialog({
                    open: true,
                    type: file.isFolder ? 'folder' : 'file',
                    item: { id: file.id, name: file.name },
                });
                break;
            case "move":
                // Move requires folder picker — not yet implemented
                break;
            case "delete":
                setDeleteDialog({
                    open: true,
                    type: file.isFolder ? 'folder' : 'file',
                    item: { id: file.id, name: file.name },
                });
                break;
            case "info":
                const infoFile = filesData?.files.find(f => f.id === file.id);
                if (infoFile) {
                    setPreviewFile(infoFile as MobileFileItem);
                    setShowPreview(true);
                }
                break;
            default:
                toast.info(`Action: ${action}`);
        }
    }, [filesData, handleDownload]);

    const handleRename = useCallback((newName: string) => {
        if (!renameDialog.item || !newName.trim()) return;

        if (renameDialog.type === 'file') {
            renameFile.mutate({ fileId: renameDialog.item.id, newName: newName.trim() });
        } else {
            renameFolder.mutate({ folderId: renameDialog.item.id, newName: newName.trim() });
        }
    }, [renameDialog, renameFile, renameFolder]);

    const closeRenameDialog = useCallback(() => {
        setRenameDialog({ open: false, type: 'file', item: null });
    }, []);

    const handleDelete = useCallback(() => {
        if (!deleteDialog.item) return;

        if (deleteDialog.type === 'file') {
            deleteFile.mutate({ fileId: deleteDialog.item.id });
        } else {
            deleteFolder.mutate({ folderId: deleteDialog.item.id });
        }
    }, [deleteDialog, deleteFile, deleteFolder]);

    const handleBack = useCallback(() => {
        hapticTap();
        if (breadcrumbPath.length > 1) {
            const parentFolder = breadcrumbPath[breadcrumbPath.length - 2];
            setCurrentFolderId(parentFolder?.id ?? null);
        } else {
            setCurrentFolderId(null);
        }
    }, [breadcrumbPath]);

    const closePreview = useCallback(() => {
        setShowPreview(false);
        setPreviewFile(null);
    }, []);

    const closeShare = useCallback(() => {
        setShowShare(false);
        setShareFile(null);
    }, []);

    const closeTimestamp = useCallback(() => {
        setShowTimestamp(false);
        setTimestampFile(null);
    }, []);

    const openTimestamp = useCallback((file: { id: number; filename: string }) => {
        setTimestampFile(file);
        setShowTimestamp(true);
    }, []);

    const closeDeleteDialog = useCallback(() => {
        setDeleteDialog({ open: false, type: 'file', item: null });
    }, []);

    const closeUploader = useCallback(() => {
        setShowUploader(false);
        // Refresh lists
        refetchFiles();
        refetchFolders();
        // Clear URL param if present
        const params = new URLSearchParams(window.location.search);
        if (params.get('action') === 'upload') {
            setLocation('/drive', { replace: true });
        }
    }, [refetchFiles, refetchFolders, setLocation]);

    const openUploader = useCallback(() => {
        setShowUploader(true);
    }, []);

    // Phase 5 Zero-Knowledge: Decrypt filenames for mobile display
    const { decryptFilenames } = useFilenameDecryption();
    const rawFiles = useMemo(() => filesData?.files || [], [filesData?.files]);
    const [decryptedFiles, setDecryptedFiles] = useState<PreviewableFile[]>([]);

    useEffect(() => {
        if (rawFiles.length > 0) {
            decryptFilenames(rawFiles as unknown as FileItem[]).then(result => setDecryptedFiles(result as unknown as PreviewableFile[]));
        } else {
            setDecryptedFiles(prev => prev.length === 0 ? prev : []);
        }
    }, [rawFiles, decryptFilenames]);

    // Derived state (useMemo prevents unstable refs that could cause infinite loops)
    const isLoading = filesLoading || foldersLoading;
    const folders = useMemo(() => foldersData || [], [foldersData]);
    const files = decryptedFiles.length > 0 ? decryptedFiles : rawFiles;
    const isEmpty = !isLoading && folders.length === 0 && files.length === 0;
    const isDeleting = deleteFile.isPending || deleteFolder.isPending;

    return {
        // State
        currentFolderId,
        selectedFile,
        actionSheetOpen,
        setActionSheetOpen,
        showUploader,
        setShowUploader,
        previewFile,
        showPreview,
        shareFile,
        showShare,
        timestampFile,
        showTimestamp,
        deleteDialog,
        renameDialog,

        // Data
        folders,
        files,
        breadcrumbPath,
        organizationId: organizationId ?? null,

        // Derived
        isLoading,
        isEmpty,
        isDeleting,

        // Handlers
        handleRefresh,
        handleFolderClick,
        handleFileClick,
        handleFileLongPress,
        handleFolderLongPress,
        handleFileAction,
        handleDelete,
        handleRename,
        closeRenameDialog,
        handleBack,
        closePreview,
        closeShare,
        closeTimestamp,
        openTimestamp,
        closeDeleteDialog,
        closeUploader,
        openUploader,

        // Phase C: Folder name decryption
        getFolderDisplayName: getFolderDisplayName as (folder: FolderItem) => string,
    };
}

export type UseMobileDriveReturn = ReturnType<typeof useMobileDrive>;
