/**
 * useDrive - Custom hook for Drive page state and logic
 *
 * Extracts all state management and handlers from Drive component
 * following the same pattern as useMobileDrive.ts.
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { trpc } from '@/lib/trpc';
import { useCurrentOrgId } from '@/contexts/OrganizationContext';
import { toast } from 'sonner';
import { useMasterKey } from '@/hooks/useMasterKey';
import { useOrgMasterKey } from '@/hooks/useOrgMasterKey';
import { useDirectDownload } from '@/hooks/useDirectDownload';
import { useFoldernameDecryption } from '@/hooks/useFoldernameDecryption';
import { useFoldernameMigration } from '@/hooks/useFoldernameMigration';
import { encryptFilename } from '@/lib/fileCrypto';
import {
  getStoredViewMode,
  setStoredViewMode,
  type ViewMode,
} from '@/components/drive';
import type { FileItem, FolderItem } from '@/components/files/types';

// ─────────────────────────────────────────────────────────────
// PURE FUNCTIONS (exported for testing)
// ─────────────────────────────────────────────────────────────

export function parseDriveParams(searchString: string, storedViewMode: string = 'grid') {
  const params = new URLSearchParams(searchString);
  const viewMode = params.get('view') ?? storedViewMode;
  const searchQuery = params.get('q') ?? '';
  const action = params.get('action');
  return { viewMode, searchQuery, action };
}

export function buildDriveUrl(searchString: string, updates: { view?: string; q?: string }) {
  const p = new URLSearchParams(searchString);
  if (updates.view !== undefined) p.set('view', updates.view);
  if (updates.q !== undefined) {
    if (updates.q) p.set('q', updates.q);
    else p.delete('q');
  }
  return `/drive${p.toString() ? `?${p}` : ''}`;
}

// ─────────────────────────────────────────────────────────────
// HOOK
// ─────────────────────────────────────────────────────────────

export function useDrive() {
  const setLocation = useNavigate();
  const [searchParams] = useSearchParams();
  const searchString = searchParams.toString();

  // State
  const [currentFolderId, setCurrentFolderId] = useState<number | null>(null);
  const [folderPath, setFolderPath] = useState<{ id: number; name: string }[]>([]);
  const [previewFile, setPreviewFile] = useState<FileItem | null>(null);
  const [showUploader, setShowUploader] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [showNewFolderDialog, setShowNewFolderDialog] = useState(false);
  const [unlockModalOpen, setUnlockModalOpen] = useState(false);

  // URL-backed state: view mode and search query persist in URL
  const params = new URLSearchParams(searchString);
  const viewMode: ViewMode = (params.get('view') as ViewMode) ?? getStoredViewMode();
  const searchQuery = params.get('q') ?? '';

  const setViewMode = useCallback((mode: ViewMode) => {
    const p = new URLSearchParams(searchString);
    p.set('view', mode);
    setStoredViewMode(mode);
    setLocation(`/drive${p.toString() ? `?${p}` : ''}`, { replace: true });
  }, [searchString, setLocation]);

  const setSearchQuery = useCallback((q: string) => {
    const p = new URLSearchParams(searchString);
    if (q) p.set('q', q); else p.delete('q');
    setLocation(`/drive${p.toString() ? `?${p}` : ''}`, { replace: true });
  }, [searchString, setLocation]);

  // Master Key state
  const { isUnlocked, isConfigured, isLoading: masterKeyLoading, deriveFoldernameKey } = useMasterKey();
  const { unlockOrgVault, isOrgUnlocked, deriveOrgFoldernameKey } = useOrgMasterKey();
  const { download: directDownload } = useDirectDownload();
  const orgId = useCurrentOrgId();

  // Auto-unlock org vault when personal vault is unlocked and in org context
  const orgVaultUnlocked = orgId ? isOrgUnlocked(orgId) : true;
  useEffect(() => {
    if (orgId && isUnlocked && !orgVaultUnlocked) {
      unlockOrgVault(orgId).catch((err) => {
        const msg = err instanceof Error ? err.message : '';
        if (msg.includes('NOT_FOUND') || msg.includes('No wrapped')) {
          toast.info("An admin needs to grant you encryption access to this organization.", { duration: 6000 });
        } else {
          console.error('[Drive] Org vault auto-unlock failed:', err);
          toast.error(`Organization vault could not be unlocked: ${msg || 'Unknown error'}`);
        }
      });
    }
  }, [orgId, isUnlocked, orgVaultUnlocked, unlockOrgVault]);

  // Effective unlock: personal vault + org vault (if in org context)
  const effectiveUnlocked = isUnlocked && orgVaultUnlocked;

  const utils = trpc.useUtils();

  // Queries
  const { data: storageStats, isLoading: statsLoading } = trpc.files.getStorageStats.useQuery({ organizationId: orgId });
  const { data: allFolders } = trpc.folders.list.useQuery({ organizationId: orgId });

  // Folder name decryption + migration
  const { getDisplayName: getFolderDisplayName, decryptFoldernames } = useFoldernameDecryption();
  useFoldernameMigration();

  useEffect(() => {
    if (allFolders && allFolders.length > 0) {
      decryptFoldernames(allFolders as FolderItem[]);
    }
  }, [allFolders, decryptFoldernames]);

  // Handle URL query params for triggering actions
  useEffect(() => {
    const params = new URLSearchParams(searchString);
    const action = params.get('action');

    if (action === 'upload') {
      setShowUploader(true);
      setLocation('/drive', { replace: true });
    } else if (action === 'new-folder') {
      setShowNewFolderDialog(true);
      setLocation('/drive', { replace: true });
    }
  }, [searchString, setLocation]);

  // Build folder path when currentFolderId changes
  useEffect(() => {
    if (!allFolders || currentFolderId === null) {
      setFolderPath([]);
      return;
    }

    const buildPath = (folderId: number): { id: number; name: string }[] => {
      const folder = allFolders.find(f => f.id === folderId);
      if (!folder) return [];

      const parentPath = folder.parentId ? buildPath(folder.parentId) : [];
      return [...parentPath, { id: folder.id, name: getFolderDisplayName(folder as FolderItem) }];
    };

    setFolderPath(buildPath(currentFolderId));
  }, [currentFolderId, allFolders, getFolderDisplayName]);

  // Mutations
  const createFolder = trpc.folders.create.useMutation({
    onSuccess: () => {
      toast.success('Folder created successfully');
      utils.folders.list.invalidate();
      setShowNewFolderDialog(false);
      setNewFolderName('');
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  // Handlers
  const handleFolderClick = useCallback((folderId: number) => {
    setCurrentFolderId(folderId);
  }, []);

  const handleNavigateToFolder = useCallback((folderId: number | null) => {
    setCurrentFolderId(folderId);
  }, []);

  const handleFilePreview = useCallback((file: FileItem) => {
    setPreviewFile(file);
  }, []);

  const handleFileDownload = useCallback((file: FileItem) => {
    directDownload(file);
  }, [directDownload]);

  const handleCreateFolder = useCallback(async () => {
    if (!newFolderName.trim()) return;
    const trimmedName = newFolderName.trim();

    // Encrypt folder name if vault is unlocked
    if (effectiveUnlocked) {
      try {
        // Use org foldername key when in org context, personal key otherwise
        const foldernameKey = orgId
          ? await deriveOrgFoldernameKey(orgId)
          : await deriveFoldernameKey();
        const { encryptedFilename: encryptedName, iv: nameIv } = await encryptFilename(trimmedName, foldernameKey);
        createFolder.mutate({
          name: "Folder",
          encryptedName,
          nameIv,
          parentId: currentFolderId,
          organizationId: orgId,
        });
        return;
      } catch (error) {
        console.error('[Drive] Failed to encrypt folder name:', error);
        // Rule 1: Zero-Knowledge — never store plaintext when vault is unlocked
        toast.error('Failed to encrypt folder name. Please re-unlock the vault and try again.');
        return;
      }
    }

    if (orgId) {
      // Rule 1: org context requires encryption — block plaintext creation
      toast.error('Organization vault must be unlocked to create folders.');
      return;
    }

    createFolder.mutate({
      name: trimmedName,
      parentId: currentFolderId,
    });
  }, [newFolderName, currentFolderId, createFolder, effectiveUnlocked, orgId, deriveFoldernameKey, deriveOrgFoldernameKey]);

  const handleUploadComplete = useCallback(() => {
    utils.files.list.invalidate();
    utils.files.getStorageStats.invalidate();
    setShowUploader(false);
  }, [utils]);

  const toggleUploader = useCallback(() => {
    setShowUploader(prev => !prev);
  }, []);

  const handleForgotPassword = useCallback(() => {
    setUnlockModalOpen(false);
    setLocation('/auth/recovery-code-reset');
  }, [setLocation]);

  return {
    // URL state
    viewMode,
    searchQuery,
    setViewMode,
    setSearchQuery,

    // Folder navigation
    currentFolderId,
    folderPath,
    handleFolderClick,
    handleNavigateToFolder,

    // Folder creation
    newFolderName,
    setNewFolderName,
    showNewFolderDialog,
    setShowNewFolderDialog,
    handleCreateFolder,
    isCreatingFolder: createFolder.isPending,

    // File preview/download
    previewFile,
    setPreviewFile,
    handleFilePreview,
    handleFileDownload,

    // Upload
    showUploader,
    setShowUploader,
    toggleUploader,
    handleUploadComplete,

    // Vault
    unlockModalOpen,
    setUnlockModalOpen,
    isUnlocked: effectiveUnlocked,
    isConfigured,
    masterKeyLoading,

    // Storage
    storageStats,
    statsLoading,

    // Organization context
    orgId,

    // Navigation
    handleForgotPassword,
  };
}

export type UseDriveReturn = ReturnType<typeof useDrive>;
