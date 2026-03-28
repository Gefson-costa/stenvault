/**
 * MobileDrive - Mobile-optimized Drive Page
 * 
 * File browser with grid view, breadcrumbs, pull-to-refresh and long press actions.
 * Implements real file actions: preview, download, share, delete.
 * 
 * Logic extracted to useMobileDrive hook for maintainability.
 */

import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { FolderOpen, ChevronLeft } from "lucide-react";
import { motion } from "framer-motion";
import { Drawer } from "vaul";
import { FileUploader } from "@/components/FileUploader/index";
import { VaultPicker } from "../VaultPicker";
import {
    PageTransition,
    PullToRefresh,
    EmptyState,
    LoadingState,
    SectionHeader,
    FileCard,
} from "@/components/mobile-v2";
import { FileActionSheet, type FileType, type FileInfo } from "../FileActionSheet";
import { type PreviewableFile } from "@/components/files/types";
import { FilePreviewModal } from "@/components/FilePreviewModal/index";
import { ShareFileModal } from "@/components/ShareFileModal";
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useMobileDrive } from "./hooks/useMobileDrive";
import { useBatchTimestampStatus } from "@/hooks/useTimestamp";
import { useFavoriteToggle } from "@/hooks/useFavoriteToggle";
import { TimestampDetails } from "@/components/files/components/TimestampDetails";
import type { TimestampStatus } from "@stenvault/shared";

// ─────────────────────────────────────────────────────────────
// COMPONENT
// ─────────────────────────────────────────────────────────────

interface MobileDriveProps {
    organizationId?: number | null;
}

export function MobileDrive({ organizationId: propOrgId }: MobileDriveProps = {}) {
    const setLocation = useNavigate();
    const [searchParams] = useSearchParams();
    const searchString = searchParams.toString();
    const [activeOrgId, setActiveOrgId] = useState<number | null>(propOrgId ?? null);

    // Parse folder from URL
    const urlFolderId = searchParams.get("folder");
    const initialFolderId = urlFolderId ? parseInt(urlFolderId, 10) : null;

    // Effective org ID: prop takes priority, then user selection
    const effectiveOrgId = propOrgId !== undefined ? propOrgId : activeOrgId;

    // Use extracted hook for all logic
    const {
        currentFolderId,
        selectedFile,
        actionSheetOpen,
        setActionSheetOpen,
        previewFile,
        showPreview,
        shareFile,
        showShare,
        deleteDialog,
        folders,
        files,
        breadcrumbPath,
        isLoading,
        isEmpty,
        isDeleting,
        handleRefresh,
        handleFolderClick,
        handleFileClick,
        handleFileLongPress,
        handleFolderLongPress,
        handleFileAction,
        handleDelete,
        handleRename,
        closeRenameDialog,
        renameDialog,
        handleBack,
        closePreview,
        closeShare,
        closeDeleteDialog,
        showUploader,
        closeUploader,
        setShowUploader,
        timestampFile,
        showTimestamp,
        closeTimestamp,
        openTimestamp,
        getFolderDisplayName,
    } = useMobileDrive(initialFolderId, effectiveOrgId);

    const [renameValue, setRenameValue] = useState("");

    // Batch timestamp status for all files
    const fileIds = files.map(f => f.id);
    const { getStatus: getTimestampStatus, isEnabled: isTimestampEnabled } = useBatchTimestampStatus(fileIds);

    // Favorites
    const { toggleFavorite } = useFavoriteToggle();

    return (
        <PageTransition>
            <PullToRefresh onRefresh={handleRefresh}>
                <div style={{ minHeight: "100%" }}>
                    {/* Vault Picker — only shown when not in fixed org context */}
                    {propOrgId === undefined && (
                        <VaultPicker
                            activeOrgId={activeOrgId}
                            onSelectVault={setActiveOrgId}
                        />
                    )}

                    {/* Breadcrumb / Back Button */}
                    <BreadcrumbHeader
                        currentFolderId={currentFolderId}
                        breadcrumbPath={breadcrumbPath}
                        onBack={handleBack}
                    />

                    {/* Content */}
                    {isLoading ? (
                        <LoadingState skeleton skeletonCount={6} />
                    ) : isEmpty ? (
                        <EmptyState
                            icon={FolderOpen}
                            title="Empty folder"
                            description="Add files to get started"
                        />
                    ) : (
                        <>
                            {/* Folders Section */}
                            <FoldersSection
                                folders={folders}
                                onFolderClick={handleFolderClick}
                                onFolderLongPress={handleFolderLongPress}
                                getFolderDisplayName={getFolderDisplayName}
                            />

                            {/* Files Section */}
                            <FilesSection
                                files={files}
                                onFileClick={handleFileClick}
                                onFileLongPress={handleFileLongPress}
                                getTimestampStatus={isTimestampEnabled ? getTimestampStatus : undefined}
                                onTimestampClick={(file) => openTimestamp({ id: file.id, filename: file.filename })}
                                onFavoriteToggle={(fileId) => toggleFavorite(fileId)}
                            />
                        </>
                    )}
                </div>

                {/* File Action Sheet */}
                <FileActionSheet
                    file={selectedFile}
                    open={actionSheetOpen}
                    onOpenChange={setActionSheetOpen}
                    onAction={handleFileAction}
                    isFavorite={!!(selectedFile && files.find(f => f.id === selectedFile.id && (f as any).isFavorite))}
                />

                {/* File Preview Modal */}
                {previewFile && (
                    <FilePreviewModal
                        file={previewFile}
                        open={showPreview}
                        onClose={closePreview}
                    />
                )}

                {/* Share Modal */}
                <ShareFileModal
                    file={shareFile}
                    open={showShare}
                    onClose={closeShare}
                />

                {/* Delete Confirmation */}
                <AlertDialog
                    open={deleteDialog.open}
                    onOpenChange={(open) => !open && closeDeleteDialog()}
                >
                    <AlertDialogContent>
                        <AlertDialogHeader>
                            <AlertDialogTitle>
                                Delete {deleteDialog.type === 'folder' ? 'folder' : 'file'}?
                            </AlertDialogTitle>
                            <AlertDialogDescription>
                                This action cannot be undone. The {deleteDialog.type === 'folder' ? 'folder' : 'file'} "{deleteDialog.item?.name}" will be permanently deleted.
                            </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                            <AlertDialogCancel disabled={isDeleting}>
                                Cancel
                            </AlertDialogCancel>
                            <AlertDialogAction
                                onClick={handleDelete}
                                disabled={isDeleting}
                                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                            >
                                {isDeleting ? "Deleting..." : "Delete"}
                            </AlertDialogAction>
                        </AlertDialogFooter>
                    </AlertDialogContent>
                </AlertDialog>

                {/* Rename Dialog */}
                <Dialog
                    open={renameDialog.open}
                    onOpenChange={(open) => {
                        if (!open) closeRenameDialog();
                        else if (renameDialog.item) setRenameValue(renameDialog.item.name);
                    }}
                >
                    <DialogContent className="max-w-[92vw] sm:max-w-md">
                        <DialogHeader>
                            <DialogTitle>Rename {renameDialog.type}</DialogTitle>
                        </DialogHeader>
                        <Input
                            value={renameValue || renameDialog.item?.name || ''}
                            onChange={(e) => setRenameValue(e.target.value)}
                            placeholder="New name"
                            autoFocus
                            onFocus={() => { if (!renameValue && renameDialog.item) setRenameValue(renameDialog.item.name); }}
                            onKeyDown={(e) => { if (e.key === 'Enter' && renameValue.trim()) handleRename(renameValue); }}
                        />
                        <DialogFooter className="gap-2">
                            <Button variant="outline" onClick={closeRenameDialog}>Cancel</Button>
                            <Button onClick={() => handleRename(renameValue)} disabled={!renameValue.trim()}>Rename</Button>
                        </DialogFooter>
                    </DialogContent>
                </Dialog>

                {/* Timestamp Details Dialog */}
                {timestampFile && (
                    <TimestampDetails
                        fileId={timestampFile.id}
                        filename={timestampFile.filename}
                        open={showTimestamp}
                        onClose={closeTimestamp}
                    />
                )}

                {/* File Upload Drawer */}
                <Drawer.Root open={showUploader} onOpenChange={setShowUploader}>
                    <Drawer.Portal>
                        <Drawer.Overlay
                            style={{
                                position: "fixed",
                                inset: 0,
                                backgroundColor: "rgba(0, 0, 0, 0.4)",
                                zIndex: 100,
                            }}
                        />
                        <Drawer.Content
                            style={{
                                position: "fixed",
                                bottom: 0,
                                left: 0,
                                right: 0,
                                maxHeight: "90vh",
                                backgroundColor: "var(--background)",
                                borderTopLeftRadius: 16,
                                borderTopRightRadius: 16,
                                zIndex: 100,
                                outline: "none",
                                paddingBottom: "env(safe-area-inset-bottom, 0px)",
                                display: "flex",
                                flexDirection: "column",
                            }}
                        >
                            <div
                                style={{
                                    display: "flex",
                                    justifyContent: "center",
                                    paddingTop: 12,
                                    paddingBottom: 8,
                                    flexShrink: 0,
                                }}
                            >
                                <div
                                    style={{
                                        width: 36,
                                        height: 4,
                                        borderRadius: 2,
                                        backgroundColor: "var(--muted-foreground)",
                                        opacity: 0.3,
                                    }}
                                />
                            </div>

                            <div style={{ padding: "0 16px 24px", overflowY: "auto" }}>
                                <Drawer.Title
                                    style={{
                                        fontSize: 18,
                                        fontWeight: 600,
                                        margin: "0 0 16px 0",
                                        color: "var(--foreground)",
                                    }}
                                >
                                    Upload Files
                                </Drawer.Title>

                                <FileUploader
                                    folderId={currentFolderId}
                                    onUploadComplete={closeUploader}
                                    className="w-full"
                                />
                            </div>
                        </Drawer.Content>
                    </Drawer.Portal>
                </Drawer.Root>
            </PullToRefresh>
        </PageTransition >
    );
}

// ─────────────────────────────────────────────────────────────
// SUB-COMPONENTS
// ─────────────────────────────────────────────────────────────

interface BreadcrumbHeaderProps {
    currentFolderId: number | null;
    breadcrumbPath: { id: number | null; name: string }[];
    onBack: () => void;
}

function BreadcrumbHeader({ currentFolderId, breadcrumbPath, onBack }: BreadcrumbHeaderProps) {
    if (currentFolderId === null) return null;

    return (
        <motion.div
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "12px 16px",
                borderBottom: "1px solid var(--border)",
            }}
        >
            <motion.button
                onClick={onBack}
                whileTap={{ scale: 0.95 }}
                style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    width: 36,
                    height: 36,
                    borderRadius: 10,
                    backgroundColor: "var(--muted)",
                    border: "none",
                    cursor: "pointer",
                }}
            >
                <ChevronLeft size={20} style={{ color: "var(--foreground)" }} />
            </motion.button>
            <div style={{ flex: 1, overflow: "hidden" }}>
                <p
                    style={{
                        fontSize: 16,
                        fontWeight: 600,
                        color: "var(--foreground)",
                        margin: 0,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                    }}
                >
                    {breadcrumbPath[breadcrumbPath.length - 1]?.name || "Folder"}
                </p>
                {breadcrumbPath.length > 1 && (
                    <p
                        style={{
                            fontSize: 11,
                            color: "var(--muted-foreground)",
                            margin: "2px 0 0",
                        }}
                    >
                        {breadcrumbPath.slice(0, -1).map(f => f.name).join(" / ")}
                    </p>
                )}
            </div>
        </motion.div>
    );
}

interface FoldersSectionProps {
    folders: { id: number; name: string; parentId: number | null }[];
    onFolderClick: (id: number) => void;
    onFolderLongPress: (folder: { id: number; name: string; parentId: number | null }) => void;
    getFolderDisplayName?: (folder: { id: number; name: string; parentId: number | null }) => string;
}

function FoldersSection({ folders, onFolderClick, onFolderLongPress, getFolderDisplayName }: FoldersSectionProps) {
    if (folders.length === 0) return null;

    return (
        <>
            <SectionHeader title={`Folders (${folders.length})`} />
            <div
                style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(3, 1fr)",
                    gap: 12,
                    padding: "0 16px 16px",
                }}
            >
                {folders.map((folder) => (
                    <FileCard
                        key={`folder-${folder.id}`}
                        name={getFolderDisplayName ? getFolderDisplayName(folder) : folder.name}
                        type="folder"
                        onClick={() => onFolderClick(folder.id)}
                        onLongPress={() => onFolderLongPress(folder)}
                        onMenuClick={() => onFolderLongPress(folder)}
                    />
                ))}
            </div>
        </>
    );
}

interface FilesSectionProps {
    files: PreviewableFile[];
    onFileClick: (file: PreviewableFile) => void;
    onFileLongPress: (file: FileInfo) => void;
    getTimestampStatus?: (fileId: number) => TimestampStatus | null;
    onTimestampClick?: (file: PreviewableFile) => void;
    onFavoriteToggle?: (fileId: number) => void;
}

function FilesSection({ files, onFileClick, onFileLongPress, getTimestampStatus, onTimestampClick, onFavoriteToggle }: FilesSectionProps) {
    if (files.length === 0) return null;

    return (
        <>
            <SectionHeader title={`Files (${files.length})`} />
            <div
                style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(3, 1fr)",
                    gap: 12,
                    padding: "0 16px 16px",
                }}
            >
                {files.map((file) => {
                    const displayName = (file as any).decryptedFilename || file.filename;
                    return (
                        <FileCard
                            key={`file-${file.id}`}
                            name={displayName}
                            type={file.fileType as FileType}
                            size={file.size}
                            onClick={() => onFileClick(file)}
                            onLongPress={() => onFileLongPress({
                                id: file.id,
                                name: displayName,
                                type: file.fileType as FileType,
                                size: file.size,
                            })}
                            onMenuClick={() => onFileLongPress({
                                id: file.id,
                                name: displayName,
                                type: file.fileType as FileType,
                                size: file.size,
                            })}
                            timestampStatus={getTimestampStatus?.(file.id)}
                            onTimestampClick={() => onTimestampClick?.(file)}
                            isFavorite={!!(file as any).isFavorite}
                            onFavoriteToggle={onFavoriteToggle ? () => onFavoriteToggle(file.id) : undefined}
                        />
                    );
                })}
            </div>
        </>
    );
}

export default MobileDrive;
