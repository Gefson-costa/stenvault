/**
 * FileGrid View Component
 * 
 * Grid view for displaying files and folders.
 */

import { cn } from '@/lib/utils';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Folder,
    MoreVertical,
    Download,
    Trash2,
    Pencil,
    Eye,
    Share2,
    History,
    Clock,
    Star,
    Copy,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useIsMobile } from '@/hooks/useMobile';
import { containerVariants, itemVariants, formatFileSize, renderFileIcon } from '../utils';
import { TimestampIcon } from '../components/TimestampBadge';
import { SignatureIcon } from '../components/SignatureIcon';
import { EncryptedThumbnailMemo } from '@/components/EncryptedThumbnail';
import type { FileItem, FolderItem, TimestampProps } from '../types';

interface FileGridProps {
    files: FileItem[];
    folders: FolderItem[];
    onFolderClick?: (folderId: number) => void;
    onFilePreview?: (file: FileItem) => void;
    onDownload: (file: FileItem) => void;
    onShare: (file: FileItem) => void;
    onRename: (item: FileItem | FolderItem, type: 'file' | 'folder') => void;
    onDelete: (item: FileItem | FolderItem, type: 'file' | 'folder') => void;
    // Long press handlers for mobile
    handleClick: (e: React.MouseEvent | React.TouchEvent, callback: () => void) => void;
    longPressHandlers: {
        onTouchStart: (e: React.TouchEvent, file: FileItem | null, folder: FolderItem | null) => void;
        onTouchEnd: () => void;
        onTouchMove: (e: React.TouchEvent) => void;
    };
    onFolderDownload?: (folder: FolderItem) => void;
    onMove?: (fileId: number, targetFolderId: number) => void;
    // Selection
    isSelected?: (fileId: number) => boolean;
    onToggleSelection?: (fileId: number) => void;
    // Version history
    onVersionHistory?: (file: FileItem) => void;
    /** Timestamp props - grouped for consistency */
    timestamp?: TimestampProps<FileItem>;
    // Favorites
    onToggleFavorite?: (fileId: number) => void;
    // Duplicate
    onDuplicate?: (file: FileItem) => void;
    /** Get decrypted display name for a folder */
    getFolderDisplayName?: (folder: FolderItem) => string;
}

export function FileGrid({
    files,
    folders,
    onFolderClick,
    onFilePreview,
    onDownload,
    onShare,
    onRename,
    onDelete,
    onFolderDownload,
    handleClick,
    longPressHandlers,
    onMove,
    isSelected,
    onToggleSelection,
    onVersionHistory,
    timestamp,
    onToggleFavorite,
    onDuplicate,
    getFolderDisplayName,
}: FileGridProps) {
    const isMobile = useIsMobile();

    return (
        <motion.div
            className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4"
            variants={containerVariants}
            initial="hidden"
            animate="show"
        >
            {/* Folders */}
            <AnimatePresence mode='popLayout'>
                {folders.map((folder) => (
                    <motion.div
                        layout
                        key={`folder-${folder.id}`}
                        variants={itemVariants}
                        className={cn(
                            "group relative p-4 rounded-sm border border-border/50 bg-card hover:bg-accent/50 hover:border-primary/30 transition-colors cursor-pointer select-none",
                        )}
                        onClick={(e) => handleClick(e, () => onFolderClick?.(folder.id))}
                        onTouchStart={(e) => longPressHandlers.onTouchStart(e, null, folder)}
                        onTouchEnd={longPressHandlers.onTouchEnd}
                        onTouchMove={longPressHandlers.onTouchMove}
                        onDragOver={(e: any) => {
                            e.preventDefault();
                            e.currentTarget.classList.add('border-primary', 'bg-primary/5', 'ring-1', 'ring-primary/20');
                        }}
                        onDragLeave={(e: any) => {
                            e.currentTarget.classList.remove('border-primary', 'bg-primary/5', 'ring-1', 'ring-primary/20');
                        }}
                        onDrop={(e: any) => {
                            e.preventDefault();
                            e.currentTarget.classList.remove('border-primary', 'bg-primary/5', 'ring-1', 'ring-primary/20');
                            const fileId = e.dataTransfer.getData('fileId');
                            if (fileId && onMove) {
                                onMove(parseInt(fileId), folder.id);
                            }
                        }}
                        style={{ WebkitUserSelect: 'none', WebkitTouchCallout: 'none' }}
                    >
                        <div className="flex flex-col items-center gap-3">
                            <div className="p-3 rounded-sm bg-primary/10">
                                <Folder className="w-8 h-8 text-primary" />
                            </div>
                            <span className="text-sm font-medium text-center truncate w-full">
                                {getFolderDisplayName ? getFolderDisplayName(folder) : folder.name}
                            </span>
                        </div>

                        {/* Actions - Always visible on mobile */}
                        <div className={`absolute top-2 right-2 transition-opacity ${isMobile ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
                            <DropdownMenu>
                                <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
                                    <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="Folder actions">
                                        <MoreVertical className="w-4 h-4" />
                                    </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                    {onFolderDownload && (
                                        <DropdownMenuItem
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                onFolderDownload(folder);
                                            }}
                                        >
                                            <Download className="w-4 h-4 mr-2" />
                                            Download as ZIP
                                        </DropdownMenuItem>
                                    )}
                                    <DropdownMenuItem
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onRename(folder, 'folder');
                                        }}
                                    >
                                        <Pencil className="w-4 h-4 mr-2" />
                                        Rename
                                    </DropdownMenuItem>
                                    <DropdownMenuSeparator />
                                    <DropdownMenuItem
                                        className="text-destructive"
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onDelete(folder, 'folder');
                                        }}
                                    >
                                        <Trash2 className="w-4 h-4 mr-2" />
                                        Delete
                                    </DropdownMenuItem>
                                </DropdownMenuContent>
                            </DropdownMenu>
                        </div>
                    </motion.div>
                ))}
            </AnimatePresence>

            {/* Files */}
            <AnimatePresence mode='popLayout'>
                {files.map((file) => (
                    <motion.div
                        layout
                        variants={itemVariants}
                        key={`file-${file.id}`}
                        draggable
                        onDragStart={(e: any) => {
                            e.dataTransfer.setData('fileId', file.id.toString());
                            e.dataTransfer.effectAllowed = 'move';
                            // Add a Ghost image or subtle effect if needed
                        }}
                        className="group relative p-4 rounded-sm border border-border/50 bg-card hover:bg-accent/50 hover:border-primary/30 transition-colors cursor-pointer select-none active:scale-[0.98] active:border-primary/50"
                        onClick={(e) => handleClick(e, () => onFilePreview?.(file))}
                        onTouchStart={(e) => longPressHandlers.onTouchStart(e, file, null)}
                        onTouchEnd={longPressHandlers.onTouchEnd}
                        onTouchMove={longPressHandlers.onTouchMove}
                        style={{ WebkitUserSelect: 'none', WebkitTouchCallout: 'none' }}
                    >
                        <div className="flex flex-col items-center gap-3">
                            {/* Selection Checkbox */}
                            {isSelected && onToggleSelection && (
                                <div
                                    className="absolute top-1 left-1 z-10 min-w-[44px] min-h-[44px] flex items-center justify-center"
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        onToggleSelection(file.id);
                                    }}
                                >
                                    <input
                                        type="checkbox"
                                        checked={isSelected(file.id)}
                                        onChange={() => { }}
                                        className="w-6 h-6 cursor-pointer accent-primary"
                                    />
                                </div>
                            )}

                            <div className="p-3 rounded-sm bg-muted relative">
                                {/* Phase 7.2: Show encrypted thumbnail if available, otherwise icon */}
                                {file.thumbnailUrl && file.thumbnailIv ? (
                                    <EncryptedThumbnailMemo
                                        fileId={file.id}
                                        thumbnailUrl={file.thumbnailUrl}
                                        thumbnailIv={file.thumbnailIv}
                                        mimeType={file.mimeType}
                                        keyDerivationFileId={file.duplicatedFromId ?? undefined}
                                        organizationId={file.organizationId}
                                        width={32}
                                        height={32}
                                        className="rounded-sm"
                                    />
                                ) : (
                                    renderFileIcon(file.fileType, 'w-8 h-8')
                                )}
                                {/* Timestamp & Signature indicators */}
                                {timestamp?.getStatus && timestamp.getStatus(file.id) && (
                                    <TimestampIcon
                                        status={timestamp.getStatus(file.id)}
                                        className="absolute -bottom-1 -right-1"
                                        onClick={() => timestamp?.onClick?.(file)}
                                    />
                                )}
                                {file.isSigned && (
                                    <SignatureIcon
                                        signedAt={file.signedAt}
                                        className="absolute -bottom-1 -left-1"
                                    />
                                )}
                            </div>
                            <div className="w-full text-center">
                                <span className="text-sm font-medium truncate block">
                                    {file.decryptedFilename || file.filename}
                                </span>
                                <span className="text-xs text-muted-foreground">
                                    {formatFileSize(file.size)}
                                </span>
                            </div>
                        </div>

                        {/* Actions - Always visible on mobile */}
                        <div className={`absolute top-2 right-2 transition-opacity ${isMobile ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
                            <DropdownMenu>
                                <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
                                    <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="File actions">
                                        <MoreVertical className="w-4 h-4" />
                                    </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                    <DropdownMenuItem
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onFilePreview?.(file);
                                        }}
                                    >
                                        <Eye className="w-4 h-4 mr-2" />
                                        Preview
                                    </DropdownMenuItem>
                                    <DropdownMenuItem
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onDownload(file);
                                        }}
                                    >
                                        <Download className="w-4 h-4 mr-2" />
                                        Download
                                    </DropdownMenuItem>
                                    <DropdownMenuItem
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onShare(file);
                                        }}
                                    >
                                        <Share2 className="w-4 h-4 mr-2" />
                                        Share
                                    </DropdownMenuItem>
                                    {onDuplicate && (
                                        <DropdownMenuItem
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                onDuplicate(file);
                                            }}
                                        >
                                            <Copy className="w-4 h-4 mr-2" />
                                            Duplicate
                                        </DropdownMenuItem>
                                    )}
                                    {onToggleFavorite && (
                                        <DropdownMenuItem
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                onToggleFavorite(file.id);
                                            }}
                                        >
                                            <Star className={`w-4 h-4 mr-2 ${file.isFavorite ? 'fill-amber-400 text-amber-400' : ''}`} />
                                            {file.isFavorite ? 'Remove Favorite' : 'Favorite'}
                                        </DropdownMenuItem>
                                    )}
                                    <DropdownMenuSeparator />
                                    <DropdownMenuItem
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onRename(file, 'file');
                                        }}
                                    >
                                        <Pencil className="w-4 h-4 mr-2" />
                                        Rename
                                    </DropdownMenuItem>
                                    {onVersionHistory && (
                                        <DropdownMenuItem
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                onVersionHistory(file);
                                            }}
                                        >
                                            <History className="w-4 h-4 mr-2" />
                                            Version History
                                        </DropdownMenuItem>
                                    )}
                                    {timestamp?.onClick && (
                                        <DropdownMenuItem
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                timestamp.onClick?.(file);
                                            }}
                                        >
                                            <Clock className="w-4 h-4 mr-2" />
                                            Blockchain Timestamp
                                        </DropdownMenuItem>
                                    )}
                                    <DropdownMenuItem
                                        className="text-destructive"
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onDelete(file, 'file');
                                        }}
                                    >
                                        <Trash2 className="w-4 h-4 mr-2" />
                                        Delete
                                    </DropdownMenuItem>
                                </DropdownMenuContent>
                            </DropdownMenu>
                        </div>
                    </motion.div>
                ))}
            </AnimatePresence>
        </motion.div>
    );
}
