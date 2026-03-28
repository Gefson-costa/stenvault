/**
 * Trash Page
 *
 * Displays soft-deleted files with restore and permanent delete options.
 * Files are retained for 30 days before automatic permanent deletion.
 */

import { useState, useCallback, useEffect, useMemo } from 'react';
import { useIsMobile } from '@/hooks/useMobile';
import { MobileTrash } from '@/components/mobile-v2/pages/MobileTrash';
import { trpc } from '@/lib/trpc';
import { useCurrentOrgId } from '@/contexts/OrganizationContext';
import { toast } from 'sonner';
import { formatBytes } from '@stenvault/shared';
import {
  Trash2,
  RotateCcw,
  AlertTriangle,
  Clock,
  File,
  Image,
  Video,
  Music,
  FileText,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { EmptyState } from '@/components/ui/empty-state';
import { PageLoading } from '@/components/ui/page-loading';
import { AuroraCard, AuroraCardContent } from '@/components/ui/aurora-card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { FadeIn } from '@/components/ui/animated';
import { useTheme } from '@/contexts/ThemeContext';
import { useFilenameDecryption } from '@/hooks/useFilenameDecryption';
import type { FileItem } from '@/components/files/types';

/** FileItem extended with trash-specific fields from listDeleted */
interface TrashFileItem extends FileItem {
  deletedAt: Date | string;
  daysUntilPermanentDeletion: number;
}

// ─────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────

function getFileTypeIcon(fileType: string) {
  switch (fileType) {
    case 'image': return Image;
    case 'video': return Video;
    case 'audio': return Music;
    case 'document': return FileText;
    default: return File;
  }
}

function formatDeletedDate(date: Date | string): string {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

// ─────────────────────────────────────────────────────────────
// COMPONENT
// ─────────────────────────────────────────────────────────────

export default function Trash() {
  const isMobile = useIsMobile();
  const { theme } = useTheme();
  const utils = trpc.useUtils();
  const orgId = useCurrentOrgId();

  // State
  const [confirmEmpty, setConfirmEmpty] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<number | null>(null);

  // Queries
  const { data: deletedFiles, isLoading } = trpc.files.listDeleted.useQuery({ organizationId: orgId });

  // Filename decryption
  const { getDisplayName, decryptFilenames } = useFilenameDecryption();
  const [decryptedFiles, setDecryptedFiles] = useState<TrashFileItem[]>([]);

  const rawFiles = useMemo(() => deletedFiles ?? [], [deletedFiles]);

  useEffect(() => {
    if (rawFiles.length > 0) {
      decryptFilenames(rawFiles as TrashFileItem[]).then(
        (result) => setDecryptedFiles(result as TrashFileItem[])
      );
    } else {
      setDecryptedFiles(prev => prev.length === 0 ? prev : []);
    }
  }, [rawFiles, decryptFilenames]);

  // Mutations
  const restoreMutation = trpc.files.restore.useMutation({
    onSuccess: () => {
      toast.success('File restored');
      utils.files.listDeleted.invalidate();
      utils.files.list.invalidate();
      utils.files.getStorageStats.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const permanentDeleteMutation = trpc.files.permanentDelete.useMutation({
    onSuccess: () => {
      toast.success('File permanently deleted');
      setDeleteTarget(null);
      utils.files.listDeleted.invalidate();
      utils.files.getStorageStats.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const emptyTrashMutation = trpc.files.emptyTrash.useMutation({
    onSuccess: (data) => {
      toast.success(`Permanently deleted ${data.deletedCount} file(s)`);
      setConfirmEmpty(false);
      utils.files.listDeleted.invalidate();
      utils.files.getStorageStats.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  // Handlers
  const handleRestore = useCallback((fileId: number) => {
    restoreMutation.mutate({ fileId });
  }, [restoreMutation]);

  const handlePermanentDelete = useCallback(() => {
    if (deleteTarget !== null) {
      permanentDeleteMutation.mutate({ fileId: deleteTarget });
    }
  }, [deleteTarget, permanentDeleteMutation]);

  const handleEmptyTrash = useCallback(() => {
    emptyTrashMutation.mutate({ organizationId: orgId });
  }, [emptyTrashMutation, orgId]);

  if (isMobile) return <MobileTrash />;

  const isEmpty = decryptedFiles.length === 0 && !isLoading;
  const totalSize = decryptedFiles.reduce((sum, f) => sum + (f.size || 0), 0);

  return (
    <>
      <div className="flex flex-col h-full">
        {/* Header */}
        <FadeIn>
          <AuroraCard variant="glass" className="relative overflow-hidden mb-6">
            <div
              className="absolute -top-10 -right-10 w-28 h-28 rounded-full blur-3xl opacity-15 pointer-events-none"
              style={{ backgroundColor: theme.brand.primary }}
            />
            <AuroraCardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div
                    className="p-2 rounded-lg"
                    style={{ backgroundColor: `${theme.brand.primary}15` }}
                  >
                    <Trash2
                      className="h-5 w-5"
                      style={{ color: theme.brand.primary }}
                    />
                  </div>
                  <div>
                    <h1 className="text-xl md:text-2xl font-semibold tracking-tight text-foreground">
                      Trash
                    </h1>
                    {!isEmpty && (
                      <p className="text-xs text-muted-foreground">
                        {decryptedFiles.length} file{decryptedFiles.length !== 1 ? 's' : ''} &middot; {formatBytes(totalSize)}
                      </p>
                    )}
                  </div>
                </div>

                {!isEmpty && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setConfirmEmpty(true)}
                    className="text-destructive hover:text-destructive"
                  >
                    <Trash2 className="w-4 h-4 mr-2" />
                    Empty Trash
                  </Button>
                )}
              </div>
            </AuroraCardContent>
          </AuroraCard>
        </FadeIn>

        {/* Content */}
        <FadeIn delay={0.1} className="flex-1 min-h-0">
          {isLoading ? (
            <PageLoading />
          ) : isEmpty ? (
            <EmptyState
              icon={Trash2}
              title="Trash is empty"
              description="Files you delete will appear here for 30 days before being permanently removed."
            />
          ) : (
            <AuroraCard variant="glass">
              <AuroraCardContent className="p-0">
                <div className="divide-y divide-border">
                  {decryptedFiles.map((file) => {
                    const Icon = getFileTypeIcon(file.fileType);
                    const displayName = getDisplayName(file);
                    const deletedAt = file.deletedAt;
                    const daysLeft = file.daysUntilPermanentDeletion;
                    const isUrgent = daysLeft <= 7;

                    return (
                      <div
                        key={file.id}
                        className="flex items-center gap-3 px-4 py-3 hover:bg-muted/50 transition-colors"
                      >
                        {/* Icon */}
                        <div className="shrink-0">
                          <Icon className="h-5 w-5 text-muted-foreground" />
                        </div>

                        {/* File info */}
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{displayName}</p>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <span>{formatBytes(file.size)}</span>
                            {deletedAt && (
                              <>
                                <span>&middot;</span>
                                <span>Deleted {formatDeletedDate(deletedAt)}</span>
                              </>
                            )}
                          </div>
                        </div>

                        {/* Retention countdown */}
                        <div className={`hidden sm:flex items-center gap-1 text-xs shrink-0 ${isUrgent ? 'text-destructive' : 'text-muted-foreground'}`}>
                          {isUrgent ? <AlertTriangle className="h-3 w-3" /> : <Clock className="h-3 w-3" />}
                          <span>{daysLeft}d left</span>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center gap-1 shrink-0">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleRestore(file.id)}
                            disabled={restoreMutation.isPending}
                            title="Restore"
                          >
                            <RotateCcw className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setDeleteTarget(file.id)}
                            className="text-destructive hover:text-destructive"
                            title="Delete permanently"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </AuroraCardContent>
            </AuroraCard>
          )}
        </FadeIn>
      </div>

      {/* Empty Trash Confirmation */}
      <Dialog open={confirmEmpty} onOpenChange={setConfirmEmpty}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Empty Trash?</DialogTitle>
            <DialogDescription>
              This will permanently delete {decryptedFiles.length} file{decryptedFiles.length !== 1 ? 's' : ''} ({formatBytes(totalSize)}).
              This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmEmpty(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleEmptyTrash}
              disabled={emptyTrashMutation.isPending}
            >
              {emptyTrashMutation.isPending ? 'Deleting...' : 'Empty Trash'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Permanent Delete Confirmation */}
      <Dialog open={deleteTarget !== null} onOpenChange={() => setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Permanently delete?</DialogTitle>
            <DialogDescription>
              This file will be permanently deleted and cannot be recovered.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handlePermanentDelete}
              disabled={permanentDeleteMutation.isPending}
            >
              {permanentDeleteMutation.isPending ? 'Deleting...' : 'Delete Forever'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
