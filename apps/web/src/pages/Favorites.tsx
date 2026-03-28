/**
 * Favorites Page
 *
 * Displays starred/favorite files with quick unfavorite action.
 * Pattern follows Trash.tsx for consistency.
 */

import { useState, useEffect, useMemo } from 'react';
import { useIsMobile } from '@/hooks/useMobile';
import { MobileFavorites } from '@/components/mobile-v2/pages/MobileFavorites';
import { trpc } from '@/lib/trpc';
import { useCurrentOrgId } from '@/contexts/OrganizationContext';
import { formatBytes } from '@stenvault/shared';
import {
    Star,
    File,
    Image,
    Video,
    Music,
    FileText,
} from 'lucide-react';

import { AuroraCard, AuroraCardContent } from '@/components/ui/aurora-card';
import { EmptyState } from '@/components/ui/empty-state';
import { PageLoading } from '@/components/ui/page-loading';
import { FadeIn } from '@/components/ui/animated';
import { useTheme } from '@/contexts/ThemeContext';
import { useFilenameDecryption } from '@/hooks/useFilenameDecryption';
import { useFavoriteToggle } from '@/hooks/useFavoriteToggle';
import { FavoriteStar } from '@/components/files/components/FavoriteStar';
import { FilePreviewModal } from '@/components/FilePreviewModal/index';
import type { FileItem } from '@/components/files/types';

function getFileTypeIcon(fileType: string) {
    switch (fileType) {
        case 'image': return Image;
        case 'video': return Video;
        case 'audio': return Music;
        case 'document': return FileText;
        default: return File;
    }
}

export default function Favorites() {
    const isMobile = useIsMobile();
    const { theme } = useTheme();
    const orgId = useCurrentOrgId();

    // Queries
    const { data: favoriteFiles, isLoading } = trpc.files.listFavorites.useQuery({ limit: 100, organizationId: orgId });

    // Filename decryption
    const { getDisplayName, decryptFilenames } = useFilenameDecryption();
    const [decryptedFiles, setDecryptedFiles] = useState<FileItem[]>([]);

    const rawFiles = useMemo(() => favoriteFiles ?? [], [favoriteFiles]);

    useEffect(() => {
        if (rawFiles.length > 0) {
            decryptFilenames(rawFiles as FileItem[]).then(
                (result) => setDecryptedFiles(result as FileItem[])
            );
        } else {
            setDecryptedFiles(prev => prev.length === 0 ? prev : []);
        }
    }, [rawFiles, decryptFilenames]);

    // Favorites
    const { toggleFavorite } = useFavoriteToggle();

    // Preview
    const [previewFile, setPreviewFile] = useState<FileItem | null>(null);

    if (isMobile) return <MobileFavorites />;

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
                            style={{ backgroundColor: '#f59e0b' }}
                        />
                        <AuroraCardContent className="p-4">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div
                                        className="p-2 rounded-lg"
                                        style={{ backgroundColor: 'rgba(245, 158, 11, 0.15)' }}
                                    >
                                        <Star
                                            className="h-5 w-5 fill-amber-400 text-amber-400"
                                        />
                                    </div>
                                    <div>
                                        <h1 className="text-xl md:text-2xl font-semibold tracking-tight text-foreground">
                                            Favorites
                                        </h1>
                                        {!isEmpty && (
                                            <p className="text-xs text-muted-foreground">
                                                {decryptedFiles.length} file{decryptedFiles.length !== 1 ? 's' : ''} &middot; {formatBytes(totalSize)}
                                            </p>
                                        )}
                                    </div>
                                </div>
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
                            icon={Star}
                            title="No favorites yet"
                            description="Star files from Drive to see them here."
                        />
                    ) : (
                        <AuroraCard variant="glass">
                            <AuroraCardContent className="p-0">
                                <div className="divide-y divide-border">
                                    {decryptedFiles.map((file) => {
                                        const Icon = getFileTypeIcon(file.fileType);
                                        const displayName = getDisplayName(file);

                                        return (
                                            <div
                                                key={file.id}
                                                className="flex items-center gap-3 px-4 py-3 hover:bg-muted/50 transition-colors cursor-pointer"
                                                onClick={() => setPreviewFile(file)}
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
                                                    </div>
                                                </div>

                                                {/* Favorite star */}
                                                <div className="shrink-0">
                                                    <FavoriteStar
                                                        isFavorite={true}
                                                        onClick={() => toggleFavorite(file.id)}
                                                    />
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

            {/* Preview Modal */}
            {previewFile && (
                <FilePreviewModal
                    file={previewFile}
                    open={!!previewFile}
                    onClose={() => setPreviewFile(null)}
                />
            )}
        </>
    );
}
