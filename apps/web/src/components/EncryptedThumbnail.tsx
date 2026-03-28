/**
 * EncryptedThumbnail Component (Phase 7.2)
 *
 * Displays encrypted thumbnails by decrypting them client-side.
 * Shows loading skeleton while decrypting and falls back to icon on error.
 *
 * @module EncryptedThumbnail
 */

import React, { useMemo } from 'react';
import { useThumbnailDecryption } from '@/hooks/useThumbnailDecryption';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { FileIcon, ImageIcon, VideoIcon, FileAudioIcon, FileTextIcon } from 'lucide-react';

// ===== TYPES =====

export interface EncryptedThumbnailProps {
    /** File ID for cache key and key derivation */
    fileId: number;
    /** URL to fetch encrypted thumbnail from R2 */
    thumbnailUrl: string | null;
    /** IV used for thumbnail encryption */
    thumbnailIv: string | null;
    /** Original MIME type for fallback icon */
    mimeType: string | null;
    /** Override fileId for HKDF key derivation (for duplicated files) */
    keyDerivationFileId?: number;
    /** Organization ID — if set, derives thumbnail key from OMK */
    organizationId?: number | null;
    /** Alt text for the image */
    alt?: string;
    /** Additional CSS classes */
    className?: string;
    /** Width of the thumbnail container */
    width?: number | string;
    /** Height of the thumbnail container */
    height?: number | string;
    /** Object-fit style for the image */
    objectFit?: 'cover' | 'contain' | 'fill' | 'none';
    /** Whether decryption is disabled (e.g., vault locked) */
    disabled?: boolean;
}

// ===== HELPER FUNCTIONS =====

/**
 * Get fallback icon component based on MIME type
 */
function getFallbackIcon(mimeType: string | null): React.ComponentType<{ className?: string }> {
    if (!mimeType) return FileIcon;

    if (mimeType.startsWith('image/')) return ImageIcon;
    if (mimeType.startsWith('video/')) return VideoIcon;
    if (mimeType.startsWith('audio/')) return FileAudioIcon;
    if (mimeType.startsWith('text/') || mimeType.includes('pdf') || mimeType.includes('document')) {
        return FileTextIcon;
    }

    return FileIcon;
}

// ===== COMPONENT =====

/**
 * EncryptedThumbnail - Displays an encrypted thumbnail with decryption
 *
 * @example
 * ```tsx
 * <EncryptedThumbnail
 *   fileId={file.id}
 *   thumbnailUrl={file.thumbnailUrl}
 *   thumbnailIv={file.thumbnailIv}
 *   mimeType={file.mimeType}
 *   className="w-20 h-20 rounded-md"
 * />
 * ```
 */
export function EncryptedThumbnail({
    fileId,
    thumbnailUrl,
    thumbnailIv,
    mimeType,
    keyDerivationFileId,
    organizationId,
    alt = 'Thumbnail',
    className,
    width = 80,
    height = 80,
    objectFit = 'cover',
    disabled = false,
}: EncryptedThumbnailProps) {
    const { url, isLoading, error } = useThumbnailDecryption({
        fileId,
        thumbnailUrl: disabled ? null : thumbnailUrl,
        thumbnailIv: disabled ? null : thumbnailIv,
        keyDerivationFileId,
        organizationId,
        autoFetch: true,
    });

    const FallbackIcon = useMemo(() => getFallbackIcon(mimeType), [mimeType]);

    const containerStyle = useMemo(() => ({
        width: typeof width === 'number' ? `${width}px` : width,
        height: typeof height === 'number' ? `${height}px` : height,
    }), [width, height]);

    // ===== LOADING STATE =====
    if (isLoading) {
        return (
            <Skeleton
                className={cn('rounded-md', className)}
                style={containerStyle}
            />
        );
    }

    // ===== DECRYPTED IMAGE =====
    if (url) {
        return (
            <img
                src={url}
                alt={alt}
                className={cn('rounded-md', className)}
                style={{
                    ...containerStyle,
                    objectFit,
                }}
                loading="lazy"
            />
        );
    }

    // ===== FALLBACK ICON =====
    // Show when:
    // - No thumbnail URL provided
    // - Decryption failed
    // - Disabled
    return (
        <div
            className={cn(
                'flex items-center justify-center rounded-md bg-muted',
                className
            )}
            style={containerStyle}
            title={error || undefined}
        >
            <FallbackIcon
                className={cn(
                    'text-muted-foreground',
                    typeof width === 'number' && width <= 40 ? 'h-4 w-4' :
                        typeof width === 'number' && width <= 80 ? 'h-6 w-6' : 'h-8 w-8'
                )}
            />
        </div>
    );
}

/**
 * EncryptedThumbnailMemo - Memoized version for performance in lists
 */
export const EncryptedThumbnailMemo = React.memo(EncryptedThumbnail);
