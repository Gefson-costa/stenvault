/**
 * DropZone Component
 * 
 * Drag and drop zone for file uploads.
 */

import { forwardRef, useRef } from 'react';
import { Upload, Camera } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useTheme } from '@/contexts/ThemeContext';
import { useIsMobile } from '@/hooks/useMobile';

interface DropZoneProps {
    isDragging: boolean;
    maxFiles: number;
    maxSizeMB: number;
    onDragOver: (e: React.DragEvent) => void;
    onDragLeave: (e: React.DragEvent) => void;
    onDrop: (e: React.DragEvent) => void;
    onClick: () => void;
    onFileChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
    onFolderClick?: () => void;
    onFolderChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
    folderInputRef?: React.RefObject<HTMLInputElement | null>;
}

export const DropZone = forwardRef<HTMLInputElement, DropZoneProps>(
    function DropZone(
        {
            isDragging,
            maxFiles,
            maxSizeMB,
            onDragOver,
            onDragLeave,
            onDrop,
            onClick,
            onFileChange,
            onFolderClick,
            onFolderChange,
            folderInputRef,
        },
        ref
    ) {
        const { theme } = useTheme();
        const isMobile = useIsMobile();
        const cameraInputRef = useRef<HTMLInputElement>(null);

        return (
            <div
                onClick={onClick}
                onDragOver={onDragOver}
                onDragLeave={onDragLeave}
                onDrop={onDrop}
                className={cn(
                    'relative flex flex-col items-center justify-center w-full min-h-[200px] p-8 rounded-sm border-2 border-dashed transition-all duration-300 cursor-pointer',
                    isDragging
                        ? 'border-primary bg-primary/5 scale-[1.02]'
                        : 'border-border/50 hover:border-primary/50 hover:bg-accent/30',
                    'group'
                )}
            >
                <input
                    ref={ref}
                    type="file"
                    multiple
                    accept="*/*"
                    onChange={onFileChange}
                    className="hidden"
                />
                {isMobile && (
                    <input
                        ref={cameraInputRef}
                        type="file"
                        accept="image/*,video/*"
                        capture="environment"
                        onChange={onFileChange}
                        className="hidden"
                    />
                )}
                {folderInputRef && (
                    <input
                        ref={folderInputRef}
                        type="file"
                        // @ts-expect-error webkitdirectory is a non-standard attribute
                        webkitdirectory=""
                        onChange={onFolderChange}
                        className="hidden"
                    />
                )}

                <div className={cn(
                    'flex flex-col items-center gap-4 transition-transform duration-300',
                    isDragging && 'scale-110'
                )}>
                    <div
                        className="p-4 rounded-lg transition-colors"
                        style={{ backgroundColor: `${theme.brand.primary}10` }}
                    >
                        <Upload className="w-8 h-8" style={{ color: theme.brand.primary }} />
                    </div>

                    <div className="text-center space-y-2">
                        <p className="text-lg font-medium text-foreground">
                            {isDragging ? 'Drop files here' : isMobile ? 'Tap to upload files' : 'Drag & drop files here'}
                        </p>
                        <p className="text-sm text-muted-foreground">
                            {isMobile ? (
                                <>
                                    or{' '}
                                    <span
                                        className="text-primary hover:underline"
                                        onClick={(e) => { e.stopPropagation(); cameraInputRef.current?.click(); }}
                                        role="button"
                                        tabIndex={0}
                                        onKeyDown={(e) => { if (e.key === 'Enter') { e.stopPropagation(); cameraInputRef.current?.click(); } }}
                                    >
                                        <Camera className="w-4 h-4 inline mr-1" />
                                        take a photo
                                    </span>
                                </>
                            ) : (
                                <>
                                    or <span className="text-primary hover:underline">browse</span> to choose files
                                    {onFolderClick && (
                                        <>
                                            {' '}or{' '}
                                            <span
                                                className="text-primary hover:underline"
                                                onClick={(e) => { e.stopPropagation(); onFolderClick(); }}
                                                role="button"
                                                tabIndex={0}
                                                onKeyDown={(e) => { if (e.key === 'Enter') { e.stopPropagation(); onFolderClick(); } }}
                                            >
                                                upload a folder
                                            </span>
                                        </>
                                    )}
                                </>
                            )}
                        </p>
                        <p className="text-xs text-muted-foreground/60">
                            Max {maxFiles} files, up to {maxSizeMB}MB each
                        </p>
                    </div>
                </div>

                {/* Animated border */}
                {isDragging && (
                    <div className="absolute inset-0 rounded-sm overflow-hidden pointer-events-none">
                        <div className="absolute inset-0 border-2 border-primary rounded-sm animate-pulse" />
                    </div>
                )}
            </div>
        );
    }
);
