/**
 * ImageViewer Component
 *
 * Image viewer with zoom, rotation, and error handling.
 */

import { useCallback, useEffect, useRef } from 'react';
import { Download, ImageOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useGestures } from '@/hooks/useGestures';
import type { ImageState } from '../types';

interface ImageViewerProps {
    mediaUrl: string;
    filename: string;
    imageState: ImageState;
    onLoad: () => void;
    onError: (message: string) => void;
    onDownload: () => void;
    onZoomTo?: (scale: number) => void;
    onResetZoom?: () => void;
}

/** Timeout for image loading - if image hasn't loaded in 30s, show error */
const IMAGE_LOAD_TIMEOUT_MS = 30_000;

export function ImageViewer({
    mediaUrl,
    filename,
    imageState,
    onLoad,
    onError,
    onDownload,
    onZoomTo,
    onResetZoom,
}: ImageViewerProps) {
    const { zoom, rotation, error } = imageState;
    const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const loadedRef = useRef(false);
    const containerRef = useRef<HTMLDivElement>(null);
    const baseZoomRef = useRef(1);
    // Use ref for onError to avoid resetting timeout when parent re-renders
    const onErrorRef = useRef(onError);
    onErrorRef.current = onError;

    // Set timeout for image loading - only reset when mediaUrl actually changes
    useEffect(() => {
        loadedRef.current = false;

        timeoutRef.current = setTimeout(() => {
            if (!loadedRef.current) {
                onErrorRef.current('Image loading timed out. The file may be corrupted or too large. Try downloading it instead.');
            }
        }, IMAGE_LOAD_TIMEOUT_MS);

        return () => {
            if (timeoutRef.current) {
                clearTimeout(timeoutRef.current);
            }
        };
    }, [mediaUrl]);

    const handleLoad = useCallback(() => {
        loadedRef.current = true;
        if (timeoutRef.current) {
            clearTimeout(timeoutRef.current);
        }
        onLoad();
    }, [onLoad]);

    const handleError = useCallback(() => {
        loadedRef.current = true;
        if (timeoutRef.current) {
            clearTimeout(timeoutRef.current);
        }
        onErrorRef.current('Failed to load image. The file may be corrupted or in an unsupported format. Try downloading it instead.');
    }, []);

    // Pinch-to-zoom and double-tap gestures
    useGestures(containerRef as React.RefObject<HTMLElement>, {
        onPinch: (scale) => {
            onZoomTo?.(baseZoomRef.current * scale);
        },
        onDoubleTap: () => {
            if (zoom !== 1) {
                onResetZoom?.();
            } else {
                onZoomTo?.(2);
            }
        },
    });

    // Track base zoom when pinch starts
    useEffect(() => {
        baseZoomRef.current = zoom;
    }, [zoom]);

    if (error) {
        return (
            <div className="flex flex-col items-center justify-center gap-4 p-6 w-full h-full">
                <ImageOff className="w-16 h-16 text-red-400" />
                <p className="text-red-400 text-lg font-medium text-center max-w-md">{error}</p>
                <p className="text-white/50 text-sm">{filename}</p>
                <Button onClick={onDownload} variant="outline" className="mt-2">
                    <Download className="w-4 h-4 mr-2" />
                    Download file
                </Button>
            </div>
        );
    }

    return (
        <div ref={containerRef} className="relative overflow-auto w-full h-full flex items-center justify-center touch-none">
            <img
                src={mediaUrl}
                alt={filename}
                className="transition-transform duration-200"
                style={{
                    transform: `scale(${zoom}) rotate(${rotation}deg)`,
                    maxWidth: zoom > 1 ? 'none' : '100%',
                    maxHeight: zoom > 1 ? 'none' : '100%',
                }}
                onLoad={handleLoad}
                onError={handleError}
            />
        </div>
    );
}
