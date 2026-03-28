/**
 * ImageControls Component
 * 
 * Zoom and rotation controls for image viewer.
 */

import { ZoomIn, ZoomOut, RotateCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { ImageState } from '../types';

interface ImageControlsProps {
    state: ImageState;
    onZoomIn: () => void;
    onZoomOut: () => void;
    onRotate: () => void;
}

export function ImageControls({
    state,
    onZoomIn,
    onZoomOut,
    onRotate,
}: ImageControlsProps) {
    const { zoom } = state;

    return (
        <div className="px-4 py-3 border-t bg-background flex-shrink-0">
            <div className="flex items-center justify-center gap-1">
                <Button variant="ghost" size="icon-lg" onClick={onZoomOut} disabled={zoom <= 0.25} aria-label="Zoom out">
                    <ZoomOut className="w-5 h-5" />
                </Button>
                <span className="text-sm text-muted-foreground w-16 text-center">
                    {Math.round(zoom * 100)}%
                </span>
                <Button variant="ghost" size="icon-lg" onClick={onZoomIn} disabled={zoom >= 3} aria-label="Zoom in">
                    <ZoomIn className="w-5 h-5" />
                </Button>
                <div className="w-px h-6 bg-border mx-2" />
                <Button variant="ghost" size="icon-lg" onClick={onRotate} aria-label="Rotate">
                    <RotateCw className="w-5 h-5" />
                </Button>
            </div>
        </div>
    );
}
