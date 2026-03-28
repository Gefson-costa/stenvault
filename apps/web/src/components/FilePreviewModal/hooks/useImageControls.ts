/**
 * useImageControls Hook
 * 
 * Manages image viewer controls (zoom and rotation).
 */

import { useState, useCallback } from 'react';
import type { ImageState } from '../types';

interface UseImageControlsReturn {
    state: ImageState;
    zoomIn: () => void;
    zoomOut: () => void;
    zoomTo: (value: number) => void;
    rotate: () => void;
    reset: () => void;
    setError: (error: string | null) => void;
}

const MIN_ZOOM = 0.25;
const MAX_ZOOM = 3;
const ZOOM_STEP = 0.25;

export function useImageControls(): UseImageControlsReturn {
    const [zoom, setZoom] = useState(1);
    const [rotation, setRotation] = useState(0);
    const [error, setError] = useState<string | null>(null);

    const zoomIn = useCallback(() => {
        setZoom((z) => Math.min(z + ZOOM_STEP, MAX_ZOOM));
    }, []);

    const zoomOut = useCallback(() => {
        setZoom((z) => Math.max(z - ZOOM_STEP, MIN_ZOOM));
    }, []);

    const zoomTo = useCallback((value: number) => {
        setZoom(Math.max(MIN_ZOOM, Math.min(value, MAX_ZOOM)));
    }, []);

    const rotate = useCallback(() => {
        setRotation((r) => (r + 90) % 360);
    }, []);

    const reset = useCallback(() => {
        setZoom(1);
        setRotation(0);
        setError(null);
    }, []);

    return {
        state: { zoom, rotation, error },
        zoomIn,
        zoomOut,
        zoomTo,
        rotate,
        reset,
        setError,
    };
}
