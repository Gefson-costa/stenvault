/**
 * VideoPlayer Component
 * 
 * Video player with fullscreen controls and error handling.
 */

import { forwardRef, RefObject } from 'react';
import { Play, Pause, Minimize2, Download, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Slider } from '@/components/ui/slider';
import { cn } from '@/lib/utils';
import { formatTime } from '../utils/formatTime';
import type { MediaState } from '../types';

interface VideoPlayerProps {
    mediaUrl: string;
    filename?: string;
    mimeType?: string;
    state: MediaState;
    videoContainerRef: React.RefObject<HTMLDivElement | null>;
    onLoadedMetadata: (e: React.SyntheticEvent<HTMLVideoElement>) => void;
    onTimeUpdate: (e: React.SyntheticEvent<HTMLVideoElement>) => void;
    onEnded: () => void;
    onError: (e: React.SyntheticEvent<HTMLVideoElement>) => void;
    onTogglePlay: () => void;
    onToggleFullscreen: () => void;
    onSeek: (value: number[]) => void;
    onDownload: () => void;
    onStalled?: () => void;
}

export const VideoPlayer = forwardRef<HTMLVideoElement, VideoPlayerProps>(
    function VideoPlayer(
        {
            mediaUrl,
            filename,
            mimeType,
            state,
            videoContainerRef,
            onLoadedMetadata,
            onTimeUpdate,
            onEnded,
            onError,
            onTogglePlay,
            onToggleFullscreen,
            onSeek,
            onDownload,
            onStalled,
        },
        ref
    ) {
        const { isPlaying, isFullscreen, currentTime, duration, error } = state;

        return (
            <div
                ref={videoContainerRef}
                className={cn(
                    "relative flex items-center justify-center w-full h-full",
                    isFullscreen && "bg-black"
                )}
            >
                <video
                    ref={ref}
                    className={cn(
                        "max-w-full max-h-full object-contain",
                        isFullscreen && "w-full h-full"
                    )}
                    onLoadedMetadata={onLoadedMetadata}
                    onTimeUpdate={onTimeUpdate}
                    onEnded={onEnded}
                    onError={onError}
                    onStalled={onStalled}
                    onClick={onTogglePlay}
                    onDoubleClick={onToggleFullscreen}
                    playsInline
                    preload="metadata"
                >
                    <source src={mediaUrl} type={mimeType} />
                </video>

                {/* Fullscreen controls overlay */}
                {isFullscreen && (
                    <div className="absolute bottom-0 left-0 right-0 p-4 bg-gradient-to-t from-black/80 to-transparent opacity-0 hover:opacity-100 transition-opacity duration-300">
                        <div className="flex items-center gap-4 text-white">
                            <Button variant="ghost" size="icon" onClick={onTogglePlay} className="text-white hover:bg-white/20" aria-label={isPlaying ? "Pause" : "Play"}>
                                {isPlaying ? <Pause className="w-6 h-6" /> : <Play className="w-6 h-6" />}
                            </Button>
                            <span className="text-sm">{formatTime(currentTime)} / {formatTime(duration)}</span>
                            <Slider
                                value={[currentTime]}
                                min={0}
                                max={duration || 100}
                                step={0.1}
                                onValueChange={onSeek}
                                className="flex-1"
                            />
                            <Button variant="ghost" size="icon" onClick={onToggleFullscreen} className="text-white hover:bg-white/20" aria-label="Exit fullscreen">
                                <Minimize2 className="w-5 h-5" />
                            </Button>
                        </div>
                    </div>
                )}

                {/* Error Overlay */}
                {error && (
                    <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/80 gap-4">
                        <AlertTriangle className="w-12 h-12 text-red-500" />
                        <p className="text-white text-lg font-medium text-center max-w-md px-4">{error}</p>
                        {filename && <p className="text-white/50 text-sm">{filename}</p>}
                        {mimeType && mimeType !== 'application/octet-stream' && (
                            <p className="text-white/40 text-xs">Format: {mimeType}</p>
                        )}
                        <Button onClick={onDownload} variant="outline">
                            <Download className="w-4 h-4 mr-2" />
                            Download file
                        </Button>
                    </div>
                )}
            </div>
        );
    }
);
