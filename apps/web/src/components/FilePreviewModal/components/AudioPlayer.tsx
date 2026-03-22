/**
 * AudioPlayer Component
 * 
 * Audio player with visualization and error handling.
 */

import { forwardRef } from 'react';
import { Download, Music } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { formatTime } from '../utils/formatTime';
import type { MediaState } from '../types';

interface AudioPlayerProps {
    mediaUrl: string;
    filename: string;
    mimeType?: string;
    state: MediaState;
    onLoadedMetadata: (e: React.SyntheticEvent<HTMLAudioElement>) => void;
    onTimeUpdate: (e: React.SyntheticEvent<HTMLAudioElement>) => void;
    onEnded: () => void;
    onError: (e: React.SyntheticEvent<HTMLAudioElement>) => void;
    onDownload: () => void;
}

export const AudioPlayer = forwardRef<HTMLAudioElement, AudioPlayerProps>(
    function AudioPlayer(
        {
            mediaUrl,
            filename,
            mimeType,
            state,
            onLoadedMetadata,
            onTimeUpdate,
            onEnded,
            onError,
            onDownload,
        },
        ref
    ) {
        const { currentTime, duration, error } = state;

        return (
            <div className="flex flex-col items-center justify-center gap-6 md:gap-8 p-6 md:p-8 w-full">
                <audio
                    ref={ref}
                    onLoadedMetadata={onLoadedMetadata}
                    onTimeUpdate={onTimeUpdate}
                    onEnded={onEnded}
                    onError={onError}
                    preload="metadata"
                >
                    <source src={mediaUrl} type={mimeType} />
                </audio>

                {/* Audio visualization icon */}
                <div className="w-24 h-24 md:w-32 md:h-32 rounded-full bg-gradient-to-br from-primary to-primary/50 flex items-center justify-center">
                    <Music className="w-8 h-8 md:w-10 md:h-10 text-primary-foreground" />
                </div>

                {error ? (
                    <div className="text-center">
                        <p className="text-red-400 text-lg font-medium max-w-md">{error}</p>
                        <p className="text-white/50 text-sm mt-2">{filename}</p>
                        {mimeType && mimeType !== 'application/octet-stream' && (
                            <p className="text-white/40 text-xs mt-1">Format: {mimeType}</p>
                        )}
                        <Button onClick={onDownload} variant="outline" className="mt-4">
                            <Download className="w-4 h-4 mr-2" />
                            Download file
                        </Button>
                    </div>
                ) : (
                    <div className="text-center text-white w-full max-w-md px-4">
                        <p className="text-base md:text-lg font-medium truncate">{filename}</p>
                        <p className="text-sm text-white/60">
                            {formatTime(currentTime)} / {formatTime(duration)}
                        </p>
                    </div>
                )}
            </div>
        );
    }
);
