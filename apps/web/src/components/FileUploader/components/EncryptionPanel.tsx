/**
 * EncryptionPanel Component
 *
 * Displays encryption status for file uploads.
 * Encryption is always mandatory via Master Key - no toggle needed.
 */

import { Lock } from 'lucide-react';

export function EncryptionPanel() {
    return (
        <div className="flex items-center gap-2 px-1 text-sm text-green-600 dark:text-green-400">
            <Lock className="w-4 h-4 shrink-0" />
            <span>Zero-knowledge encryption active — files are encrypted locally before upload</span>
        </div>
    );
}
