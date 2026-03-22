/**
 * FileEmptyState Component
 * 
 * Empty state display when no files or folders exist.
 */

import { motion } from 'framer-motion';
import { FolderOpen, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface FileEmptyStateProps {
    onUploadRequest?: () => void;
}

export function FileEmptyState({ onUploadRequest }: FileEmptyStateProps) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, ease: "easeOut" }}
            className="flex flex-col items-center justify-center py-24 text-center relative rounded-2xl border border-dashed border-border/40"
        >
            <div className="relative z-10 flex flex-col items-center">
                <div className="p-5 rounded-2xl bg-muted/50 border border-border/50 mb-6">
                    <FolderOpen className="w-10 h-10 text-muted-foreground" />
                </div>

                <h3 className="text-xl font-medium tracking-tight mb-2 text-foreground">
                    No files yet
                </h3>
                <p className="text-muted-foreground max-w-xs mb-8 text-sm">
                    Drop files here or click upload to get started.
                </p>

                <Button
                    onClick={onUploadRequest}
                    size="lg"
                    variant="glow"
                >
                    <Upload className="w-4 h-4" />
                    Upload
                </Button>
            </div>
        </motion.div>
    );
}
