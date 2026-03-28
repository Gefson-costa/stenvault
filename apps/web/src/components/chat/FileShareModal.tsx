/**
 * FileShareModal - Select vault files to share in chat
 *
 * Modal for selecting files from the user's vault to share in chat.
 * Includes:
 * - File browser with search
 * - Permission selection (view/download)
 * - Expiration presets
 * - Download limits
 *
 * @module components/chat/FileShareModal
 */

import { useState, useMemo, useCallback, useEffect } from "react";
import { cn } from "@/lib/utils";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import {
    Search,
    FileText,
    Image as ImageIcon,
    Video as VideoIcon,
    Music,
    File,
    Folder,
    Check,
    Loader2,
    Lock,
    Shield,
    Clock,
    Download as DownloadIcon,
    Eye,
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { formatBytes } from "@/utils/formatters";
import { useChatFileShare, type ShareFileOptions } from "@/hooks/useChatFileShare";
import { useFilenameDecryption } from "@/hooks/useFilenameDecryption";
import type { FileItem as VaultFileItem } from "@/components/files/types";

// File type to icon mapping
const FILE_TYPE_ICONS: Record<string, typeof File> = {
    image: ImageIcon,
    video: VideoIcon,
    audio: Music,
    document: FileText,
    folder: Folder,
    other: File,
};

// Expiration presets
const EXPIRATION_PRESETS = [
    { value: "1h", label: "1 hour" },
    { value: "24h", label: "24 hours" },
    { value: "7d", label: "7 days" },
    { value: "30d", label: "30 days" },
    { value: "never", label: "Never" },
] as const;

interface FileShareModalProps {
    /** Whether the modal is open */
    open: boolean;
    /** Callback when modal closes */
    onOpenChange: (open: boolean) => void;
    /** Recipient user ID */
    recipientUserId: number;
    /** Recipient name for display */
    recipientName?: string;
    /** Callback when share is complete */
    onShareComplete?: (shareId: number, messageId: number) => void;
}

interface FileItem {
    id: number;
    filename: string;
    fileType: string;
    size: number;
    mimeType: string | null;
    createdAt: Date;
}

/**
 * Modal for selecting and sharing vault files
 */
export function FileShareModal({
    open,
    onOpenChange,
    recipientUserId,
    recipientName,
    onShareComplete,
}: FileShareModalProps) {
    // State
    const [searchQuery, setSearchQuery] = useState("");
    const [selectedFile, setSelectedFile] = useState<FileItem | null>(null);
    const [permission, setPermission] = useState<"view" | "download">("download");
    const [expiresIn, setExpiresIn] = useState<string>("7d");
    const [maxDownloads, setMaxDownloads] = useState<string>("");

    // Hooks
    const { shareFile, isSharing, hasKeys } = useChatFileShare();
    const { getDisplayName, decryptFilenames } = useFilenameDecryption();

    // Fetch user's files
    const { data: filesData, isLoading: isLoadingFiles } = trpc.files.list.useQuery(
        {
            folderId: null, // Root folder
        },
        { enabled: open }
    );

    // Map files including encrypted filename fields for decryption
    const vaultFiles = useMemo(() => {
        if (!filesData?.files) return [];
        return filesData.files.map((f) => ({
            id: f.id,
            filename: f.filename,
            fileType: f.fileType,
            size: Number(f.size),
            mimeType: f.mimeType,
            createdAt: f.createdAt,
            encryptedFilename: f.encryptedFilename,
            filenameIv: f.filenameIv,
            plaintextExtension: f.plaintextExtension,
            encryptionVersion: f.encryptionVersion,
        })) as (FileItem & Partial<VaultFileItem>)[];
    }, [filesData?.files]);

    // Decrypt filenames when files load
    useEffect(() => {
        if (vaultFiles.length > 0) {
            decryptFilenames(vaultFiles as VaultFileItem[]);
        }
    }, [vaultFiles, decryptFilenames]);

    // Filter files based on search (exclude folders and deleted files)
    const filteredFiles = useMemo(() => {
        if (vaultFiles.length === 0) return [];

        if (!searchQuery) return vaultFiles;

        const query = searchQuery.toLowerCase();
        return vaultFiles.filter((file) => {
            const displayName = getDisplayName(file as VaultFileItem);
            return displayName.toLowerCase().includes(query);
        });
    }, [vaultFiles, searchQuery, getDisplayName]);

    // Handle share
    const handleShare = useCallback(async () => {
        if (!selectedFile) return;

        const options: ShareFileOptions = {
            fileId: selectedFile.id,
            recipientUserId,
            permission,
            expiresIn: expiresIn as ShareFileOptions["expiresIn"],
            maxDownloads: maxDownloads ? parseInt(maxDownloads, 10) : undefined,
        };

        try {
            const result = await shareFile(options);
            onShareComplete?.(result.shareId, result.messageId);
            onOpenChange(false);
            // Reset state
            setSelectedFile(null);
            setSearchQuery("");
        } catch {
            // Error handled in hook
        }
    }, [
        selectedFile,
        recipientUserId,
        permission,
        expiresIn,
        maxDownloads,
        shareFile,
        onShareComplete,
        onOpenChange,
    ]);

    // Handle close
    const handleClose = (open: boolean) => {
        if (!open) {
            setSelectedFile(null);
            setSearchQuery("");
        }
        onOpenChange(open);
    };

    return (
        <Dialog open={open} onOpenChange={handleClose}>
            <DialogContent className="max-w-[92vw] sm:max-w-[600px] max-h-[90vh] flex flex-col">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <Shield className="w-5 h-5 text-emerald-500" />
                        Share Vault File
                    </DialogTitle>
                    <DialogDescription>
                        Select a file to share with{" "}
                        <span className="font-medium">{recipientName || "this user"}</span>.
                        The file key will be securely re-encrypted.
                    </DialogDescription>
                </DialogHeader>

                {/* E2E Keys Warning */}
                {!hasKeys && (
                    <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3 flex items-start gap-2">
                        <Lock className="w-4 h-4 text-amber-500 mt-0.5" />
                        <div className="text-sm">
                            <p className="font-medium text-amber-600 dark:text-amber-400">
                                E2E keys not configured
                            </p>
                            <p className="text-muted-foreground">
                                Configure E2E encryption in chat settings first.
                            </p>
                        </div>
                    </div>
                )}

                {/* Search */}
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                        placeholder="Search files..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-9"
                    />
                </div>

                {/* File List */}
                <ScrollArea className="flex-1 min-h-[200px] max-h-[300px] border rounded-lg">
                    {isLoadingFiles ? (
                        <div className="flex items-center justify-center h-full py-12">
                            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                        </div>
                    ) : filteredFiles.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-full py-12 text-muted-foreground">
                            <File className="w-10 h-10 mb-2 opacity-50" />
                            <p>
                                {searchQuery
                                    ? "No files found"
                                    : "No files in Vault"}
                            </p>
                        </div>
                    ) : (
                        <div className="p-2 space-y-1">
                            {filteredFiles.map((file) => {
                                const Icon = FILE_TYPE_ICONS[file.fileType] || File;
                                const isSelected = selectedFile?.id === file.id;

                                return (
                                    <button
                                        key={file.id}
                                        onClick={() => setSelectedFile(file)}
                                        className={cn(
                                            "w-full flex items-center gap-3 p-2.5 rounded-lg transition-colors text-left",
                                            isSelected
                                                ? "bg-primary/10 ring-2 ring-primary"
                                                : "hover:bg-muted"
                                        )}
                                    >
                                        <div
                                            className={cn(
                                                "p-2 rounded-lg",
                                                isSelected
                                                    ? "bg-primary/20"
                                                    : "bg-muted"
                                            )}
                                        >
                                            <Icon className="w-4 h-4" />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm font-medium truncate">
                                                {getDisplayName(file as VaultFileItem)}
                                            </p>
                                            <p className="text-xs text-muted-foreground">
                                                {formatBytes(file.size)}
                                            </p>
                                        </div>
                                        {isSelected && (
                                            <div className="p-1 bg-primary rounded-full">
                                                <Check className="w-3 h-3 text-primary-foreground" />
                                            </div>
                                        )}
                                    </button>
                                );
                            })}
                        </div>
                    )}
                </ScrollArea>

                {/* Options */}
                {selectedFile && (
                    <div className="space-y-4 pt-2 border-t">
                        {/* Permission */}
                        <div className="space-y-2">
                            <Label>Permissions</Label>
                            <RadioGroup
                                value={permission}
                                onValueChange={(v) => setPermission(v as "view" | "download")}
                                className="flex gap-4"
                            >
                                <div className="flex items-center space-x-2">
                                    <RadioGroupItem value="download" id="download" />
                                    <Label
                                        htmlFor="download"
                                        className="flex items-center gap-1.5 cursor-pointer"
                                    >
                                        <DownloadIcon className="w-4 h-4" />
                                        Download allowed
                                    </Label>
                                </div>
                                <div className="flex items-center space-x-2">
                                    <RadioGroupItem value="view" id="view" />
                                    <Label
                                        htmlFor="view"
                                        className="flex items-center gap-1.5 cursor-pointer"
                                    >
                                        <Eye className="w-4 h-4" />
                                        View only
                                    </Label>
                                </div>
                            </RadioGroup>
                        </div>

                        {/* Expiration and Download Limit */}
                        <div className="flex gap-4">
                            <div className="flex-1 space-y-2">
                                <Label className="flex items-center gap-1.5">
                                    <Clock className="w-4 h-4" />
                                    Expires in
                                </Label>
                                <Select value={expiresIn} onValueChange={setExpiresIn}>
                                    <SelectTrigger>
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {EXPIRATION_PRESETS.map((preset) => (
                                            <SelectItem key={preset.value} value={preset.value}>
                                                {preset.label}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>

                            <div className="flex-1 space-y-2">
                                <Label className="flex items-center gap-1.5">
                                    <DownloadIcon className="w-4 h-4" />
                                    Download limit
                                </Label>
                                <Input
                                    type="number"
                                    min="1"
                                    max="100"
                                    placeholder="Unlimited"
                                    value={maxDownloads}
                                    onChange={(e) => setMaxDownloads(e.target.value)}
                                />
                            </div>
                        </div>
                    </div>
                )}

                <DialogFooter>
                    <Button variant="outline" onClick={() => handleClose(false)}>
                        Cancel
                    </Button>
                    <Button
                        onClick={handleShare}
                        disabled={!selectedFile || isSharing || !hasKeys}
                    >
                        {isSharing ? (
                            <>
                                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                Sharing...
                            </>
                        ) : (
                            <>
                                <Shield className="w-4 h-4 mr-2" />
                                Share
                            </>
                        )}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

export default FileShareModal;
