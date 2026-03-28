/**
 * FileActionSheet - Bottom sheet with file actions
 * 
 * Shows actions like download, share, rename, delete when triggered by long press.
 */

import { Drawer } from "vaul";
import { motion } from "framer-motion";
import {
    Download,
    Share2,
    Pencil,
    Trash2,
    Eye,
    Info,
    X,
    FileText,
    Image,
    Film,
    Music,
    Folder,
    Clock,
    Star,
} from "lucide-react";
import { useTheme } from "@/contexts/ThemeContext";
import { hapticTap } from "@/lib/haptics";
import { type FileType, FILE_TYPE_COLORS } from "@stenvault/shared";
import { formatBytes } from "@/utils/formatters";

// Re-export for backward compatibility
export type { FileType } from "@stenvault/shared";

export interface FileInfo {
    id: number;
    name: string;
    type: FileType;
    size?: number;
    isFolder?: boolean;
}

interface FileActionSheetProps {
    file: FileInfo | null;
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onAction: (action: FileAction, file: FileInfo) => void;
    isFavorite?: boolean;
}

export type FileAction =
    | "preview"
    | "download"
    | "share"
    | "favorite"
    | "rename"
    | "move"
    | "copy"
    | "delete"
    | "info"
    | "timestamp";

interface ActionItem {
    id: FileAction;
    icon: React.ElementType;
    label: string;
    description?: string;
    color?: string;
    danger?: boolean;
    condition?: (file: FileInfo) => boolean;
}

const fileIcons: Record<FileType, typeof FileText> = {
    image: Image,
    video: Film,
    audio: Music,
    document: FileText,
    folder: Folder,
    other: FileText,
};

// Use centralized colors from @stenvault/shared
const fileColors = FILE_TYPE_COLORS;

const actions: ActionItem[] = [
    {
        id: "preview",
        icon: Eye,
        label: "Preview",
        description: "View file",
        condition: (f) => !f.isFolder,
    },
    {
        id: "download",
        icon: Download,
        label: "Download",
        description: "Save to device",
        condition: (f) => !f.isFolder,
    },
    {
        id: "share",
        icon: Share2,
        label: "Share",
        description: "Create share link",
        condition: (f) => !f.isFolder,
    },
    {
        id: "favorite",
        icon: Star,
        label: "Favorite",
        description: "Add to or remove from favorites",
        condition: (f) => !f.isFolder,
    },
    {
        id: "timestamp",
        icon: Clock,
        label: "Blockchain Timestamp",
        description: "Proof of existence via Bitcoin",
        condition: (f) => !f.isFolder,
    },
    {
        id: "rename",
        icon: Pencil,
        label: "Rename",
        description: "Change name",
    },
    {
        id: "info",
        icon: Info,
        label: "Details",
        description: "View information",
    },
    {
        id: "delete",
        icon: Trash2,
        label: "Delete",
        description: "Move to trash",
        danger: true,
    },
];

// formatSize removed - using formatBytes from @/utils/formatters
function formatSize(bytes?: number): string {
    if (!bytes) return "";
    return formatBytes(bytes);
}

export function FileActionSheet({ file, open, onOpenChange, onAction, isFavorite }: FileActionSheetProps) {
    const { theme } = useTheme();

    if (!file) return null;

    const FileIcon = file.isFolder ? Folder : fileIcons[file.type] || FileText;
    const fileColor = file.isFolder ? theme.brand.primary : fileColors[file.type] || fileColors.other;

    const handleAction = (action: FileAction) => {
        hapticTap();
        onOpenChange(false);
        onAction(action, file);
    };

    const availableActions = actions.filter(
        (action) => !action.condition || action.condition(file)
    );

    return (
        <Drawer.Root open={open} onOpenChange={onOpenChange}>
            <Drawer.Portal>
                <Drawer.Overlay
                    style={{
                        position: "fixed",
                        inset: 0,
                        backgroundColor: "rgba(0, 0, 0, 0.5)",
                        zIndex: 9998,
                    }}
                />
                <Drawer.Content
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="file-action-sheet-title"
                    style={{
                        position: "fixed",
                        bottom: 0,
                        left: 0,
                        right: 0,
                        backgroundColor: "var(--background)",
                        borderTopLeftRadius: 20,
                        borderTopRightRadius: 20,
                        maxHeight: "85vh",
                        zIndex: 9999,
                        outline: "none",
                    }}
                >
                    {/* Drag Handle */}
                    <div
                        style={{
                            display: "flex",
                            justifyContent: "center",
                            padding: "12px 0 8px",
                        }}
                    >
                        <div
                            style={{
                                width: 36,
                                height: 4,
                                borderRadius: 2,
                                backgroundColor: "var(--muted-foreground)",
                                opacity: 0.3,
                            }}
                        />
                    </div>

                    {/* File Header */}
                    <div
                        style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 14,
                            padding: "8px 20px 16px",
                            borderBottom: "1px solid var(--border)",
                        }}
                    >
                        <div
                            style={{
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                width: 52,
                                height: 52,
                                borderRadius: 14,
                                backgroundColor: `${fileColor}15`,
                            }}
                        >
                            <FileIcon size={26} style={{ color: fileColor }} />
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                            <p
                                id="file-action-sheet-title"
                                style={{
                                    fontSize: 16,
                                    fontWeight: 600,
                                    color: "var(--foreground)",
                                    margin: 0,
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                }}
                            >
                                {file.name}
                            </p>
                            <p
                                style={{
                                    fontSize: 13,
                                    color: "var(--muted-foreground)",
                                    margin: "4px 0 0",
                                }}
                            >
                                {file.isFolder ? "Pasta" : formatSize(file.size)}
                            </p>
                        </div>
                        <motion.button
                            onClick={() => onOpenChange(false)}
                            whileTap={{ scale: 0.9 }}
                            aria-label="Close"
                            style={{
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                width: 36,
                                height: 36,
                                borderRadius: 18,
                                backgroundColor: "var(--muted)",
                                border: "none",
                                cursor: "pointer",
                            }}
                        >
                            <X size={18} style={{ color: "var(--muted-foreground)" }} />
                        </motion.button>
                    </div>

                    {/* Actions List */}
                    <div
                        style={{
                            padding: "12px 16px",
                            paddingBottom: `calc(12px + env(safe-area-inset-bottom, 0px))`,
                            overflowY: "auto",
                            maxHeight: "60vh",
                        }}
                    >
                        {availableActions.map((action, index) => {
                            const Icon = action.icon;
                            const isLast = index === availableActions.length - 1;
                            const label = action.id === 'favorite'
                                ? (isFavorite ? 'Remove from Favorites' : 'Add to Favorites')
                                : action.label;
                            const description = action.id === 'favorite'
                                ? (isFavorite ? 'Remove from starred files' : 'Star this file')
                                : action.description;

                            return (
                                <motion.button
                                    key={action.id}
                                    onClick={() => handleAction(action.id)}
                                    whileTap={{ scale: 0.98 }}
                                    aria-label={action.label}
                                    style={{
                                        display: "flex",
                                        alignItems: "center",
                                        gap: 14,
                                        width: "100%",
                                        padding: "14px 8px",
                                        backgroundColor: "transparent",
                                        border: "none",
                                        borderBottom: isLast ? "none" : "1px solid var(--border)",
                                        cursor: "pointer",
                                        textAlign: "left",
                                    }}
                                >
                                    <div
                                        style={{
                                            display: "flex",
                                            alignItems: "center",
                                            justifyContent: "center",
                                            width: 40,
                                            height: 40,
                                            borderRadius: 12,
                                            backgroundColor: action.danger
                                                ? `${theme.semantic.error}15`
                                                : "var(--muted)",
                                        }}
                                    >
                                        <Icon
                                            size={20}
                                            style={{
                                                color: action.danger
                                                    ? theme.semantic.error
                                                    : "var(--foreground)",
                                            }}
                                        />
                                    </div>
                                    <div style={{ flex: 1 }}>
                                        <p
                                            style={{
                                                fontSize: 15,
                                                fontWeight: 500,
                                                color: action.danger
                                                    ? theme.semantic.error
                                                    : "var(--foreground)",
                                                margin: 0,
                                            }}
                                        >
                                            {label}
                                        </p>
                                        {description && (
                                            <p
                                                style={{
                                                    fontSize: 12,
                                                    color: "var(--muted-foreground)",
                                                    margin: "2px 0 0",
                                                }}
                                            >
                                                {description}
                                            </p>
                                        )}
                                    </div>
                                </motion.button>
                            );
                        })}
                    </div>
                </Drawer.Content>
            </Drawer.Portal>
        </Drawer.Root>
    );
}

export default FileActionSheet;
