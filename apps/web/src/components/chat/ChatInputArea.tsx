/**
 * ═══════════════════════════════════════════════════════════════
 * CHAT INPUT AREA - UNIFIED VAULT UPLOAD
 * ═══════════════════════════════════════════════════════════════
 *
 * Premium floating input with unified file handling.
 * All files (local or vault) go through the Vault storage system.
 *
 * File upload flow:
 * 1. Local file → Upload to Vault ("Chat Files" folder)
 * 2. Auto-share to recipient via E2E encryption
 * 3. Message created as vault_file type
 *
 * ═══════════════════════════════════════════════════════════════
 */

import { useState, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip";
import {
    Send,
    Paperclip,
    Image,
    FileText,
    X,
    Loader2,
    Vault,
    AlertCircle,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import { FileShareModal } from "./FileShareModal";
import { useChatLocalUpload } from "@/hooks/useChatLocalUpload";
import { trpc } from "@/lib/trpc";
import { formatBytes } from "@stenvault/shared";

interface ChatInputAreaProps {
    onSendMessage: (content: string) => void;
    onTypingChange: (isTyping: boolean) => void;
    /** Recipient user ID for vault file sharing */
    recipientUserId?: number;
    /** Recipient name for display */
    recipientName?: string;
}

/**
 * Chat Input Area - Unified Vault Upload
 */
export function ChatInputArea({
    onSendMessage,
    onTypingChange,
    recipientUserId,
    recipientName,
}: ChatInputAreaProps) {
    const [message, setMessage] = useState("");
    const [attachedFile, setAttachedFile] = useState<File | null>(null);
    const [isFocused, setIsFocused] = useState(false);
    const [isVaultModalOpen, setIsVaultModalOpen] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const textareaRef = useRef<HTMLTextAreaElement>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    // Use unified upload hook
    const { uploadAndShare, isUploading, hasKeys } = useChatLocalUpload();

    // Plan-aware file size limit
    const { data: subscription } = trpc.stripe.getSubscription.useQuery(undefined, { staleTime: 60000 });
    const chatFileMaxSize = subscription?.features?.chatFileMaxSize || 25 * 1024 * 1024;

    const handleMessageChange = (value: string) => {
        setMessage(value);
        onTypingChange(true);

        if (typingTimeoutRef.current) {
            clearTimeout(typingTimeoutRef.current);
        }

        typingTimeoutRef.current = setTimeout(() => {
            onTypingChange(false);
        }, 1000);
    };

    const handleSend = async () => {
        // If only text, send as text message
        if (message.trim() && !attachedFile) {
            onSendMessage(message.trim());
            setMessage("");
            onTypingChange(false);
            if (textareaRef.current) {
                textareaRef.current.style.height = "auto";
            }
            return;
        }

        // If file attached, upload to Vault and auto-share
        if (attachedFile && recipientUserId) {
            // Check E2E keys
            if (!hasKeys) {
                toast.error("Configure E2E encryption first to send files");
                return;
            }

            try {
                setUploadProgress(0);

                await uploadAndShare({
                    file: attachedFile,
                    recipientUserId,
                    permission: "download",
                    expiresIn: "7d",
                    messageContent: message.trim() || undefined,
                    onProgress: setUploadProgress,
                });

                // Clear input after successful upload
                setMessage("");
                setAttachedFile(null);
                setUploadProgress(0);
                onTypingChange(false);

                if (textareaRef.current) {
                    textareaRef.current.style.height = "auto";
                }
            } catch {
                // Error already handled by hook with toast
                setUploadProgress(0);
            }
            return;
        }

        // File without recipient - shouldn't happen but handle gracefully
        if (attachedFile && !recipientUserId) {
            toast.error("Select a recipient to send files");
            return;
        }
    };

    const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) {
            if (file.size > chatFileMaxSize) {
                toast.error(`Maximum file size: ${formatBytes(chatFileMaxSize)}`);
                return;
            }

            // Check E2E keys before allowing file selection
            if (!hasKeys) {
                toast.error("Configure E2E encryption first to send files");
                return;
            }

            setAttachedFile(file);
        }
        // Reset input
        if (fileInputRef.current) {
            fileInputRef.current.value = "";
        }
    };

    const isDisabled = isUploading || (!message.trim() && !attachedFile);
    const canSendFile = recipientUserId && hasKeys;

    return (
        <div className="relative overflow-y-auto">
            {/* Upload Progress */}
            <AnimatePresence>
                {isUploading && uploadProgress > 0 && (
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 10 }}
                        className="mb-3"
                    >
                        <div className="flex items-center gap-2 text-xs text-foreground-muted mb-1">
                            <Loader2 className="h-3 w-3 animate-spin" />
                            <span>
                                {uploadProgress < 30
                                    ? "Encrypting..."
                                    : uploadProgress < 70
                                      ? "Uploading to Vault..."
                                      : uploadProgress < 90
                                        ? "Sharing..."
                                        : "Finishing..."}
                            </span>
                            <span className="ml-auto">{uploadProgress}%</span>
                        </div>
                        <Progress value={uploadProgress} className="h-1" />
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Attached file preview */}
            <AnimatePresence>
                {attachedFile && !isUploading && (
                    <motion.div
                        initial={{ opacity: 0, y: 10, scale: 0.98 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, y: 10, scale: 0.98 }}
                        transition={{ type: "spring", stiffness: 400, damping: 30 }}
                        className={cn(
                            "mb-3 p-4 rounded-xl",
                            "bg-background-elevated/90 backdrop-blur-xl",
                            "border border-border",
                            "shadow-lg",
                            "flex items-center justify-between"
                        )}
                    >
                        <div className="flex items-center gap-3">
                            <div
                                className={cn(
                                    "p-2.5 rounded-lg",
                                    "bg-primary/10",
                                    "border border-primary/20"
                                )}
                            >
                                {attachedFile.type.startsWith("image/") ? (
                                    <Image className="h-5 w-5 text-primary" />
                                ) : (
                                    <FileText className="h-5 w-5 text-primary" />
                                )}
                            </div>
                            <div className="flex flex-col">
                                <span className="text-sm font-medium text-foreground">
                                    {attachedFile.name}
                                </span>
                                <span className="text-xs text-foreground-muted">
                                    {(attachedFile.size / 1024).toFixed(1)} KB • Goes to Vault
                                </span>
                            </div>
                        </div>

                        <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => setAttachedFile(null)}
                            className={cn(
                                "h-8 w-8 rounded-lg",
                                "text-foreground-muted hover:text-destructive",
                                "hover:bg-destructive/10",
                                "transition-all duration-200"
                            )}
                        >
                            <X className="h-4 w-4" />
                        </Button>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* E2E Keys Warning */}
            {recipientUserId && !hasKeys && (
                <div className="mb-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center gap-2 text-sm text-amber-600 dark:text-amber-400">
                    <AlertCircle className="h-4 w-4 flex-shrink-0" />
                    <span>Configure E2E encryption to send files</span>
                </div>
            )}

            {/* Main input container */}
            <div
                className={cn(
                    "relative rounded-2xl overflow-hidden",
                    "transition-all duration-300 ease-out",
                    // Glass background
                    "bg-background-elevated/90 backdrop-blur-xl",
                    // Border
                    "border-2",
                    isFocused ? "border-primary/40" : "border-border",
                    // Shadow
                    isFocused
                        ? "shadow-[0_0_30px_var(--glow),0_8px_32px_rgba(0,0,0,0.2)]"
                        : "shadow-lg",
                    // Hover
                    "hover:border-primary/25"
                )}
            >
                {/* Top shine */}
                <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/20 to-transparent" />

                <div className="relative flex items-end gap-2 p-3">
                    {/* Attachment button - uploads to Vault */}
                    <TooltipProvider>
                        <Tooltip>
                            <TooltipTrigger asChild>
                                <Button
                                    size="icon"
                                    variant="ghost"
                                    onClick={() => fileInputRef.current?.click()}
                                    disabled={!canSendFile || isUploading}
                                    className={cn(
                                        "flex-shrink-0 h-10 w-10 rounded-xl",
                                        "text-foreground-muted",
                                        "hover:text-primary",
                                        "hover:bg-primary/10",
                                        "transition-all duration-200",
                                        "disabled:opacity-50 disabled:cursor-not-allowed"
                                    )}
                                >
                                    <Paperclip className="h-5 w-5" />
                                </Button>
                            </TooltipTrigger>
                            <TooltipContent>
                                {canSendFile
                                    ? "Send file (goes to Vault)"
                                    : "Configure E2E first"}
                            </TooltipContent>
                        </Tooltip>
                    </TooltipProvider>

                    <input
                        ref={fileInputRef}
                        type="file"
                        className="hidden"
                        onChange={handleFileSelect}
                        accept="image/*,video/*,application/pdf,.doc,.docx,.txt,.xlsx,.xls,.pptx,.ppt,.zip,.rar"
                    />

                    {/* Vault button - Share existing files from vault */}
                    {recipientUserId && (
                        <TooltipProvider>
                            <Tooltip>
                                <TooltipTrigger asChild>
                                    <Button
                                        size="icon"
                                        variant="ghost"
                                        onClick={() => setIsVaultModalOpen(true)}
                                        disabled={!hasKeys || isUploading}
                                        className={cn(
                                            "flex-shrink-0 h-10 w-10 rounded-xl",
                                            "text-foreground-muted",
                                            "hover:text-emerald-500",
                                            "hover:bg-emerald-500/10",
                                            "transition-all duration-200",
                                            "disabled:opacity-50 disabled:cursor-not-allowed"
                                        )}
                                    >
                                        <Vault className="h-5 w-5" />
                                    </Button>
                                </TooltipTrigger>
                                <TooltipContent>
                                    {hasKeys
                                        ? "Share from Vault"
                                        : "Configure E2E first"}
                                </TooltipContent>
                            </Tooltip>
                        </TooltipProvider>
                    )}

                    {/* Textarea */}
                    <Textarea
                        ref={textareaRef}
                        value={message}
                        onChange={(e) => handleMessageChange(e.target.value)}
                        onKeyDown={handleKeyDown}
                        onFocus={() => setIsFocused(true)}
                        onBlur={() => setIsFocused(false)}
                        placeholder="Type your message..."
                        disabled={isUploading}
                        className={cn(
                            "flex-1 min-h-[44px] max-h-[120px] resize-none",
                            "border-0 focus-visible:ring-0 focus-visible:ring-offset-0",
                            "bg-transparent",
                            "text-foreground text-sm",
                            "placeholder:text-foreground-muted",
                            "disabled:opacity-50"
                        )}
                        rows={1}
                        onInput={(e) => {
                            const target = e.target as HTMLTextAreaElement;
                            target.style.height = "auto";
                            target.style.height = `${target.scrollHeight}px`;
                        }}
                    />

                    {/* Send button */}
                    <TooltipProvider>
                        <Tooltip>
                            <TooltipTrigger asChild>
                                <Button
                                    size="icon"
                                    onClick={handleSend}
                                    disabled={isDisabled}
                                    className={cn(
                                        "flex-shrink-0 h-10 w-10 rounded-xl",
                                        "transition-all duration-300",
                                        isDisabled
                                            ? [
                                                  "bg-background-muted",
                                                  "text-foreground-muted",
                                                  "cursor-not-allowed",
                                              ]
                                            : [
                                                  "bg-primary",
                                                  "text-primary-foreground",
                                                  "hover:shadow-[0_0_25px_var(--glow-strong)]",
                                                  "hover:scale-105",
                                                  "active:scale-95",
                                              ]
                                    )}
                                >
                                    {isUploading ? (
                                        <Loader2 className="h-5 w-5 animate-spin" />
                                    ) : (
                                        <Send className="h-5 w-5" />
                                    )}
                                </Button>
                            </TooltipTrigger>
                            <TooltipContent>
                                Send message {!isDisabled && "(Enter)"}
                            </TooltipContent>
                        </Tooltip>
                    </TooltipProvider>
                </div>
            </div>

            {/* Helper text */}
            <div className="mt-3 flex items-center justify-center gap-3">
                <div className="flex items-center gap-1.5 text-foreground-muted">
                    <kbd
                        className={cn(
                            "px-2 py-0.5 rounded-md text-[10px] font-mono",
                            "bg-background-surface",
                            "border border-border",
                            "text-foreground-muted"
                        )}
                    >
                        Enter
                    </kbd>
                    <span className="text-[10px]">send</span>
                </div>
                <div className="w-px h-3 bg-border" />
                <div className="flex items-center gap-1.5 text-foreground-muted">
                    <kbd
                        className={cn(
                            "px-2 py-0.5 rounded-md text-[10px] font-mono",
                            "bg-background-surface",
                            "border border-border",
                            "text-foreground-muted"
                        )}
                    >
                        Shift + Enter
                    </kbd>
                    <span className="text-[10px]">new line</span>
                </div>
            </div>

            {/* Vault File Share Modal */}
            {recipientUserId && (
                <FileShareModal
                    open={isVaultModalOpen}
                    onOpenChange={setIsVaultModalOpen}
                    recipientUserId={recipientUserId}
                    recipientName={recipientName}
                />
            )}
        </div>
    );
}
