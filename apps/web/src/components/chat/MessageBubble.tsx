/**
 * Message Bubble - P2P Chat message bubble
 *
 * Uses hybrid post-quantum KEM (X25519 + ML-KEM-768) for E2E decryption.
 *
 * Features:
 * - Auto-decrypt encrypted messages via hybrid KEM
 * - Read receipts (double check)
 * - Elegant timestamps
 * - Modern gradients
 */
import { useState, useEffect } from "react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Check, CheckCheck, Lock } from "lucide-react";
import { format } from "date-fns";
import { cn } from "@/lib/utils";
import { useE2ECrypto } from "@/hooks/useE2ECrypto";
import { useMasterKey } from "@/hooks/useMasterKey";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { AttachmentPreview } from "./shared";
import { SharedFileCard } from "./SharedFileCard";

interface Message {
    id: number;
    createdAt: Date;
    fromUserId: number;
    content: string | null;
    messageType: "text" | "file" | "image" | "video" | "vault_file";
    isEncrypted: boolean;
    iv?: string | null;
    salt?: string | null;
    kemCiphertext?: string | null;
    isRead: boolean;
    fileKey?: string | null;
    filename?: string | null;
    fileSize?: number | null;
    // For vault_file messages
    chatFileShareId?: number | null;
}

interface MessageBubbleProps {
    message: Message;
    isOwn: boolean;
    showAvatar?: boolean;
    /** Name of the sender (for avatar initials on received messages) */
    senderName?: string;
    /** SVCP channel secret for decryption (both sender + recipient use the same key) */
    channelSecret?: CryptoKey | null;
}

/**
 * Message Bubble - Individual message bubble
 */
export function MessageBubble({ message, isOwn, showAvatar = true, senderName, channelSecret }: MessageBubbleProps) {
    const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
    const [isDecrypting, setIsDecrypting] = useState(false);

    const { decryptMessage, decryptChannelMessage } = useE2ECrypto();
    const { getUnlockedHybridSecretKey, isUnlocked } = useMasterKey();
    const utils = trpc.useUtils();

    // Fetch share details for vault_file messages
    const { data: shareDetails } = trpc.chatFileShare.getShareDetails.useQuery(
        { shareId: message.chatFileShareId! },
        {
            enabled: message.messageType === "vault_file" && !!message.chatFileShareId,
        }
    );

    // Auto-decrypt encrypted messages
    // SVCP: messages without kemCiphertext use channel secret (both sender + recipient)
    // Legacy: messages with kemCiphertext use per-message KEM (recipient only)
    useEffect(() => {
        if (!message.isEncrypted) {
            setDecryptedContent(message.content);
            return;
        }

        if (!message.content || !message.iv || !message.salt) {
            setDecryptedContent(message.content);
            return;
        }

        // SVCP path: no kemCiphertext → use channel secret (both own + received)
        if (!message.kemCiphertext) {
            if (!channelSecret) {
                setDecryptedContent(isUnlocked ? "[Channel not ready]" : "[Vault locked]");
                return;
            }
            setIsDecrypting(true);
            (async () => {
                try {
                    const plain = await decryptChannelMessage(
                        message.content!,
                        message.iv!,
                        message.salt!,
                        channelSecret
                    );
                    setDecryptedContent(plain);
                } catch (err) {
                    console.warn("[SVCP] Decrypt failed:", err);
                    setDecryptedContent("[Encrypted message]");
                } finally {
                    setIsDecrypting(false);
                }
            })();
            return;
        }

        // Legacy: per-message KEM (only recipient can decrypt)
        if (message.kemCiphertext && !isOwn) {
            setIsDecrypting(true);
            (async () => {
                try {
                    const hybridSecretKey = await getUnlockedHybridSecretKey();
                    if (!hybridSecretKey) {
                        setDecryptedContent("[Vault locked - cannot decrypt]");
                        return;
                    }

                    const plain = await decryptMessage(
                        message.content!,
                        message.iv!,
                        message.salt!,
                        message.kemCiphertext!,
                        hybridSecretKey
                    );
                    setDecryptedContent(plain);
                } catch (err) {
                    console.warn("[Legacy KEM] Decrypt failed:", err);
                    setDecryptedContent("[Decryption error]");
                } finally {
                    setIsDecrypting(false);
                }
            })();
            return;
        }

        // Legacy own message with KEM: can't decrypt (sender used per-message KEM)
        if (message.kemCiphertext && isOwn) {
            setDecryptedContent("[Encrypted - legacy message]");
        }
    }, [message, isOwn, channelSecret, decryptMessage, decryptChannelMessage,
        getUnlockedHybridSecretKey, isUnlocked]);

    const displayContent = decryptedContent || message.content;
    const timeStr = format(new Date(message.createdAt), "HH:mm");

    // Handle file download
    const handleDownload = async () => {
        if (!message.fileKey) return;

        try {
            const result = await utils.chat.getAttachmentDownloadUrl.fetch({
                fileKey: message.fileKey,
            });

            const link = document.createElement("a");
            link.href = result.url;
            link.download = message.filename || "download";
            link.click();

            toast.success("Download started");
        } catch {
            toast.error("Failed to download file");
        }
    };

    // Generate initials from sender name or fallback to "U"
    const initials = senderName
        ? senderName.split(" ").map(n => n[0]).join("").slice(0, 2).toUpperCase()
        : "U";

    // Map messageType to FileType (using shared FileTypeNoFolder)
    const getFileType = () => {
        switch (message.messageType) {
            case "image": return "image" as const;
            case "video": return "video" as const;
            default: return "other" as const;
        }
    };

    return (
        <div
            className={cn(
                "flex gap-2 animate-in slide-in-from-bottom-2 duration-300",
                isOwn ? "flex-row-reverse" : "flex-row"
            )}
        >
            {/* Avatar (only for received messages) */}
            {!isOwn && (
                <div className="flex-shrink-0">
                    {showAvatar ? (
                        <Avatar className="h-8 w-8 border-2 border-background shadow-sm">
                            <AvatarFallback className="bg-muted text-muted-foreground text-xs font-semibold">
                                {initials}
                            </AvatarFallback>
                        </Avatar>
                    ) : (
                        <div className="w-8" />
                    )}
                </div>
            )}

            {/* Message Content */}
            <div
                className={cn(
                    "flex flex-col max-w-[70%] sm:max-w-[60%]",
                    isOwn ? "items-end" : "items-start"
                )}
            >
                {/* Message Bubble */}
                <div
                    className={cn(
                        "relative px-4 py-2.5 rounded-2xl shadow-sm",
                        "transition-all duration-200 hover:shadow-md",
                        isOwn
                            ? "bg-primary text-primary-foreground rounded-tr-sm"
                            : "bg-muted text-foreground rounded-tl-sm"
                    )}
                >
                    {/* Encryption indicator */}
                    {message.isEncrypted && (
                        <div className="absolute -top-2 -right-2">
                            <div className="bg-green-500 rounded-full p-1 shadow-lg">
                                <Lock className="h-3 w-3 text-white" />
                            </div>
                        </div>
                    )}

                    {/* Content based on type */}
                    {message.messageType === "text" ? (
                        <p className="text-sm whitespace-pre-wrap break-words leading-relaxed">
                            {isDecrypting ? (
                                <span className="italic opacity-60">Decrypting...</span>
                            ) : (
                                displayContent || "[Empty message]"
                            )}
                        </p>
                    ) : message.messageType === "vault_file" && shareDetails?.share ? (
                        <SharedFileCard
                            shareId={shareDetails.share.id}
                            file={{
                                filename: shareDetails.share.file.filename,
                                fileType: shareDetails.share.file.fileType,
                                size: shareDetails.share.file.size,
                                mimeType: shareDetails.share.file.mimeType,
                            }}
                            permission={shareDetails.share.permission}
                            downloadCount={shareDetails.share.downloadCount}
                            maxDownloads={shareDetails.share.maxDownloads}
                            expiresAt={shareDetails.share.expiresAt}
                            status={shareDetails.share.status}
                            isOwn={isOwn}
                        />
                    ) : message.messageType === "vault_file" ? (
                        <div className="text-sm opacity-60 italic">
                            Loading shared file...
                        </div>
                    ) : (
                        <AttachmentPreview
                            fileName={message.filename || "file"}
                            fileSize={message.fileSize || 0}
                            fileType={getFileType()}
                            isOwn={isOwn}
                            onDownload={handleDownload}
                            variant="default"
                        />
                    )}

                    {/* Timestamp and read status */}
                    <div
                        className={cn(
                            "flex items-center gap-1.5 mt-1 text-xs",
                            isOwn ? "text-primary-foreground/70" : "text-muted-foreground"
                        )}
                    >
                        <span>{timeStr}</span>

                        {isOwn && (
                            message.isRead ? (
                                <CheckCheck className="h-3.5 w-3.5 text-primary-foreground/90" />
                            ) : (
                                <Check className="h-3.5 w-3.5" />
                            )
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
