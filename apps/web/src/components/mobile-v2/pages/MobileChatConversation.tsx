/**
 * MobileChatConversation - Active Chat View
 * 
 * Shows message thread with a specific user.
 * Optimized for mobile with:
 * - Sticky header with back navigation
 * - Scrollable message list
 * - Fixed bottom input
 * - Keyboard-aware layout
 * - E2E encryption/decryption support
 */

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { motion } from "framer-motion";
import {
    ChevronLeft,
    Send,
    Shield,
    Check,
    CheckCheck,
    Loader2,
    Lock,
} from "lucide-react";
import { format, isToday, isYesterday } from "date-fns";
import { trpc } from "@/lib/trpc";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useE2ECrypto } from "@/hooks/useE2ECrypto";
import { useMasterKey } from "@/hooks/useMasterKey";
import { useChatChannel } from "@/hooks/useChatChannel";
import { useCryptoStore } from "@/stores/cryptoStore";
import { useAuth } from "@/_core/hooks/useAuth";
import { useTheme } from "@/contexts/ThemeContext";
import { hapticTap, hapticMedium } from "@/lib/haptics";
import { toast } from "sonner";
import { deserializeHybridPublicKey } from "@/lib/platform";
import type { HybridPublicKeySerialized } from "@/lib/platform";
import { VaultUnlockModal } from "@/components/VaultUnlockModal";

// Local types for chat data
interface ChatMessage {
    id: number;
    fromUserId: number;
    toUserId: number;
    messageType: 'text' | 'file' | 'image' | 'video';
    content?: string | null;
    fileKey?: string | null;
    filename?: string | null;
    fileSize?: number | null;
    iv?: string | null;
    salt?: string | null;
    kemCiphertext?: string | null;
    isEncrypted: boolean;
    keyVersion?: number | null;
    isRead: boolean;
    isDeleted: boolean;
    createdAt: Date | string;
}

interface ChatConnection {
    id: number;
    userId: number;
    connectedUserId: number;
    nickname?: string | null;
    status: 'pending' | 'accepted' | 'blocked';
    createdAt: Date | string;
    updatedAt: Date | string;
    connectedUserEmail?: string | null;
    connectedUserName?: string | null;
}
import {
    TYPING_DEBOUNCE_MS,
    MESSAGE_BORDER_RADIUS,
    MESSAGE_MAX_WIDTH,
    AVATAR_SIZE,
    ONLINE_INDICATOR_SIZE,
    MESSAGES_LIMIT,
    MESSAGE_INPUT_MAX_HEIGHT,
} from "./constants";
import type {
    Message,
    GroupedMessages,
    MobileChatConversationProps,
    ChatHeaderProps,
    MessageBubbleProps,
    MessageInputProps,
} from "./types";

// ─────────────────────────────────────────────────────────────
// MAIN COMPONENT
// ─────────────────────────────────────────────────────────────

export function MobileChatConversation({ userId, onBack }: MobileChatConversationProps) {
    const { theme } = useTheme();
    const { user } = useAuth();
    const { cacheHybridPublicKey, getCachedHybridPublicKey } = useCryptoStore();
    const { encryptMessage, encryptChannelMessage } = useE2ECrypto();
    const { isUnlocked, isConfigured } = useMasterKey();
    const {
        channelSecret,
        channelKeyVersion,
        initiateChannel,
    } = useChatChannel(userId);
    const {
        sendMessage: sendWsMessage,
        sendTyping,
        onNewMessage,
        onTyping,
        isConnected,
    } = useWebSocket();

    // State
    const [message, setMessage] = useState("");
    const [isTyping, setIsTyping] = useState(false);
    const [peerTyping, setPeerTyping] = useState(false);
    const [unlockModalOpen, setUnlockModalOpen] = useState(false);

    // Refs
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    // State for messages
    const [localMessages, setLocalMessages] = useState<Message[]>([]);
    const [isSending, setIsSending] = useState(false);

    const utils = trpc.useUtils();

    // Fetch connection details via tRPC
    const { data: connectionsData } = trpc.chat.getMyConnections.useQuery();
    const connection = connectionsData?.connections?.find(c => c.connectedUserId === userId) as ChatConnection | undefined ?? null;

    // Fetch messages via tRPC
    const { data: messagesData, isLoading: isLoadingMessages, refetch: refetchMessages } = trpc.chat.getMessages.useQuery(
        { withUserId: userId, limit: MESSAGES_LIMIT },
        { enabled: !!userId }
    );

    // Sync messages from tRPC to local state
    useEffect(() => {
        if (messagesData?.messages) {
            const transformedMessages = messagesData.messages.map(msg => ({
                ...msg,
                createdAt: new Date(msg.createdAt),
            })) as unknown as Message[];
            setLocalMessages(transformedMessages);
        }
    }, [messagesData]);

    const messages = localMessages;

    // Wrapper function for refetch
    const fetchMessages = useCallback(() => {
        refetchMessages();
    }, [refetchMessages]);

    // Fetch peer's hybrid public key via tRPC
    const { data: peerHybridKeyData } = trpc.chat.getPeerHybridPublicKey.useQuery(
        { userId },
        { enabled: !!userId }
    );

    // Cache peer hybrid public key when fetched
    useEffect(() => {
        if (peerHybridKeyData?.hybridPublicKey) {
            const { x25519PublicKey, mlkem768PublicKey, keyVersion } = peerHybridKeyData.hybridPublicKey;
            cacheHybridPublicKey(userId, x25519PublicKey, mlkem768PublicKey, keyVersion);
        }
    }, [peerHybridKeyData, userId, cacheHybridPublicKey]);

    const displayName = connection?.nickname || connection?.connectedUserName || "User";

    // Effect: Listen for new messages
    useEffect(() => {
        const unsubscribe = onNewMessage((msg) => {
            if (msg.fromUserId === userId || msg.toUserId === userId) {
                fetchMessages();
            }
        });
        return unsubscribe;
    }, [onNewMessage, userId, fetchMessages]);

    // Effect: Listen for typing status
    useEffect(() => {
        const unsubscribe = onTyping((indicator) => {
            if (indicator.fromUserId === userId) {
                setPeerTyping(indicator.isTyping);
            }
        });
        return unsubscribe;
    }, [onTyping, userId]);

    // CRITICAL: Cleanup typing timeout on unmount to prevent memory leak
    useEffect(() => {
        return () => {
            if (typingTimeoutRef.current) {
                clearTimeout(typingTimeoutRef.current);
            }
        };
    }, []);

    // Handle typing indicator
    const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        setMessage(e.target.value);

        // Send typing status
        if (!isTyping) {
            setIsTyping(true);
            sendTyping(userId, true);
        }

        // Clear previous timeout
        if (typingTimeoutRef.current) {
            clearTimeout(typingTimeoutRef.current);
        }

        // Set new timeout to stop typing
        typingTimeoutRef.current = setTimeout(() => {
            setIsTyping(false);
            sendTyping(userId, false);
        }, TYPING_DEBOUNCE_MS);
    };

    // Send message mutation via tRPC
    const sendMessageMutation = trpc.chat.sendMessage.useMutation({
        onSuccess: (data, variables) => {
            // Send via WebSocket for real-time delivery
            sendWsMessage({
                toUserId: userId,
                messageId: data.messageId,
                content: variables.content || "",
                messageType: variables.messageType || "text",
                isEncrypted: variables.isEncrypted ?? false,
                iv: variables.iv,
            });

            // Clear message and refresh
            setMessage("");
            fetchMessages();
            hapticTap();

            // Stop typing indicator
            setIsTyping(false);
            sendTyping(userId, false);
            setIsSending(false);
        },
        onError: (error) => {
            console.error("Failed to send message:", error);
            toast.error("Failed to send message");
            setIsSending(false);
        },
    });

    // Handle send
    const handleSend = async () => {
        if (!message.trim()) return;

        hapticMedium();
        setIsSending(true);

        try {
            if (!isUnlocked) {
                toast.error("Vault must be unlocked to send encrypted messages.");
                setIsSending(false);
                return;
            }

            const trimmed = message.trim();

            // SVCP: use channel secret if available, auto-initiate if needed
            let activeChannelSecret = channelSecret;

            if (!activeChannelSecret) {
                activeChannelSecret = await initiateChannel();
            }

            if (activeChannelSecret) {
                // SVCP path: encrypt with channel secret (both sender + recipient can decrypt)
                const { ciphertext, iv, salt } = await encryptChannelMessage(
                    trimmed,
                    activeChannelSecret
                );

                sendMessageMutation.mutate({
                    toUserId: userId,
                    messageType: "text",
                    content: ciphertext,
                    iv,
                    salt,
                    isEncrypted: true,
                    keyVersion: channelKeyVersion,
                });
                return;
            }

            // Fallback: legacy per-message KEM
            const cachedKey = getCachedHybridPublicKey(userId);
            if (!cachedKey) {
                toast.error("Recipient's encryption key not available.");
                setIsSending(false);
                return;
            }

            const recipientHybridPubKey = deserializeHybridPublicKey({
                classical: cachedKey.x25519PublicKey,
                postQuantum: cachedKey.mlkem768PublicKey,
                algorithm: 'x25519-ml-kem-768',
            } as HybridPublicKeySerialized);

            const { ciphertext, iv, salt, kemCiphertext } = await encryptMessage(
                trimmed,
                recipientHybridPubKey
            );

            sendMessageMutation.mutate({
                toUserId: userId,
                content: ciphertext,
                iv,
                salt,
                kemCiphertext,
                messageType: "text",
                isEncrypted: true,
                keyVersion: cachedKey.keyVersion,
            });
        } catch (error) {
            console.error("Failed to send message:", error);
            toast.error("Failed to send message");
            setIsSending(false);
        }
    };

    // Handle key press
    const handleKeyPress = (e: React.KeyboardEvent) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    // Attachment and more options — hidden until implemented
    // (buttons removed from MessageInput and ChatHeader)

    // Group messages by date
    const groupedMessages = groupMessagesByDate(messages);

    const vaultLocked = isConfigured && !isUnlocked;

    return (
        <div
            style={{
                display: "flex",
                flexDirection: "column",
                height: "100%",
                backgroundColor: "var(--background)",
                position: "relative",
            }}
        >
            {/* Vault Lock Overlay */}
            {vaultLocked && (
                <div
                    style={{
                        position: "absolute",
                        inset: 0,
                        zIndex: 50,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        backdropFilter: "blur(8px)",
                        WebkitBackdropFilter: "blur(8px)",
                        backgroundColor: "rgba(var(--background-rgb, 0 0 0) / 0.8)",
                    }}
                >
                    <div style={{ textAlign: "center", padding: 32, maxWidth: 320 }}>
                        <div
                            style={{
                                width: 64,
                                height: 64,
                                borderRadius: 32,
                                backgroundColor: "rgba(245, 158, 11, 0.1)",
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                margin: "0 auto 24px",
                            }}
                        >
                            <Shield size={32} style={{ color: "#f59e0b" }} />
                        </div>
                        <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 8, color: "var(--foreground)" }}>
                            Vault Locked
                        </h2>
                        <p style={{ fontSize: 14, color: "var(--muted-foreground)", marginBottom: 24 }}>
                            Unlock your vault to send and read encrypted messages.
                        </p>
                        <motion.button
                            onClick={() => setUnlockModalOpen(true)}
                            whileTap={{ scale: 0.97 }}
                            style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 8,
                                padding: "12px 24px",
                                borderRadius: 12,
                                backgroundColor: theme.brand.primary,
                                color: "#FFFFFF",
                                fontSize: 15,
                                fontWeight: 500,
                                border: "none",
                                cursor: "pointer",
                            }}
                        >
                            <Lock size={16} />
                            Unlock Vault
                        </motion.button>
                    </div>
                </div>
            )}

            {/* Vault Unlock Modal */}
            <VaultUnlockModal
                isOpen={unlockModalOpen}
                onUnlock={() => setUnlockModalOpen(false)}
                onClose={() => setUnlockModalOpen(false)}
            />

            {/* Header */}
            <ChatHeader
                name={displayName}
                isOnline={isConnected}
                onBack={() => {
                    hapticTap();
                    onBack();
                }}
            />

            {/* Messages Area */}
            <div
                style={{
                    flex: 1,
                    overflowY: "auto",
                    overflowX: "hidden",
                    padding: "8px 12px",
                    WebkitOverflowScrolling: "touch",
                }}
                role="log"
                aria-label="Message history"
                aria-live="polite"
            >
                {/* Loading state */}
                {isLoadingMessages && (
                    <div style={{ display: "flex", justifyContent: "center", padding: 20 }}>
                        <Loader2 size={24} style={{ animation: "spin 1s linear infinite", color: "var(--muted-foreground)" }} />
                    </div>
                )}

                {/* Messages */}
                {groupedMessages.map(({ date, messages: dayMessages }) => (
                    <div key={date}>
                        {/* Date Separator */}
                        <div
                            style={{
                                display: "flex",
                                justifyContent: "center",
                                margin: "16px 0 12px",
                            }}
                        >
                            <span
                                style={{
                                    fontSize: 11,
                                    color: "var(--muted-foreground)",
                                    backgroundColor: "var(--muted)",
                                    padding: "4px 12px",
                                    borderRadius: 12,
                                }}
                            >
                                {date}
                            </span>
                        </div>

                        {/* Messages */}
                        {dayMessages.map((msg) => (
                            <MessageBubble
                                key={msg.id}
                                message={msg}
                                isOwn={msg.fromUserId === user?.id}
                                channelSecret={channelSecret}
                            />
                        ))}
                    </div>
                ))}

                {/* Typing Indicator */}
                {peerTyping && (
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 6,
                            padding: "8px 12px",
                            marginBottom: 8,
                        }}
                    >
                        <TypingIndicator />
                        <span style={{ fontSize: 12, color: "var(--muted-foreground)" }}>
                            {displayName} is typing...
                        </span>
                    </motion.div>
                )}

                <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            <MessageInput
                value={message}
                onChange={handleInputChange}
                onSend={handleSend}
                onKeyPress={handleKeyPress}
                disabled={isSending}
            />
        </div>
    );
}

// ─────────────────────────────────────────────────────────────
// CHAT HEADER
// ─────────────────────────────────────────────────────────────

function ChatHeader({ name, isOnline, onBack }: ChatHeaderProps) {
    const { theme } = useTheme();
    const initials = name.charAt(0).toUpperCase();

    return (
        <div
            style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "12px 12px 12px 8px",
                borderBottom: "1px solid var(--border)",
                backgroundColor: "var(--background)",
            }}
        >
            {/* Back Button */}
            <motion.button
                onClick={onBack}
                whileTap={{ scale: 0.9 }}
                aria-label="Go back to conversations"
                style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    width: 36,
                    height: 36,
                    borderRadius: 10,
                    backgroundColor: "transparent",
                    border: "none",
                    cursor: "pointer",
                }}
            >
                <ChevronLeft size={24} style={{ color: "var(--foreground)" }} />
            </motion.button>

            {/* Avatar */}
            <div style={{ position: "relative" }}>
                <div
                    style={{
                        width: AVATAR_SIZE.header,
                        height: AVATAR_SIZE.header,
                        borderRadius: 12,
                        backgroundColor: `${theme.brand.primary}15`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontSize: 16,
                        fontWeight: 600,
                        color: theme.brand.primary,
                    }}
                >
                    {initials}
                </div>
                {isOnline && (
                    <div
                        style={{
                            position: "absolute",
                            bottom: -1,
                            right: -1,
                            width: ONLINE_INDICATOR_SIZE.header,
                            height: ONLINE_INDICATOR_SIZE.header,
                            borderRadius: "50%",
                            backgroundColor: theme.semantic.success,
                            border: "2px solid var(--background)",
                        }}
                    />
                )}
            </div>

            {/* Name & Status */}
            <div style={{ flex: 1 }}>
                <p
                    style={{
                        fontSize: 16,
                        fontWeight: 600,
                        color: "var(--foreground)",
                        margin: 0,
                    }}
                >
                    {name}
                </p>
                <p
                    style={{
                        fontSize: 12,
                        color: "var(--muted-foreground)",
                        margin: "2px 0 0",
                        display: "flex",
                        alignItems: "center",
                        gap: 4,
                    }}
                >
                    {isOnline ? "Online" : "Offline"}
                </p>
            </div>

        </div>
    );
}

// ─────────────────────────────────────────────────────────────
// MESSAGE BUBBLE WITH DECRYPTION
// ─────────────────────────────────────────────────────────────

function MessageBubble({ message, isOwn, channelSecret }: MessageBubbleProps) {
    const { theme } = useTheme();
    const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
    const [isDecrypting, setIsDecrypting] = useState(false);
    const [decryptError, setDecryptError] = useState(false);
    const { decryptMessage, decryptChannelMessage } = useE2ECrypto();
    const { getUnlockedHybridSecretKey, isUnlocked } = useMasterKey();

    // Auto-decrypt encrypted messages
    // SVCP: messages without kemCiphertext use channel secret (both sender + recipient)
    // Legacy: messages with kemCiphertext use per-message KEM (recipient only)
    useEffect(() => {
        if (!message.isEncrypted) {
            setDecryptedContent(message.content ?? null);
            return;
        }

        if (!message.content || !message.iv || !message.salt) {
            setDecryptedContent(message.content ?? null);
            return;
        }

        // SVCP path: no kemCiphertext → use channel secret
        if (!message.kemCiphertext && channelSecret) {
            setIsDecrypting(true);
            setDecryptError(false);
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
                    setDecryptError(true);
                } finally {
                    setIsDecrypting(false);
                }
            })();
            return;
        }

        // SVCP message but channel not ready yet
        if (!message.kemCiphertext && !channelSecret) {
            setDecryptedContent(isUnlocked ? null : null);
            setDecryptError(!isUnlocked);
            return;
        }

        // Legacy: per-message KEM (only recipient can decrypt)
        if (message.kemCiphertext && !isOwn) {
            setIsDecrypting(true);
            setDecryptError(false);
            (async () => {
                try {
                    const hybridSecretKey = await getUnlockedHybridSecretKey();
                    if (!hybridSecretKey) {
                        setDecryptError(true);
                        return;
                    }
                    const plaintext = await decryptMessage(
                        message.content!,
                        message.iv!,
                        message.salt!,
                        message.kemCiphertext!,
                        hybridSecretKey
                    );
                    setDecryptedContent(plaintext);
                } catch (error) {
                    console.error("Failed to decrypt message:", error);
                    setDecryptError(true);
                } finally {
                    setIsDecrypting(false);
                }
            })();
            return;
        }

        // Legacy own message with KEM: can't decrypt
        if (message.kemCiphertext && isOwn) {
            setDecryptedContent(null);
            setDecryptError(true);
        }
    }, [message, isOwn, channelSecret, decryptMessage, decryptChannelMessage,
        getUnlockedHybridSecretKey, isUnlocked]);

    // Determine what content to display
    let displayContent: string;
    if (isDecrypting) {
        displayContent = "Decrypting...";
    } else if (decryptError) {
        displayContent = "Could not decrypt";
    } else if (decryptedContent) {
        displayContent = decryptedContent;
    } else if (message.isEncrypted) {
        displayContent = "Encrypted";
    } else {
        displayContent = message.content || "";
    }

    return (
        <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            style={{
                display: "flex",
                justifyContent: isOwn ? "flex-end" : "flex-start",
                marginBottom: 6,
            }}
        >
            <div
                style={{
                    maxWidth: MESSAGE_MAX_WIDTH,
                    padding: "10px 14px",
                    borderRadius: isOwn ? MESSAGE_BORDER_RADIUS.own : MESSAGE_BORDER_RADIUS.other,
                    backgroundColor: isOwn ? theme.brand.primary : "var(--muted)",
                    color: isOwn ? "#FFFFFF" : "var(--foreground)",
                }}
            >
                <p
                    style={{
                        fontSize: 15,
                        lineHeight: 1.4,
                        margin: 0,
                        wordBreak: "break-word",
                        fontStyle: isDecrypting || decryptError ? "italic" : "normal",
                        opacity: isDecrypting || decryptError ? 0.7 : 1,
                    }}
                >
                    {displayContent}
                </p>
                <div
                    style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "flex-end",
                        gap: 4,
                        marginTop: 4,
                    }}
                >
                    {message.isEncrypted && !decryptError && (
                        <Shield size={10} style={{ opacity: 0.5 }} />
                    )}
                    <span
                        style={{
                            fontSize: 10,
                            opacity: 0.7,
                        }}
                    >
                        {format(new Date(message.createdAt), "HH:mm")}
                    </span>
                    {isOwn && (
                        message.isRead ? (
                            <CheckCheck size={12} style={{ opacity: 0.7 }} />
                        ) : (
                            <Check size={12} style={{ opacity: 0.7 }} />
                        )
                    )}
                </div>
            </div>
        </motion.div>
    );
}

// ─────────────────────────────────────────────────────────────
// MESSAGE INPUT
// ─────────────────────────────────────────────────────────────

function MessageInput({
    value,
    onChange,
    onSend,
    onKeyPress,
    disabled,
}: MessageInputProps) {
    const { theme } = useTheme();
    const canSend = value.trim().length > 0 && !disabled;

    return (
        <div
            style={{
                display: "flex",
                alignItems: "flex-end",
                gap: 8,
                padding: "12px 12px calc(12px + env(safe-area-inset-bottom, 0px))",
                borderTop: "1px solid var(--border)",
                backgroundColor: "var(--background)",
            }}
        >
            {/* Input */}
            <div
                style={{
                    flex: 1,
                    backgroundColor: "var(--muted)",
                    borderRadius: 20,
                    padding: "10px 16px",
                }}
            >
                <textarea
                    value={value}
                    onChange={onChange}
                    onKeyDown={onKeyPress}
                    placeholder="Message..."
                    rows={1}
                    aria-label="Message input"
                    style={{
                        width: "100%",
                        backgroundColor: "transparent",
                        border: "none",
                        outline: "none",
                        resize: "none",
                        fontSize: 15,
                        lineHeight: 1.4,
                        color: "var(--foreground)",
                        maxHeight: MESSAGE_INPUT_MAX_HEIGHT,
                    }}
                />
            </div>

            {/* Send Button */}
            <motion.button
                onClick={onSend}
                disabled={!canSend}
                whileTap={canSend ? { scale: 0.9 } : {}}
                aria-label="Send message"
                style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    width: 40,
                    height: 40,
                    borderRadius: 12,
                    backgroundColor: canSend ? theme.brand.primary : "var(--muted)",
                    border: "none",
                    cursor: canSend ? "pointer" : "default",
                    flexShrink: 0,
                    transition: "background-color 0.2s",
                }}
            >
                <Send
                    size={18}
                    style={{
                        color: canSend ? "#FFFFFF" : "var(--muted-foreground)",
                        transform: "rotate(-45deg)",
                    }}
                />
            </motion.button>
        </div>
    );
}

// ─────────────────────────────────────────────────────────────
// TYPING INDICATOR
// ─────────────────────────────────────────────────────────────

function TypingIndicator() {
    return (
        <div style={{ display: "flex", gap: 3 }} aria-label="User is typing">
            {[0, 1, 2].map((i) => (
                <motion.div
                    key={i}
                    animate={{
                        y: [0, -4, 0],
                        opacity: [0.4, 1, 0.4],
                    }}
                    transition={{
                        duration: 0.8,
                        repeat: Infinity,
                        delay: i * 0.15,
                    }}
                    style={{
                        width: 6,
                        height: 6,
                        borderRadius: "50%",
                        backgroundColor: "var(--muted-foreground)",
                    }}
                />
            ))}
        </div>
    );
}

// ─────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────

function groupMessagesByDate(messages: Message[]): GroupedMessages[] {
    const groups: GroupedMessages[] = [];
    let currentDate = "";
    let currentGroup: Message[] = [];

    for (const message of messages) {
        const msgDate = new Date(message.createdAt);
        let dateLabel: string;

        if (isToday(msgDate)) {
            dateLabel = "Today";
        } else if (isYesterday(msgDate)) {
            dateLabel = "Yesterday";
        } else {
            dateLabel = format(msgDate, "MMMM d, yyyy");
        }

        if (dateLabel !== currentDate) {
            if (currentGroup.length > 0) {
                groups.push({ date: currentDate, messages: currentGroup });
            }
            currentDate = dateLabel;
            currentGroup = [message];
        } else {
            currentGroup.push(message);
        }
    }

    if (currentGroup.length > 0) {
        groups.push({ date: currentDate, messages: currentGroup });
    }

    return groups;
}

export default MobileChatConversation;
