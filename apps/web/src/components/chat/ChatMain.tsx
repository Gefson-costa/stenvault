import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
    Menu,
    Phone,
    Video,
    MoreVertical,
    Info,
    UserX,
    Search,
    MessageSquarePlus,
    Loader2,
    Shield,
    Lock,
} from "lucide-react";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useAuth } from "@/_core/hooks/useAuth";
import { useCryptoStore } from "@/stores/cryptoStore";
import { useE2ECrypto } from "@/hooks/useE2ECrypto";
import { useMasterKey } from "@/hooks/useMasterKey";
import { useChatChannel } from "@/hooks/useChatChannel";
import { ChatInputArea } from "./ChatInputArea";
import { VaultUnlockModal } from "@/components/VaultUnlockModal";
import { MessageBubble } from "./MessageBubble";
import { format, isToday, isYesterday } from "date-fns";
import { enGB } from "date-fns/locale";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { trpc } from "@/lib/trpc";
import {
    base64ToUint8Array,
    deserializeHybridPublicKey,
} from "@/lib/platform";
import type { HybridPublicKeySerialized } from "@/lib/platform";

// Types for chat message and connection from tRPC
interface ChatMessage {
    id: number;
    fromUserId: number;
    toUserId: number;
    messageType: 'text' | 'file' | 'image' | 'video' | 'vault_file';
    content?: string | null;
    fileKey?: string | null;
    filename?: string | null;
    fileSize?: number | null;
    iv?: string | null;
    salt?: string | null;
    isEncrypted: boolean;
    keyVersion?: number | null;
    kemCiphertext?: string | null;
    isRead: boolean;
    isDeleted: boolean;
    createdAt: Date | string;
    chatFileShareId?: number | null;
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

interface ChatMainProps {
    selectedUserId: number | null;
    onOpenMenu: () => void;
    onCreateInvite: () => void;
}

/**
 * Chat Main - Main chat area
 *
 * Features:
 * - Header with user info and actions
 * - Auto-scrolling message list
 * - Floating input with animations
 * - Typing indicator
 * - Hybrid PQC E2E encryption
 */
export function ChatMain({ selectedUserId, onOpenMenu, onCreateInvite }: ChatMainProps) {
    // Empty state when no chat is selected
    if (!selectedUserId) {
        return (
            <div className="h-full flex items-center justify-center">
                <div className="text-center space-y-6 max-w-md px-4">
                    {/* Decorative illustration */}
                    <div className="relative w-32 h-32 mx-auto">
                        <div className="absolute inset-0 bg-primary/20 rounded-full animate-pulse" />
                        <div className="absolute inset-4 bg-primary/40 rounded-full animate-pulse animation-delay-300" />
                        <div className="absolute inset-8 bg-primary rounded-full flex items-center justify-center">
                            <Search className="w-12 h-12 text-primary-foreground" />
                        </div>
                    </div>

                    <div className="space-y-2">
                        <h2 className="text-2xl font-bold text-foreground">
                            Select a conversation
                        </h2>
                        <p className="text-muted-foreground">
                            Choose a conversation from the sidebar to start messaging
                        </p>
                    </div>

                    <div className="flex flex-col sm:flex-row gap-3 justify-center">
                        <Button
                            size="lg"
                            onClick={onOpenMenu}
                            className="lg:hidden"
                        >
                            <Menu className="h-5 w-5 mr-2" />
                            Open Conversations
                        </Button>

                        <Button
                            size="lg"
                            onClick={onCreateInvite}
                            aria-label="Create new chat invite"
                        >
                            <MessageSquarePlus className="h-5 w-5 mr-2" />
                            Create Invite
                        </Button>
                    </div>
                </div>
            </div>
        );
    }

    return <ActiveChat userId={selectedUserId} onOpenMenu={onOpenMenu} />;
}

/**
 * Active Chat - Chat with messages
 */
interface ActiveChatProps {
    userId: number;
    onOpenMenu: () => void;
}

function ActiveChat({ userId, onOpenMenu }: ActiveChatProps) {
    const { user } = useAuth();
    const [isTyping, setIsTyping] = useState(false);
    const [localMessages, setLocalMessages] = useState<ChatMessage[]>([]);
    const [isLoadingMore, setIsLoadingMore] = useState(false);
    const [hasMoreMessages, setHasMoreMessages] = useState(true);
    const [beforeId, setBeforeId] = useState<number | undefined>(undefined);
    const [unlockModalOpen, setUnlockModalOpen] = useState(false);
    const scrollRef = useRef<HTMLDivElement>(null);
    const messagesContainerRef = useRef<HTMLDivElement>(null);
    const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const previousScrollHeight = useRef(0);
    // PERF FIX: Debounce message refetch to prevent N+1 queries
    const fetchDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const pendingMessageIdsRef = useRef<Set<number>>(new Set());

    const { cacheHybridPublicKey, getCachedHybridPublicKey } = useCryptoStore();
    const { encryptMessage, encryptChannelMessage } = useE2ECrypto();
    const { isUnlocked, isConfigured } = useMasterKey();
    const {
        channelSecret,
        channelStatus,
        channelKeyVersion,
        isChannelReady,
        isSettingUp,
        initiateChannel,
    } = useChatChannel(userId);
    const {
        sendMessage: sendWsMessage,
        sendTyping,
        onNewMessage,
        onTyping,
    } = useWebSocket();

    const utils = trpc.useUtils();

    // Fetch connection details via tRPC
    const { data: connectionsData } = trpc.chat.getMyConnections.useQuery();
    const connection = connectionsData?.connections?.find(c => c.connectedUserId === userId) as ChatConnection | undefined ?? null;

    // Fetch messages via tRPC
    const { data: messagesData, isLoading: isLoadingMessages, refetch: refetchMessages } = trpc.chat.getMessages.useQuery(
        { withUserId: userId, limit: 50, beforeId },
        { enabled: !!userId }
    );

    // Sync messages from tRPC to local state
    useEffect(() => {
        if (messagesData?.messages) {
            const transformed = messagesData.messages.map(msg => ({
                ...msg,
                createdAt: msg.createdAt,
            })) as ChatMessage[];
            if (beforeId) {
                // Prepend older messages
                setLocalMessages(prev => [...transformed, ...prev]);
            } else {
                // Replace all
                setLocalMessages(transformed);
            }
            setHasMoreMessages(messagesData.messages.length === 50);
        }
    }, [messagesData, beforeId, userId]);

    const messages = localMessages;

    // Wrapper function for refetch (compatible with existing code)
    const fetchMessages = useCallback(() => {
        setBeforeId(undefined);
        refetchMessages();
    }, [refetchMessages]);

    // Load more messages (infinite scroll)
    const loadMoreMessages = useCallback(async () => {
        if (isLoadingMore || !hasMoreMessages || messages.length === 0) return;

        const oldestMessageId = messages[0]?.id;
        if (!oldestMessageId) return;

        // Save scroll position before loading
        if (messagesContainerRef.current) {
            previousScrollHeight.current = messagesContainerRef.current.scrollHeight;
        }

        setIsLoadingMore(true);
        setBeforeId(oldestMessageId);
        // The query will auto-refetch with new beforeId and update via useEffect
        setTimeout(() => setIsLoadingMore(false), 500);
    }, [messages, isLoadingMore, hasMoreMessages]);

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

    // Auto-scroll to bottom on new messages
    // Uses direct scrollTop on the Radix viewport instead of scrollIntoView
    // to prevent scrolling the outer page when the viewport isn't the nearest scrollable ancestor.
    useEffect(() => {
        if (!scrollRef.current || isLoadingMore) return;
        const viewport = scrollRef.current.closest('[data-slot="scroll-area-viewport"]');
        if (viewport) {
            viewport.scrollTo({ top: viewport.scrollHeight, behavior: "smooth" });
        }
    }, [messages, isLoadingMore]);

    // Restore scroll position after loading more messages
    useEffect(() => {
        if (isLoadingMore === false && messagesContainerRef.current && previousScrollHeight.current > 0) {
            const newScrollHeight = messagesContainerRef.current.scrollHeight;
            const scrollDiff = newScrollHeight - previousScrollHeight.current;
            messagesContainerRef.current.scrollTop = scrollDiff;
            previousScrollHeight.current = 0;
        }
    }, [isLoadingMore]);

    // Detect scroll to top for infinite scroll
    const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
        const target = e.currentTarget;
        if (target.scrollTop < 100 && !isLoadingMore && hasMoreMessages) {
            loadMoreMessages();
        }
    }, [isLoadingMore, hasMoreMessages, loadMoreMessages]);

    // Listen for new messages via WebSocket with debouncing
    // PERF FIX: Instead of fetching all 50 messages for each incoming message,
    // we debounce the fetch to batch multiple rapid messages into a single request
    useEffect(() => {
        const cleanup = onNewMessage((message) => {
            if (message.fromUserId === userId || message.toUserId === userId) {
                // Track pending message IDs for debugging
                pendingMessageIdsRef.current.add(message.messageId);

                // Clear existing debounce timer
                if (fetchDebounceRef.current) {
                    clearTimeout(fetchDebounceRef.current);
                }

                // Debounce: wait 300ms before fetching to batch rapid messages
                fetchDebounceRef.current = setTimeout(() => {
                    setBeforeId(undefined);
                    utils.chat.getMessages.invalidate({ withUserId: userId });
                    pendingMessageIdsRef.current.clear();
                }, 300);
            }
        });

        // Cleanup debounce timer on unmount
        return () => {
            cleanup?.();
            if (fetchDebounceRef.current) {
                clearTimeout(fetchDebounceRef.current);
            }
        };
    }, [onNewMessage, userId, utils]);

    // Listen for typing indicators
    useEffect(() => {
        onTyping((indicator) => {
            if (indicator.fromUserId === userId) {
                setIsTyping(indicator.isTyping);
            }
        });
    }, [onTyping, userId]);

    // Send message mutation via tRPC
    const sendMessageMutation = trpc.chat.sendMessage.useMutation({
        onSuccess: (data, variables) => {
            const messageId = data.messageId;

            // Send via WebSocket for real-time delivery
            sendWsMessage({
                toUserId: userId,
                messageId,
                content: variables.content || "",
                messageType: variables.messageType || "text",
                isEncrypted: variables.isEncrypted ?? false,
                iv: variables.iv,
            });

            // Optimistic: show the message immediately with encrypted flag
            // SVCP messages will be decrypted by MessageBubble using channelSecret
            const newMessage: ChatMessage = {
                id: messageId,
                fromUserId: user?.id ?? 0,
                toUserId: userId,
                messageType: variables.messageType || "text",
                content: variables.content,
                fileKey: variables.fileKey,
                filename: variables.filename,
                fileSize: variables.fileSize,
                iv: variables.iv,
                salt: variables.salt,
                isEncrypted: variables.isEncrypted ?? false,
                keyVersion: variables.keyVersion ?? 1,
                kemCiphertext: variables.kemCiphertext,
                isRead: false,
                isDeleted: false,
                createdAt: new Date().toISOString(),
            };
            setLocalMessages(prev => [...prev, newMessage]);
        },
        onError: () => {
            toast.error("Failed to send message");
        },
    });

    // Handle send message (text only - files go through useChatLocalUpload)
    const handleSendMessage = async (content: string) => {
        try {
            if (!isUnlocked) {
                toast.error("Vault must be unlocked to send encrypted messages.");
                return;
            }

            // SVCP: use channel secret if available, auto-initiate if needed
            const activeChannelSecret = channelSecret ?? await initiateChannel();

            if (activeChannelSecret) {
                // SVCP path: encrypt with channel secret (both sender + recipient can decrypt)
                const { ciphertext, iv, salt } = await encryptChannelMessage(
                    content,
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
                    // No kemCiphertext — SVCP messages don't need per-message KEM
                });
                return;
            }

            // Fallback: legacy per-message KEM (if channel initiation failed)
            const cachedKey = getCachedHybridPublicKey(userId);
            if (!cachedKey) {
                toast.error("Recipient's encryption key not available. Try again shortly.");
                return;
            }

            const recipientHybridPubKey = deserializeHybridPublicKey({
                classical: cachedKey.x25519PublicKey,
                postQuantum: cachedKey.mlkem768PublicKey,
                algorithm: 'x25519-ml-kem-768',
            } as HybridPublicKeySerialized);

            const { ciphertext, iv, salt, kemCiphertext } = await encryptMessage(
                content,
                recipientHybridPubKey
            );

            sendMessageMutation.mutate({
                toUserId: userId,
                messageType: "text",
                content: ciphertext,
                iv,
                salt,
                kemCiphertext,
                isEncrypted: true,
                keyVersion: cachedKey.keyVersion,
            });
        } catch (error) {
            console.error("Failed to encrypt/send message:", error);
            toast.error("Failed to send encrypted message");
        }
    };

    // Handle typing indicator
    const handleTyping = (typing: boolean) => {
        sendTyping(userId, typing);

        if (typing) {
            if (typingTimeoutRef.current) {
                clearTimeout(typingTimeoutRef.current);
            }
            typingTimeoutRef.current = setTimeout(() => {
                sendTyping(userId, false);
            }, 3000);
        }
    };

    const rawName = connection?.nickname || connection?.connectedUserName || connection?.connectedUserEmail || "Unknown";
    const userName = rawName.includes("@") ? rawName : rawName.replace(/\b\w/g, c => c.toUpperCase());
    const initials = userName
        .split(" ")
        .map((n: string) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2);

    // Group messages by date
    type MessageType = {
        id: number;
        createdAt: Date | string;
        fromUserId: number;
        toUserId: number;
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
        chatFileShareId?: number | null;
    };

    const groupedMessages = messages.reduce((groups: Record<string, MessageType[]>, message) => {
        const date = format(new Date(message.createdAt), "yyyy-MM-dd");
        if (!groups[date]) {
            groups[date] = [];
        }
        groups[date].push(message as MessageType);
        return groups;
    }, {} as Record<string, MessageType[]>);

    // Vault locked: show overlay blocking the chat
    const vaultLocked = isConfigured && !isUnlocked;

    return (
        <div className="h-full grid grid-rows-[auto_1fr_auto] relative min-h-0 overflow-hidden">
            {/* Vault Lock Overlay */}
            {vaultLocked && (
                <div className="absolute inset-0 z-50 flex items-center justify-center backdrop-blur-md bg-background/80">
                    <div className="text-center p-8 max-w-md">
                        <div className="mx-auto mb-6 h-16 w-16 rounded-full bg-amber-500/10 flex items-center justify-center">
                            <Shield className="h-8 w-8 text-amber-500" />
                        </div>
                        <h2 className="text-xl font-semibold mb-2">Vault Locked</h2>
                        <p className="text-muted-foreground mb-6">
                            Unlock your vault to send and read encrypted messages.
                        </p>
                        <Button
                            onClick={() => setUnlockModalOpen(true)}
                            size="lg"
                            className="gap-2"
                        >
                            <Lock className="h-4 w-4" />
                            Unlock Vault
                        </Button>
                    </div>
                </div>
            )}

            {/* Vault Unlock Modal (inline) */}
            <VaultUnlockModal
                isOpen={unlockModalOpen}
                onUnlock={() => setUnlockModalOpen(false)}
                onClose={() => setUnlockModalOpen(false)}
            />

            {/* Header - Premium design */}
            <header className="relative z-10 px-6 py-4 bg-background/80 backdrop-blur-xl border-b border-border/50 shadow-sm">
                <div className="flex items-center justify-between">
                    {/* User info */}
                    <div className="flex items-center gap-4">
                        {/* Mobile menu button */}
                        <Button
                            size="icon"
                            variant="ghost"
                            onClick={onOpenMenu}
                            className="lg:hidden"
                            aria-label="Open menu"
                        >
                            <Menu className="h-5 w-5" />
                        </Button>

                        {/* Avatar with online status */}
                        <div className="relative">
                            <Avatar className="h-11 w-11 border-2 border-background shadow-md">
                                <AvatarFallback className="bg-primary text-primary-foreground font-semibold">
                                    {initials}
                                </AvatarFallback>
                            </Avatar>
                            <div className="absolute bottom-0 right-0 w-3.5 h-3.5 bg-green-500 border-2 border-background rounded-full" />
                        </div>

                        {/* Name and status */}
                        <div>
                            <h2 className="font-semibold text-foreground">
                                {userName}
                            </h2>
                            {isTyping ? (
                                <p className="text-sm text-primary font-medium animate-pulse">
                                    typing...
                                </p>
                            ) : (
                                <p className="text-sm text-muted-foreground">
                                    Online
                                </p>
                            )}
                        </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2">
                        {/* Call buttons */}
                        <Button
                            size="icon"
                            variant="ghost"
                            className="hidden sm:inline-flex"
                            aria-label="Voice call"
                        >
                            <Phone className="h-5 w-5" />
                        </Button>

                        <Button
                            size="icon"
                            variant="ghost"
                            className="hidden sm:inline-flex"
                            aria-label="Video call"
                        >
                            <Video className="h-5 w-5" />
                        </Button>

                        {/* More options */}
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button size="icon" variant="ghost" aria-label="More options">
                                    <MoreVertical className="h-5 w-5" />
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-48">
                                <DropdownMenuItem>
                                    <Info className="h-4 w-4 mr-2" />
                                    View Info
                                </DropdownMenuItem>
                                <DropdownMenuItem>
                                    <Search className="h-4 w-4 mr-2" />
                                    Search Chat
                                </DropdownMenuItem>
                                <DropdownMenuItem className="text-destructive">
                                    <UserX className="h-4 w-4 mr-2" />
                                    Block User
                                </DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>
                    </div>
                </div>
            </header>

            {/* Messages Area */}
            <div className="min-h-0 overflow-hidden">
            <ScrollArea
                className="h-full p-4"
                onScrollCapture={handleScroll}
            >
                <div ref={messagesContainerRef} className="space-y-6">
                    {/* Loading more indicator */}
                    {isLoadingMore && (
                        <div className="flex justify-center py-4">
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                <Loader2 className="h-4 w-4 animate-spin" />
                                <span>Loading earlier messages...</span>
                            </div>
                        </div>
                    )}

                    {/* End of messages indicator */}
                    {!hasMoreMessages && messages.length > 0 && (
                        <div className="flex justify-center py-4">
                            <div className="text-xs text-muted-foreground">
                                Start of conversation
                            </div>
                        </div>
                    )}
                    {Object.entries(groupedMessages || {}).map(([date, dateMessages]) => {
                        const messageDate = new Date(date);
                        let dateLabel = format(messageDate, "d MMMM yyyy", { locale: enGB });

                        if (isToday(messageDate)) {
                            dateLabel = "Today";
                        } else if (isYesterday(messageDate)) {
                            dateLabel = "Yesterday";
                        }

                        return (
                            <div key={date} className="space-y-4">
                                {/* Date Divider */}
                                <div className="flex items-center justify-center my-6">
                                    <div className="flex-1 h-px bg-gradient-to-r from-transparent via-border to-transparent" />
                                    <Badge
                                        variant="outline"
                                        className="mx-4 bg-background border-border text-muted-foreground px-3 py-1 shadow-sm"
                                    >
                                        {dateLabel}
                                    </Badge>
                                    <div className="flex-1 h-px bg-gradient-to-r from-transparent via-border to-transparent" />
                                </div>

                                {/* Messages for this date */}
                                <div className="space-y-3">
                                    {(dateMessages as MessageType[]).map((message: MessageType) => {
                                        const msgIsOwn = message.fromUserId !== userId;
                                        return (
                                            <MessageBubble
                                                key={message.id}
                                                message={message as any}
                                                isOwn={msgIsOwn}
                                                senderName={message.fromUserId === userId ? userName : undefined}
                                                channelSecret={channelSecret}
                                            />
                                        );
                                    })}
                                </div>
                            </div>
                        );
                    })}

                    <div ref={scrollRef} />
                </div>
            </ScrollArea>
            </div>

            {/* Input Area - Floating design */}
            <div className="relative z-10 px-4 pb-4 pt-2 bg-gradient-to-t from-background via-background/50 to-transparent">
                <ChatInputArea
                    onSendMessage={handleSendMessage}
                    onTypingChange={handleTyping}
                    recipientUserId={userId}
                    recipientName={userName}
                />
            </div>
        </div>
    );
}
