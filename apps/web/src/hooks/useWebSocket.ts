import { useEffect, useRef, useState, useCallback } from "react";
import { io, Socket } from "socket.io-client";
import { useAuth } from "@/_core/hooks/useAuth";
import { debugLog, debugError } from "@/lib/debugLogger";

/**
 * WebSocket Events
 */
export interface ChatMessage {
    messageId: number;
    fromUserId: number;
    toUserId: number;
    content: string;
    messageType: "text" | "file" | "image" | "video" | "vault_file";
    isEncrypted: boolean;
    iv?: string;
    createdAt: Date;
}

export interface TypingIndicator {
    fromUserId: number;
    isTyping: boolean;
}

export interface PresenceUpdate {
    userId: number;
    isOnline: boolean;
    timestamp: Date;
}

export interface MessageReadEvent {
    messageIds: number[];
    readBy: number;
    readAt: Date;
}

export interface ChatInviteEvent {
    inviteId: number;
    from: {
        id: number;
        name: string;
        email: string;
    };
    message: string;
}

export interface InviteAcceptedEvent {
    userId: number;
    userName: string;
    message: string;
}

export interface ShareRevokedEvent {
    shareId: number;
    fromUserId: number;
}

export interface FileSharedEvent {
    fromUserId: number;
    shareId: number;
    filename: string;
}

/**
 * WebSocket Hook
 * Manages real-time connection for chat
 */
export function useWebSocket() {
    const { user } = useAuth();
    const [isConnected, setIsConnected] = useState(false);
    const [isConnecting, setIsConnecting] = useState(false);
    const socketRef = useRef<Socket | null>(null);
    const messageQueueRef = useRef<any[]>([]);
    const reconnectAttemptsRef = useRef(0);
    const MAX_RECONNECT_ATTEMPTS = 5;

    // Event handlers using refs to avoid re-renders
    const onNewMessageRef = useRef<(message: ChatMessage) => void>(() => { });
    const onMessageDeliveredRef = useRef<(data: { messageId: number; toUserId: number }) => void>(() => { });
    const onTypingRef = useRef<(indicator: TypingIndicator) => void>(() => { });
    const onPresenceUpdateRef = useRef<(update: PresenceUpdate) => void>(() => { });
    const onMessageReadRef = useRef<(event: MessageReadEvent) => void>(() => { });
    const onConnectionAcceptedRef = useRef<(data: { byUserId: number }) => void>(() => { });
    const onChatInviteRef = useRef<(event: ChatInviteEvent) => void>(() => { });
    const onInviteAcceptedRef = useRef<(event: InviteAcceptedEvent) => void>(() => { });
    const onShareRevokedRef = useRef<(event: ShareRevokedEvent) => void>(() => { });
    const onFileSharedRef = useRef<(event: FileSharedEvent) => void>(() => { });

    /**
     * Connect to WebSocket server
     */
    const connect = useCallback(() => {
        if (!user || socketRef.current?.connected) return;

        // Use VITE_WS_URL or derive from VITE_API_URL (unified Vault API)
        const apiUrl = import.meta.env.VITE_API_URL || '';
        const wsUrl = import.meta.env.VITE_WS_URL || apiUrl.replace('/api', '').replace('http:', 'ws:').replace('https:', 'wss:') || '';
        setIsConnecting(true);

        const socket = io(wsUrl, {
            path: "/socket.io",
            withCredentials: true, // Send HttpOnly cookies on handshake
            transports: ["websocket", "polling"],
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            reconnectionAttempts: MAX_RECONNECT_ATTEMPTS,
        });

        // Connection events
        socket.on("connect", () => {
            debugLog('[WebSocket]', 'Connected');
            setIsConnected(true);
            setIsConnecting(false);
            reconnectAttemptsRef.current = 0;

            // Process queued messages
            if (messageQueueRef.current.length > 0) {
                debugLog('[WebSocket]', `Processing ${messageQueueRef.current.length} queued messages`);
                messageQueueRef.current.forEach((msg) => {
                    socket.emit(msg.event, msg.data);
                });
                messageQueueRef.current = [];
            }
        });

        socket.on("disconnect", (reason) => {
            debugLog('[WebSocket]', 'Disconnected: ' + reason);
            setIsConnected(false);
        });

        socket.on("connect_error", (error) => {
            debugError('[WebSocket]', 'Connection error', error);
            setIsConnecting(false);
            reconnectAttemptsRef.current++;

            if (reconnectAttemptsRef.current >= MAX_RECONNECT_ATTEMPTS) {
                debugError('[WebSocket]', 'Max reconnection attempts reached');
                socket.disconnect();
            }
        });

        // Message events
        socket.on("message:new", (message: ChatMessage) => {
            onNewMessageRef.current(message);
        });

        socket.on("message:delivered", (data: { messageId: number; toUserId: number }) => {
            onMessageDeliveredRef.current(data);
        });

        socket.on("message:read", (event: MessageReadEvent) => {
            onMessageReadRef.current(event);
        });

        // Typing events
        socket.on("typing:update", (indicator: TypingIndicator) => {
            onTypingRef.current(indicator);
        });

        // Presence events
        socket.on("presence:update", (update: PresenceUpdate) => {
            onPresenceUpdateRef.current(update);
        });

        socket.on("presence:status", (statuses: { userId: number; isOnline: boolean }[]) => {
            statuses.forEach((status) => {
                onPresenceUpdateRef.current({
                    userId: status.userId,
                    isOnline: status.isOnline,
                    timestamp: new Date(),
                });
            });
        });

        // Connection events
        socket.on("connection:new", (data: { fromUserId: number; inviteCode: string }) => {
            // Handle new connection request
            debugLog('[WebSocket]', 'New connection request from: ' + data.fromUserId);
        });

        socket.on("connection:accepted", (data: { byUserId: number }) => {
            onConnectionAcceptedRef.current(data);
        });

        // Chat invite events (Signal-style discovery)
        socket.on("chat:invite", (event: ChatInviteEvent) => {
            onChatInviteRef.current(event);
        });

        socket.on("chat:invite-accepted", (event: InviteAcceptedEvent) => {
            onInviteAcceptedRef.current(event);
        });

        // File share events
        socket.on("chat:share-revoked", (event: ShareRevokedEvent) => {
            debugLog('[WebSocket]', `Share ${event.shareId} revoked by user ${event.fromUserId}`);
            onShareRevokedRef.current(event);
        });

        socket.on("chat:file-shared", (event: FileSharedEvent) => {
            debugLog('[WebSocket]', `File shared: ${event.filename} from user ${event.fromUserId}`);
            onFileSharedRef.current(event);
        });

        // Error events
        socket.on("error", (error: { message: string }) => {
            debugError('[WebSocket]', 'Server error', error);
        });

        socketRef.current = socket;
    }, [user]);

    /**
     * Disconnect from WebSocket server
     */
    const disconnect = useCallback(() => {
        if (socketRef.current) {
            socketRef.current.disconnect();
            socketRef.current = null;
            setIsConnected(false);
        }
    }, []);

    /**
     * Send a message
     */
    const sendMessage = useCallback(
        (data: {
            toUserId: number;
            messageId: number;
            content: string;
            messageType: string;
            isEncrypted: boolean;
            iv?: string;
        }) => {
            if (!socketRef.current?.connected) {
                // Queue message for later
                messageQueueRef.current.push({
                    event: "message:send",
                    data,
                });
                debugLog('[WebSocket]', 'Message queued (offline)');
                return;
            }

            socketRef.current.emit("message:send", data);
        },
        []
    );

    /**
     * Send typing indicator
     */
    const sendTyping = useCallback(
        (toUserId: number, isTyping: boolean) => {
            if (!socketRef.current?.connected) return;

            const event = isTyping ? "typing:start" : "typing:stop";
            socketRef.current.emit(event, { toUserId });
        },
        []
    );

    /**
     * Mark messages as read
     */
    const markMessagesAsRead = useCallback(
        (messageIds: number[], fromUserId: number) => {
            if (!socketRef.current?.connected) return;

            socketRef.current.emit("message:read", {
                messageIds,
                fromUserId,
            });
        },
        []
    );

    /**
     * Check online status of users
     */
    const checkPresence = useCallback(
        (userIds: number[]) => {
            if (!socketRef.current?.connected) return;

            socketRef.current.emit("presence:check", { userIds });
        },
        []
    );

    /**
     * Request connection
     */
    const requestConnection = useCallback(
        (toUserId: number, inviteCode: string) => {
            if (!socketRef.current?.connected) return;

            socketRef.current.emit("connection:request", {
                toUserId,
                inviteCode,
            });
        },
        []
    );

    /**
     * Accept connection
     */
    const acceptConnection = useCallback(
        (withUserId: number) => {
            if (!socketRef.current?.connected) return;

            socketRef.current.emit("connection:accepted", { withUserId });
        },
        []
    );

    // Auto-connect when user is authenticated
    useEffect(() => {
        if (user) {
            connect();
        } else {
            disconnect();
        }

        return () => {
            disconnect();
        };
    }, [user, connect, disconnect]);

    // SECURITY FIX: Event listener registration with cleanup functions
    // Returns a cleanup function to prevent memory leaks and stale closures
    // Golden Rule #4: Falha Visível - prevent silent memory leaks
    const createEventRegistration = <T>(ref: React.MutableRefObject<(data: T) => void>) => {
        return (handler: (data: T) => void) => {
            ref.current = handler;
            // Return cleanup function for useEffect
            return () => {
                ref.current = () => {};
            };
        };
    };

    return {
        isConnected,
        isConnecting,
        connect,
        disconnect,
        sendMessage,
        sendTyping,
        markMessagesAsRead,
        checkPresence,
        requestConnection,
        acceptConnection,
        // Event listeners with cleanup functions
        // Usage: useEffect(() => onNewMessage(handler), [deps])
        onNewMessage: createEventRegistration(onNewMessageRef),
        onMessageDelivered: createEventRegistration(onMessageDeliveredRef),
        onTyping: createEventRegistration(onTypingRef),
        onPresenceUpdate: createEventRegistration(onPresenceUpdateRef),
        onMessageRead: createEventRegistration(onMessageReadRef),
        onConnectionAccepted: createEventRegistration(onConnectionAcceptedRef),
        onChatInvite: createEventRegistration(onChatInviteRef),
        onInviteAccepted: createEventRegistration(onInviteAcceptedRef),
        // File share events
        onShareRevoked: createEventRegistration(onShareRevokedRef),
        onFileShared: createEventRegistration(onFileSharedRef),
    };
}
