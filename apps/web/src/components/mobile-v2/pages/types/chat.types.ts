/**
 * Mobile Chat Types
 * 
 * Centralized type definitions for mobile chat components.
 * Prevents importing types from UI components (bad practice).
 */

// ─────────────────────────────────────────────────────────────
// CONNECTION TYPE
// ─────────────────────────────────────────────────────────────

/**
 * Chat Connection - represents a chat contact/conversation
 * Previously defined in ChatLayout.tsx, moved here for proper separation
 */
export interface Connection {
    id: number;
    userId?: number;
    connectedUserId: number;
    nickname?: string | null;
    connectedUser?: {
        id?: number;
        name?: string | null;
        email?: string;
    };
    status?: "pending" | "accepted" | "blocked" | null;
    createdAt?: Date | string | null;
    updatedAt?: Date | string | null;
    lastMessage?: {
        id: number;
        fromUserId: number;
        toUserId: number;
        content: string | null;
        messageType: "text" | "file" | "image" | "video" | "vault_file";
        isEncrypted?: boolean;
        createdAt: Date;
    } | null;
    unreadCount?: number;
}

// ─────────────────────────────────────────────────────────────
// MESSAGE TYPES
// ─────────────────────────────────────────────────────────────

export type MessageType = "text" | "file" | "image" | "video";

export interface Message {
    id: number;
    fromUserId: number;
    toUserId: number;
    content: string | null;
    messageType: MessageType;
    createdAt: Date;
    isEncrypted: boolean;
    isRead: boolean;
    iv?: string | null;
    salt?: string | null;
    kemCiphertext?: string | null;
    fileKey?: string | null;
    filename?: string | null;
    fileSize?: number | null;
}

export interface GroupedMessages {
    date: string;
    messages: Message[];
}

// ─────────────────────────────────────────────────────────────
// STATE TYPES
// ─────────────────────────────────────────────────────────────

export interface MobileChatState {
    // Navigation
    view: "list" | "conversation";
    selectedUserId: number | null;

    // Data
    connections: Connection[];
    onlineUsers: Set<number>;

    // Modals
    showInviteModal: boolean;
    showAcceptInviteModal: boolean;

    // Status
    isConnected: boolean;
    isLoading: boolean;
}

export interface MobileChatActions {
    selectConversation: (userId: number) => void;
    goBackToList: () => void;
    openInviteModal: () => void;
    closeInviteModal: () => void;
    openAcceptInviteModal: () => void;
    closeAcceptInviteModal: () => void;
    refetchConnections: () => Promise<void>;
}

// ─────────────────────────────────────────────────────────────
// COMPONENT PROP TYPES
// ─────────────────────────────────────────────────────────────

export interface MobileChatConversationProps {
    userId: number;
    onBack: () => void;
}

export interface ConversationsListProps {
    connections: Connection[];
    onlineUsers: Set<number>;
    isConnected: boolean;
    isLoading: boolean;
    onSelectConversation: (userId: number) => void;
    onRefresh: () => Promise<void>;
    onInvite: () => void;
    onAcceptInvite: () => void;
}

export interface ConversationItemProps {
    connection: Connection;
    isOnline: boolean;
    onClick: () => void;
    delay?: number;
}

export interface ChatHeaderProps {
    name: string;
    isOnline: boolean;
    onBack: () => void;
}

export interface MessageBubbleProps {
    message: Message;
    isOwn: boolean;
    /** SVCP channel secret for decryption (both sender + recipient use the same key) */
    channelSecret?: CryptoKey | null;
}

export interface MessageInputProps {
    value: string;
    onChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void;
    onSend: () => void;
    onKeyPress: (e: React.KeyboardEvent) => void;
    disabled: boolean;
}

export interface ActionButtonProps {
    icon: React.ElementType;
    label: string;
    onClick: () => void;
    primary?: boolean;
}
