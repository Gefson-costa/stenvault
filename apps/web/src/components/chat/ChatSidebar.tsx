/**
 * ═══════════════════════════════════════════════════════════════
 * CHAT SIDEBAR - THEME ADAPTIVE
 * ═══════════════════════════════════════════════════════════════
 *
 * Premium conversations list with refined glassmorphism
 * and sophisticated micro-interactions.
 * Uses semantic tokens for full theme compatibility.
 *
 * ═══════════════════════════════════════════════════════════════
 */

import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
    Search,
    MessageSquarePlus,
    X,
    UserPlus,
    Circle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDistanceToNow } from "date-fns";
import { enGB } from "date-fns/locale";
import { motion } from "framer-motion";
import type { Connection } from "./ChatLayout";

interface ChatSidebarProps {
    connections: Connection[];
    selectedUserId: number | null;
    onlineUsers: Set<number>;
    isConnected: boolean;
    onSelectUser: (userId: number) => void;
    onClose: () => void;
    onCreateInvite: () => void;
    onAcceptInvite: () => void;
}

/**
 * Chat Sidebar - Theme Adaptive
 */
export function ChatSidebar({
    connections,
    selectedUserId,
    onlineUsers,
    isConnected,
    onSelectUser,
    onClose,
    onCreateInvite,
    onAcceptInvite,
}: ChatSidebarProps) {
    const [searchQuery, setSearchQuery] = useState("");
    const [filter, setFilter] = useState<"all" | "unread">("all");

    // Filter conversations
    const filteredConnections = useMemo(() => {
        if (!connections) return [];

        let filtered = connections;

        // Filter by search
        if (searchQuery) {
            filtered = filtered.filter(
                (conn) =>
                    (conn.connectedUser?.name?.toLowerCase().includes(searchQuery.toLowerCase())) ||
                    (conn.connectedUser?.email?.toLowerCase().includes(searchQuery.toLowerCase())) ||
                    (conn.nickname?.toLowerCase().includes(searchQuery.toLowerCase()))
            );
        }

        // Filter by unread
        if (filter === "unread") {
            filtered = filtered.filter((conn) => (conn.unreadCount ?? 0) > 0);
        }

        return filtered;
    }, [connections, searchQuery, filter]);

    const unreadCount = connections?.filter((c) => (c.unreadCount ?? 0) > 0).length || 0;

    return (
        <div className="relative h-full flex flex-col">
            {/* ═══════════ HEADER ═══════════ */}
            <div className="relative z-10 p-4 space-y-4">
                {/* Title bar */}
                <div className="flex items-center justify-between">
                    <h1 className="text-xl font-sans font-semibold text-foreground">
                        Messages
                    </h1>

                    <div className="flex items-center gap-1">
                        <Button
                            size="icon"
                            variant="ghost"
                            onClick={onAcceptInvite}
                            className={cn(
                                "h-9 w-9 rounded-lg",
                                "text-foreground-muted hover:text-primary",
                                "hover:bg-primary/10",
                                "transition-all duration-200"
                            )}
                            title="Accept Invite"
                        >
                            <UserPlus className="h-4 w-4" />
                        </Button>

                        <Button
                            size="icon"
                            variant="ghost"
                            onClick={onCreateInvite}
                            className={cn(
                                "h-9 w-9 rounded-lg",
                                "text-foreground-muted hover:text-primary",
                                "hover:bg-primary/10",
                                "transition-all duration-200"
                            )}
                            title="Create Invite"
                        >
                            <MessageSquarePlus className="h-4 w-4" />
                        </Button>

                        <Button
                            size="icon"
                            variant="ghost"
                            className={cn(
                                "lg:hidden h-9 w-9 rounded-lg",
                                "text-foreground-muted hover:text-foreground",
                                "hover:bg-background-muted",
                                "transition-all duration-200"
                            )}
                            onClick={onClose}
                        >
                            <X className="h-4 w-4" />
                        </Button>
                    </div>
                </div>

                {/* Premium Search Bar */}
                <div className="relative group">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground-muted group-focus-within:text-primary transition-colors" />
                    <Input
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Search conversations..."
                        className={cn(
                            "pl-10 h-10",
                            "bg-background-muted border-primary/10",
                            "text-foreground placeholder:text-foreground-muted",
                            "focus-visible:border-primary/30",
                            "focus-visible:ring-2 focus-visible:ring-primary/10",
                            "transition-all duration-200"
                        )}
                    />
                </div>

                {/* Filter tabs */}
                <div className="flex gap-2">
                    <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setFilter("all")}
                        className={cn(
                            "flex-1 h-9 rounded-lg transition-all duration-200",
                            filter === "all" ? [
                                "bg-primary/10",
                                "text-primary",
                                "border border-primary/20",
                                "shadow-[0_0_15px_var(--glow)]"
                            ] : [
                                "text-foreground-muted",
                                "hover:text-foreground",
                                "hover:bg-background-muted"
                            ]
                        )}
                    >
                        All
                        <Badge className={cn(
                            "ml-2 text-[10px]",
                            filter === "all"
                                ? "bg-primary/20 text-primary border-0"
                                : "bg-background-surface text-foreground-muted border-0"
                        )}>
                            {connections?.length || 0}
                        </Badge>
                    </Button>

                    <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setFilter("unread")}
                        className={cn(
                            "flex-1 h-9 rounded-lg transition-all duration-200",
                            filter === "unread" ? [
                                "bg-primary/10",
                                "text-primary",
                                "border border-primary/20",
                                "shadow-[0_0_15px_var(--glow)]"
                            ] : [
                                "text-foreground-muted",
                                "hover:text-foreground",
                                "hover:bg-background-muted"
                            ]
                        )}
                    >
                        Unread
                        {unreadCount > 0 && (
                            <Badge className="ml-2 bg-destructive text-destructive-foreground border-0 text-[10px]">
                                {unreadCount}
                            </Badge>
                        )}
                    </Button>
                </div>

                {/* New Chat Button - Premium */}
                <Button
                    onClick={onCreateInvite}
                    className={cn(
                        "w-full h-11 rounded-xl",
                        "bg-primary",
                        "text-primary-foreground font-medium",
                        "shadow-[0_4px_20px_var(--glow)]",
                        "hover:shadow-[0_4px_30px_var(--glow-strong)]",
                        "hover:brightness-110",
                        "transition-all duration-300",
                        "group"
                    )}
                    size="lg"
                >
                    <MessageSquarePlus className="h-5 w-5 mr-2 group-hover:scale-110 transition-transform duration-200" />
                    New Conversation
                </Button>
            </div>

            {/* ═══════════ CONVERSATIONS LIST ═══════════ */}
            <ScrollArea className={cn(
                "flex-1 px-2",
                // Premium scrollbar
                "[&_[data-radix-scroll-area-viewport]]:!overflow-y-scroll",
                "[&::-webkit-scrollbar]:w-1.5",
                "[&::-webkit-scrollbar-thumb]:bg-border",
                "[&::-webkit-scrollbar-thumb]:rounded-full",
                "[&::-webkit-scrollbar-thumb:hover]:bg-primary/40",
                "[&::-webkit-scrollbar-track]:bg-transparent"
            )}>
                <div className="space-y-1 pb-4">
                    {filteredConnections.length === 0 ? (
                        <div className="text-center py-12">
                            <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-background-muted border border-primary/10 flex items-center justify-center">
                                <MessageSquarePlus className="h-8 w-8 text-foreground-muted" />
                            </div>
                            <p className="text-sm text-foreground-muted">No conversations found</p>
                            <p className="text-xs mt-2 text-foreground-subtle">Create an invite to get started</p>
                        </div>
                    ) : (
                        filteredConnections.map((connection, index) => (
                            <motion.div
                                key={connection.id}
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: index * 0.05, duration: 0.3 }}
                            >
                                <ConversationItem
                                    connection={connection}
                                    isSelected={selectedUserId === connection.connectedUserId}
                                    isOnline={onlineUsers.has(connection.connectedUserId)}
                                    onClick={() => onSelectUser(connection.connectedUserId)}
                                />
                            </motion.div>
                        ))
                    )}
                </div>
            </ScrollArea>

            {/* ═══════════ CONNECTION STATUS FOOTER ═══════════ */}
            <div className="relative z-10 p-3 border-t border-border/50">
                <div className="flex items-center justify-center gap-2 text-xs text-foreground-muted">
                    <Circle
                        className={cn(
                            "h-2 w-2",
                            isConnected
                                ? "fill-success text-success"
                                : "fill-foreground-muted text-foreground-muted animate-pulse"
                        )}
                    />
                    <span>{isConnected ? "Connected" : "Connecting..."}</span>
                </div>
            </div>
        </div>
    );
}

/**
 * Conversation Item - Premium styled
 */
interface ConversationItemProps {
    connection: Connection;
    isSelected: boolean;
    isOnline: boolean;
    onClick: () => void;
}

function ConversationItem({ connection, isSelected, isOnline, onClick }: ConversationItemProps) {
    const rawName = connection.nickname || connection.connectedUser?.name || connection.connectedUser?.email || "Unknown";
    // Capitalize each word (handles names stored lowercase in DB)
    const userName = rawName.includes("@") ? rawName : rawName.replace(/\b\w/g, c => c.toUpperCase());
    const initials = userName
        .split(" ")
        .map((n: string) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2);

    const unreadCount = connection.unreadCount ?? 0;
    const lastMessage = connection.lastMessage;
    const lastMessageTime = lastMessage?.createdAt
        ? formatDistanceToNow(new Date(lastMessage.createdAt), {
            locale: enGB,
            addSuffix: false,
        })
        : "";

    // Determine last message preview
    let lastMessagePreview = "No messages";
    if (lastMessage) {
        const isEncrypted = (lastMessage as any).isEncrypted;
        if (isEncrypted) {
            lastMessagePreview = "Encrypted message";
        } else if (lastMessage.messageType === "text" && lastMessage.content) {
            lastMessagePreview = lastMessage.content.length > 35
                ? lastMessage.content.slice(0, 35) + "..."
                : lastMessage.content;
        } else {
            const typeLabels: Record<string, string> = {
                file: "File",
                image: "Image",
                video: "Video",
                vault_file: "Shared file",
                text: lastMessage.content || "Message",
            };
            lastMessagePreview = typeLabels[lastMessage.messageType] || "Message";
        }
    }

    return (
        <button
            onClick={onClick}
            className={cn(
                "w-full p-3 rounded-xl transition-all duration-200",
                "flex items-center gap-3 group relative overflow-hidden",
                isSelected ? [
                    "bg-primary/10",
                    "border border-primary/20",
                    "shadow-[0_0_20px_var(--glow)]"
                ] : [
                    "hover:bg-background-muted",
                    "border border-transparent"
                ]
            )}
        >
            {/* Shimmer on hover */}
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-primary/5 to-transparent translate-x-[-200%] group-hover:translate-x-[200%] transition-transform duration-700" />

            {/* Avatar with online status */}
            <div className="relative flex-shrink-0">
                <Avatar className={cn(
                    "h-12 w-12 rounded-xl",
                    "border-2 transition-all duration-200",
                    isSelected
                        ? "border-primary/30 shadow-[0_0_15px_var(--glow)]"
                        : "border-border group-hover:border-primary/20"
                )}>
                    <AvatarFallback className={cn(
                        "rounded-xl text-sm font-semibold",
                        "bg-gradient-to-br from-background-surface to-background-muted",
                        isSelected ? "text-primary" : "text-foreground"
                    )}>
                        {initials}
                    </AvatarFallback>
                </Avatar>
                {/* Online indicator */}
                {isOnline && (
                    <div className="absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 bg-success border-2 border-background rounded-full shadow-[0_0_8px_rgba(61,153,112,0.5)]" />
                )}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0 text-left">
                <div className="flex items-center justify-between mb-0.5">
                    <h3 className={cn(
                        "font-medium truncate transition-colors",
                        isSelected ? "text-primary" : "text-foreground"
                    )}>
                        {userName}
                    </h3>
                    {lastMessageTime && (
                        <span className="text-[10px] text-foreground-subtle ml-2 flex-shrink-0">
                            {lastMessageTime}
                        </span>
                    )}
                </div>

                <p className={cn(
                    "text-sm truncate",
                    unreadCount > 0 ? "text-foreground" : "text-foreground-muted"
                )}>
                    {lastMessagePreview}
                </p>
            </div>

            {/* Unread badge */}
            {unreadCount > 0 && (
                <Badge className={cn(
                    "bg-primary text-primary-foreground",
                    "border-0 px-2 py-0.5 text-xs font-bold",
                    "shadow-[0_0_10px_var(--glow)]"
                )}>
                    {unreadCount > 99 ? "99+" : unreadCount}
                </Badge>
            )}
        </button>
    );
}
