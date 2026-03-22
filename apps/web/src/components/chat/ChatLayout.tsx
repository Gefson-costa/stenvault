/**
 * ═══════════════════════════════════════════════════════════════
 * CHAT LAYOUT - NOCTURNE DESIGN SYSTEM
 * ═══════════════════════════════════════════════════════════════
 *
 * Premium chat container with luxurious ambient lighting,
 * refined glassmorphism sidebar, and sophisticated depth.
 * Designed for exclusive private messaging experience.
 *
 * ═══════════════════════════════════════════════════════════════
 */

import { useState, useEffect, useMemo } from "react";
import { ChatSidebar } from "./ChatSidebar";
import { ChatMain } from "./ChatMain";
import { AcceptInviteModal } from "./AcceptInviteModal";
import { StartChatModal } from "./StartChatModal";
import { cn } from "@/lib/utils";
import { useWebSocket } from "@/hooks/useWebSocket";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";

import type { Connection } from "../mobile-v2/pages/types";
export type { Connection };


/**
 * Chat Layout - Premium Nocturne Container
 *
 * Features:
 * - Luxurious ambient gold glow spots
 * - Premium depth gradient background
 * - Glass-effect sidebar with gold accents
 * - Smooth, refined transitions
 */
export function ChatLayout() {
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [showAcceptInviteModal, setShowAcceptInviteModal] = useState(false);
  const [showStartChatModal, setShowStartChatModal] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState<Set<number>>(new Set());

  const { isConnected, onPresenceUpdate, checkPresence, onChatInvite, onInviteAccepted } = useWebSocket();

  // Fetch connections via tRPC
  const utils = trpc.useUtils();
  const { data: connectionsData, isLoading: isLoadingConnections } = trpc.chat.getMyConnections.useQuery(undefined, {
    refetchOnWindowFocus: false,
  });

  // Filter only accepted connections
  // useMemo stabilizes the reference: without it, .filter().map() creates a new array
  // every render, causing the useEffect below to loop infinitely.
  const connections = useMemo(() => (connectionsData?.connections ?? [])
    .filter(conn => conn.status === 'accepted')
    .map(conn => ({
      id: conn.id,
      userId: conn.userId,
      connectedUserId: conn.connectedUserId,
      nickname: conn.nickname,
      status: conn.status,
      createdAt: conn.createdAt instanceof Date ? conn.createdAt.toISOString() : String(conn.createdAt),
      updatedAt: conn.updatedAt instanceof Date ? conn.updatedAt.toISOString() : String(conn.updatedAt),
      connectedUser: conn.connectedUserEmail ? {
        id: conn.connectedUserId,
        name: conn.connectedUserName,
        email: conn.connectedUserEmail,
      } : undefined,
      lastMessage: conn.lastMessage ?? undefined,
      unreadCount: conn.unreadCount ?? 0,
    })), [connectionsData?.connections]);

  // Refetch connections function
  const fetchConnections = () => {
    utils.chat.getMyConnections.invalidate();
  };

  // Check presence of all connections on mount
  useEffect(() => {
    if (connections && isConnected) {
      const userIds = connections.map((conn) => conn.connectedUserId);
      checkPresence(userIds);
    }
  }, [connections, isConnected, checkPresence]);

  // Listen for presence updates
  useEffect(() => {
    onPresenceUpdate((update) => {
      setOnlineUsers((prev) => {
        const next = new Set(prev);
        if (update.isOnline) {
          next.add(update.userId);
        } else {
          next.delete(update.userId);
        }
        return next;
      });
    });
  }, [onPresenceUpdate]);

  // Listen for chat invite events (NEW - Signal-style)
  useEffect(() => {
    onChatInvite((event) => {
      toast.info(`${event.from.name || event.from.email} wants to chat`, {
        description: "You have a new chat invite",
        action: {
          label: "View",
          onClick: () => setShowAcceptInviteModal(true),
        },
        duration: 10000,
      });
    });

    onInviteAccepted((event) => {
      toast.success(`${event.userName} accepted your invite!`, {
        description: "You can now start chatting",
        duration: 5000,
      });
      // Refresh connections to show new contact
      fetchConnections();
    });
  }, [onChatInvite, onInviteAccepted]);

  return (
    <div className="relative h-full w-full overflow-hidden bg-background">
      {/* ═══════════ PREMIUM AMBIENT BACKGROUND ═══════════ */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {/* Base gradient - uses semantic tokens */}
        <div className="absolute inset-0 bg-gradient-to-b from-background via-background-elevated to-background" />

        {/* Primary ambient glow - Top right */}
        <div
          className="absolute -top-32 -right-32 w-[600px] h-[600px] rounded-full opacity-[0.06]"
          style={{
            background: "radial-gradient(circle, hsl(var(--primary)) 0%, transparent 70%)",
          }}
        />

        {/* Primary ambient glow - Bottom left */}
        <div
          className="absolute -bottom-48 -left-48 w-[500px] h-[500px] rounded-full opacity-[0.04]"
          style={{
            background: "radial-gradient(circle, hsl(var(--primary)) 0%, transparent 70%)",
          }}
        />

        {/* Subtle accent glow - Center */}
        <div
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full opacity-[0.02]"
          style={{
            background: "radial-gradient(ellipse, hsl(var(--primary)) 0%, transparent 60%)",
          }}
        />

        {/* Noise texture overlay */}
        <div
          className="absolute inset-0 opacity-[0.015]"
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 400 400' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E")`,
          }}
        />
      </div>

      {/* ═══════════ MAIN GRID LAYOUT ═══════════ */}
      <div className="relative h-full grid grid-cols-1 lg:grid-cols-[380px_1fr] gap-0">
        {/* Sidebar - Premium Glass Effect */}
        <aside
          className={cn(
            "relative h-full",
            // Glass effect - uses semantic tokens
            "bg-background-elevated/70 backdrop-blur-2xl backdrop-saturate-[180%]",
            // Premium border with primary tint
            "border-r border-primary/10",
            // Mobile: absolute overlay
            "absolute lg:relative inset-y-0 left-0 z-40 w-full max-w-sm lg:max-w-none",
            "transform transition-all duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]",
            isMobileMenuOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
          )}
        >
          {/* Sidebar inner glow */}
          <div className="absolute inset-0 pointer-events-none">
            <div className="absolute inset-y-0 right-0 w-px bg-gradient-to-b from-transparent via-primary/15 to-transparent" />
            <div className="absolute inset-x-0 top-0 h-32 bg-gradient-to-b from-primary/5 to-transparent" />
          </div>

          <ChatSidebar
            connections={(connections as unknown as Connection[]) || []}
            selectedUserId={selectedUserId}
            onlineUsers={onlineUsers}
            isConnected={isConnected}
            onSelectUser={(userId) => {
              setSelectedUserId(userId);
              setIsMobileMenuOpen(false);
            }}
            onClose={() => setIsMobileMenuOpen(false)}
            onCreateInvite={() => setShowStartChatModal(true)}
            onAcceptInvite={() => setShowAcceptInviteModal(true)}
          />
        </aside>

        {/* Main Chat Area */}
        <main className="relative h-full overflow-hidden">
          {/* Main area subtle gradient - uses semantic tokens */}
          <div className="absolute inset-0 bg-gradient-to-br from-transparent via-transparent to-primary/[0.02] pointer-events-none" />

          <ChatMain
            selectedUserId={selectedUserId}
            onOpenMenu={() => setIsMobileMenuOpen(true)}
            onCreateInvite={() => setShowStartChatModal(true)}
          />
        </main>
      </div>

      {/* ═══════════ MOBILE OVERLAY ═══════════ */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className={cn(
              "fixed inset-0 z-30 lg:hidden",
              "bg-background/70 backdrop-blur-sm"
            )}
            onClick={() => setIsMobileMenuOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* ═══════════ MODALS ═══════════ */}

      {/* Start Chat Modal (Discovery) */}
      <StartChatModal
        open={showStartChatModal}
        onOpenChange={(open) => {
          setShowStartChatModal(open);
          if (!open) fetchConnections();
        }}
      />

      {/* Accept Invite Modal (Pending Invites List) */}
      {showAcceptInviteModal && (
        <AcceptInviteModal
          isOpen={showAcceptInviteModal}
          onClose={() => {
            setShowAcceptInviteModal(false);
            fetchConnections();
          }}
        />
      )}
    </div>
  );
}
