/**
 * Chat Page
 *
 * Displays chat with premium redesigned UI.
 * Uses MobileChat for mobile devices.
 */
import { ChatLayout } from "@/components/chat/ChatLayout";
import { MobileChat } from "@/components/mobile-v2/pages/MobileChat";
import { useIsMobile } from "@/hooks/useMobile";
import { useChatFileShareEvents } from "@/hooks/useChatFileShareEvents";
import "@/components/chat/chat-animations.css";

export function Chat() {
    const isMobile = useIsMobile();

    // Listen for file share events (revoke, new shares)
    useChatFileShareEvents();

    // Mobile: Use dedicated MobileChat component
    if (isMobile) {
        return <MobileChat />;
    }

    // Desktop: Use original ChatLayout
    // Absolute positioning fills the parent container edge-to-edge,
    // bypassing the p-4 from DashboardLayout without margin hacks
    return (
        <div className="absolute inset-0 overflow-hidden">
            <ChatLayout />
        </div>
    );
}

export default Chat;
