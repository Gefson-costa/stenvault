/**
 * ═══════════════════════════════════════════════════════════════
 * DASHBOARD LAYOUT - NOCTURNE DESIGN SYSTEM
 * ═══════════════════════════════════════════════════════════════
 *
 * Premium responsive layout with mobile-first approach.
 * Features luxurious gold accents and refined micro-interactions.
 *
 * Renders different layouts based on device:
 * - Mobile: Uses MobileLayout with bottom navigation
 * - Desktop: Uses traditional sidebar layout with premium styling
 *
 * ═══════════════════════════════════════════════════════════════
 */

import { useAuth } from "@/_core/hooks/useAuth";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  useSidebar,
} from "@/components/ui/sidebar";
import { useIsMobile } from "@/hooks/useMobile";
import { LogOut, PanelLeft, Home, Settings, HardDrive, Share2, Shield, MessageCircle, Network, Trash2, Star, Send } from "lucide-react";
import { CSSProperties, useEffect, useRef, useState } from "react";
import { useLocation } from "wouter";
import { Button } from "./ui/button";
import { EmailVerificationProvider, EmailVerificationBanner, useEmailVerificationContext } from "./email-verification";
import { CommandPalette } from "./CommandPalette";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";
import { BackgroundOperationsPanel } from "@/components/BackgroundOperationsPanel";
import { MobileShell } from "./mobile-v2";
import { ThemeSwitcher } from "./ui/theme-switcher";
import { useTheme } from "@/contexts/ThemeContext";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { trpc } from "@/lib/trpc";
import { VaultStatusIndicator } from "@/components/VaultStatusIndicator";
import { VaultUnlockModal } from "@/components/VaultUnlockModal";
import { useMasterKey } from "@/hooks/useMasterKey";
import { toast } from "sonner";
import { AlertTriangle, CreditCard, Clock, Users } from "lucide-react";
import { formatBytes } from "@stenvault/shared";
import { useBeforeUnloadWarning } from "@/stores/operationStore";

// Menu items configuration
// Note: Some items are conditionally shown based on feature flags
// Two groups: primary (core) and secondary (everything else)
const menuGroups = [
  // Primary — core navigation
  [
    { icon: Home, label: "Home", path: "/home" },
    { icon: HardDrive, label: "Drive", path: "/drive" },
    { icon: Star, label: "Favorites", path: "/favorites" },
  ],
  // Secondary — collaboration & utility (Quantum Mesh injected dynamically)
  [
    { icon: Share2, label: "Shares", path: "/shares" },
    { icon: MessageCircle, label: "Private Chat", path: "/chat" },
    { icon: Trash2, label: "Trash", path: "/trash" },
    { icon: Send, label: "Sent", path: "/sends" },
    { icon: Settings, label: "Settings", path: "/settings" },
  ],
];

// Flat list for lookups (page title, etc.)
const baseMenuItems = menuGroups.flat();

// Feature-gated menu items (added dynamically)
const quantumMeshItem = { icon: Network, label: "Quantum Mesh", path: "/quantum-mesh" };

// Sidebar width configuration
const SIDEBAR_WIDTH_KEY = "sidebar-width";
const DEFAULT_WIDTH = 280;
const MIN_WIDTH = 200;
const MAX_WIDTH = 480;

// Get page title from location
function getPageTitle(location: string): string {
  const allItems = [...baseMenuItems, quantumMeshItem];
  const menuItem = allItems.find(item => item.path === location);
  return menuItem?.label || "StenVault";
}

// Email verification notice component
function EmailVerificationNotice({ user }: { user: { email: string; emailVerified?: Date | null } | null }) {
  const { openModal } = useEmailVerificationContext();

  if (!user || user.emailVerified) {
    return null;
  }

  return (
    <EmailVerificationBanner
      email={user.email}
      onVerifyClick={openModal}
    />
  );
}

// Subscription status banner
function SubscriptionBanner() {
  const { data: subscription } = trpc.stripe.getSubscription.useQuery(undefined, {
    staleTime: 60000,
  });
  const { data: storageStats } = trpc.files.getStorageStats.useQuery(undefined, {
    staleTime: 60000,
  });
  const [quotaDismissed, setQuotaDismissed] = useState(false);

  if (!subscription || subscription.isAdmin) return null;

  // Trial ending soon (3 days or less)
  if (subscription.status === 'trialing' && subscription.trialEndsAt) {
    const daysLeft = Math.max(0, Math.ceil(
      (new Date(subscription.trialEndsAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
    ));
    if (daysLeft <= 3) {
      return (
        <div className="bg-blue-50 dark:bg-blue-950/30 border-b border-blue-200 dark:border-blue-800 px-4 py-2.5 flex items-center gap-2 text-sm text-blue-700 dark:text-blue-300">
          <Clock className="h-4 w-4 shrink-0" />
          <span>Your trial ends in <strong>{daysLeft} day{daysLeft !== 1 ? 's' : ''}</strong>. <a href="/settings?tab=subscription" className="underline hover:no-underline font-medium">Add a payment method</a> to keep your features.</span>
        </div>
      );
    }
  }

  // Payment failed — grace period (full access)
  if (subscription.accessLevel === 'full' && subscription.status === 'past_due') {
    return (
      <div className="bg-amber-50 dark:bg-amber-950/30 border-b border-amber-200 dark:border-amber-800 px-4 py-2.5 flex items-center gap-2 text-sm text-amber-700 dark:text-amber-300">
        <CreditCard className="h-4 w-4 shrink-0" />
        <span>Payment failed. <a href="/settings?tab=subscription" className="underline hover:no-underline font-medium">Update your billing info</a> to keep your features.</span>
      </div>
    );
  }

  // Read-only mode
  if (subscription.accessLevel === 'read_only') {
    return (
      <div className="bg-orange-50 dark:bg-orange-950/30 border-b border-orange-200 dark:border-orange-800 px-4 py-2.5 flex items-center gap-2 text-sm text-orange-700 dark:text-orange-300">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>Your account is in <strong>read-only mode</strong>. Uploads are blocked. <a href="/settings?tab=subscription" className="underline hover:no-underline font-medium">Update payment</a> to restore uploads.</span>
      </div>
    );
  }

  // Active dispute
  if (subscription.hasActiveDispute) {
    return (
      <div className="bg-red-50 dark:bg-red-950/30 border-b border-red-200 dark:border-red-800 px-4 py-2.5 flex items-center gap-2 text-sm text-red-700 dark:text-red-300">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>Your account has an active payment dispute. Contact support if you did not initiate this.</span>
      </div>
    );
  }

  // Suspended
  if (subscription.accessLevel === 'suspended') {
    return (
      <div className="bg-red-50 dark:bg-red-950/30 border-b border-red-200 dark:border-red-800 px-4 py-2.5 flex items-center gap-2 text-sm text-red-700 dark:text-red-300">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>Your account is <strong>suspended</strong>. <a href="/settings?tab=subscription" className="underline hover:no-underline font-medium">Update payment immediately</a> to restore access.</span>
      </div>
    );
  }

  // Proactive storage quota warning (80% / 90%)
  if (!quotaDismissed && storageStats && storageStats.storageQuota > 0 && !subscription.overQuota) {
    const pct = storageStats.storageUsed / storageStats.storageQuota;
    const used = formatBytes(storageStats.storageUsed);
    const total = formatBytes(storageStats.storageQuota);
    const pctLabel = Math.round(pct * 100);
    if (pct >= 0.95) {
      return (
        <div className="bg-red-50 dark:bg-red-950/30 border-b border-red-200 dark:border-red-800 px-4 py-2.5 flex items-center gap-2 text-sm text-red-700 dark:text-red-300">
          <HardDrive className="h-4 w-4 shrink-0" />
          <span className="flex-1">Storage almost full: <strong>{used} / {total} ({pctLabel}%)</strong> — <a href="/drive" className="underline hover:no-underline font-medium">delete files</a> or <a href="/pricing" className="underline hover:no-underline font-medium">upgrade immediately</a>.</span>
          <button onClick={() => setQuotaDismissed(true)} className="text-red-400 hover:text-red-600 dark:hover:text-red-200 shrink-0 p-0.5" aria-label="Dismiss">✕</button>
        </div>
      );
    }
    if (pct >= 0.9) {
      return (
        <div className="bg-orange-50 dark:bg-orange-950/30 border-b border-orange-200 dark:border-orange-800 px-4 py-2.5 flex items-center gap-2 text-sm text-orange-700 dark:text-orange-300">
          <HardDrive className="h-4 w-4 shrink-0" />
          <span className="flex-1">Storage: <strong>{used} / {total} ({pctLabel}%)</strong>. <a href="/pricing" className="underline hover:no-underline font-medium">Upgrade</a> to avoid upload failures.</span>
          <button onClick={() => setQuotaDismissed(true)} className="text-orange-400 hover:text-orange-600 dark:hover:text-orange-200 shrink-0 p-0.5" aria-label="Dismiss">✕</button>
        </div>
      );
    }
    if (pct >= 0.8) {
      return (
        <div className="bg-amber-50 dark:bg-amber-950/30 border-b border-amber-200 dark:border-amber-800 px-4 py-2.5 flex items-center gap-2 text-sm text-amber-700 dark:text-amber-300">
          <HardDrive className="h-4 w-4 shrink-0" />
          <span className="flex-1">Storage: <strong>{used} / {total} ({pctLabel}%)</strong>. <a href="/pricing" className="underline hover:no-underline font-medium">Upgrade to Pro</a> for more space.</span>
          <button onClick={() => setQuotaDismissed(true)} className="text-amber-400 hover:text-amber-600 dark:hover:text-amber-200 shrink-0 p-0.5" aria-label="Dismiss">✕</button>
        </div>
      );
    }
  }

  // Over quota
  if (subscription.overQuota) {
    const overUsed = storageStats ? formatBytes(storageStats.storageUsed) : '';
    const overTotal = storageStats ? formatBytes(storageStats.storageQuota) : '';
    const overLabel = storageStats && storageStats.storageQuota > 0
      ? ` (${overUsed} / ${overTotal})`
      : '';
    return (
      <div className="bg-amber-50 dark:bg-amber-950/30 border-b border-amber-200 dark:border-amber-800 px-4 py-2.5 flex items-center gap-2 text-sm text-amber-700 dark:text-amber-300">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>You've exceeded your storage quota{overLabel}. <a href="/drive" className="underline hover:no-underline font-medium">Delete files</a> or <a href="/pricing" className="underline hover:no-underline font-medium">upgrade</a> to continue uploading.</span>
      </div>
    );
  }

  return null;
}

// Recovery request banner for trusted contacts
function RecoveryRequestBanner() {
  const { data } = trpc.shamirRecovery.getPendingRecoveryRequests.useQuery(undefined, {
    staleTime: 60000,
  });
  const [, setLocation] = useLocation();
  const [dismissed, setDismissed] = useState(false);

  if (dismissed) return null;

  const actionable = data?.requests?.filter((r: { canReleaseNow: boolean }) => r.canReleaseNow) ?? [];
  if (actionable.length === 0) return null;

  const first = actionable[0] as { ownerName: string | null; ownerEmail: string };
  const label = first.ownerName || first.ownerEmail;

  return (
    <div className="bg-amber-50 dark:bg-amber-950/30 border-b border-amber-200 dark:border-amber-800 px-4 py-2.5 flex items-center gap-2 text-sm text-amber-700 dark:text-amber-300">
      <Users className="h-4 w-4 shrink-0" />
      <span className="flex-1">
        <strong>{label}</strong> needs your recovery share{actionable.length > 1 ? ` (+${actionable.length - 1} more)` : ""}.{" "}
        <button onClick={() => setLocation("/settings?tab=security")} className="underline hover:no-underline font-medium">
          Go to Security
        </button>
      </span>
      <button onClick={() => setDismissed(true)} className="text-amber-400 hover:text-amber-600 dark:hover:text-amber-200 shrink-0 p-0.5" aria-label="Dismiss">
        &#x2715;
      </button>
    </div>
  );
}

// Desktop layout content props
type DesktopLayoutContentProps = {
  children: React.ReactNode;
  setSidebarWidth: (width: number) => void;
};

// Desktop sidebar layout content
function DesktopLayoutContent({
  children,
  setSidebarWidth,
}: DesktopLayoutContentProps) {
  const { user, logout } = useAuth();
  const { theme } = useTheme();
  const [location, setLocation] = useLocation();
  const { state, toggleSidebar } = useSidebar();
  const isCollapsed = state === "collapsed";
  const [isResizing, setIsResizing] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const sidebarRef = useRef<HTMLDivElement>(null);
  const [unlockModalOpen, setUnlockModalOpen] = useState(false);
  const { isUnlocked: vaultUnlocked, clearCache: lockVault } = useMasterKey();
  useBeforeUnloadWarning();

  // Check if P2P feature is enabled (server-side toggle)
  const { data: p2pEnabled } = trpc.p2p.isEnabled.useQuery(undefined, {
    staleTime: 60000,
  });

  // Check if user's plan includes P2P
  const { data: subscription } = trpc.stripe.getSubscription.useQuery(undefined, {
    staleTime: 60000,
  });
  const hasPlanP2P = subscription?.isAdmin || subscription?.features?.p2pQuantumMesh === true;

  // Build grouped menu items based on feature flags + plan
  const resolvedGroups = menuGroups.map((group, i) => {
    // Inject Quantum Mesh only if server-enabled AND plan allows it
    if (i === 1 && p2pEnabled && hasPlanP2P) return [...group, quantumMeshItem];
    return group;
  });

  // Global keyboard shortcuts
  useKeyboardShortcuts({
    onSearch: () => setCommandPaletteOpen(true),
    onEscape: () => setCommandPaletteOpen(false),
    onUpload: () => setLocation('/drive'),
  });

  useEffect(() => {
    if (isCollapsed) {
      setIsResizing(false);
    }
  }, [isCollapsed]);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing) return;

      const sidebarLeft = sidebarRef.current?.getBoundingClientRect().left ?? 0;
      const newWidth = e.clientX - sidebarLeft;
      if (newWidth >= MIN_WIDTH && newWidth <= MAX_WIDTH) {
        setSidebarWidth(newWidth);
      }
    };

    const handleMouseUp = () => {
      setIsResizing(false);
    };

    if (isResizing) {
      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
    }

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [isResizing, setSidebarWidth]);

  return (
    <>
      {/* Command Palette - Ctrl+K */}
      <CommandPalette
        open={commandPaletteOpen}
        onOpenChange={setCommandPaletteOpen}
      />

      <div className="relative" ref={sidebarRef}>
        <Sidebar
          collapsible="icon"
          className="border-r border-[rgba(212,175,55,0.08)]"
          disableTransition={isResizing}
        >
          <SidebarHeader className="h-16 justify-center border-b border-[rgba(212,175,55,0.08)]">
            <div className="flex items-center gap-3 px-3 transition-all w-full group-data-[collapsible=icon]:px-0 group-data-[collapsible=icon]:justify-center">
              {/* Premium toggle button with gold hover */}
              <button
                onClick={toggleSidebar}
                className="h-8 w-8 flex items-center justify-center rounded-lg transition-all duration-200 focus:outline-none shrink-0 text-[var(--nocturne-400)] hover:text-[var(--gold-400)] hover:bg-[rgba(212,175,55,0.1)] hover:shadow-[0_0_15px_rgba(212,175,55,0.1)]"
                aria-label="Toggle navigation"
              >
                <PanelLeft className="h-4 w-4" />
              </button>
              {!isCollapsed ? (
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="h-7 w-7 rounded-lg bg-gradient-to-br from-[var(--gold-500)] to-[var(--gold-600)] flex items-center justify-center shadow-[0_0_20px_rgba(212,175,55,0.25)]">
                    <Shield className="h-3.5 w-3.5 text-[var(--nocturne-950)]" />
                  </div>
                  {/* Premium gradient text */}
                  <span className="font-display font-semibold tracking-tight text-lg truncate bg-clip-text text-transparent bg-gradient-to-r from-[var(--gold-300)] via-[var(--gold-400)] to-[var(--gold-500)]">
                    StenVault
                  </span>
                </div>
              ) : null}
            </div>
          </SidebarHeader>

          <SidebarContent className="gap-0 px-3 py-2">
            <SidebarMenu>
              {resolvedGroups.map((group, groupIndex) => {
                const isSecondary = groupIndex > 0;
                return (
                <div key={groupIndex}>
                  {/* Gold separator between groups */}
                  {groupIndex > 0 && (
                    <div className="my-1.5 px-2">
                      <div className="h-px bg-gradient-to-r from-transparent via-[rgba(212,175,55,0.15)] to-transparent" />
                    </div>
                  )}
                  {group.map(item => {
                    const isActive = location === item.path;
                    return (
                      <SidebarMenuItem key={item.path} className="mb-0.5">
                        <div className="relative">
                          <SidebarMenuButton
                            isActive={isActive}
                            onClick={() => setLocation(item.path)}
                            tooltip={item.label}
                            className={cn(
                              "transition-all duration-200 font-medium rounded-lg relative z-20 overflow-hidden",
                              isSecondary ? "h-9" : "h-10",
                              isActive
                                ? "hover:bg-transparent"
                                : isSecondary
                                  ? "text-[var(--nocturne-400)] hover:text-[var(--gold-300)] hover:bg-[rgba(212,175,55,0.08)]"
                                  : "text-[var(--nocturne-300)] hover:text-[var(--gold-300)] hover:bg-[rgba(212,175,55,0.08)]"
                            )}
                          >
                            <item.icon
                              aria-hidden="true"
                              className={cn(
                                "transition-colors duration-200 z-20 relative",
                                isSecondary ? "h-3.5 w-3.5" : "h-4 w-4",
                                isActive ? "text-[var(--gold-400)]" : isSecondary ? "text-[var(--nocturne-500)]" : "text-[var(--nocturne-400)]"
                              )}
                            />
                            <span className={cn(
                              "z-20 relative transition-colors duration-200",
                              isSecondary && "text-[0.8125rem]",
                              isActive ? "text-[var(--gold-300)]" : ""
                            )}>
                              {item.label}
                            </span>

                            {/* Nocturne Gold Active Pill */}
                            {isActive && (
                              <motion.div
                                layoutId="sidebar-active-pill"
                                className="absolute inset-0 z-10 rounded-lg overflow-hidden"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                                transition={{ type: "spring", stiffness: 400, damping: 35 }}
                              >
                                {/* Gold gradient background */}
                                <div className="absolute inset-0 bg-gradient-to-r from-[rgba(212,175,55,0.12)] via-[rgba(212,175,55,0.08)] to-[rgba(212,175,55,0.12)]" />
                                {/* Gold left indicator bar */}
                                <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-[60%] bg-gradient-to-b from-[var(--gold-400)] via-[var(--gold-500)] to-[var(--gold-400)] rounded-full shadow-[0_0_8px_rgba(212,175,55,0.5)]" />
                                {/* Subtle inner border */}
                                <div className="absolute inset-0 border border-[rgba(212,175,55,0.15)] rounded-lg" />
                                {/* Ambient glow */}
                                <div className="absolute inset-0 shadow-[inset_0_0_20px_rgba(212,175,55,0.05)]" />
                              </motion.div>
                            )}
                          </SidebarMenuButton>
                        </div>
                      </SidebarMenuItem>
                    );
                  })}
                </div>
                );
              })}

              {/* Premium Admin Panel Link */}
              {user?.role === "admin" && (
                <>
                  {/* Gold-tinted divider */}
                  <div className="my-3 px-2">
                    <div className="h-px bg-gradient-to-r from-transparent via-[rgba(212,175,55,0.2)] to-transparent" />
                  </div>
                  <SidebarMenuItem className="mb-8">
                    <div className="relative">
                      <SidebarMenuButton
                        isActive={location === "/admin"}
                        onClick={() => setLocation("/admin")}
                        tooltip="Admin Panel"
                        className={cn(
                          "h-10 transition-all duration-200 font-medium rounded-lg relative z-20",
                          location === "/admin"
                            ? "hover:bg-transparent"
                            : "text-[var(--nocturne-300)] hover:text-[var(--gold-300)] hover:bg-[rgba(212,175,55,0.08)]"
                        )}
                      >
                        <Shield
                          aria-hidden="true"
                          className={cn(
                            "h-4 w-4 transition-colors duration-200 z-20 relative",
                            location === "/admin" ? "text-[var(--gold-400)]" : "text-[var(--nocturne-400)]"
                          )}
                        />
                        <span className={cn(
                          "z-20 relative transition-colors duration-200",
                          location === "/admin" ? "text-[var(--gold-300)]" : ""
                        )}>
                          Admin Panel
                        </span>
                        {/* Nocturne Gold Active Pill for Admin */}
                        {location === "/admin" && (
                          <motion.div
                            layoutId="sidebar-active-pill"
                            className="absolute inset-0 z-10 rounded-lg overflow-hidden"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            transition={{ type: "spring", stiffness: 400, damping: 35 }}
                          >
                            <div className="absolute inset-0 bg-gradient-to-r from-[rgba(212,175,55,0.12)] via-[rgba(212,175,55,0.08)] to-[rgba(212,175,55,0.12)]" />
                            <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-[60%] bg-gradient-to-b from-[var(--gold-400)] via-[var(--gold-500)] to-[var(--gold-400)] rounded-full shadow-[0_0_8px_rgba(212,175,55,0.5)]" />
                            <div className="absolute inset-0 border border-[rgba(212,175,55,0.15)] rounded-lg" />
                          </motion.div>
                        )}
                      </SidebarMenuButton>
                    </div>
                  </SidebarMenuItem>
                </>
              )}
            </SidebarMenu>
          </SidebarContent>

          <SidebarFooter className="p-3 border-t border-[rgba(212,175,55,0.08)]">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="flex items-center gap-3 rounded-lg px-2 py-2 transition-all duration-200 w-full text-left group-data-[collapsible=icon]:justify-center focus:outline-none focus-visible:ring-2 focus-visible:ring-[rgba(212,175,55,0.4)] hover:bg-[rgba(212,175,55,0.06)] group/user">
                  {/* Premium avatar with gold ring on hover */}
                  <Avatar className="h-9 w-9 shrink-0 rounded-lg border border-[rgba(212,175,55,0.15)] group-hover/user:border-[rgba(212,175,55,0.3)] transition-colors duration-200 shadow-[0_0_0_0_rgba(212,175,55,0)] group-hover/user:shadow-[0_0_12px_rgba(212,175,55,0.15)]">
                    <AvatarFallback className="text-xs font-semibold rounded-lg bg-gradient-to-br from-[var(--nocturne-700)] to-[var(--nocturne-800)] text-[var(--gold-400)]">
                      {user?.name?.charAt(0).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex-1 min-w-0 group-data-[collapsible=icon]:hidden">
                    <p className="text-sm font-medium truncate leading-none text-[var(--nocturne-100)] group-hover/user:text-[var(--gold-300)] transition-colors duration-200">
                      {user?.name || "-"}
                    </p>
                    <p className="text-xs text-[var(--nocturne-400)] truncate mt-1.5">
                      {user?.email || "-"}
                    </p>
                  </div>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48 rounded-lg border-[rgba(212,175,55,0.15)] bg-[var(--nocturne-900)]">
                <DropdownMenuItem
                  onClick={logout}
                  className="cursor-pointer text-[var(--burgundy-400)] focus:text-[var(--burgundy-300)] focus:bg-[rgba(199,80,80,0.1)] rounded-md transition-colors"
                >
                  <LogOut className="mr-2 h-4 w-4" />
                  <span>Sign out</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            {/* Theme Switcher */}
            <div className="mt-2 group-data-[collapsible=icon]:hidden">
              <ThemeSwitcher variant="minimal" align="start" className="w-full justify-start text-[var(--nocturne-300)] hover:text-[var(--gold-400)] hover:bg-[rgba(212,175,55,0.08)] rounded-lg transition-all duration-200" />
            </div>

            {/* Vault Status Indicator (Phase 1.1 NEW_DAY) */}
            <div className="mt-2 px-2 group-data-[collapsible=icon]:px-0 group-data-[collapsible=icon]:flex group-data-[collapsible=icon]:justify-center">
              <VaultStatusIndicator
                showLabel={!isCollapsed}
                size="md"
                onClick={() => {
                  if (vaultUnlocked) {
                    lockVault();
                    toast.info('Vault locked', { description: 'Your encryption keys have been cleared from memory.' });
                  } else {
                    setUnlockModalOpen(true);
                  }
                }}
              />
            </div>
          </SidebarFooter>
        </Sidebar>
        {/* Premium resize handle with gold glow */}
        <div
          className={cn(
            "absolute top-0 right-0 w-1 h-full cursor-col-resize transition-all duration-200",
            "hover:bg-[rgba(212,175,55,0.3)] hover:shadow-[0_0_8px_rgba(212,175,55,0.3)]",
            isCollapsed && "hidden"
          )}
          onMouseDown={() => {
            if (isCollapsed) return;
            setIsResizing(true);
          }}
          style={{ zIndex: 50 }}
        />
      </div>

      <SidebarInset className="min-h-0 overflow-hidden">
        {/* Email Verification Banner */}
        <EmailVerificationNotice user={user} />
        {/* Subscription Status Banner */}
        <SubscriptionBanner />
        {/* Recovery Request Banner for Trusted Contacts */}
        <RecoveryRequestBanner />

        <main className="flex-1 p-4 min-h-0 overflow-auto relative">{children}</main>
      </SidebarInset>

      {/* Vault Unlock Modal (Phase 1.1 NEW_DAY) */}
      <VaultUnlockModal
        isOpen={unlockModalOpen}
        onUnlock={() => setUnlockModalOpen(false)}
        onClose={() => setUnlockModalOpen(false)}
        onForgotPassword={() => {
          setUnlockModalOpen(false);
          setLocation('/auth/recovery-code-reset');
        }}
      />

    </>
  );
}

// Main DashboardLayout component
export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    const saved = localStorage.getItem(SIDEBAR_WIDTH_KEY);
    return saved ? parseInt(saved, 10) : DEFAULT_WIDTH;
  });
  const { user } = useAuth();
  const isMobile = useIsMobile();
  const [location, setLocation] = useLocation();

  useEffect(() => {
    localStorage.setItem(SIDEBAR_WIDTH_KEY, sidebarWidth.toString());
  }, [sidebarWidth]);

  // Handle FAB click - navigate to drive for upload
  const handleUpload = () => {
    setLocation('/drive?action=upload');
  };

  // Handle new folder click
  const handleNewFolder = () => {
    setLocation('/drive?action=new-folder');
  };

  // Mobile Layout - New V2 shell with simplified architecture
  if (isMobile) {
    return (
      <>
        <MobileShell
          title={getPageTitle(location)}
          onUpload={handleUpload}
          onNewFolder={handleNewFolder}
        >
          <EmailVerificationNotice user={user} />
          <SubscriptionBanner />
          <RecoveryRequestBanner />
          {children}
        </MobileShell>
        <BackgroundOperationsPanel />
      </>
    );
  }

  // Desktop Layout - existing sidebar layout
  return (
    <>
      <SidebarProvider
        style={
          {
            "--sidebar-width": `${sidebarWidth}px`,
          } as CSSProperties
        }
      >
        <DesktopLayoutContent setSidebarWidth={setSidebarWidth}>
          {children}
        </DesktopLayoutContent>
      </SidebarProvider>
      <BackgroundOperationsPanel />
    </>
  );
}
