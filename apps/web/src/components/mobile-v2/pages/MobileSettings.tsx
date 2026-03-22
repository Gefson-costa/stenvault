/**
 * MobileSettings - Mobile-optimized Settings Page
 * 
 * Simple list-based settings interface.
 * Logic extracted to useMobileSettings hook for consistency with MobileDrive.
 */

import { ChevronRight } from "lucide-react";
import { motion } from "framer-motion";
import { PageTransition, StorageIndicator } from "@/components/mobile-v2";
import { useMobileSettings, type SettingsGroup } from "./hooks/useMobileSettings";
import { ChangeEmailDialog } from "@/components/settings/ChangeEmailDialog";
import { DeleteAccountDialog } from "@/components/settings/DeleteAccountDialog";
import type { SanitizedUser } from "@/types/user";

// ─────────────────────────────────────────────────────────────
// COMPONENT
// ─────────────────────────────────────────────────────────────

export function MobileSettings() {
    const {
        user,
        storageStats,
        theme,
        settingsGroups,
        handleNavigate,
        changeEmailOpen,
        setChangeEmailOpen,
        deleteAccountOpen,
        setDeleteAccountOpen,
    } = useMobileSettings();

    return (
        <PageTransition>
            <div style={{ minHeight: "100%" }}>
                {/* User Header */}
                <UserHeader user={user} theme={theme} />

                {/* Storage */}
                {storageStats && (
                    <StorageIndicator
                        used={storageStats.storageUsed}
                        total={storageStats.storageQuota}
                    />
                )}

                {/* Settings Groups */}
                {settingsGroups.map((group, groupIndex) => (
                    <SettingsGroupSection
                        key={group.title || `group-${groupIndex}`}
                        group={group}
                        theme={theme}
                        onNavigate={handleNavigate}
                    />
                ))}

                {/* Version Footer */}
                <p
                    style={{
                        fontSize: 11,
                        color: "var(--muted-foreground)",
                        textAlign: "center",
                        padding: "16px 0 32px",
                        margin: 0,
                    }}
                >
                    StenVault v2.0.0
                </p>
            </div>

            {/* Profile management dialogs */}
            <ChangeEmailDialog
                open={changeEmailOpen}
                onOpenChange={setChangeEmailOpen}
                currentEmail={user?.email || ""}
            />
            <DeleteAccountDialog
                open={deleteAccountOpen}
                onOpenChange={setDeleteAccountOpen}
            />
        </PageTransition>
    );
}

// ─────────────────────────────────────────────────────────────
// SUB-COMPONENTS
// ─────────────────────────────────────────────────────────────

interface UserHeaderProps {
    user: SanitizedUser | null;
    theme: { brand: { primary: string } };
}

function UserHeader({ user, theme }: UserHeaderProps) {
    return (
        <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            style={{
                display: "flex",
                alignItems: "center",
                gap: 16,
                padding: "24px 16px",
                borderBottom: "1px solid var(--border)",
            }}
        >
            {/* Avatar */}
            <div
                style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    width: 64,
                    height: 64,
                    borderRadius: 16,
                    backgroundColor: `${theme.brand.primary}15`,
                    fontSize: 24,
                    fontWeight: 600,
                    color: theme.brand.primary,
                }}
            >
                {user?.name?.charAt(0).toUpperCase() || "U"}
            </div>

            {/* Info */}
            <div style={{ flex: 1 }}>
                <h1
                    style={{
                        fontSize: 20,
                        fontWeight: 600,
                        color: "var(--foreground)",
                        margin: "0 0 4px",
                    }}
                >
                    {user?.name || "User"}
                </h1>
                <p
                    style={{
                        fontSize: 13,
                        color: "var(--muted-foreground)",
                        margin: 0,
                    }}
                >
                    {user?.email}
                </p>
            </div>
        </motion.div>
    );
}

interface SettingsGroupSectionProps {
    group: SettingsGroup;
    theme: { brand: { primary: string }; semantic: { error: string } };
    onNavigate: (path: string) => void;
}

function SettingsGroupSection({ group, theme, onNavigate }: SettingsGroupSectionProps) {
    return (
        <div>
            {group.title && (
                <p
                    style={{
                        fontSize: 12,
                        fontWeight: 600,
                        color: "var(--muted-foreground)",
                        padding: "16px 16px 8px",
                        margin: 0,
                        textTransform: "uppercase",
                        letterSpacing: "0.05em",
                    }}
                >
                    {group.title}
                </p>
            )}

            <div
                style={{
                    margin: "0 16px 16px",
                    backgroundColor: "var(--card)",
                    border: "1px solid var(--border)",
                    borderRadius: 16,
                    overflow: "hidden",
                }}
            >
                {group.items.map((item, itemIndex) => {
                    const Icon = item.icon;
                    const isLast = itemIndex === group.items.length - 1;

                    return (
                        <motion.button
                            key={item.id}
                            onClick={() => {
                                if (item.action) {
                                    item.action();
                                } else if (item.path) {
                                    onNavigate(item.path);
                                }
                            }}
                            whileTap={{ scale: 0.99 }}
                            style={{
                                display: "flex",
                                alignItems: "center",
                                gap: 12,
                                width: "100%",
                                padding: 16,
                                backgroundColor: "transparent",
                                border: "none",
                                borderBottom: isLast ? "none" : "1px solid var(--border)",
                                cursor: "pointer",
                                textAlign: "left",
                            }}
                        >
                            <div
                                style={{
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",
                                    width: 36,
                                    height: 36,
                                    borderRadius: 10,
                                    backgroundColor: item.danger
                                        ? `${theme.semantic.error}15`
                                        : "var(--muted)",
                                }}
                            >
                                <Icon
                                    size={18}
                                    style={{
                                        color: item.danger
                                            ? theme.semantic.error
                                            : "var(--foreground)",
                                    }}
                                />
                            </div>

                            <div style={{ flex: 1 }}>
                                <p
                                    style={{
                                        fontSize: 15,
                                        fontWeight: 500,
                                        color: item.danger
                                            ? theme.semantic.error
                                            : "var(--foreground)",
                                        margin: 0,
                                    }}
                                >
                                    {item.label}
                                </p>
                                {item.description && (
                                    <p
                                        style={{
                                            fontSize: 12,
                                            color: "var(--muted-foreground)",
                                            margin: "2px 0 0",
                                        }}
                                    >
                                        {item.description}
                                    </p>
                                )}
                            </div>

                            {!item.danger && (
                                <ChevronRight
                                    size={18}
                                    style={{ color: "var(--muted-foreground)" }}
                                />
                            )}
                        </motion.button>
                    );
                })}
            </div>
        </div>
    );
}

export default MobileSettings;
