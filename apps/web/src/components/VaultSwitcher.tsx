/**
 * VaultSwitcher - Desktop sidebar context switcher
 *
 * Allows switching between personal vault and organization vaults.
 * Sits between the sidebar header and navigation menu.
 * Only renders when the user belongs to at least one organization.
 */

import { useState } from "react";
import { ChevronsUpDown, Check, Plus, User, Building2 } from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useOrganizationContext } from "@/contexts/OrganizationContext";
import { useSidebar } from "@/components/ui/sidebar";
import { cn } from "@/lib/utils";
import { CreateOrgModal } from "@/components/organizations/CreateOrgModal";
import { toast } from "sonner";
import { useMasterKey } from "@/hooks/useMasterKey";
import { useOrgMasterKey } from "@/hooks/useOrgMasterKey";

export function VaultSwitcher() {
    const {
        organizations,
        currentOrg,
        isPersonalContext,
        switchToOrg,
        switchToPersonal,
        refreshOrganizations,
    } = useOrganizationContext();
    const { state } = useSidebar();
    const isCollapsed = state === "collapsed";
    const { isUnlocked: isPersonalUnlocked } = useMasterKey();
    const { unlockOrgVault } = useOrgMasterKey();

    const [open, setOpen] = useState(false);
    const [createModalOpen, setCreateModalOpen] = useState(false);

    // Don't render if user has no organizations
    if (organizations.length === 0) return null;

    const handleSelect = async (orgId: number | null) => {
        setOpen(false);
        try {
            if (orgId === null) {
                await switchToPersonal();
            } else {
                await switchToOrg(orgId);
                // Auto-unlock org vault if personal vault is unlocked
                if (isPersonalUnlocked) {
                    unlockOrgVault(orgId).catch((err) => {
                        console.error('[VaultSwitcher] Org vault auto-unlock failed:', err);
                        toast.error("Could not unlock organization vault. Try unlocking your personal vault first.");
                    });
                }
            }
        } catch {
            toast.error("Failed to switch vault context");
        }
    };

    const handleCreateSuccess = (orgId: number) => {
        refreshOrganizations();
        handleSelect(orgId);
    };

    const currentLabel = isPersonalContext ? "My Vault" : (currentOrg?.name ?? "My Vault");
    const currentRole = currentOrg?.role;

    return (
        <>
            <div className="px-3 py-2 border-b border-[rgba(212,175,55,0.08)]">
                <Popover open={open} onOpenChange={setOpen}>
                    <PopoverTrigger asChild>
                        <button
                            className={cn(
                                "flex items-center gap-2.5 w-full rounded-lg px-2.5 py-2 transition-all duration-200",
                                "text-left text-sm font-medium",
                                "hover:bg-[rgba(212,175,55,0.08)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[rgba(212,175,55,0.4)]",
                                "text-[var(--nocturne-200)]",
                                isCollapsed && "justify-center px-0"
                            )}
                            aria-label="Switch vault"
                        >
                            {/* Context icon */}
                            <div className={cn(
                                "h-7 w-7 rounded-md flex items-center justify-center shrink-0 transition-colors duration-200",
                                isPersonalContext
                                    ? "bg-[rgba(212,175,55,0.12)] text-[var(--gold-400)]"
                                    : "bg-[rgba(99,102,241,0.12)] text-indigo-400"
                            )}>
                                {isPersonalContext
                                    ? <User className="h-3.5 w-3.5" />
                                    : <Building2 className="h-3.5 w-3.5" />
                                }
                            </div>

                            {!isCollapsed && (
                                <>
                                    <div className="flex-1 min-w-0">
                                        <p className="truncate leading-tight">
                                            {currentLabel}
                                        </p>
                                        {currentRole && (
                                            <p className="text-[0.6875rem] text-[var(--nocturne-500)] leading-tight mt-0.5 capitalize">
                                                {currentRole}
                                            </p>
                                        )}
                                    </div>
                                    <ChevronsUpDown className="h-3.5 w-3.5 text-[var(--nocturne-500)] shrink-0" />
                                </>
                            )}
                        </button>
                    </PopoverTrigger>

                    <PopoverContent
                        side="right"
                        align="start"
                        sideOffset={8}
                        className="w-64 p-1.5 rounded-xl border-[rgba(212,175,55,0.15)] bg-[var(--nocturne-900)] shadow-[0_8px_32px_rgba(0,0,0,0.5)]"
                    >
                        <div className="px-2 py-1.5 mb-1">
                            <p className="text-[0.6875rem] font-semibold uppercase tracking-wider text-[var(--nocturne-500)]">
                                Vaults
                            </p>
                        </div>

                        {/* Personal vault */}
                        <button
                            onClick={() => handleSelect(null)}
                            className={cn(
                                "flex items-center gap-2.5 w-full rounded-lg px-2.5 py-2 text-sm transition-all duration-150",
                                "hover:bg-[rgba(212,175,55,0.08)] text-left",
                                isPersonalContext
                                    ? "text-[var(--gold-300)]"
                                    : "text-[var(--nocturne-200)]"
                            )}
                        >
                            <div className={cn(
                                "h-7 w-7 rounded-md flex items-center justify-center shrink-0",
                                isPersonalContext
                                    ? "bg-[rgba(212,175,55,0.15)] text-[var(--gold-400)]"
                                    : "bg-[var(--nocturne-800)] text-[var(--nocturne-400)]"
                            )}>
                                <User className="h-3.5 w-3.5" />
                            </div>
                            <span className="flex-1 truncate font-medium">My Vault</span>
                            {isPersonalContext && (
                                <Check className="h-3.5 w-3.5 text-[var(--gold-400)] shrink-0" />
                            )}
                        </button>

                        {/* Organization vaults */}
                        {organizations.map(org => {
                            const isActive = currentOrg?.id === org.id;
                            return (
                                <button
                                    key={org.id}
                                    onClick={() => handleSelect(org.id)}
                                    className={cn(
                                        "flex items-center gap-2.5 w-full rounded-lg px-2.5 py-2 text-sm transition-all duration-150",
                                        "hover:bg-[rgba(212,175,55,0.08)] text-left",
                                        isActive
                                            ? "text-[var(--gold-300)]"
                                            : "text-[var(--nocturne-200)]"
                                    )}
                                >
                                    <div className={cn(
                                        "h-7 w-7 rounded-md flex items-center justify-center shrink-0",
                                        isActive
                                            ? "bg-[rgba(99,102,241,0.2)] text-indigo-300"
                                            : "bg-[var(--nocturne-800)] text-[var(--nocturne-400)]"
                                    )}>
                                        <Building2 className="h-3.5 w-3.5" />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <p className="truncate font-medium">{org.name}</p>
                                        <p className="text-[0.6875rem] text-[var(--nocturne-500)] capitalize">{org.role}</p>
                                    </div>
                                    {isActive && (
                                        <Check className="h-3.5 w-3.5 text-[var(--gold-400)] shrink-0" />
                                    )}
                                </button>
                            );
                        })}

                        {/* Separator + Create */}
                        <div className="my-1.5 mx-2">
                            <div className="h-px bg-[rgba(212,175,55,0.1)]" />
                        </div>
                        <button
                            onClick={() => {
                                setOpen(false);
                                setCreateModalOpen(true);
                            }}
                            className="flex items-center gap-2.5 w-full rounded-lg px-2.5 py-2 text-sm transition-all duration-150 hover:bg-[rgba(212,175,55,0.08)] text-[var(--nocturne-400)] hover:text-[var(--gold-300)]"
                        >
                            <div className="h-7 w-7 rounded-md flex items-center justify-center shrink-0 border border-dashed border-[var(--nocturne-700)]">
                                <Plus className="h-3.5 w-3.5" />
                            </div>
                            <span className="font-medium">Create Organization</span>
                        </button>
                    </PopoverContent>
                </Popover>
            </div>

            <CreateOrgModal
                open={createModalOpen}
                onOpenChange={setCreateModalOpen}
                onSuccess={handleCreateSuccess}
            />
        </>
    );
}
