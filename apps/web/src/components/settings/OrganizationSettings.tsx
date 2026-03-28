/**
 * Organization Settings Component
 *
 * Displays organization list, creation, member management, and invitations.
 * Wires existing org components (CreateOrgModal, MembersList, InviteMemberModal)
 * into the Settings page.
 */

import { useState } from "react";
import {
    Building2,
    Plus,
    Users,
    UserPlus,
    ChevronRight,
    ArrowLeft,
    HardDrive,
    Loader2,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AuroraCard, AuroraCardContent } from "@/components/ui/aurora-card";
import { Separator } from "@/components/ui/separator";
import { useOrganizationContext } from "@/contexts/OrganizationContext";
import { useOrganizationStorageStats } from "@/hooks/organizations/useOrganizations";
import { useAuth } from "@/_core/hooks/useAuth";
import { CreateOrgModal } from "@/components/organizations/CreateOrgModal";
import { InviteMemberModal } from "@/components/organizations/InviteMemberModal";
import { MembersList } from "@/components/organizations/MembersList";
import { KeyDistributionPanel } from "@/components/organizations/KeyDistributionPanel";
import { formatBytes } from "@stenvault/shared";
import { cn } from "@/lib/utils";

const roleLabels = {
    owner: "Owner",
    admin: "Admin",
    member: "Member",
} as const;

const roleColors = {
    owner: "text-amber-500",
    admin: "text-blue-500",
    member: "text-muted-foreground",
} as const;

export function OrganizationSettings() {
    const { user } = useAuth();
    const { organizations, isLoading, refreshOrganizations } = useOrganizationContext();

    const [createModalOpen, setCreateModalOpen] = useState(false);
    const [selectedOrgId, setSelectedOrgId] = useState<number | null>(null);
    const [inviteModalOpen, setInviteModalOpen] = useState(false);

    const selectedOrg = selectedOrgId
        ? organizations.find(o => o.id === selectedOrgId) ?? null
        : null;

    const handleOrgCreated = (orgId: number) => {
        refreshOrganizations();
        setSelectedOrgId(orgId);
        toast.success("Organization created");
    };

    // ─── Detail view for a selected org ───
    if (selectedOrg && user) {
        return (
            <OrgDetailView
                org={selectedOrg}
                userId={user.id}
                onBack={() => setSelectedOrgId(null)}
                onInvite={() => setInviteModalOpen(true)}
                inviteModalOpen={inviteModalOpen}
                onInviteModalChange={setInviteModalOpen}
            />
        );
    }

    // ─── Organization list view ───
    return (
        <div className="space-y-6">
            <AuroraCard variant="glass">
                <AuroraCardContent className="p-6">
                    <div className="flex items-center justify-between mb-6">
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-primary/10">
                                <Building2 className="w-5 h-5 text-primary" />
                            </div>
                            <div>
                                <h2 className="text-lg font-semibold">Organizations</h2>
                                <p className="text-sm text-muted-foreground">
                                    Manage your team workspaces
                                </p>
                            </div>
                        </div>
                        <Button onClick={() => setCreateModalOpen(true)} size="sm">
                            <Plus className="w-4 h-4 mr-2" />
                            Create
                        </Button>
                    </div>

                    {isLoading ? (
                        <div className="flex items-center justify-center py-12">
                            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                        </div>
                    ) : organizations.length === 0 ? (
                        <div className="text-center py-12 space-y-3">
                            <Building2 className="w-12 h-12 mx-auto text-muted-foreground/50" />
                            <div>
                                <p className="font-medium text-muted-foreground">No organizations yet</p>
                                <p className="text-sm text-muted-foreground/70">
                                    Create an organization to collaborate with your team.
                                </p>
                            </div>
                            <Button
                                variant="outline"
                                onClick={() => setCreateModalOpen(true)}
                                className="mt-2"
                            >
                                <Plus className="w-4 h-4 mr-2" />
                                Create Organization
                            </Button>
                        </div>
                    ) : (
                        <div className="space-y-2">
                            {organizations.map(org => (
                                <button
                                    key={org.id}
                                    onClick={() => setSelectedOrgId(org.id)}
                                    className={cn(
                                        "w-full flex items-center gap-4 p-4 rounded-lg",
                                        "border border-border/50 hover:border-border",
                                        "hover:bg-accent/50 transition-colors text-left"
                                    )}
                                >
                                    <div className="p-2 rounded-lg bg-primary/10 shrink-0">
                                        <Building2 className="w-5 h-5 text-primary" />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2">
                                            <span className="font-medium truncate">{org.name}</span>
                                            <Badge variant="outline" className="text-[10px] shrink-0">
                                                <span className={roleColors[org.role]}>
                                                    {roleLabels[org.role]}
                                                </span>
                                            </Badge>
                                        </div>
                                        <p className="text-sm text-muted-foreground truncate">
                                            /{org.slug}
                                        </p>
                                    </div>
                                    <div className="text-sm text-muted-foreground shrink-0">
                                        {formatBytes(org.storageUsed)} / {formatBytes(org.storageQuota)}
                                    </div>
                                    <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
                                </button>
                            ))}
                        </div>
                    )}
                </AuroraCardContent>
            </AuroraCard>

            <CreateOrgModal
                open={createModalOpen}
                onOpenChange={setCreateModalOpen}
                onSuccess={handleOrgCreated}
            />
        </div>
    );
}

// ─── Org Detail Sub-view ───

interface OrgDetailViewProps {
    org: { id: number; name: string; slug: string; role: "owner" | "admin" | "member"; storageQuota: number; storageUsed: number };
    userId: number;
    onBack: () => void;
    onInvite: () => void;
    inviteModalOpen: boolean;
    onInviteModalChange: (open: boolean) => void;
}

function OrgDetailView({ org, userId, onBack, onInvite, inviteModalOpen, onInviteModalChange }: OrgDetailViewProps) {
    const { data: storageStats } = useOrganizationStorageStats(org.id);
    const canInvite = org.role === "owner" || org.role === "admin";

    return (
        <div className="space-y-6">
            {/* Header */}
            <AuroraCard variant="glass">
                <AuroraCardContent className="p-6">
                    <div className="flex items-center gap-3">
                        <Button variant="ghost" size="icon" onClick={onBack} className="shrink-0">
                            <ArrowLeft className="w-5 h-5" />
                        </Button>
                        <div className="p-2 rounded-lg bg-primary/10 shrink-0">
                            <Building2 className="w-5 h-5 text-primary" />
                        </div>
                        <div className="flex-1 min-w-0">
                            <h2 className="text-lg font-semibold truncate">{org.name}</h2>
                            <p className="text-sm text-muted-foreground">/{org.slug}</p>
                        </div>
                        <Badge variant="outline">
                            <span className={roleColors[org.role]}>
                                {roleLabels[org.role]}
                            </span>
                        </Badge>
                    </div>
                </AuroraCardContent>
            </AuroraCard>

            {/* Storage */}
            <AuroraCard variant="glass">
                <AuroraCardContent className="p-6">
                    <div className="flex items-center gap-3 mb-4">
                        <HardDrive className="w-5 h-5 text-muted-foreground" />
                        <h3 className="font-medium">Storage</h3>
                    </div>
                    <div className="space-y-2">
                        <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">Used</span>
                            <span>{formatBytes(storageStats?.storageUsed ?? org.storageUsed)}</span>
                        </div>
                        <div className="h-2 rounded-full bg-secondary overflow-hidden">
                            <div
                                className="h-full rounded-full bg-primary transition-all"
                                style={{
                                    width: `${Math.min(100, ((storageStats?.storageUsed ?? org.storageUsed) / (storageStats?.storageQuota ?? org.storageQuota)) * 100)}%`,
                                }}
                            />
                        </div>
                        <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">Quota</span>
                            <span>{formatBytes(storageStats?.storageQuota ?? org.storageQuota)}</span>
                        </div>
                    </div>
                </AuroraCardContent>
            </AuroraCard>

            {/* Members */}
            <AuroraCard variant="glass">
                <AuroraCardContent className="p-6">
                    <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                            <Users className="w-5 h-5 text-muted-foreground" />
                            <h3 className="font-medium">Members</h3>
                        </div>
                        {canInvite && (
                            <Button onClick={onInvite} size="sm" variant="outline">
                                <UserPlus className="w-4 h-4 mr-2" />
                                Invite
                            </Button>
                        )}
                    </div>
                    <Separator className="mb-4" />
                    <MembersList
                        organizationId={org.id}
                        currentUserRole={org.role}
                        currentUserId={userId}
                    />
                    <KeyDistributionPanel
                        organizationId={org.id}
                        currentUserRole={org.role}
                    />
                </AuroraCardContent>
            </AuroraCard>

            {/* Invite Modal */}
            <InviteMemberModal
                open={inviteModalOpen}
                onOpenChange={onInviteModalChange}
                organizationId={org.id}
                organizationName={org.name}
            />
        </div>
    );
}
