/**
 * Organization Detail View
 *
 * Full management panel for a single organization.
 * Shows header (editable name/slug), storage, members, invites, and danger zone.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
    Building2,
    Users,
    UserPlus,
    ArrowLeft,
    HardDrive,
    Pencil,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { AuroraCard, AuroraCardContent } from "@/components/ui/aurora-card";
import { Separator } from "@/components/ui/separator";
import { useOrganizationStorageStats, useOrganizationMutations } from "@/hooks/organizations/useOrganizations";
import { useOrganizationContext } from "@/contexts/OrganizationContext";
import { InviteMemberModal } from "./InviteMemberModal";
import { MembersList } from "./MembersList";
import { KeyDistributionPanel } from "./KeyDistributionPanel";
import { PendingInvitesList } from "./PendingInvitesList";
import { OrgDangerZone } from "./OrgDangerZone";
import { formatBytes } from "@stenvault/shared";

const roleLabels = { owner: "Owner", admin: "Admin", member: "Member" } as const;
const roleColors = { owner: "text-amber-500", admin: "text-blue-500", member: "text-muted-foreground" } as const;

export interface OrgDetailViewProps {
    org: { id: number; name: string; slug: string; role: "owner" | "admin" | "member"; storageQuota: number; storageUsed: number };
    userId: number;
    onBack?: () => void;
}

export function OrgDetailView({ org, userId, onBack }: OrgDetailViewProps) {
    const navigate = useNavigate();
    const { data: storageStats } = useOrganizationStorageStats(org.id);
    const { updateOrg } = useOrganizationMutations();
    const { refreshOrganizations } = useOrganizationContext();
    const canManage = org.role === "owner" || org.role === "admin";

    const [inviteModalOpen, setInviteModalOpen] = useState(false);
    const [editing, setEditing] = useState<"name" | "slug" | null>(null);
    const [editName, setEditName] = useState(org.name);
    const [editSlug, setEditSlug] = useState(org.slug);

    const handleSave = async (field: "name" | "slug") => {
        const value = field === "name" ? editName.trim() : editSlug.trim().toLowerCase();
        const original = field === "name" ? org.name : org.slug;
        if (!value || value === original) { setEditing(null); return; }

        try {
            await updateOrg.mutateAsync({
                organizationId: org.id,
                ...(field === "name" ? { name: value } : { slug: value }),
            });
            refreshOrganizations();
            setEditing(null);
            toast.success(`Organization ${field} updated`);
        } catch (err) {
            const msg = err instanceof Error ? err.message : `Failed to update ${field}`;
            toast.error(msg);
        }
    };

    const cancelEdit = () => {
        setEditName(org.name);
        setEditSlug(org.slug);
        setEditing(null);
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <AuroraCard variant="glass">
                <AuroraCardContent className="p-6">
                    <div className="flex items-center gap-3">
                        {onBack && (
                            <Button variant="ghost" size="icon" onClick={onBack} className="shrink-0">
                                <ArrowLeft className="w-5 h-5" />
                            </Button>
                        )}
                        <div className="p-2 rounded-lg bg-primary/10 shrink-0">
                            <Building2 className="w-5 h-5 text-primary" />
                        </div>
                        <div className="flex-1 min-w-0">
                            {/* Name */}
                            {editing === "name" ? (
                                <div className="flex items-center gap-2">
                                    <Input
                                        value={editName}
                                        onChange={(e) => setEditName(e.target.value)}
                                        onKeyDown={(e) => {
                                            if (e.key === "Enter") handleSave("name");
                                            if (e.key === "Escape") cancelEdit();
                                        }}
                                        className="h-8 text-sm"
                                        maxLength={255}
                                        autoFocus
                                    />
                                    <Button size="sm" onClick={() => handleSave("name")} disabled={updateOrg.isPending}>Save</Button>
                                    <Button size="sm" variant="ghost" onClick={cancelEdit}>Cancel</Button>
                                </div>
                            ) : (
                                <div className="flex items-center gap-2">
                                    <h2 className="text-lg font-semibold truncate">{org.name}</h2>
                                    {canManage && (
                                        <Button variant="ghost" size="icon" className="h-6 w-6 shrink-0"
                                            onClick={() => { setEditName(org.name); setEditing("name"); }}>
                                            <Pencil className="w-3.5 h-3.5" />
                                        </Button>
                                    )}
                                </div>
                            )}
                            {/* Slug */}
                            {editing === "slug" ? (
                                <div className="flex items-center gap-2 mt-1">
                                    <span className="text-sm text-muted-foreground">/</span>
                                    <Input
                                        value={editSlug}
                                        onChange={(e) => setEditSlug(e.target.value.replace(/[^a-z0-9-]/g, ""))}
                                        onKeyDown={(e) => {
                                            if (e.key === "Enter") handleSave("slug");
                                            if (e.key === "Escape") cancelEdit();
                                        }}
                                        className="h-7 text-xs w-40"
                                        maxLength={100}
                                        autoFocus
                                    />
                                    <Button size="sm" className="h-7 text-xs" onClick={() => handleSave("slug")} disabled={updateOrg.isPending}>Save</Button>
                                    <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={cancelEdit}>Cancel</Button>
                                </div>
                            ) : (
                                <div className="flex items-center gap-1">
                                    <p className="text-sm text-muted-foreground">/{org.slug}</p>
                                    {canManage && (
                                        <Button variant="ghost" size="icon" className="h-5 w-5 shrink-0"
                                            onClick={() => { setEditSlug(org.slug); setEditing("slug"); }}>
                                            <Pencil className="w-3 h-3" />
                                        </Button>
                                    )}
                                </div>
                            )}
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

            {/* Members + Invites */}
            <AuroraCard variant="glass">
                <AuroraCardContent className="p-6">
                    <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                            <Users className="w-5 h-5 text-muted-foreground" />
                            <h3 className="font-medium">Members</h3>
                        </div>
                        {canManage && (
                            <Button onClick={() => setInviteModalOpen(true)} size="sm" variant="outline">
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
                    {canManage && (
                        <PendingInvitesList
                            organizationId={org.id}
                            canManage={canManage}
                        />
                    )}
                </AuroraCardContent>
            </AuroraCard>

            {/* Leave / Delete */}
            <OrgDangerZone
                orgId={org.id}
                orgName={org.name}
                role={org.role}
                onLeft={onBack ?? (() => navigate('/home'))}
            />

            {/* Invite Modal */}
            <InviteMemberModal
                open={inviteModalOpen}
                onOpenChange={setInviteModalOpen}
                organizationId={org.id}
                organizationName={org.name}
            />
        </div>
    );
}
