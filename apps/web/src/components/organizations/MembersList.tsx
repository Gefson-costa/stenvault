/**
 * Organization Members List
 * 
 * Component for viewing and managing organization members.
 */

import React, { useState } from "react";
import { Crown, Shield, Users, MoreHorizontal, UserMinus, RefreshCw, Loader2 } from "lucide-react";
import { Button } from "../ui/button";
import { Badge } from "../ui/badge";
import { Avatar, AvatarFallback } from "../ui/avatar";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
    DropdownMenuSeparator,
} from "../ui/dropdown-menu";
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from "../ui/alert-dialog";
import { useOrganizationMembers, useOrganizationMutations } from "../../hooks/organizations/useOrganizations";
import { toast } from "sonner";
import { cn } from "../../lib/utils";
import { trpc } from "@/lib/trpc";
import { useOrgMasterKey } from "@/hooks/useOrgMasterKey";
import { buildRotationPayload } from "@/lib/orgKeyRotation";

interface MembersListProps {
    organizationId: number;
    currentUserRole: "owner" | "admin" | "member";
    currentUserId: number;
}

const roleIcons = {
    owner: Crown,
    admin: Shield,
    member: Users,
};

const roleLabels = {
    owner: "Owner",
    admin: "Admin",
    member: "Member",
};

const roleBadgeVariants = {
    owner: "default" as const,
    admin: "secondary" as const,
    member: "outline" as const,
};

export function MembersList({ organizationId, currentUserRole, currentUserId }: MembersListProps) {
    const { data: members, isLoading, refetch } = useOrganizationMembers(organizationId);
    const { removeMember, updateMemberRole, transferOwnership } = useOrganizationMutations();
    const utils = trpc.useUtils();
    const rotateOMK = trpc.orgKeys.rotateOMK.useMutation();
    const { unlockOrgVault, getOrgMasterKey } = useOrgMasterKey();

    const [confirmAction, setConfirmAction] = useState<{
        type: "remove" | "transfer" | "demote";
        memberId: number;
        memberName: string;
    } | null>(null);

    const canManageMembers = currentUserRole === "owner" || currentUserRole === "admin";
    const isOwner = currentUserRole === "owner";

    const handleRemoveMember = async () => {
        if (!confirmAction || confirmAction.type !== "remove") return;

        try {
            await removeMember.mutateAsync({
                organizationId,
                userId: confirmAction.memberId,
            });
            toast.success(`${confirmAction.memberName} has been removed`);

            // Trigger OMK rotation to revoke the removed member's access to new files
            try {
                await unlockOrgVault(organizationId);

                // Get remaining members' hybrid public keys
                const remainingMembers = (members ?? []).filter(
                    (m: any) => m.userId !== confirmAction.memberId,
                );
                const memberPubKeys = await Promise.all(
                    remainingMembers.map(async (m: any) => {
                        const pk = await utils.orgKeys.getMemberHybridPublicKey.fetch({
                            organizationId,
                            targetUserId: m.userId,
                        });
                        return pk;
                    }).filter(Boolean),
                );

                const payload = await buildRotationPayload(
                    organizationId,
                    memberPubKeys,
                    `member_removed: ${confirmAction.memberName}`,
                );
                await rotateOMK.mutateAsync(payload);
                toast.success("Organization keys rotated");
            } catch (rotErr: any) {
                console.warn('[MembersList] OMK rotation failed:', rotErr);
                toast.warning("Member removed, but key rotation failed. Rotate manually from settings.");
            }
        } catch (error: any) {
            toast.error(error.message || "Failed to remove member");
        } finally {
            setConfirmAction(null);
        }
    };

    const handleTransferOwnership = async () => {
        if (!confirmAction || confirmAction.type !== "transfer") return;

        try {
            await transferOwnership.mutateAsync({
                organizationId,
                newOwnerId: confirmAction.memberId,
            });
            toast.success(`Ownership transferred to ${confirmAction.memberName}`);
        } catch (error: any) {
            toast.error(error.message || "Failed to transfer ownership");
        } finally {
            setConfirmAction(null);
        }
    };

    const handleRoleChange = async (memberId: number, newRole: "admin" | "member") => {
        try {
            await updateMemberRole.mutateAsync({
                organizationId,
                userId: memberId,
                role: newRole,
            });
            toast.success(`Role updated to ${roleLabels[newRole]}`);
        } catch (error: any) {
            toast.error(error.message || "Failed to update role");
        }
    };

    if (isLoading) {
        return (
            <div className="flex items-center justify-center py-8">
                <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
        );
    }

    return (
        <div className="space-y-4">
            {/* Header */}
            <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold">Members ({members?.length || 0})</h3>
                <Button variant="ghost" size="icon" onClick={() => refetch()}>
                    <RefreshCw className="w-4 h-4" />
                </Button>
            </div>

            {/* Members List */}
            <div className="space-y-2">
                {members?.map((member: any) => {
                    const RoleIcon = roleIcons[member.role as keyof typeof roleIcons];
                    const isCurrentUser = member.userId === currentUserId;
                    const canManageThisMember = canManageMembers && !isCurrentUser && member.role !== "owner";

                    return (
                        <div
                            key={member.id}
                            className={cn(
                                "flex items-center gap-3 p-3 rounded-lg",
                                "border border-border/50 hover:border-border",
                                "transition-colors"
                            )}
                        >
                            <Avatar className="h-10 w-10">
                                <AvatarFallback className="text-sm">
                                    {member.userName?.charAt(0).toUpperCase() || "?"}
                                </AvatarFallback>
                            </Avatar>

                            <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                    <span className="font-medium truncate">
                                        {member.userName || "Unknown"}
                                    </span>
                                    {isCurrentUser && (
                                        <Badge variant="outline" className="text-[10px]">
                                            You
                                        </Badge>
                                    )}
                                </div>
                                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                    <span className="truncate">{member.userEmail}</span>
                                </div>
                            </div>

                            <Badge variant={roleBadgeVariants[member.role as keyof typeof roleBadgeVariants]}>
                                <RoleIcon className="w-3 h-3 mr-1" />
                                {roleLabels[member.role as keyof typeof roleLabels]}
                            </Badge>

                            {canManageThisMember && (
                                <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                        <Button variant="ghost" size="icon" className="h-8 w-8">
                                            <MoreHorizontal className="w-4 h-4" />
                                        </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent align="end">
                                        {/* Role change options */}
                                        {member.role === "member" && (
                                            <DropdownMenuItem onClick={() => handleRoleChange(member.userId, "admin")}>
                                                <Shield className="w-4 h-4 mr-2" />
                                                Promote to Admin
                                            </DropdownMenuItem>
                                        )}
                                        {member.role === "admin" && (
                                            <DropdownMenuItem onClick={() => handleRoleChange(member.userId, "member")}>
                                                <Users className="w-4 h-4 mr-2" />
                                                Demote to Member
                                            </DropdownMenuItem>
                                        )}

                                        {/* Transfer ownership (owner only) */}
                                        {isOwner && (
                                            <>
                                                <DropdownMenuSeparator />
                                                <DropdownMenuItem
                                                    onClick={() => setConfirmAction({
                                                        type: "transfer",
                                                        memberId: member.userId,
                                                        memberName: member.userName,
                                                    })}
                                                    className="text-amber-500"
                                                >
                                                    <Crown className="w-4 h-4 mr-2" />
                                                    Transfer Ownership
                                                </DropdownMenuItem>
                                            </>
                                        )}

                                        <DropdownMenuSeparator />
                                        <DropdownMenuItem
                                            onClick={() => setConfirmAction({
                                                type: "remove",
                                                memberId: member.userId,
                                                memberName: member.userName,
                                            })}
                                            className="text-destructive"
                                        >
                                            <UserMinus className="w-4 h-4 mr-2" />
                                            Remove from Organization
                                        </DropdownMenuItem>
                                    </DropdownMenuContent>
                                </DropdownMenu>
                            )}
                        </div>
                    );
                })}
            </div>

            {/* Confirmation Dialogs */}
            <AlertDialog open={confirmAction?.type === "remove"} onOpenChange={() => setConfirmAction(null)}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>Remove Member</AlertDialogTitle>
                        <AlertDialogDescription>
                            Are you sure you want to remove <strong>{confirmAction?.memberName}</strong> from
                            this organization? They will lose access to all organization files.
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction
                            onClick={handleRemoveMember}
                            className="bg-destructive hover:bg-destructive/90"
                        >
                            Remove
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>

            <AlertDialog open={confirmAction?.type === "transfer"} onOpenChange={() => setConfirmAction(null)}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>Transfer Ownership</AlertDialogTitle>
                        <AlertDialogDescription>
                            Are you sure you want to transfer ownership to <strong>{confirmAction?.memberName}</strong>?
                            You will become an admin and lose owner privileges.
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction
                            onClick={handleTransferOwnership}
                            className="bg-amber-500 hover:bg-amber-600"
                        >
                            Transfer Ownership
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </div>
    );
}

export default MembersList;
