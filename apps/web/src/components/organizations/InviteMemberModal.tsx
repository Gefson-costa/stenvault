/**
 * Invite Member Modal
 * 
 * Modal dialog for inviting new members to an organization.
 */

import React, { useState } from "react";
import { Mail, Loader2, UserPlus } from "lucide-react";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "../ui/select";
import { useOrganizationMutations } from "../../hooks/organizations/useOrganizations";
import { useOrgMasterKey } from "../../hooks/useOrgMasterKey";
import { wrapOMKForInvite } from "../../hooks/orgMasterKeyCrypto";
import { toast } from "sonner";

interface InviteMemberModalProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    organizationId: number;
    organizationName: string;
}

type InviteRole = "admin" | "member";

export function InviteMemberModal({
    open,
    onOpenChange,
    organizationId,
    organizationName,
}: InviteMemberModalProps) {
    const [email, setEmail] = useState("");
    const [role, setRole] = useState<InviteRole>("member");

    const { inviteMember } = useOrganizationMutations();
    const { getOrgMasterKey } = useOrgMasterKey();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!email.trim()) {
            toast.error("Email is required");
            return;
        }

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            toast.error("Please enter a valid email address");
            return;
        }

        try {
            // Wrap OMK with invite key if org vault is unlocked
            let cryptoFields: { omkWrappedForInvite?: string; inviteKeyFragment?: string } = {};
            const omk = getOrgMasterKey(organizationId);
            if (omk) {
                try {
                    cryptoFields = await wrapOMKForInvite(omk);
                } catch (err) {
                    console.warn('[InviteMember] Key wrapping failed, using manual distribution:', err);
                }
            }

            await inviteMember.mutateAsync({
                organizationId,
                email: email.trim(),
                role,
                ...cryptoFields,
            });

            toast.success(`Invitation sent to ${email}`);
            onOpenChange(false);
            setEmail("");
            setRole("member");
        } catch (error: any) {
            toast.error(error.message || "Failed to send invitation");
        }
    };

    const handleClose = () => {
        setEmail("");
        setRole("member");
        onOpenChange(false);
    };

    return (
        <Dialog open={open} onOpenChange={handleClose}>
            <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-primary/10">
                            <UserPlus className="w-5 h-5 text-primary" />
                        </div>
                        <div>
                            <DialogTitle>Invite Team Member</DialogTitle>
                            <DialogDescription>
                                Send an invitation to join{" "}
                                <span className="font-medium">{organizationName}</span>
                            </DialogDescription>
                        </div>
                    </div>
                </DialogHeader>

                <form onSubmit={handleSubmit}>
                    <div className="grid gap-4 py-4">
                        <div className="grid gap-2">
                            <Label htmlFor="email">Email Address</Label>
                            <div className="relative">
                                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                                <Input
                                    id="email"
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    placeholder="colleague@company.com"
                                    className="pl-10"
                                    autoFocus
                                />
                            </div>
                        </div>

                        <div className="grid gap-2">
                            <Label htmlFor="role">Role</Label>
                            <Select value={role} onValueChange={(v) => setRole(v as InviteRole)}>
                                <SelectTrigger id="role">
                                    <SelectValue placeholder="Select a role" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="member">
                                        <div className="flex flex-col">
                                            <span>Member</span>
                                            <span className="text-xs text-muted-foreground">
                                                Can view and upload files
                                            </span>
                                        </div>
                                    </SelectItem>
                                    <SelectItem value="admin">
                                        <div className="flex flex-col">
                                            <span>Admin</span>
                                            <span className="text-xs text-muted-foreground">
                                                Can manage members and settings
                                            </span>
                                        </div>
                                    </SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </div>

                    <DialogFooter>
                        <Button
                            type="button"
                            variant="outline"
                            onClick={handleClose}
                            disabled={inviteMember.isPending}
                        >
                            Cancel
                        </Button>
                        <Button type="submit" disabled={inviteMember.isPending || !email.trim()}>
                            {inviteMember.isPending ? (
                                <>
                                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                    Sending...
                                </>
                            ) : (
                                "Send Invitation"
                            )}
                        </Button>
                    </DialogFooter>
                </form>
            </DialogContent>
        </Dialog>
    );
}

export default InviteMemberModal;
