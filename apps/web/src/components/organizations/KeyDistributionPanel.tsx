/**
 * Key Distribution Panel
 *
 * Shows pending members who need OMK distribution and lets admin/owner
 * distribute encryption keys via hybrid PQC encapsulation.
 */

import { useState } from "react";
import { KeyRound, Loader2, CheckCircle2, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { useOrgMasterKey } from "@/hooks/useOrgMasterKey";
import { encapsulateOMKForMember } from "@/lib/orgKeyDistribution";

interface KeyDistributionPanelProps {
    organizationId: number;
    currentUserRole: string;
}

export function KeyDistributionPanel({ organizationId, currentUserRole }: KeyDistributionPanelProps) {
    const isAdminOrOwner = currentUserRole === "owner" || currentUserRole === "admin";

    const { data, isLoading, refetch } = trpc.orgKeys.getPendingKeyDistributions.useQuery(
        { organizationId },
        { enabled: isAdminOrOwner },
    );

    const utils = trpc.useUtils();
    const distributeKey = trpc.orgKeys.wrapOMKForMember.useMutation();
    const { unlockOrgVault, getOrgMasterKey } = useOrgMasterKey();

    const [distributing, setDistributing] = useState<Record<number, boolean>>({});

    if (!isAdminOrOwner || isLoading || !data) return null;

    const pendingMembers = data.pendingMembers.filter(
        (m) => m.keyDistributionStatus !== "confirmed",
    );

    if (pendingMembers.length === 0) return null;

    const handleDistribute = async (targetUserId: number) => {
        setDistributing((prev) => ({ ...prev, [targetUserId]: true }));
        try {
            // Ensure org vault is unlocked
            await unlockOrgVault(organizationId);
            const omk = getOrgMasterKey(organizationId);
            if (!omk) throw new Error("Org vault is locked");

            // Fetch target member's hybrid public key
            const memberPubKey = await utils.orgKeys.getMemberHybridPublicKey.fetch({
                organizationId,
                targetUserId,
            });

            // Hybrid-encapsulate OMK for the member
            const payload = await encapsulateOMKForMember(omk, memberPubKey);

            // Send to backend
            await distributeKey.mutateAsync({
                organizationId,
                targetUserId,
                ...payload,
            });

            toast.success("Encryption key distributed");
            refetch();
        } catch (err: any) {
            console.warn("[KeyDist] Distribution failed:", err);
            toast.error(err.message || "Failed to distribute key");
        } finally {
            setDistributing((prev) => ({ ...prev, [targetUserId]: false }));
        }
    };

    const handleDistributeAll = async () => {
        for (const member of pendingMembers) {
            if (!member.hasHybridKey) continue;
            await handleDistribute(member.userId);
        }
    };

    return (
        <div className="mt-4 rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-4">
            <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                    <KeyRound className="w-4 h-4 text-yellow-500" />
                    <h4 className="text-sm font-medium">
                        {pendingMembers.length} member{pendingMembers.length !== 1 ? "s" : ""} need encryption keys
                    </h4>
                </div>
                {pendingMembers.filter((m) => m.hasHybridKey).length > 1 && (
                    <Button size="sm" variant="outline" onClick={handleDistributeAll}>
                        Distribute all
                    </Button>
                )}
            </div>

            <div className="space-y-2">
                {pendingMembers.map((member) => (
                    <div
                        key={member.userId}
                        className="flex items-center justify-between py-2 px-3 rounded-md bg-background/50"
                    >
                        <div className="min-w-0">
                            <p className="text-sm font-medium truncate">
                                {member.userName || member.userEmail}
                            </p>
                            <p className="text-xs text-muted-foreground">
                                {member.keyDistributionStatus === "pending"
                                    ? "Waiting for key"
                                    : "Key distributed, awaiting confirmation"}
                            </p>
                        </div>

                        {!member.hasHybridKey ? (
                            <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                <AlertTriangle className="w-3 h-3" />
                                No keypair
                            </div>
                        ) : member.keyDistributionStatus === "distributed" ? (
                            <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                <CheckCircle2 className="w-3 h-3 text-blue-400" />
                                Distributed
                            </div>
                        ) : (
                            <Button
                                size="sm"
                                variant="secondary"
                                onClick={() => handleDistribute(member.userId)}
                                disabled={distributing[member.userId]}
                            >
                                {distributing[member.userId] ? (
                                    <Loader2 className="w-3 h-3 animate-spin mr-1" />
                                ) : (
                                    <KeyRound className="w-3 h-3 mr-1" />
                                )}
                                Distribute
                            </Button>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}
