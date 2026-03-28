/**
 * Auto Key Distribution Hook
 *
 * Background hook for admin/owner users. Polls for org members pending
 * OMK distribution and batch-distributes via hybrid encapsulation.
 *
 * Fallback for: legacy invites (no key-in-URL blob), key rotation,
 * or any edge case where the key-in-URL flow didn't complete.
 */

import { useEffect, useRef } from "react";
import { trpc } from "@/lib/trpc";
import { useOrganizationContext } from "@/contexts/OrganizationContext";
import { useOrgMasterKey } from "./useOrgMasterKey";
import { encapsulateOMKForMember } from "@/lib/orgKeyDistribution";
import { toast } from "sonner";

const POLL_INTERVAL_MS = 60_000;
const BATCH_LIMIT = 20;
const FAIL_COOLDOWN_MS = 5 * 60_000;

export function useAutoKeyDistribution() {
    const { currentOrg } = useOrganizationContext();
    const { getOrgMasterKey, isOrgUnlocked } = useOrgMasterKey();
    const wrapForMember = trpc.orgKeys.wrapOMKForMember.useMutation();
    const utils = trpc.useUtils();

    const isDistributingRef = useRef(false);
    const failedIdsRef = useRef<Map<number, number>>(new Map());
    // Stable refs for values used inside the async distribute function
    const wrapForMemberRef = useRef(wrapForMember);
    wrapForMemberRef.current = wrapForMember;
    const getOrgMasterKeyRef = useRef(getOrgMasterKey);
    getOrgMasterKeyRef.current = getOrgMasterKey;
    const utilsRef = useRef(utils);
    utilsRef.current = utils;

    const orgId = currentOrg?.id ?? null;
    const isAdminOrOwner = currentOrg?.role === "owner" || currentOrg?.role === "admin";
    const vaultUnlocked = orgId ? isOrgUnlocked(orgId) : false;
    const enabled = !!orgId && isAdminOrOwner && vaultUnlocked;

    const { data: pendingData } = trpc.orgKeys.getPendingKeyDistributions.useQuery(
        { organizationId: orgId! },
        {
            enabled,
            refetchInterval: enabled ? POLL_INTERVAL_MS : false,
            staleTime: POLL_INTERVAL_MS,
        },
    );

    useEffect(() => {
        if (!orgId || !pendingData || pendingData.pendingMembers.length === 0) return;
        if (isDistributingRef.current) return;

        const distribute = async () => {
            const now = Date.now();
            const eligible = pendingData.pendingMembers
                .filter(m => m.hasHybridKey)
                .filter(m => {
                    const failedAt = failedIdsRef.current.get(m.userId);
                    return !failedAt || now - failedAt > FAIL_COOLDOWN_MS;
                })
                .slice(0, BATCH_LIMIT);

            if (eligible.length === 0) return;

            const omk = getOrgMasterKeyRef.current(orgId);
            if (!omk) return;

            isDistributingRef.current = true;
            let distributed = 0;

            try {
                for (const member of eligible) {
                    try {
                        const pubKey = await utilsRef.current.orgKeys.getMemberHybridPublicKey.fetch({
                            organizationId: orgId,
                            targetUserId: member.userId,
                        });

                        const payload = await encapsulateOMKForMember(omk, {
                            x25519PublicKey: pubKey.x25519PublicKey,
                            mlkem768PublicKey: pubKey.mlkem768PublicKey,
                        });

                        await wrapForMemberRef.current.mutateAsync({
                            organizationId: orgId,
                            targetUserId: member.userId,
                            ...payload,
                        });

                        distributed++;
                        failedIdsRef.current.delete(member.userId);
                    } catch (err) {
                        console.warn(`[AutoKeyDist] Failed for user ${member.userId}:`, err);
                        failedIdsRef.current.set(member.userId, Date.now());
                    }
                }

                if (distributed > 0) {
                    toast.success(`Distributed encryption keys to ${distributed} member(s).`);
                    utilsRef.current.orgKeys.getPendingKeyDistributions.invalidate({ organizationId: orgId });
                }
            } finally {
                isDistributingRef.current = false;
            }
        };

        distribute();
    }, [orgId, pendingData]);
}
