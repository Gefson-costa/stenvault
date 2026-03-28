/**
 * Organizations Hooks
 * 
 * React hooks for organization-related operations.
 */

import { trpc } from "../../lib/trpc";
import { useCallback, useMemo } from "react";

/**
 * Hook for listing user's organizations
 * Only queries if user is authenticated to avoid UNAUTHORIZED errors on public pages
 */
export function useOrganizationsList() {
    const { data: user } = trpc.auth.me.useQuery(undefined, {
        staleTime: Infinity,
        retry: false,
    });

    return trpc.organizations.list.useQuery(undefined, {
        enabled: !!user,
    });
}

/**
 * Hook for getting a specific organization by ID
 */
export function useOrganization(id: number | null) {
    return trpc.organizations.getById.useQuery(
        { id: id! },
        { enabled: !!id }
    );
}

/**
 * Hook for getting organization members
 */
export function useOrganizationMembers(organizationId: number | null) {
    return trpc.organizations.getMembers.useQuery(
        { organizationId: organizationId! },
        { enabled: !!organizationId }
    );
}

/**
 * Hook for getting pending invites
 */
export function useOrganizationInvites(organizationId: number | null) {
    return trpc.organizations.getPendingInvites.useQuery(
        { organizationId: organizationId! },
        { enabled: !!organizationId }
    );
}

/**
 * Hook for organization storage stats
 */
export function useOrganizationStorageStats(organizationId: number | null) {
    return trpc.organizations.getStorageStats.useQuery(
        { organizationId: organizationId! },
        { enabled: !!organizationId }
    );
}

/**
 * Hook for pending invites addressed to the current user
 */
export function useMyPendingOrgInvites() {
    return trpc.organizations.getMyPendingInvites.useQuery(undefined, {
        staleTime: 60_000,
    });
}

/**
 * Hook for organization mutations
 */
export function useOrganizationMutations() {
    const utils = trpc.useUtils();

    const createOrg = trpc.organizations.create.useMutation({
        onSuccess: () => {
            utils.organizations.list.invalidate();
        },
    });

    const updateOrg = trpc.organizations.update.useMutation({
        onSuccess: () => {
            utils.organizations.list.invalidate();
        },
    });

    const deleteOrg = trpc.organizations.delete.useMutation({
        onSuccess: () => {
            utils.organizations.list.invalidate();
        },
    });

    const inviteMember = trpc.organizations.inviteMember.useMutation({
        onSuccess: (_, variables) => {
            utils.organizations.getPendingInvites.invalidate({ organizationId: variables.organizationId });
        },
    });

    const acceptInvite = trpc.organizations.acceptInvite.useMutation({
        onSuccess: () => {
            utils.organizations.list.invalidate();
        },
    });

    const cancelInvite = trpc.organizations.cancelInvite.useMutation({
        onSuccess: () => {
            utils.organizations.list.invalidate();
            utils.organizations.getPendingInvites.invalidate();
        },
    });

    const updateMemberRole = trpc.organizations.updateMemberRole.useMutation({
        onSuccess: (_, variables) => {
            utils.organizations.getMembers.invalidate({ organizationId: variables.organizationId });
        },
    });

    const removeMember = trpc.organizations.removeMember.useMutation({
        onSuccess: (_, variables) => {
            utils.organizations.getMembers.invalidate({ organizationId: variables.organizationId });
        },
    });

    const leaveOrg = trpc.organizations.leave.useMutation({
        onSuccess: () => {
            utils.organizations.list.invalidate();
        },
    });

    const transferOwnership = trpc.organizations.transferOwnership.useMutation({
        onSuccess: (_, variables) => {
            utils.organizations.getMembers.invalidate({ organizationId: variables.organizationId });
            utils.organizations.list.invalidate();
        },
    });

    const switchContext = trpc.organizations.switchContext.useMutation();

    return useMemo(() => ({
        createOrg,
        updateOrg,
        deleteOrg,
        inviteMember,
        acceptInvite,
        cancelInvite,
        updateMemberRole,
        removeMember,
        leaveOrg,
        transferOwnership,
        switchContext,
    }), [
        createOrg,
        updateOrg,
        deleteOrg,
        inviteMember,
        acceptInvite,
        cancelInvite,
        updateMemberRole,
        removeMember,
        leaveOrg,
        transferOwnership,
        switchContext,
    ]);
}
