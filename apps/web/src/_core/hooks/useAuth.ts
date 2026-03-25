import { trpc } from "@/lib/trpc";
import { TRPCClientError } from "@trpc/client";
import { useCallback, useEffect, useMemo } from "react";
import { clearAllTokens, cancelProactiveRefresh } from "@/lib/auth";
import { clearMasterKeyCache, clearDeviceWrappedMK } from "@/hooks/useMasterKey";

type UseAuthOptions = {
  redirectOnUnauthenticated?: boolean;
  redirectPath?: string;
};

export function useAuth(options?: UseAuthOptions) {
  const { redirectOnUnauthenticated = false, redirectPath = "/auth/login" } =
    options ?? {};
  const utils = trpc.useUtils();

  const meQuery = trpc.auth.me.useQuery(undefined, {
    retry: false,
    refetchOnWindowFocus: false,
  });

  const logoutMutation = trpc.auth.logout.useMutation({
    onSuccess: () => {
      utils.auth.me.setData(undefined, null);
    },
  });

  const logout = useCallback(async () => {
    try {
      await logoutMutation.mutateAsync();
    } catch (error: unknown) {
      if (
        error instanceof TRPCClientError &&
        error.data?.code === "UNAUTHORIZED"
      ) {
        // Already logged out, continue with cleanup
      } else {
        // Log error but continue with cleanup anyway
        console.error("Logout error:", error);
      }
    } finally {
      // Cancel proactive token refresh
      cancelProactiveRefresh();

      // Clear master key and derived keys from memory
      clearMasterKeyCache();
      clearDeviceWrappedMK();

      // CRITICAL: Clear all tokens from storage BEFORE redirect
      // This prevents auto-refresh from re-authenticating the user
      clearAllTokens();

      // Clear user info from localStorage
      localStorage.removeItem("stenvault-user-info");

      // Clear legacy auth token (backward compatibility)
      localStorage.removeItem("authToken");

      // Clear email verification banner dismissal
      localStorage.removeItem("email-verification-banner-dismissed");

      // Clear React Query cache
      utils.auth.me.setData(undefined, null);
      await utils.auth.me.invalidate();

      // Redirect to landing page after logout
      window.location.href = "/landing";
    }
  }, [logoutMutation, utils]);

  // Pure computation - no side effects
  const state = useMemo(() => {
    return {
      user: meQuery.data ?? null,
      loading: meQuery.isLoading || logoutMutation.isPending,
      error: meQuery.error ?? logoutMutation.error ?? null,
      isAuthenticated: Boolean(meQuery.data),
    };
  }, [
    meQuery.data,
    meQuery.error,
    meQuery.isLoading,
    logoutMutation.error,
    logoutMutation.isPending,
  ]);

  // Side effect: persist user info to localStorage (separate from useMemo)
  useEffect(() => {
    localStorage.setItem(
      "stenvault-user-info",
      JSON.stringify(state.user)
    );
  }, [state.user]);

  useEffect(() => {
    if (!redirectOnUnauthenticated) return;
    if (meQuery.isLoading || logoutMutation.isPending) return;
    if (state.user) return;
    if (typeof window === "undefined") return;
    if (window.location.pathname === redirectPath) return;
    // Don't redirect if already on auth pages
    if (window.location.pathname.startsWith("/auth/")) return;

    window.location.href = redirectPath;
  }, [
    redirectOnUnauthenticated,
    redirectPath,
    logoutMutation.isPending,
    meQuery.isLoading,
    state.user,
  ]);

  return {
    ...state,
    refresh: () => meQuery.refetch(),
    logout,
  };
}
