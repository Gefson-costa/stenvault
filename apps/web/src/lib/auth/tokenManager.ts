/**
 * Token Manager - Web
 *
 * With HttpOnly cookies, the browser handles token lifecycle automatically.
 * The server sets/clears cookies; the frontend just needs to call the
 * refresh endpoint when a 401 occurs.
 *
 * Proactive refresh: schedules a silent refresh before the access token
 * expires, so 401s rarely happen during normal usage.
 *
 * @version 3.0.0
 */

import { clearTokens, type TokenPair } from './tokenStorage';

// ============ Config ============

/** Access token TTL on the server (must match AUTH_STANDALONE ACCESS_TOKEN_EXPIRY) */
const ACCESS_TOKEN_TTL_MS = 30 * 60 * 1000; // 30 minutes

/** Refresh proactively at 80% of TTL (i.e. 24 min into a 30 min token) */
const PROACTIVE_REFRESH_MS = ACCESS_TOKEN_TTL_MS * 0.8;

// ============ State ============

/** Lock to prevent concurrent refresh attempts */
let isRefreshing = false;

/** Queue of callbacks waiting for refresh to complete */
let refreshSubscribers: Array<(success: boolean) => void> = [];

/** Proactive refresh timer */
let proactiveTimer: ReturnType<typeof setTimeout> | null = null;

// ============ Internal Functions ============

function notifySubscribers(success: boolean): void {
    refreshSubscribers.forEach(callback => callback(success));
    refreshSubscribers = [];
}

function subscribeToRefresh(): Promise<boolean> {
    return new Promise(resolve => {
        refreshSubscribers.push(resolve);
    });
}

/**
 * Call the refresh endpoint. The refresh token is sent automatically
 * via HttpOnly cookie (credentials: 'include').
 */
async function callRefreshEndpoint(): Promise<boolean> {
    try {
        const response = await fetch('/api/trpc/auth.refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ json: {} }),
        });

        if (!response.ok) {
            console.warn('[TokenManager] Refresh failed:', response.status);
            return false;
        }

        const data = await response.json();
        const result = data?.result?.data?.json ?? data?.result?.data ?? data;
        return result?.success === true;
    } catch (error) {
        console.error('[TokenManager] Refresh error:', error);
        return false;
    }
}

// ============ Public Functions ============

/**
 * No-op: tokens are set as HttpOnly cookies by the server response.
 * Kept for API compatibility during migration.
 */
export function storeTokenPair(_credentials: TokenPair): void {
    // Server sets HttpOnly cookies — nothing to store client-side
}

/**
 * Attempt to refresh the session via HttpOnly cookie.
 * Returns null since access token is not readable from JS.
 *
 * This is called by the tRPC error handler on 401 responses.
 */
export async function getValidAccessToken(): Promise<string | null> {
    // With HttpOnly cookies, we can't read the token.
    // The cookie is sent automatically with credentials: 'include'.
    // This function now only handles refresh logic for 401 recovery.
    return null;
}

/**
 * Attempt to refresh the session. Returns true if refresh succeeded.
 * The server sets new HttpOnly cookies in the response.
 * On success, schedules the next proactive refresh automatically.
 */
export async function refreshSession(): Promise<boolean> {
    if (isRefreshing) {
        return subscribeToRefresh();
    }

    isRefreshing = true;

    try {
        const success = await callRefreshEndpoint();

        if (success) {
            scheduleProactiveRefresh();
        } else {
            cancelProactiveRefresh();
            clearTokens();
        }

        notifySubscribers(success);
        return success;
    } catch (error) {
        console.error('[TokenManager] Refresh error:', error);
        cancelProactiveRefresh();
        clearTokens();
        notifySubscribers(false);
        return false;
    } finally {
        isRefreshing = false;
    }
}

/**
 * Schedule a silent refresh before the access token expires.
 * Called after login and after every successful refresh.
 */
export function scheduleProactiveRefresh(): void {
    cancelProactiveRefresh();
    proactiveTimer = setTimeout(async () => {
        proactiveTimer = null;
        const ok = await refreshSession();
        if (!ok) {
            console.warn('[TokenManager] Proactive refresh failed — will retry on next 401');
        }
    }, PROACTIVE_REFRESH_MS);
}

/**
 * Cancel the proactive refresh timer (on logout or failed refresh).
 */
export function cancelProactiveRefresh(): void {
    if (proactiveTimer) {
        clearTimeout(proactiveTimer);
        proactiveTimer = null;
    }
}

/**
 * Clear legacy tokens from storage.
 * HttpOnly cookies are cleared by the server on logout.
 */
export function clearAllTokens(): void {
    clearTokens();
}

/**
 * Cannot determine session validity from JS (HttpOnly cookies).
 * Auth state is managed by the auth.me tRPC query.
 */
export function hasValidSession(): boolean {
    return false;
}

export type { TokenPair } from './tokenStorage';
