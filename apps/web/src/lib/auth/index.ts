/**
 * Auth Module - Web
 *
 * Centralized exports for authentication utilities.
 * Tokens are now HttpOnly cookies — most functions are no-ops.
 *
 * @version 2.0.0
 */

// Token Manager - High-level API
export {
    storeTokenPair,
    getValidAccessToken,
    clearAllTokens,
    hasValidSession,
    refreshSession,
    scheduleProactiveRefresh,
    cancelProactiveRefresh,
    type TokenPair,
} from './tokenManager';

// Token Storage - Low-level API (legacy cleanup)
export {
    saveTokens,
    getAccessToken,
    getRefreshToken,
    getTokenExpiresAt,
    clearTokens,
    isAccessTokenValid,
    hasRefreshToken,
} from './tokenStorage';
