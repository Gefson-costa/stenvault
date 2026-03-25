export declare const appRouter: import("@trpc/server").TRPCBuiltRouter<{
    ctx: import("./_core/context").TrpcContext;
    meta: object;
    errorShape: {
        message: string;
        data: {
            stack: undefined;
            code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
            httpStatus: number;
            path?: string;
        };
        code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
    };
    transformer: true;
}, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
    auth: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        getRegistrationStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                allowPublicRegistration: boolean;
                requireInviteCode: boolean;
                registrationClosedMessage: string;
                isOpen: boolean;
            };
            meta: object;
        }>;
        validateInviteCode: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                code: string;
            };
            output: {
                valid: boolean;
                reason?: string;
                codeId?: number;
                label?: string;
            };
            meta: object;
        }>;
        opaqueRegisterStart: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                email: string;
                registrationRequest: string;
            };
            output: {
                registrationResponse: string;
            };
            meta: object;
        }>;
        opaqueRegisterFinish: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                email: string;
                registrationRecord: string;
                name?: string | undefined;
                inviteCode?: string | undefined;
            };
            output: {
                success: boolean;
                user: Omit<{
                    id: number;
                    openId: string | null;
                    name: string | null;
                    email: string;
                    password: string | null;
                    opaqueRecord: string | null;
                    authMethod: string | null;
                    loginMethod: string | null;
                    role: "user" | "admin";
                    emailVerified: Date | null;
                    storageUsed: number;
                    storageQuota: number;
                    maxFileSize: number;
                    maxShares: number;
                    sharesUsed: number;
                    stripeCustomerId: string | null;
                    stripeSubscriptionId: string | null;
                    stripePriceId: string | null;
                    subscriptionStatus: "free" | "trialing" | "active" | "past_due" | "canceled" | "incomplete";
                    subscriptionPlan: "free" | "pro" | "business";
                    trialEndsAt: Date | null;
                    subscriptionEndsAt: Date | null;
                    hasCustomQuotas: boolean;
                    pastDueSince: Date | null;
                    overQuotaSince: Date | null;
                    cardFingerprint: string | null;
                    cardLast4: string | null;
                    hasActiveDispute: boolean;
                    cancelAtPeriodEnd: boolean;
                    mfaEnabled: boolean;
                    mfaSecret: string | null;
                    backupCodes: string | null;
                    createdAt: Date;
                    updatedAt: Date;
                    lastSignedIn: Date;
                }, "password" | "opaqueRecord" | "mfaSecret" | "backupCodes">;
                accessToken: string;
                credentials: {
                    accessToken: string;
                    refreshToken: string;
                    expiresIn: number;
                    sessionId: string;
                };
            };
            meta: object;
        }>;
        opaqueLoginStart: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                email: string;
                startLoginRequest: string;
            };
            output: {
                loginResponse: string;
            };
            meta: object;
        }>;
        opaqueLoginFinish: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                email: string;
                finishLoginRequest: string;
            };
            output: {
                success: true;
                mfaRequired: true;
                mfaToken: string;
                user?: undefined;
                accessToken?: undefined;
                credentials?: undefined;
            } | {
                success: true;
                mfaRequired: false;
                user: Omit<{
                    id: number;
                    openId: string | null;
                    name: string | null;
                    email: string;
                    password: string | null;
                    opaqueRecord: string | null;
                    authMethod: string | null;
                    loginMethod: string | null;
                    role: "user" | "admin";
                    emailVerified: Date | null;
                    storageUsed: number;
                    storageQuota: number;
                    maxFileSize: number;
                    maxShares: number;
                    sharesUsed: number;
                    stripeCustomerId: string | null;
                    stripeSubscriptionId: string | null;
                    stripePriceId: string | null;
                    subscriptionStatus: "free" | "trialing" | "active" | "past_due" | "canceled" | "incomplete";
                    subscriptionPlan: "free" | "pro" | "business";
                    trialEndsAt: Date | null;
                    subscriptionEndsAt: Date | null;
                    hasCustomQuotas: boolean;
                    pastDueSince: Date | null;
                    overQuotaSince: Date | null;
                    cardFingerprint: string | null;
                    cardLast4: string | null;
                    hasActiveDispute: boolean;
                    cancelAtPeriodEnd: boolean;
                    mfaEnabled: boolean;
                    mfaSecret: string | null;
                    backupCodes: string | null;
                    createdAt: Date;
                    updatedAt: Date;
                    lastSignedIn: Date;
                }, "password" | "opaqueRecord" | "mfaSecret" | "backupCodes">;
                accessToken: string;
                credentials: {
                    accessToken: string;
                    refreshToken: string;
                    expiresIn: number;
                    sessionId: string;
                };
                mfaToken?: undefined;
            };
            meta: object;
        }>;
        verifyMFA: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                mfaToken: string;
                totpCode: string;
            };
            output: {
                success: boolean;
                user: Omit<{
                    id: number;
                    openId: string | null;
                    name: string | null;
                    email: string;
                    password: string | null;
                    opaqueRecord: string | null;
                    authMethod: string | null;
                    loginMethod: string | null;
                    role: "user" | "admin";
                    emailVerified: Date | null;
                    storageUsed: number;
                    storageQuota: number;
                    maxFileSize: number;
                    maxShares: number;
                    sharesUsed: number;
                    stripeCustomerId: string | null;
                    stripeSubscriptionId: string | null;
                    stripePriceId: string | null;
                    subscriptionStatus: "free" | "trialing" | "active" | "past_due" | "canceled" | "incomplete";
                    subscriptionPlan: "free" | "pro" | "business";
                    trialEndsAt: Date | null;
                    subscriptionEndsAt: Date | null;
                    hasCustomQuotas: boolean;
                    pastDueSince: Date | null;
                    overQuotaSince: Date | null;
                    cardFingerprint: string | null;
                    cardLast4: string | null;
                    hasActiveDispute: boolean;
                    cancelAtPeriodEnd: boolean;
                    mfaEnabled: boolean;
                    mfaSecret: string | null;
                    backupCodes: string | null;
                    createdAt: Date;
                    updatedAt: Date;
                    lastSignedIn: Date;
                }, "password" | "opaqueRecord" | "mfaSecret" | "backupCodes">;
                accessToken: string;
                credentials: {
                    accessToken: string;
                    refreshToken: string;
                    expiresIn: number;
                    sessionId: string;
                };
            };
            meta: object;
        }>;
        opaqueChangePasswordStart: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                startLoginRequest: string;
            };
            output: {
                loginResponse: string;
            };
            meta: object;
        }>;
        opaqueChangePasswordFinish: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                finishLoginRequest: string;
                newRegistrationRecord: string;
                masterKeyEncrypted?: string | undefined;
                newSalt?: string | undefined;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        opaqueResetPasswordStart: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                token: string;
                registrationRequest: string;
            };
            output: {
                registrationResponse: string;
                email: string;
            };
            meta: object;
        }>;
        opaqueResetPasswordFinish: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                token: string;
                registrationRecord: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        /**
         * Refresh access token using refresh token
         *
         * Security Features:
         * - Validates refresh token signature
         * - Checks revocation status (fail-closed)
         * - Token family rotation detection (detects stolen tokens)
         * - Generates new token pair
         * - Revokes old refresh token
         */
        refresh: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                refreshToken?: string | undefined;
            };
            output: {
                user: Omit<{
                    id: number;
                    openId: string | null;
                    name: string | null;
                    email: string;
                    password: string | null;
                    opaqueRecord: string | null;
                    authMethod: string | null;
                    loginMethod: string | null;
                    role: "user" | "admin";
                    emailVerified: Date | null;
                    storageUsed: number;
                    storageQuota: number;
                    maxFileSize: number;
                    maxShares: number;
                    sharesUsed: number;
                    stripeCustomerId: string | null;
                    stripeSubscriptionId: string | null;
                    stripePriceId: string | null;
                    subscriptionStatus: "free" | "trialing" | "active" | "past_due" | "canceled" | "incomplete";
                    subscriptionPlan: "free" | "pro" | "business";
                    trialEndsAt: Date | null;
                    subscriptionEndsAt: Date | null;
                    hasCustomQuotas: boolean;
                    pastDueSince: Date | null;
                    overQuotaSince: Date | null;
                    cardFingerprint: string | null;
                    cardLast4: string | null;
                    hasActiveDispute: boolean;
                    cancelAtPeriodEnd: boolean;
                    mfaEnabled: boolean;
                    mfaSecret: string | null;
                    backupCodes: string | null;
                    createdAt: Date;
                    updatedAt: Date;
                    lastSignedIn: Date;
                }, "password" | "opaqueRecord" | "mfaSecret" | "backupCodes">;
                accessToken: string;
                refreshToken: string;
                expiresIn: number;
                success: boolean;
            };
            meta: object;
        }>;
        sendVerificationEmail: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                email: string;
            };
            output: {
                success: boolean;
                emailSent: boolean;
            };
            meta: object;
        }>;
        verifyEmailToken: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                token: string;
            };
            output: {
                success: boolean;
                user: Omit<{
                    id: number;
                    openId: string | null;
                    name: string | null;
                    email: string;
                    password: string | null;
                    opaqueRecord: string | null;
                    authMethod: string | null;
                    loginMethod: string | null;
                    role: "user" | "admin";
                    emailVerified: Date | null;
                    storageUsed: number;
                    storageQuota: number;
                    maxFileSize: number;
                    maxShares: number;
                    sharesUsed: number;
                    stripeCustomerId: string | null;
                    stripeSubscriptionId: string | null;
                    stripePriceId: string | null;
                    subscriptionStatus: "free" | "trialing" | "active" | "past_due" | "canceled" | "incomplete";
                    subscriptionPlan: "free" | "pro" | "business";
                    trialEndsAt: Date | null;
                    subscriptionEndsAt: Date | null;
                    hasCustomQuotas: boolean;
                    pastDueSince: Date | null;
                    overQuotaSince: Date | null;
                    cardFingerprint: string | null;
                    cardLast4: string | null;
                    hasActiveDispute: boolean;
                    cancelAtPeriodEnd: boolean;
                    mfaEnabled: boolean;
                    mfaSecret: string | null;
                    backupCodes: string | null;
                    createdAt: Date;
                    updatedAt: Date;
                    lastSignedIn: Date;
                }, "password" | "opaqueRecord" | "mfaSecret" | "backupCodes">;
                accessToken: string;
                credentials: {
                    accessToken: string;
                    refreshToken: string;
                    expiresIn: number;
                };
            };
            meta: object;
        }>;
        verifyEmailOTP: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                email: string;
                otp: string;
            };
            output: {
                success: boolean;
                user: Omit<{
                    id: number;
                    openId: string | null;
                    name: string | null;
                    email: string;
                    password: string | null;
                    opaqueRecord: string | null;
                    authMethod: string | null;
                    loginMethod: string | null;
                    role: "user" | "admin";
                    emailVerified: Date | null;
                    storageUsed: number;
                    storageQuota: number;
                    maxFileSize: number;
                    maxShares: number;
                    sharesUsed: number;
                    stripeCustomerId: string | null;
                    stripeSubscriptionId: string | null;
                    stripePriceId: string | null;
                    subscriptionStatus: "free" | "trialing" | "active" | "past_due" | "canceled" | "incomplete";
                    subscriptionPlan: "free" | "pro" | "business";
                    trialEndsAt: Date | null;
                    subscriptionEndsAt: Date | null;
                    hasCustomQuotas: boolean;
                    pastDueSince: Date | null;
                    overQuotaSince: Date | null;
                    cardFingerprint: string | null;
                    cardLast4: string | null;
                    hasActiveDispute: boolean;
                    cancelAtPeriodEnd: boolean;
                    mfaEnabled: boolean;
                    mfaSecret: string | null;
                    backupCodes: string | null;
                    createdAt: Date;
                    updatedAt: Date;
                    lastSignedIn: Date;
                }, "password" | "opaqueRecord" | "mfaSecret" | "backupCodes">;
                accessToken: string;
                credentials: {
                    accessToken: string;
                    refreshToken: string;
                    expiresIn: number;
                };
            };
            meta: object;
        }>;
        sendMagicLink: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                email: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        verifyMagicLink: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                token: string;
            };
            output: {
                success: true;
                mfaRequired: true;
                mfaToken: string;
                user?: undefined;
                accessToken?: undefined;
                credentials?: undefined;
            } | {
                success: true;
                mfaRequired: false;
                user: Omit<{
                    id: number;
                    openId: string | null;
                    name: string | null;
                    email: string;
                    password: string | null;
                    opaqueRecord: string | null;
                    authMethod: string | null;
                    loginMethod: string | null;
                    role: "user" | "admin";
                    emailVerified: Date | null;
                    storageUsed: number;
                    storageQuota: number;
                    maxFileSize: number;
                    maxShares: number;
                    sharesUsed: number;
                    stripeCustomerId: string | null;
                    stripeSubscriptionId: string | null;
                    stripePriceId: string | null;
                    subscriptionStatus: "free" | "trialing" | "active" | "past_due" | "canceled" | "incomplete";
                    subscriptionPlan: "free" | "pro" | "business";
                    trialEndsAt: Date | null;
                    subscriptionEndsAt: Date | null;
                    hasCustomQuotas: boolean;
                    pastDueSince: Date | null;
                    overQuotaSince: Date | null;
                    cardFingerprint: string | null;
                    cardLast4: string | null;
                    hasActiveDispute: boolean;
                    cancelAtPeriodEnd: boolean;
                    mfaEnabled: boolean;
                    mfaSecret: string | null;
                    backupCodes: string | null;
                    createdAt: Date;
                    updatedAt: Date;
                    lastSignedIn: Date;
                }, "password" | "opaqueRecord" | "mfaSecret" | "backupCodes">;
                accessToken: string;
                credentials: {
                    accessToken: string;
                    refreshToken: string;
                    expiresIn: number;
                };
                mfaToken?: undefined;
            };
            meta: object;
        }>;
        verifyOTP: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                email: string;
                otp: string;
            };
            output: {
                success: true;
                mfaRequired: true;
                mfaToken: string;
                user?: undefined;
                accessToken?: undefined;
                credentials?: undefined;
            } | {
                success: true;
                mfaRequired: false;
                user: Omit<{
                    id: number;
                    openId: string | null;
                    name: string | null;
                    email: string;
                    password: string | null;
                    opaqueRecord: string | null;
                    authMethod: string | null;
                    loginMethod: string | null;
                    role: "user" | "admin";
                    emailVerified: Date | null;
                    storageUsed: number;
                    storageQuota: number;
                    maxFileSize: number;
                    maxShares: number;
                    sharesUsed: number;
                    stripeCustomerId: string | null;
                    stripeSubscriptionId: string | null;
                    stripePriceId: string | null;
                    subscriptionStatus: "free" | "trialing" | "active" | "past_due" | "canceled" | "incomplete";
                    subscriptionPlan: "free" | "pro" | "business";
                    trialEndsAt: Date | null;
                    subscriptionEndsAt: Date | null;
                    hasCustomQuotas: boolean;
                    pastDueSince: Date | null;
                    overQuotaSince: Date | null;
                    cardFingerprint: string | null;
                    cardLast4: string | null;
                    hasActiveDispute: boolean;
                    cancelAtPeriodEnd: boolean;
                    mfaEnabled: boolean;
                    mfaSecret: string | null;
                    backupCodes: string | null;
                    createdAt: Date;
                    updatedAt: Date;
                    lastSignedIn: Date;
                }, "password" | "opaqueRecord" | "mfaSecret" | "backupCodes">;
                accessToken: string;
                credentials: {
                    accessToken: string;
                    refreshToken: string;
                    expiresIn: number;
                };
                mfaToken?: undefined;
            };
            meta: object;
        }>;
        sendPasswordReset: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                email: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        me: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: Omit<{
                role: "user" | "admin";
                id: number;
                openId: string | null;
                name: string | null;
                email: string;
                password: string | null;
                opaqueRecord: string | null;
                authMethod: string | null;
                loginMethod: string | null;
                emailVerified: Date | null;
                storageUsed: number;
                storageQuota: number;
                maxFileSize: number;
                maxShares: number;
                sharesUsed: number;
                stripeCustomerId: string | null;
                stripeSubscriptionId: string | null;
                stripePriceId: string | null;
                subscriptionStatus: "free" | "trialing" | "active" | "past_due" | "canceled" | "incomplete";
                subscriptionPlan: "free" | "pro" | "business";
                trialEndsAt: Date | null;
                subscriptionEndsAt: Date | null;
                hasCustomQuotas: boolean;
                pastDueSince: Date | null;
                overQuotaSince: Date | null;
                cardFingerprint: string | null;
                cardLast4: string | null;
                hasActiveDispute: boolean;
                cancelAtPeriodEnd: boolean;
                mfaEnabled: boolean;
                mfaSecret: string | null;
                backupCodes: string | null;
                createdAt: Date;
                updatedAt: Date;
                lastSignedIn: Date;
            }, "password" | "opaqueRecord" | "mfaSecret" | "backupCodes"> | null;
            meta: object;
        }>;
        logout: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                readonly success: true;
            };
            meta: object;
        }>;
        /**
         * Get all active sessions for the current user
         */
        getSessions: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                sessions: import("./db/schema").SessionInfo[];
                maxSessions: number;
                inactivityTimeoutMinutes: number;
            };
            meta: object;
        }>;
        /**
         * Terminate a specific session
         */
        terminateSession: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        /**
         * Terminate all sessions except the current one
         * "Logout from all other devices"
         */
        terminateOtherSessions: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                success: boolean;
                terminatedCount: number;
            };
            meta: object;
        }>;
    }>>;
    settings: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        getPublicConfig: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                rateLimitRequests: any;
                rateLimitWindowMs: any;
                maxFileSize: any;
                maxStoragePerUser: any;
            };
            meta: object;
        }>;
        getSystemHealth: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                status: string;
                timestamp: string;
                services: {
                    database: boolean;
                    redis: boolean | null;
                    r2Storage: boolean | null;
                    email: boolean;
                };
            };
            meta: object;
        }>;
        get: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                key: string;
                defaultValue: string;
            };
            output: string;
            meta: object;
        }>;
        set: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                key: string;
                value: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
    }>>;
    chat: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        getPeerHybridPublicKey: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                userId: number;
            };
            output: {
                success: boolean;
                hybridPublicKey: null;
            } | {
                success: boolean;
                hybridPublicKey: {
                    x25519PublicKey: string;
                    mlkem768PublicKey: string;
                    keyVersion: number;
                    fingerprint: string | null;
                };
            };
            meta: object;
        }>;
        getMyConnections: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                success: boolean;
                connections: {
                    lastMessage: {
                        id: number;
                        fromUserId: number;
                        toUserId: number;
                        content: string | null;
                        messageType: string;
                        isEncrypted: boolean;
                        createdAt: Date;
                    } | null;
                    unreadCount: number;
                    id: number;
                    userId: number;
                    connectedUserId: number;
                    nickname: string | null;
                    status: "pending" | "accepted" | "blocked";
                    createdAt: Date;
                    updatedAt: Date;
                    connectedUserEmail: string | null;
                    connectedUserName: string | null;
                }[];
            };
            meta: object;
        }>;
        blockConnection: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                connectionId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        unblockConnection: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                connectionId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        updateConnectionNickname: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                connectionId: number;
                nickname: string | null;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        deleteConnection: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                connectionId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        getUnreadCount: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                success: boolean;
                count: number;
            };
            meta: object;
        }>;
        getMessages: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                withUserId: number;
                limit?: number | undefined;
                beforeId?: number | undefined;
            };
            output: {
                success: boolean;
                messages: {
                    id: number;
                    fromUserId: number | null;
                    toUserId: number | null;
                    messageType: "image" | "video" | "text" | "file" | "vault_file";
                    content: string | null;
                    fileKey: string | null;
                    filename: string | null;
                    fileSize: number | null;
                    iv: string | null;
                    salt: string | null;
                    isEncrypted: boolean;
                    keyVersion: number | null;
                    kemCiphertext: string | null;
                    isRead: boolean;
                    isDeleted: boolean;
                    deletedAt: Date | null;
                    createdAt: Date;
                    chatFileShareId: number | null;
                }[];
            };
            meta: object;
        }>;
        sendMessage: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                toUserId: number;
                messageType?: "image" | "video" | "text" | "file" | undefined;
                content?: string | undefined;
                fileKey?: string | undefined;
                filename?: string | undefined;
                fileSize?: number | undefined;
                iv?: string | undefined;
                salt?: string | undefined;
                isEncrypted?: boolean | undefined;
                keyVersion?: number | undefined;
                kemCiphertext?: string | undefined;
            };
            output: {
                success: boolean;
                messageId: number;
            };
            meta: object;
        }>;
        markAsRead: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                messageIds: number[];
            };
            output: {
                success: boolean;
                updated: number;
            };
            meta: object;
        }>;
        deleteMessage: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                messageId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        clearConversation: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                withUserId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        createInvite: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                toEmail: string;
                expiresInHours?: number | undefined;
            };
            output: {
                success: boolean;
                invite: {
                    id: number;
                    inviteCode: string;
                    toEmail: string;
                    expiresAt: Date;
                    fromUserId?: undefined;
                    status?: undefined;
                    createdAt?: undefined;
                };
            } | {
                success: boolean;
                invite: {
                    id: number;
                    inviteCode: string;
                    toEmail: string;
                    expiresAt: Date;
                    fromUserId: number;
                    status: "pending" | "expired" | "revoked" | "accepted";
                    createdAt: Date;
                };
            };
            meta: object;
        }>;
        acceptInvite: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                inviteCode: string;
            };
            output: {
                success: boolean;
                connectionUserId: number;
                message: string;
            } | {
                success: boolean;
                connectionUserId: number;
                message?: undefined;
            };
            meta: object;
        }>;
        getMySentInvites: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                limit?: number | undefined;
                offset?: number | undefined;
                status?: "pending" | "expired" | "revoked" | "accepted" | "all" | undefined;
            };
            output: {
                success: boolean;
                invites: {
                    id: number;
                    fromUserId: number;
                    toEmail: string;
                    inviteCode: string;
                    inviteType: "platform" | "chat";
                    status: "pending" | "expired" | "revoked" | "accepted";
                    expiresAt: Date;
                    createdAt: Date;
                }[];
                pagination: {
                    total: number;
                    limit: number;
                    offset: number;
                    hasMore: boolean;
                };
            };
            meta: object;
        }>;
        revokeInvite: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                inviteId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        autoInvite: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                targetUserId: number;
            };
            output: {
                success: boolean;
                inviteId: number;
                message: string;
                inviteCode?: undefined;
            } | {
                success: boolean;
                inviteId: number;
                inviteCode: string;
                message: string;
            };
            meta: object;
        }>;
        getMyPendingInvites: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                success: boolean;
                invites: {
                    id: number;
                    inviteCode: string;
                    from: {
                        id: number;
                        email: string | null;
                        name: string | null;
                    };
                    createdAt: Date;
                    expiresAt: Date;
                }[];
                count: number;
            };
            meta: object;
        }>;
        getAttachmentUploadUrl: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                filename: string;
                mimeType: "application/msword" | "image/jpeg" | "image/jpg" | "image/png" | "image/webp" | "image/gif" | "video/mp4" | "video/webm" | "video/quicktime" | "application/pdf" | "application/vnd.openxmlformats-officedocument.wordprocessingml.document" | "text/plain" | "text/csv" | "application/json" | "application/xml" | "text/xml";
                size: number;
            };
            output: {
                uploadUrl: string;
                fileKey: string;
            };
            meta: object;
        }>;
        getAttachmentDownloadUrl: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileKey: string;
            };
            output: {
                url: string;
            };
            meta: object;
        }>;
        initiateChannel: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                peerUserId: number;
                kemCiphertext: string;
                salt: string;
                initiatorX25519Public: string;
                wrappedSecret: string;
                keyVersion?: number | undefined;
            };
            output: {
                channelId: number;
                keyVersion: number;
                alreadyActive: boolean;
            };
            meta: object;
        }>;
        completeChannel: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                peerUserId: number;
                wrappedSecret: string;
            };
            output: {
                success: boolean;
                keyVersion: number;
            };
            meta: object;
        }>;
        getChannelSecret: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                peerUserId: number;
                keyVersion?: number | undefined;
            };
            output: {
                status: string;
                keyVersion: number;
                wrappedSecret: string | null;
                initiatedBy: number;
                kemCiphertext?: string | null;
                agreementSalt?: string | null;
                initiatorX25519Public?: string | null;
            } | null;
            meta: object;
        }>;
        getChannelStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                peerUserId: number;
            };
            output: {
                status: "active" | "pending" | "rotated";
                keyVersion: number;
                initiatedBy: number;
            } | null;
            meta: object;
        }>;
        rotateChannel: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                peerUserId: number;
                kemCiphertext: string;
                salt: string;
                initiatorX25519Public: string;
                wrappedSecret: string;
            };
            output: {
                channelId: number;
                keyVersion: number;
            };
            meta: object;
        }>;
    }>>;
    chatFileShare: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        shareFileToChat: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                recipientUserId: number;
                encryptedFileKey: string;
                keyIv: string;
                keyDerivationSalt: string;
                kemCiphertext: string;
                recipientKeyFingerprint?: string | undefined;
                permission?: "view" | "download" | undefined;
                expiresIn?: "never" | "7d" | "1h" | "24h" | "30d" | undefined;
                expiresAt?: Date | undefined;
                maxDownloads?: number | undefined;
                messageContent?: string | undefined;
            };
            output: import("./_core/chatFileShare").ShareFileToChatResponse;
            meta: object;
        }>;
        getShareDetails: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                shareId: number;
            };
            output: import("./_core/chatFileShare").ShareDetailsResponse;
            meta: object;
        }>;
        getFileAccess: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                shareId: number;
            };
            output: import("./_core/chatFileShare").FileAccessResponse;
            meta: object;
        }>;
        revokeShare: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                shareId: number;
                reason?: string | undefined;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        listMyShares: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                limit?: number | undefined;
                offset?: number | undefined;
                status?: "active" | "expired" | "revoked" | "all" | undefined;
            };
            output: {
                success: boolean;
                shares: import("./_core/chatFileShare").ShareListItem[];
                total: number;
                hasMore: boolean;
            };
            meta: object;
        }>;
        listSharedWithMe: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                limit?: number | undefined;
                offset?: number | undefined;
                status?: "active" | "expired" | "revoked" | "all" | undefined;
            };
            output: {
                success: boolean;
                shares: import("./_core/chatFileShare").SharedWithMeItem[];
                total: number;
                hasMore: boolean;
            };
            meta: object;
        }>;
        getShareStats: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                success: boolean;
                sent: {
                    total: number;
                    active: number;
                    revoked: number;
                    expired: number;
                };
                received: {
                    total: number;
                    active: number;
                    revoked: number;
                    expired: number;
                };
            };
            meta: object;
        }>;
    }>>;
    files: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        getUploadUrl: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                filename: string;
                contentType: string;
                size: number;
                folderId?: number | null | undefined;
                organizationId?: number | null | undefined;
                encryptedFilename?: string | undefined;
                filenameIv?: string | undefined;
                plaintextExtension?: string | undefined;
                originalMimeType?: string | undefined;
            };
            output: {
                uploadUrl: string;
                fileId: number;
                fileKey: string;
                createdAt: Date;
                expiresIn: number;
            };
            meta: object;
        }>;
        confirmUpload: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                contentHash?: string | undefined;
                fingerprintVersion?: number | undefined;
                encryptionIv?: string | undefined;
                encryptionSalt?: string | undefined;
                encryptionVersion?: number | undefined;
                orgKeyVersion?: number | undefined;
                signatureParams?: {
                    classicalSignature: string;
                    pqSignature: string;
                    signingContext: "FILE" | "TIMESTAMP" | "SHARE";
                    signedAt: number;
                    signerFingerprint: string;
                    signerKeyVersion: number;
                    signedHash?: string | undefined;
                } | undefined;
                thumbnailMetadata?: {
                    thumbnailKey: string;
                    thumbnailIv: string;
                    thumbnailSize: number;
                } | undefined;
            };
            output: {
                success: boolean;
                file: {
                    id: number;
                    filename: string;
                    mimeType: string | null;
                    size: number;
                    createdAt: Date;
                };
            };
            meta: object;
        }>;
        cancelUpload: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        checkDuplicate: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                contentHash: string;
                size: number;
                folderId?: number | null | undefined;
            };
            output: {
                isDuplicate: false;
                existingFileId?: undefined;
                existingEncryptedFilename?: undefined;
                existingFilenameIv?: undefined;
                existingSize?: undefined;
                existingFolderId?: undefined;
                existingCreatedAt?: undefined;
            } | {
                isDuplicate: true;
                existingFileId: number;
                existingEncryptedFilename: string | null;
                existingFilenameIv: string | null;
                existingSize: number;
                existingFolderId: number | null;
                existingCreatedAt: Date;
            };
            meta: object;
        }>;
        getThumbnailUploadUrl: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                size: number;
            };
            output: {
                uploadUrl: string;
                thumbnailKey: string;
                expiresIn: number;
            };
            meta: object;
        }>;
        list: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                folderId?: number | null | undefined;
                orderBy?: "date" | "name" | "size" | undefined;
                order?: "asc" | "desc" | undefined;
                cursor?: number | undefined;
                limit?: number | undefined;
                organizationId?: number | null | undefined;
            };
            output: {
                files: never[];
                nextCursor: null;
                hasMore?: undefined;
            } | {
                files: {
                    id: number;
                    filename: string;
                    mimeType: string | null;
                    size: number;
                    folderId: number | null;
                    fileType: "image" | "video" | "audio" | "document" | "other";
                    createdAt: Date;
                    updatedAt: Date;
                    isFavorite: boolean;
                    organizationId: number | null;
                    userId: number;
                    encryptedFilename: string | null;
                    filenameIv: string | null;
                    plaintextExtension: string | null;
                    encryptionVersion: number | null;
                    orgKeyVersion: number | null;
                    thumbnailUrl: string | null;
                    thumbnailIv: string | null;
                    duplicatedFromId: number | null;
                    isSigned: boolean;
                    signedAt: Date | null;
                }[];
                nextCursor: number | null | undefined;
                hasMore: boolean;
            };
            meta: object;
        }>;
        getById: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileId: number;
            };
            output: {
                id: number;
                filename: string;
                mimeType: string | null;
                size: number;
                folderId: number | null;
                fileKey: string;
                fileType: "image" | "video" | "audio" | "document" | "other";
                createdAt: Date;
                updatedAt: Date;
            };
            meta: object;
        }>;
        getDownloadUrl: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileId: number;
            };
            output: {
                url: string;
                filename: string;
                contentType: string | null;
                expiresIn: any;
                encryptionIv: string | null;
                encryptionSalt: string | null;
                encryptionVersion: number | null;
                organizationId: number | null;
                orgKeyVersion: number | null;
                signatureInfo: {
                    signerId: number;
                    signerFingerprint: string | null;
                    signerKeyVersion: number;
                    signedAt: Date;
                    signingContext: "FILE" | "TIMESTAMP" | "SHARE";
                } | null;
                encryptedFilename: string | null;
                filenameIv: string | null;
                plaintextExtension: string | null;
            };
            meta: object;
        }>;
        getStreamUrl: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileId: number;
            };
            output: {
                url: string;
                filename: string;
                contentType: string | null;
                size: number;
                fileType: "video" | "audio";
                encryptionIv: string | null;
                encryptionSalt: string | null;
                encryptionVersion: number | null;
                organizationId: number | null;
                orgKeyVersion: number | null;
            };
            meta: object;
        }>;
        getThumbnailUrl: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileId: number;
            };
            output: {
                url: string;
                filename: string;
                mimeType: string | null;
                hasThumbnail: boolean;
                isEncryptedThumbnail: boolean;
                thumbnailIv: string | null;
            };
            meta: object;
        }>;
        getThumbnailUrls: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileIds: number[];
            };
            output: {
                thumbnails: {
                    fileId: number;
                    url: string;
                    filename: string;
                    mimeType: string | null;
                    hasThumbnail: boolean;
                    isEncryptedThumbnail: boolean;
                    thumbnailIv: string | null;
                }[];
            };
            meta: object;
        }>;
        listRecent: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileIds?: number[] | undefined;
            } | undefined;
            output: {
                id: number;
                filename: string;
                mimeType: string | null;
                size: number;
                fileKey: string;
                fileType: "image" | "video" | "audio" | "document" | "other";
                folderId: number | null;
                createdAt: Date;
                updatedAt: Date;
            }[];
            meta: object;
        }>;
        listFavorites: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                limit?: number | undefined;
            };
            output: {
                id: number;
                filename: string;
                mimeType: string | null;
                size: number;
                fileKey: string;
                fileType: "image" | "video" | "audio" | "document" | "other";
                isFavorite: boolean;
                folderId: number | null;
                createdAt: Date;
                updatedAt: Date;
            }[];
            meta: object;
        }>;
        search: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                query: string;
                limit?: number | undefined;
                folderId?: number | null | undefined;
            };
            output: {
                id: number;
                filename: string;
                mimeType: string | null;
                size: number;
                fileKey: string;
                fileType: "image" | "video" | "audio" | "document" | "other";
                isFavorite: boolean;
                folderId: number | null;
                createdAt: Date;
                updatedAt: Date;
                encryptedFilename: string | null;
                filenameIv: string | null;
                plaintextExtension: string | null;
            }[];
            meta: object;
        }>;
        delete: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        deleteMany: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileIds: number[];
            };
            output: {
                deleted: number[];
                failed: {
                    id: number;
                    error: string;
                }[];
            };
            meta: object;
        }>;
        rename: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                newName: string;
            };
            output: {
                success: boolean;
                file: {
                    id: number;
                    filename: string;
                };
            };
            meta: object;
        }>;
        renameMany: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                renames: {
                    fileId: number;
                    newName: string;
                }[];
            };
            output: {
                renamed: {
                    fileId: number;
                    newName: string;
                }[];
                failed: {
                    fileId: number;
                    error: string;
                }[];
            };
            meta: object;
        }>;
        move: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                targetFolderId: number | null;
            };
            output: {
                success: boolean;
                file: {
                    id: number;
                    folderId: number | null;
                };
            };
            meta: object;
        }>;
        listDeleted: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                deletedAt: Date;
                daysUntilPermanentDeletion: number;
                id: number;
                userId: number;
                organizationId: number | null;
                fileKey: string;
                url: string;
                filename: string;
                mimeType: string | null;
                size: number;
                fileType: "image" | "video" | "audio" | "document" | "other";
                folderId: number | null;
                isDeleted: boolean;
                isFavorite: boolean;
                encryptionIv: string | null;
                encryptionSalt: string | null;
                encryptionVersion: number | null;
                encryptedFilename: string | null;
                filenameIv: string | null;
                plaintextExtension: string | null;
                contentHash: string | null;
                fingerprintVersion: number | null;
                thumbnailKey: string | null;
                encryptedThumbnailKey: string | null;
                thumbnailIv: string | null;
                duplicatedFromId: number | null;
                orgKeyVersion: number | null;
                timestampEnabled: boolean | null;
                createdAt: Date;
                updatedAt: Date;
            }[];
            meta: object;
        }>;
        restore: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
            };
            output: {
                success: boolean;
                message: string;
            } | {
                success: boolean;
                message?: undefined;
            };
            meta: object;
        }>;
        permanentDelete: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        emptyTrash: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                success: boolean;
                deletedCount: number;
                message: string;
            };
            meta: object;
        }>;
        toggleFavorite: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
            };
            output: {
                success: boolean;
                isFavorite: boolean;
                fileId: number;
            };
            meta: object;
        }>;
        duplicate: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
            };
            output: {
                success: boolean;
                fileId: number;
            };
            meta: object;
        }>;
        getStorageStats: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                totalSize: number;
                fileCount: number;
                storageQuota: any;
                storageUsed: number;
                percentUsed: number;
                remainingSpace: number;
                maxFileSize?: undefined;
                folderUploadMaxFiles?: undefined;
            } | {
                totalSize: number;
                fileCount: number;
                storageQuota: any;
                storageUsed: number;
                percentUsed: number;
                remainingSpace: number;
                maxFileSize: any;
                folderUploadMaxFiles: number;
            };
            meta: object;
        }>;
        getStorageDistribution: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                image: {
                    size: number;
                    count: number;
                };
                video: {
                    size: number;
                    count: number;
                };
                audio: {
                    size: number;
                    count: number;
                };
                document: {
                    size: number;
                    count: number;
                };
                other: {
                    size: number;
                    count: number;
                };
            };
            meta: object;
        }>;
        getVaultSecurityStats: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                totalFiles: number;
                v4Count: number;
                pqcPercentage: number;
            };
            meta: object;
        }>;
        getMultipartConfig: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                threshold: number;
                partSize: number;
                maxParts: number;
                maxFileSize: number;
            };
            meta: object;
        }>;
        initiateMultipartUpload: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                filename: string;
                contentType: string;
                size: number;
                folderId?: number | null | undefined;
                organizationId?: number | null | undefined;
                encryptedFilename?: string | undefined;
                filenameIv?: string | undefined;
                plaintextExtension?: string | undefined;
                originalMimeType?: string | undefined;
            };
            output: {
                uploadId: string;
                fileId: number;
                fileKey: string;
                createdAt: Date;
                partSize: number;
                totalParts: number;
            };
            meta: object;
        }>;
        getUploadPartUrl: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                uploadId: string;
                fileKey: string;
                partNumber: number;
                partSize: number;
            };
            output: {
                uploadUrl: string;
            };
            meta: object;
        }>;
        completeMultipartUpload: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                uploadId: string;
                fileKey: string;
                parts: {
                    partNumber: number;
                    etag: string;
                }[];
                contentHash?: string | undefined;
                fingerprintVersion?: number | undefined;
                encryptionIv?: string | undefined;
                encryptionSalt?: string | undefined;
                encryptionVersion?: number | undefined;
                orgKeyVersion?: number | undefined;
                signatureParams?: {
                    classicalSignature: string;
                    pqSignature: string;
                    signingContext: "FILE" | "TIMESTAMP" | "SHARE";
                    signedAt: number;
                    signerFingerprint: string;
                    signerKeyVersion: number;
                    signedHash?: string | undefined;
                } | undefined;
                thumbnailMetadata?: {
                    thumbnailKey: string;
                    thumbnailIv: string;
                    thumbnailSize: number;
                } | undefined;
            };
            output: {
                success: boolean;
                fileId: number;
                message: string;
            };
            meta: object;
        }>;
        abortMultipartUpload: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                uploadId: string;
                fileKey: string;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        listVersions: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileId: number;
            };
            output: {
                currentVersion: number;
                versions: {
                    id: number;
                    versionNumber: number;
                    size: number;
                    createdBy: number | null;
                    comment: string | null;
                    createdAt: Date;
                }[];
            };
            meta: object;
        }>;
        createVersion: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                comment?: string | undefined;
            };
            output: {
                success: boolean;
                versionNumber: number;
                uploadUrl: string;
                newFileKey: string;
            };
            meta: object;
        }>;
        restoreVersion: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                versionId: number;
            };
            output: {
                success: boolean;
                restoredVersion: number;
                newVersionNumber: number;
            };
            meta: object;
        }>;
        deleteVersion: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                versionId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        getVersionDownloadUrl: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                versionId: number;
            };
            output: {
                url: string;
                filename: string;
                size: number;
                encryptionIv: string | null;
                encryptionSalt: string | null;
                encryptionVersion: number | null;
            };
            meta: object;
        }>;
        getFileDownload: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileId: number;
            };
            output: {
                url: string;
                filename: string;
                contentType: string | null;
                expiresIn: any;
                encryptionIv: string | null;
                encryptionSalt: string | null;
                encryptionVersion: number | null;
                organizationId: number | null;
                orgKeyVersion: number | null;
                signatureInfo: {
                    signerId: number;
                    signerFingerprint: string | null;
                    signerKeyVersion: number;
                    signedAt: Date;
                    signingContext: "FILE" | "TIMESTAMP" | "SHARE";
                } | null;
                encryptedFilename: string | null;
                filenameIv: string | null;
                plaintextExtension: string | null;
            };
            meta: object;
        }>;
    }>>;
    folders: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        createBatch: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                parentId: number | null;
                folders: {
                    tempId: string;
                    parentTempId: string | null;
                    name: string;
                    encryptedName: string;
                    nameIv: string;
                }[];
            };
            output: {
                folderMap: Record<string, number>;
                count: number;
            };
            meta: object;
        }>;
        create: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                name: string;
                parentId?: number | null | undefined;
                encryptedName?: string | undefined;
                nameIv?: string | undefined;
            };
            output: {
                id: number;
                name: string;
                parentId: number | null;
            };
            meta: object;
        }>;
        list: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                parentId?: number | null | undefined;
            };
            output: {
                id: number;
                name: string;
                encryptedName: string | null;
                nameIv: string | null;
                parentId: number | null;
                organizationId: number | null;
                createdAt: Date;
                updatedAt: Date;
            }[];
            meta: object;
        }>;
        getById: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                folderId: number;
            };
            output: {
                id: number;
                name: string;
                encryptedName: string | null;
                nameIv: string | null;
                parentId: number | null;
                organizationId: number | null;
                createdAt: Date;
                updatedAt: Date;
                folders: {
                    id: number;
                    name: string;
                    encryptedName: string | null;
                    nameIv: string | null;
                    parentId: number | null;
                    organizationId: number | null;
                    createdAt: Date;
                }[];
                files: {
                    id: number;
                    filename: string;
                    mimeType: string | null;
                    size: number;
                    fileType: "image" | "video" | "audio" | "document" | "other";
                    createdAt: Date;
                }[];
            };
            meta: object;
        }>;
        rename: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                folderId: number;
                newName: string;
                encryptedName?: string | undefined;
                nameIv?: string | undefined;
            };
            output: {
                success: boolean;
                folder: {
                    id: number;
                    name: string;
                };
            };
            meta: object;
        }>;
        move: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                folderId: number;
                targetParentId: number | null;
            };
            output: {
                success: boolean;
                folder: {
                    id: number;
                    parentId: number | null;
                };
            };
            meta: object;
        }>;
        delete: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                folderId: number;
                recursive?: boolean | undefined;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        listFolderTree: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                folderId: number;
            };
            output: {
                folders: {
                    id: number;
                    name: string;
                    encryptedName: string | null;
                    nameIv: string | null;
                    parentId: number | null;
                    organizationId: number | null;
                }[];
                files: {
                    id: number;
                    filename: string;
                    size: number;
                    folderId: number | null;
                    encryptedFilename: string | null;
                    filenameIv: string | null;
                    plaintextExtension: string | null;
                    encryptionVersion: number | null;
                    encryptionIv: string | null;
                    orgKeyVersion: number | null;
                    mimeType: string | null;
                    createdAt: Date;
                    organizationId: number | null;
                }[];
                totalSize: number;
                totalFiles: number;
            };
            meta: object;
        }>;
        getBreadcrumbs: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                folderId: number | null;
            };
            output: ({
                id: number;
                name: string;
                encryptedName: string | null;
                nameIv: string | null;
                organizationId: number | null;
            } | {
                id: null;
                name: string;
            })[];
            meta: object;
        }>;
    }>>;
    shares: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        createShare: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                recipientEmail?: string | undefined;
                expiration?: "never" | "7d" | "1h" | "24h" | "30d" | undefined;
                maxDownloads?: number | undefined;
                password?: string | undefined;
                encryptedShareKey?: string | undefined;
                shareKeyIv?: string | undefined;
                shareKeySalt?: string | undefined;
                displayFilename?: string | undefined;
                linkFragmentKey?: string | undefined;
            };
            output: {
                success: boolean;
                shareCode: string;
                downloadLink: string;
                expiresAt: Date | null;
            };
            meta: object;
        }>;
        getShareInfo: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                shareCode: string;
            };
            output: {
                file: {
                    filename: string;
                    mimeType: string | null;
                    size: number;
                    fileType: "image" | "video" | "audio" | "document" | "other";
                };
                sharedBy: string;
                hasPassword: boolean;
                hasShareKey: boolean;
                isLinkShare: boolean;
                expiresAt: Date | null;
                downloadsRemaining: number | null;
            };
            meta: object;
        }>;
        downloadShared: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                shareCode: string;
                password?: string | undefined;
            };
            output: {
                url: string;
                filename: string;
                mimeType: string | null;
                encryptionIv: string | null;
                encryptionSalt: string | null;
                encryptionVersion: number | null;
                shareKeyData: {
                    key: string;
                    iv: string;
                    salt: string;
                } | null;
            };
            meta: object;
        }>;
        listMyShares: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                includeExpired?: boolean | undefined;
                includeRevoked?: boolean | undefined;
            } | undefined;
            output: {
                downloadLink: string;
                isExpired: boolean;
                isLimitReached: boolean;
                id: number;
                shareCode: string;
                recipientEmail: string | null;
                expiresAt: Date | null;
                downloadCount: number;
                maxDownloads: number | null;
                isRevoked: boolean;
                createdAt: Date;
                file: {
                    id: number;
                    filename: string;
                    fileType: "image" | "video" | "audio" | "document" | "other";
                    size: number;
                    encryptionVersion: number | null;
                    createdAt: Date;
                    encryptedFilename: string | null;
                    filenameIv: string | null;
                    plaintextExtension: string | null;
                };
            }[];
            meta: object;
        }>;
        listSharedWithMe: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                includeExpired?: boolean | undefined;
            } | undefined;
            output: {
                id: number;
                shareCode: string;
                sharedAt: Date;
                expiresAt: Date | null;
                hasPassword: boolean;
                file: {
                    id: number;
                    filename: string;
                    fileType: "image" | "video" | "audio" | "document" | "other";
                    mimeType: string | null;
                    size: number;
                    encryptedFilename: string | null;
                    filenameIv: string | null;
                    plaintextExtension: string | null;
                };
                sharedBy: {
                    name: string;
                    email: string;
                };
                downloadLink: string;
                isExpired: boolean;
            }[];
            meta: object;
        }>;
        revokeShare: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                shareId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        updateShare: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                shareId: number;
                expiration?: "never" | "7d" | "1h" | "24h" | "30d" | undefined;
                maxDownloads?: number | undefined;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        getShareStats: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                totalShares: number;
                activeShares: number;
                revokedShares: number;
                expiredShares: number;
                totalDownloads: number;
                sharesUsed: number;
                maxShares: number;
            };
            meta: object;
        }>;
    }>>;
    admin: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        getUsers: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                limit?: number | undefined;
                offset?: number | undefined;
                search?: string | undefined;
                role?: "user" | "admin" | "all" | undefined;
            };
            output: {
                users: {
                    fileCount: number;
                    folderCount: number;
                    storageUsedMB: number;
                    storageQuotaMB: number;
                    id: number;
                    email: string;
                    name: string | null;
                    role: "user" | "admin";
                    storageUsed: number;
                    storageQuota: number;
                    maxFileSize: number;
                    maxShares: number;
                    sharesUsed: number;
                    hasCustomQuotas: boolean;
                    subscriptionPlan: "free" | "pro" | "business";
                    createdAt: Date;
                    lastSignedIn: Date;
                }[];
                total: number;
                hasMore: boolean;
            };
            meta: object;
        }>;
        updateUserRole: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                userId: number;
                role: "user" | "admin";
                subscriptionPlan?: "free" | "pro" | "business" | undefined;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        updateUserLimits: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                userId: number;
                storageQuota?: number | undefined;
                maxFileSize?: number | undefined;
                maxShares?: number | undefined;
                hasCustomQuotas?: boolean | undefined;
            };
            output: {
                success: boolean;
                message: string;
                hasCustomQuotas: boolean;
            };
            meta: object;
        }>;
        deleteUser: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                userId: number;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        resetUserRateLimit: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                userId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        getSystemStats: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                users: {
                    total: number;
                    admins: number;
                    regular: number;
                };
                files: {
                    total: number;
                    active: number;
                    deleted: number;
                };
                folders: {
                    total: number;
                    active: number;
                    deleted: number;
                };
                shares: {
                    total: number;
                    active: number;
                    revoked: number;
                };
                storage: {
                    totalBytes: number;
                    totalMB: number;
                    totalGB: number;
                };
                rateLimits: import("./_core/rateLimiter").RateLimitStats;
                timestamp: string;
            };
            meta: object;
        }>;
        getSystemHealth: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                database: boolean;
                redis: boolean;
                storage: boolean;
                timestamp: string;
            };
            meta: object;
        }>;
        getRecentActivity: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                id: number;
                fileType: "image" | "video" | "audio" | "document" | "other";
                size: number;
                createdAt: Date;
                user: {
                    id: number;
                    name: string;
                };
            }[];
            meta: object;
        }>;
        getMetrics: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: import("./_core/metrics").MetricsSummary;
            meta: object;
        }>;
        getHistoricalMetrics: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                hours?: number | undefined;
            };
            output: {
                createdAt: string;
                cpuUsage: number;
                memoryUsed: number;
                memoryTotal: number;
                activeUsers24h: number;
                totalFiles: number;
                totalStorageBytes: number;
                activeConnections: number;
                requestsPerMinute: number;
            }[];
            meta: object;
        }>;
        getAuditLogs: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                limit?: number | undefined;
                offset?: number | undefined;
                search?: string | undefined;
            };
            output: {
                logs: {
                    id: number;
                    userId: number | null;
                    userEmail: string | null;
                    action: "login_success" | "login_failed" | "logout" | "register" | "email_verified" | "password_reset" | "magic_link_sent" | "token_refresh" | "token_refresh_failed" | "file_upload" | "file_download" | "file_delete" | "file_restore" | "file_permanent_delete" | "file_rename" | "file_move" | "file_rejected" | "file_share_create" | "file_share_access" | "file_share_revoke" | "folder_create" | "folder_delete" | "folder_rename" | "folder_move" | "trash_empty" | "admin_user_update" | "admin_quota_change" | "admin_settings_change" | "rate_limit_exceeded" | "suspicious_activity" | "websocket_connect" | "websocket_disconnect" | "account_locked" | "account_unlocked" | "token_family_compromised" | "session_terminated" | "logout_all_devices" | "account_deleted" | "mfa_enabled" | "mfa_disabled" | "master_key_changed" | "admin_account_delete" | "admin_send_delete" | "admin_send_dismiss" | "admin_send_ip_ban" | "admin_send_ip_unban";
                    resourceType: "user" | "file" | "chat" | "folder" | "share" | "system" | null;
                    resourceId: number | null;
                    details: string | null;
                    ipAddress: string | null;
                    userAgent: string | null;
                    success: boolean;
                    errorMessage: string | null;
                    createdAt: Date;
                }[];
                total: number;
            };
            meta: object;
        }>;
        getSettings: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                enableStripe: true;
                stripeConfigStatus: {
                    secretKey: boolean;
                    publishableKey: boolean;
                    webhookSecret: boolean;
                    priceProMonthly: boolean;
                    priceBusinessMonthly: boolean;
                    isFullyConfigured: boolean;
                };
                maxFileSize: any;
                maxStoragePerUser: any;
            };
            meta: object;
        }>;
        updateSettings: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                maxFileSize?: number | undefined;
                maxStoragePerUser?: number | undefined;
                enableStripe?: boolean | undefined;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        getCacheStats: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: import("./_core/folderCache").CacheStats;
            meta: object;
        }>;
        flushAllCaches: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                success: boolean;
                message: string;
                keysDeleted: number;
            };
            meta: object;
        }>;
        invalidateUserCaches: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                userId: number;
            };
            output: {
                success: boolean;
                message: string;
                keysDeleted: number;
            };
            meta: object;
        }>;
        getRegistrationSettings: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                activeCodesCount: number;
                allowPublicRegistration: boolean;
                requireInviteCode: boolean;
                registrationClosedMessage: string;
            };
            meta: object;
        }>;
        updateRegistrationSettings: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                allowPublicRegistration?: boolean | undefined;
                requireInviteCode?: boolean | undefined;
                registrationClosedMessage?: string | undefined;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        getInviteCodes: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                includeRevoked?: boolean | undefined;
                includeExpired?: boolean | undefined;
            } | undefined;
            output: {
                id: number;
                code: string;
                label: string | null;
                usesCount: number;
                maxUses: number | null;
                expiresAt: Date | null;
                isRevoked: boolean;
                createdAt: Date;
                createdByEmail?: string;
                isExpired: boolean;
                isActive: boolean;
            }[];
            meta: object;
        }>;
        createInviteCode: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                label?: string | undefined;
                maxUses?: number | undefined;
                expiresInDays?: number | undefined;
                customCode?: string | undefined;
            };
            output: {
                success: boolean;
                code: string;
                id: number;
                message: string;
            };
            meta: object;
        }>;
        revokeInviteCode: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                codeId: number;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        getCodeUsageHistory: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                codeId: number;
            };
            output: {
                userId: number;
                userEmail: string;
                usedAt: Date;
                ipAddress: string | null;
            }[];
            meta: object;
        }>;
        exportAuditLogs: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                format: "pdf" | "csv";
                startDate: Date;
                endDate: Date;
                userId?: number | null | undefined;
            };
            output: {
                success: boolean;
                data: string;
                format: "pdf" | "csv";
                filename: string;
            };
            meta: object;
        }>;
        diagnoseFiles: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                total: number;
                active: number;
                deleted: number;
                deletedSample: {
                    id: number;
                    filename: string;
                    size: number;
                    createdAt: Date;
                    updatedAt: Date;
                    userId: number;
                }[];
                message: string;
            };
            meta: object;
        }>;
        recoverAllFiles: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                success: boolean;
                recoveredCount: number;
                totalActiveNow: number;
                message: string;
            };
            meta: object;
        }>;
        listSendAbuseReports: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                limit?: number | undefined;
                offset?: number | undefined;
            };
            output: {
                items: {
                    sessionId: string;
                    session: {
                        uploaderIp: string;
                        fileSize: number;
                        mimeType: string;
                        status: import("./_core/publicSend/types").SendStatus;
                        createdAt: string;
                        expiresAt: string;
                        downloadCount: number;
                    } | null;
                    reports: {
                        ip: string;
                        reason: string;
                        details?: string;
                        createdAt: string;
                    }[];
                    reportCount: number;
                }[];
                total: number;
            };
            meta: object;
        }>;
        getSendAbuseDetail: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                sessionId: string;
                session: {
                    uploaderIp: string;
                    fileSize: number;
                    mimeType: string;
                    status: import("./_core/publicSend/types").SendStatus;
                    createdAt: string;
                    expiresAt: string;
                    downloadCount: number;
                    maxDownloads: number | null;
                    r2Key: string;
                } | null;
                reports: {
                    ip: string;
                    reason: string;
                    details?: string;
                    createdAt: string;
                }[];
            };
            meta: object;
        }>;
        dismissSendAbuseReport: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        deleteSendSession: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        banSendIp: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                ip: string;
                reason: string;
                permanent?: boolean | undefined;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        unbanSendIp: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                ip: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        listBlockedSendIps: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                limit?: number | undefined;
                cursor?: string | undefined;
            };
            output: {
                entries: Array<{
                    ip: string;
                } & import("./_core/publicSend/blocklist").BlockedIpInfo>;
                nextCursor: string;
            };
            meta: object;
        }>;
        getSendAnalytics: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                days?: number | undefined;
            };
            output: {
                daily: Array<{
                    date: string;
                    uploads: number;
                    downloads: number;
                    reports: number;
                    replies: number;
                    totalBytes: number;
                }>;
                totals: {
                    uploads: number;
                    downloads: number;
                    reports: number;
                    replies: number;
                    totalBytes: number;
                };
            };
            meta: object;
        }>;
    }>>;
    stripe: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        isConfigured: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                configured: boolean;
                enabled: true;
                active: boolean;
            };
            meta: object;
        }>;
        getSubscription: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: import("./_core/stripe").UserSubscriptionStatus;
            meta: object;
        }>;
        createCheckout: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                plan: "pro" | "business";
                billingCycle?: "monthly" | "yearly" | undefined;
                seats?: number | undefined;
            };
            output: {
                url: string | null;
            };
            meta: object;
        }>;
        openPortal: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                url: string;
            };
            meta: object;
        }>;
        getPricing: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                plans: ({
                    id: "free";
                    name: string;
                    monthlyPrice: number;
                    yearlyPrice: number;
                    currency: string;
                    perUser: boolean;
                    minUsers: number;
                    features: string[];
                    limits: import("./_core/stripe").PlanLimits;
                    planFeatures: import("./_core/stripe").PlanFeatures;
                    highlighted: boolean;
                } | {
                    id: "pro";
                    name: string;
                    monthlyPrice: number;
                    yearlyPrice: number;
                    currency: string;
                    perUser: boolean;
                    minUsers: number;
                    features: string[];
                    limits: import("./_core/stripe").PlanLimits;
                    planFeatures: import("./_core/stripe").PlanFeatures;
                    highlighted: boolean;
                } | {
                    id: "business";
                    name: string;
                    monthlyPrice: number;
                    yearlyPrice: number;
                    currency: string;
                    perUser: boolean;
                    minUsers: number;
                    features: string[];
                    limits: import("./_core/stripe").PlanLimits;
                    planFeatures: import("./_core/stripe").PlanFeatures;
                    highlighted: boolean;
                })[];
                stripeConfigured: boolean;
                publishableKey: any;
            };
            meta: object;
        }>;
    }>>;
    mfa: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        setup: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                success: boolean;
                secret: string;
                qrCodeUrl: string;
                recoveryCodes: never[];
            };
            meta: object;
        }>;
        verify: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                secret: string;
                token: string;
            };
            output: {
                success: boolean;
                backupCodes: string[];
            };
            meta: object;
        }>;
        disable: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                totpCode: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        getStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                enabled: boolean;
            };
            meta: object;
        }>;
    }>>;
    p2p: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        createSession: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                recipientEmail?: string | undefined;
                encryptionMethod?: "shamir" | "webrtc" | "double" | undefined;
                splitShares?: number | undefined;
                expiresInMinutes?: number | undefined;
                senderPublicKey?: string | undefined;
            };
            output: {
                sessionId: string;
                shareUrl: string;
                expiresAt: Date;
                fileName: string;
                fileSize: number;
                senderId: number;
            };
            meta: object;
        }>;
        joinSession: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                recipientPublicKey?: string | undefined;
            };
            output: {
                session: {
                    status: "connecting";
                    recipientId: number;
                    recipientPublicKey: string | undefined;
                    id: number;
                    sessionId: string;
                    senderId: number;
                    senderName?: string;
                    senderEmail?: string;
                    fileId: number;
                    fileName?: string;
                    fileSize?: number;
                    fileMimeType?: string;
                    recipientEmail?: string;
                    encryptionMethod: import("./_core/p2p").EncryptionMethodType;
                    splitShares: number;
                    progress: number;
                    bytesTransferred: number;
                    expiresAt: Date;
                    createdAt: Date;
                    connectedAt?: Date;
                    completedAt?: Date;
                    senderPublicKey?: string;
                    senderFingerprint?: string;
                    recipientFingerprint?: string;
                };
                config: {
                    maxFileSizeMb: number;
                    signalingTimeoutMs: any;
                    maxConcurrentTransfers: any;
                    trysteroFallbackEnabled: boolean;
                };
                iceServers: import("./_core/p2p").ICEServer[];
            };
            meta: object;
        }>;
        getSession: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                sessionId: string;
            };
            output: import("./_core/p2p").P2PSession;
            meta: object;
        }>;
        listSessions: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                status?: "active" | "completed" | "failed" | "all" | undefined;
                limit?: number | undefined;
                offset?: number | undefined;
            };
            output: {
                sessions: import("./_core/p2p").P2PSession[];
                stats: {
                    total: number;
                    waiting: number;
                    active: number;
                    completed: number;
                    failed: number;
                };
            };
            meta: object;
        }>;
        updateProgress: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                progress: number;
                bytesTransferred: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        completeSession: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                success: boolean;
                errorMessage?: string | undefined;
            };
            output: {
                success: boolean;
                status: "completed" | "failed";
            };
            meta: object;
        }>;
        cancelSession: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        sendSignal: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                signalType: "offer" | "answer" | "ice_candidate" | "key_exchange" | "recipient_joined";
                signalData: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        getSignals: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                sessionId: string;
                since?: number | undefined;
            };
            output: {
                signals: never[];
                sessionStatus: null;
                sessionNotFound: boolean;
                timestamp: number;
            } | {
                signals: import("./_core/p2p").SignalQueueItem[];
                sessionStatus: import("./_core/p2p").P2PSessionStatusType;
                sessionNotFound: boolean;
                timestamp: number;
            };
            meta: object;
        }>;
        getConfig: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                iceServers: import("./_core/p2p").ICEServer[];
                maxFileSizeMb: number;
                signalingTimeoutMs: any;
                maxConcurrentTransfers: any;
                trysteroFallbackEnabled: boolean;
            };
            meta: object;
        }>;
        isEnabled: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: boolean;
            meta: object;
        }>;
        getSessionPreview: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                found: boolean;
                expired: boolean;
                fileName?: undefined;
                fileSize?: undefined;
                senderName?: undefined;
                encryptionMethod?: undefined;
                expiresAt?: undefined;
                status?: undefined;
                requiresAuth?: undefined;
            } | {
                found: boolean;
                expired: boolean;
                fileName: string | undefined;
                fileSize: number | undefined;
                senderName: string | undefined;
                encryptionMethod: import("./_core/p2p").EncryptionMethodType;
                expiresAt: Date;
                status: "completed" | "failed" | "waiting" | "connecting" | "connected" | "transferring" | "cancelled";
                requiresAuth: boolean;
            } | {
                found: boolean;
                expired: boolean;
                encryptionMethod: import("./_core/p2p").EncryptionMethodType;
                requiresAuth: boolean;
                fileName?: undefined;
                fileSize?: undefined;
                senderName?: undefined;
                expiresAt?: undefined;
                status?: undefined;
            };
            meta: object;
        }>;
        createOfflineSession: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
                recipientEmail: string;
                encryptionMethod?: "shamir" | "double" | undefined;
                splitShares?: number | undefined;
                expiresInHours?: number | undefined;
                notifyRecipient?: boolean | undefined;
            };
            output: {
                sessionId: string;
                claimUrl: string;
                expiresAt: Date;
                totalChunks: number;
                chunkSize: number;
                fileName: string;
                fileSize: number;
            };
            meta: object;
        }>;
        uploadChunk: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                chunkIndex: number;
                encryptedData: string;
                chunkHash: string;
            };
            output: {
                success: boolean;
                uploadedChunks: number;
                totalChunks: number;
                isComplete: boolean;
            };
            meta: object;
        }>;
        claimOfflineSession: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                recipientPublicKey?: string | undefined;
            };
            output: {
                session: import("./_core/p2p/offlineTypes").OfflineSession;
                manifest: {
                    fileName: string;
                    fileSize: number;
                    fileType: string;
                    totalChunks: number;
                    chunks: {
                        index: number;
                        hash: string;
                    }[];
                };
                senderName: string | undefined;
                senderEmail: string | undefined;
            };
            meta: object;
        }>;
        downloadChunk: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                sessionId: string;
                chunkIndex: number;
            };
            output: {
                index: number;
                encryptedData: string;
                hash: string;
            };
            meta: object;
        }>;
        getPendingTransfers: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                transfers: {
                    sessionId: string;
                    senderName: string | undefined;
                    senderEmail: string | undefined;
                    fileName: string | undefined;
                    fileSize: number | undefined;
                    expiresAt: Date;
                    createdAt: Date;
                }[];
                count: number;
            };
            meta: object;
        }>;
        cancelOfflineSession: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        getOfflineStats: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                total: number;
                pending: number;
                ready: number;
                claimed: number;
                completed: number;
                totalStorageBytes: number;
                storageMB: number;
                usingRedis: boolean;
            };
            meta: object;
        }>;
        isP2PDirectEnabled: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                enabled: boolean;
            };
            meta: object;
        }>;
        initiateP2PTransfer: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                recipientEmail: string;
                fileName: string;
                fileSize: number;
                mimeType: string;
                encryptedAESKey: string;
                iv: string;
                expiresInHours?: number | undefined;
            };
            output: {
                sessionId: string;
                partUrls: {
                    partNumber: number;
                    url: string;
                    partSize: number;
                }[];
                chunkSize: number;
                totalChunks: number;
                expiresAt: string;
            };
            meta: object;
        }>;
        updateP2PProgress: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                uploadedParts: {
                    partNumber: number;
                    etag: string;
                }[];
            };
            output: {
                success: boolean;
                uploadedChunks: number;
                totalChunks: number;
                progress: number;
            };
            meta: object;
        }>;
        completeP2PTransfer: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                parts: {
                    partNumber: number;
                    etag: string;
                }[];
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        claimP2PTransfer: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                downloadUrl: string;
                encryptedAESKey: string;
                iv: string;
                isE2EEncrypted: boolean;
                fileName: string;
                fileSize: number;
                mimeType: string;
                senderEmail: string;
                createdAt: string;
                expiresAt: string;
            };
            meta: object;
        }>;
        getPendingP2PTransfers: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                sessionId: string;
                fileName: string;
                fileSize: number;
                mimeType: string;
                senderEmail: string;
                status: "expired" | "completed" | "uploading" | "ready" | "cancelled" | "pending_upload" | "claimed" | "downloading";
                isE2EEncrypted: boolean;
                createdAt: string;
                expiresAt: string;
            }[];
            meta: object;
        }>;
        getSentP2PTransfers: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                sessionId: string;
                fileName: string;
                fileSize: number;
                mimeType: string;
                recipientEmail: string;
                status: "expired" | "completed" | "uploading" | "ready" | "cancelled" | "pending_upload" | "claimed" | "downloading";
                progress: number;
                createdAt: string;
                expiresAt: string;
                completedAt: string | undefined;
                isE2EEncrypted: boolean;
                isClaimed: boolean;
            }[];
            meta: object;
        }>;
        cancelP2PTransfer: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        getRecipientPublicKey: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                recipientEmail: string;
            };
            output: {
                publicKey: string;
                recipientName: string | null;
                recipientEmail: string;
            };
            meta: object;
        }>;
        getP2PSessionDetails: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                sessionId: string;
                fileName: string;
                fileSize: number;
                mimeType: string;
                status: "expired" | "completed" | "uploading" | "ready" | "cancelled" | "pending_upload" | "claimed" | "downloading";
                progress: number;
                uploadedChunks: number;
                totalChunks: number;
                isE2EEncrypted: boolean;
                senderEmail: string;
                recipientEmail: string;
                isSender: boolean;
                isRecipient: boolean;
                createdAt: string;
                expiresAt: string;
                completedAt: string | undefined;
                hoursRemaining: number;
            };
            meta: object;
        }>;
    }>>;
    encryption: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        getMasterKeyStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                isConfigured: boolean;
                recoveryCodesRemaining: number;
                hasPasswordHint: boolean;
                createdAt: null;
            } | {
                isConfigured: boolean;
                recoveryCodesRemaining: number;
                hasPasswordHint: boolean;
                createdAt: Date;
            };
            meta: object;
        }>;
        setupMasterKey: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                pbkdf2Salt: string;
                recoveryCodes: string[];
                masterKeyEncrypted: string;
                argon2Params: {
                    type: "argon2id";
                    memoryCost: number;
                    timeCost: number;
                    parallelism: number;
                    hashLength: number;
                };
                passwordHint?: string | undefined;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        changeMasterPassword: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                newPbkdf2Salt: string;
                newRecoveryCodes: string[];
                masterKeyEncrypted: string;
                argon2Params: {
                    type: "argon2id";
                    memoryCost: number;
                    timeCost: number;
                    parallelism: number;
                    hashLength: number;
                };
                newPasswordHint?: string | undefined;
            };
            output: {
                success: boolean;
                message: string;
                shamirSharesInvalidated: boolean;
            };
            meta: object;
        }>;
        validateRecoveryCode: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                recoveryCode: string;
            };
            output: {
                isValid: boolean;
            };
            meta: object;
        }>;
        resetWithRecoveryCode: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                recoveryCode: string;
                newPbkdf2Salt: string;
                newRecoveryCodes: string[];
                masterKeyEncrypted: string;
                argon2Params: {
                    type: "argon2id";
                    memoryCost: number;
                    timeCost: number;
                    parallelism: number;
                    hashLength: number;
                };
                newPasswordHint?: string | undefined;
            };
            output: {
                success: boolean;
                message: string;
                shamirSharesInvalidated: boolean;
            };
            meta: object;
        }>;
        regenerateRecoveryCodes: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                newRecoveryCodes: string[];
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        getEncryptionConfig: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                isConfigured: boolean;
                kdfAlgorithm: null;
                salt: null;
                argon2Params: null;
                masterKeyEncrypted: null;
                masterKeyVersion: null;
                passwordHint: null;
            } | {
                isConfigured: boolean;
                kdfAlgorithm: "pbkdf2" | "argon2id";
                salt: string;
                argon2Params: unknown;
                masterKeyEncrypted: string | null;
                masterKeyVersion: number;
                passwordHint: string | null;
            };
            meta: object;
        }>;
        deleteMasterKey: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
    }>>;
    devices: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        listTrustedDevices: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                deviceFingerprint: string;
            } | undefined;
            output: import("./db/schema").TrustedDeviceInfo[];
            meta: object;
        }>;
        registerTrustedDevice: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                deviceFingerprint: string;
                platform: string;
                uesEncrypted: string;
                uesEncryptionIv: string;
                deviceName?: string | undefined;
                browserInfo?: string | undefined;
            };
            output: {
                success: boolean;
                deviceId: number;
                isNew: boolean;
                isPending?: undefined;
            } | {
                success: boolean;
                deviceId: number;
                isNew: boolean;
                isPending: boolean;
            };
            meta: object;
        }>;
        removeTrustedDevice: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                deviceId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        renameTrustedDevice: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                deviceId: number;
                newName: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        isDeviceTrusted: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                deviceFingerprint: string;
            };
            output: {
                isTrusted: boolean;
                approvalStatus: null;
                deviceId: null;
            } | {
                isTrusted: boolean;
                approvalStatus: "pending" | "approved" | "rejected" | "expired";
                deviceId: number;
            };
            meta: object;
        }>;
        getDeviceUES: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                deviceFingerprint: string;
            };
            output: {
                uesEncrypted: string;
                uesEncryptionIv: string | null;
            } | null;
            meta: object;
        }>;
        updateDeviceUsage: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                deviceFingerprint: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        listPendingApprovals: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: import("./db/schema").DeviceApprovalRequest[];
            meta: object;
        }>;
        hasAnyTrustedDevice: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                hasDevice: boolean;
            };
            meta: object;
        }>;
    }>>;
    deviceApproval: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        getApprovalStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                deviceFingerprint: string;
            };
            output: {
                exists: boolean;
                status: null;
                approvedAt: null;
                uesEncrypted: null;
                uesEncryptionIv: null;
            } | {
                exists: boolean;
                status: "pending" | "approved" | "rejected" | "expired";
                approvedAt: Date | null;
                uesEncrypted: string | null;
                uesEncryptionIv: string | null;
            };
            meta: object;
        }>;
        approveDevice: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                pendingDeviceId: number;
                approvingDeviceFingerprint: string;
                uesEncrypted: string;
                uesEncryptionIv: string;
            };
            output: {
                success: boolean;
                approvedDeviceId: number;
                approvedAt: Date;
            };
            meta: object;
        }>;
        rejectDevice: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                pendingDeviceId: number;
                approvingDeviceFingerprint: string;
            };
            output: {
                success: boolean;
                rejectedDeviceId: number;
            };
            meta: object;
        }>;
        approveWithRecoveryCode: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                deviceFingerprint: string;
                recoveryCode: string;
                uesEncrypted: string;
                uesEncryptionIv: string;
            };
            output: {
                success: boolean;
                deviceId: number;
                remainingRecoveryCodes: number;
            };
            meta: object;
        }>;
        getPendingCount: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                pendingCount: number;
            };
            meta: object;
        }>;
    }>>;
    hybridKem: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        generateKeyPair: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                publicKey: {
                    classical: string;
                    postQuantum: string;
                };
                fingerprint: string;
            };
            meta: object;
        }>;
        storeKeyPair: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                x25519PublicKey: string;
                x25519SecretKeyEncrypted: string;
                mlkem768PublicKey: string;
                mlkem768SecretKeyEncrypted: string;
                fingerprint?: string | undefined;
                deviceId?: number | undefined;
            };
            output: {
                success: boolean;
                keyPairId: number;
                keyVersion: number;
                hsmProtected: boolean;
            };
            meta: object;
        }>;
        getPublicKey: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: import("./_core/hybridKemRouter").HybridPublicKeyResponse | null;
            meta: object;
        }>;
        getSecretKey: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                keyVersion?: number | undefined;
            };
            output: {
                keyVersion: number;
                x25519SecretKeyEncrypted: string;
                mlkem768SecretKeyEncrypted: string;
            };
            meta: object;
        }>;
        serverSideEncapsulate: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                ciphertext: {
                    classical: string;
                    postQuantum: string;
                };
            };
            meta: object;
        }>;
        hasKeyPair: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                hasKeyPair: boolean;
            };
            meta: object;
        }>;
        listKeyPairs: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                id: number;
                keyVersion: number;
                algorithm: "none" | "x25519-ml-kem-768";
                isActive: boolean;
                fingerprint: string | null;
                createdAt: Date;
                lastUsedAt: Date | null;
            }[];
            meta: object;
        }>;
    }>>;
    hybridSignature: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        generateKeyPair: import("@trpc/server").TRPCMutationProcedure<{
            input: void;
            output: {
                publicKey: {
                    classical: string;
                    postQuantum: string;
                };
                fingerprint: string;
            };
            meta: object;
        }>;
        storeKeyPair: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                ed25519PublicKey: string;
                ed25519SecretKeyEncrypted: string;
                mldsa65PublicKey: string;
                mldsa65SecretKeyEncrypted: string;
                fingerprint?: string | undefined;
            };
            output: {
                success: boolean;
                keyPairId: number;
                keyVersion: number;
                hsmProtected: boolean;
            };
            meta: object;
        }>;
        getPublicKey: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: import("./_core/hybridSignatureRouter").HybridSignaturePublicKeyResponse | null;
            meta: object;
        }>;
        getSecretKey: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                keyVersion?: number | undefined;
            };
            output: {
                keyVersion: number;
                ed25519SecretKeyEncrypted: string;
                mldsa65SecretKeyEncrypted: string;
            };
            meta: object;
        }>;
        serverSideSign: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                message: string;
                ed25519SecretKey: string;
                mldsa65SecretKey: string;
                context: "FILE" | "TIMESTAMP" | "SHARE";
            };
            output: {
                signature: {
                    classical: string;
                    postQuantum: string;
                    context: "FILE" | "TIMESTAMP" | "SHARE";
                    signedAt: number;
                };
            };
            meta: object;
        }>;
        verify: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                message: string;
                signature: {
                    classical: string;
                    postQuantum: string;
                    context: "FILE" | "TIMESTAMP" | "SHARE";
                    signedAt: number;
                };
                publicKey: {
                    classical: string;
                    postQuantum: string;
                };
            };
            output: {
                valid: boolean;
                classicalValid: boolean;
                postQuantumValid: boolean;
                error?: undefined;
            } | {
                valid: boolean;
                classicalValid: boolean;
                postQuantumValid: boolean;
                error: string;
            };
            meta: object;
        }>;
        hasKeyPair: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                hasKeyPair: boolean;
            };
            meta: object;
        }>;
        listKeyPairs: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                id: number;
                keyVersion: number;
                algorithm: "none" | "ed25519-ml-dsa-65";
                isActive: boolean;
                fingerprint: string | null;
                createdAt: Date;
            }[];
            meta: object;
        }>;
        getPublicKeyByUserId: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                userId: number;
            };
            output: import("./_core/hybridSignatureRouter").HybridSignaturePublicKeyResponse | null;
            meta: object;
        }>;
        getPublicKeyByFingerprint: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fingerprint: string;
            };
            output: import("./_core/hybridSignatureRouter").HybridSignaturePublicKeyResponse | null;
            meta: object;
        }>;
    }>>;
    organizations: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        list: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                role: import("./db/schema").OrgRole;
                joinedAt: Date;
                id: number;
                name: string;
                slug: string;
                ownerId: number;
                storageQuota: number;
                storageUsed: number;
                memberLimit: number;
                subscriptionPlan: string;
                subscriptionStatus: string;
                stripeCustomerId: string | null;
                stripeSubscriptionId: string | null;
                createdAt: Date;
                updatedAt: Date;
            }[];
            meta: object;
        }>;
        getById: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                id: number;
            };
            output: {
                role: import("./db/schema").OrgRole;
                id: number;
                name: string;
                slug: string;
                ownerId: number;
                storageQuota: number;
                storageUsed: number;
                memberLimit: number;
                subscriptionPlan: string;
                subscriptionStatus: string;
                stripeCustomerId: string | null;
                stripeSubscriptionId: string | null;
                createdAt: Date;
                updatedAt: Date;
            };
            meta: object;
        }>;
        getBySlug: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                slug: string;
            };
            output: {
                role: import("./db/schema").OrgRole;
                id: number;
                name: string;
                slug: string;
                ownerId: number;
                storageQuota: number;
                storageUsed: number;
                memberLimit: number;
                subscriptionPlan: string;
                subscriptionStatus: string;
                stripeCustomerId: string | null;
                stripeSubscriptionId: string | null;
                createdAt: Date;
                updatedAt: Date;
            };
            meta: object;
        }>;
        getMembers: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                organizationId: number;
            };
            output: {
                id: number;
                userId: number;
                userName: string | null;
                userEmail: string;
                name: string | null;
                email: string;
                role: import("./db/schema").OrgRole;
                joinedAt: Date;
            }[];
            meta: object;
        }>;
        getPendingInvites: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                organizationId: number;
            };
            output: {
                id: number;
                organizationId: number;
                email: string;
                role: string;
                inviteCode: string;
                invitedBy: number;
                expiresAt: Date;
                acceptedAt: Date | null;
                createdAt: Date;
            }[];
            meta: object;
        }>;
        getStorageStats: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                organizationId: number;
            };
            output: {
                storageUsed: number;
                storageQuota: number;
                percentUsed: number;
            };
            meta: object;
        }>;
        create: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                name: string;
                slug?: string | undefined;
            };
            output: {
                id: number;
                name: string;
                storageUsed: number;
                storageQuota: number;
                stripeCustomerId: string | null;
                stripeSubscriptionId: string | null;
                subscriptionStatus: string;
                subscriptionPlan: string;
                createdAt: Date;
                updatedAt: Date;
                slug: string;
                ownerId: number;
                memberLimit: number;
            };
            meta: object;
        }>;
        update: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
                name?: string | undefined;
                slug?: string | undefined;
            };
            output: {
                id: number;
                name: string;
                slug: string;
                ownerId: number;
                storageQuota: number;
                storageUsed: number;
                memberLimit: number;
                subscriptionPlan: string;
                subscriptionStatus: string;
                stripeCustomerId: string | null;
                stripeSubscriptionId: string | null;
                createdAt: Date;
                updatedAt: Date;
            } | undefined;
            meta: object;
        }>;
        delete: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        inviteMember: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
                email: string;
                role: "admin" | "member";
            };
            output: {
                role: string;
                id: number;
                email: string;
                createdAt: Date;
                expiresAt: Date;
                organizationId: number;
                invitedBy: number;
                inviteCode: string;
                acceptedAt: Date | null;
            } | undefined;
            meta: object;
        }>;
        acceptInvite: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                inviteCode: string;
            };
            output: {
                success: boolean;
                organizationId: number;
            };
            meta: object;
        }>;
        cancelInvite: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                inviteId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        updateMemberRole: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
                userId: number;
                role: "admin" | "member";
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        removeMember: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
                userId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        leave: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        transferOwnership: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
                newOwnerId: number;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        getAuditLogs: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                organizationId: number;
                limit?: number | undefined;
                offset?: number | undefined;
            };
            output: {
                logs: {
                    id: number;
                    userId: number | null;
                    userEmail: string | null;
                    action: "login_success" | "login_failed" | "logout" | "register" | "email_verified" | "password_reset" | "magic_link_sent" | "token_refresh" | "token_refresh_failed" | "file_upload" | "file_download" | "file_delete" | "file_restore" | "file_permanent_delete" | "file_rename" | "file_move" | "file_rejected" | "file_share_create" | "file_share_access" | "file_share_revoke" | "folder_create" | "folder_delete" | "folder_rename" | "folder_move" | "trash_empty" | "admin_user_update" | "admin_quota_change" | "admin_settings_change" | "rate_limit_exceeded" | "suspicious_activity" | "websocket_connect" | "websocket_disconnect" | "account_locked" | "account_unlocked" | "token_family_compromised" | "session_terminated" | "logout_all_devices" | "account_deleted" | "mfa_enabled" | "mfa_disabled" | "master_key_changed" | "admin_account_delete" | "admin_send_delete" | "admin_send_dismiss" | "admin_send_ip_ban" | "admin_send_ip_unban";
                    resourceType: "user" | "file" | "chat" | "folder" | "share" | "system" | null;
                    resourceId: number | null;
                    details: string | null;
                    ipAddress: string | null;
                    userAgent: string | null;
                    success: boolean;
                    errorMessage: string | null;
                    createdAt: Date;
                }[];
                total: number;
            };
            meta: object;
        }>;
        switchContext: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number | null;
            };
            output: {
                success: boolean;
                currentOrgId: number | null;
            };
            meta: object;
        }>;
    }>>;
    orgKeys: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        setup: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
                omkWrappedForOwner: string;
                hybridKeyPair: {
                    x25519PublicKey: string;
                    x25519SecretKeyEncrypted: string;
                    mlkem768PublicKey: string;
                    mlkem768SecretKeyEncrypted: string;
                    mlkem768SecretKeyIv: string;
                    fingerprint?: string | undefined;
                };
            };
            output: {
                success: boolean;
                keyVersion: number;
                organizationId: number;
            };
            meta: object;
        }>;
        getWrappedOMK: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                organizationId: number;
                keyVersion?: number | undefined;
            };
            output: {
                distributionIv?: string | null | undefined;
                distributionX25519Public?: string | null | undefined;
                distributionMlkemCiphertext?: string | null | undefined;
                organizationId: number;
                keyVersion: number;
                omkEncrypted: string;
                wrapMethod: "aes-kw" | "hybrid-pqc";
            };
            meta: object;
        }>;
        getOrgHybridPublicKey: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                organizationId: number;
            };
            output: {
                organizationId: number;
                keyVersion: number;
                algorithm: "none" | "x25519-ml-kem-768";
                x25519PublicKey: string;
                mlkem768PublicKey: string;
                fingerprint: string | null;
            };
            meta: object;
        }>;
        getOrgHybridSecretKey: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                organizationId: number;
                keyVersion?: number | undefined;
            };
            output: {
                organizationId: number;
                keyVersion: number;
                x25519SecretKeyEncrypted: string;
                mlkem768SecretKeyEncrypted: string;
                mlkem768SecretKeyIv: string;
            };
            meta: object;
        }>;
        wrapOMKForMember: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
                targetUserId: number;
                omkEncrypted: string;
                distributionIv: string;
                distributionX25519Public: string;
                distributionMlkemCiphertext: string;
            };
            output: {
                success: boolean;
                alreadyConfirmed: boolean;
            };
            meta: object;
        }>;
        storeWrappedOMKForSelf: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
                omkEncrypted: string;
                keyVersion: number;
            };
            output: {
                success: boolean;
                keyVersion: number;
            };
            meta: object;
        }>;
        rotateOMK: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                organizationId: number;
                memberKeys: {
                    userId: number;
                    omkEncrypted: string;
                    distributionIv: string;
                    distributionX25519Public: string;
                    distributionMlkemCiphertext: string;
                }[];
                newHybridKeyPair: {
                    x25519PublicKey: string;
                    x25519SecretKeyEncrypted: string;
                    mlkem768PublicKey: string;
                    mlkem768SecretKeyEncrypted: string;
                    mlkem768SecretKeyIv: string;
                    fingerprint?: string | undefined;
                };
                rotationReason?: string | undefined;
            };
            output: {
                success: boolean;
                newKeyVersion: number;
                membersDistributed: number;
            };
            meta: object;
        }>;
        getPendingKeyDistributions: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                organizationId: number;
            };
            output: {
                pendingMembers: {
                    userId: number;
                    userName: string | null;
                    userEmail: string;
                    role: "owner" | "admin" | "member";
                    keyDistributionStatus: "pending" | "distributed" | "confirmed";
                    currentKeyVersion: number | null;
                    activeKeyVersion: number;
                    hasHybridKey: boolean;
                }[];
                activeKeyVersion: number;
            };
            meta: object;
        }>;
        getMemberHybridPublicKey: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                organizationId: number;
                targetUserId: number;
            };
            output: {
                userId: number;
                x25519PublicKey: string;
                mlkem768PublicKey: string;
                keyVersion: number;
                fingerprint: string | null;
            };
            meta: object;
        }>;
    }>>;
    users: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        search: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                query: string;
                limit?: number | undefined;
            };
            output: {
                users: {
                    id: number;
                    name: string | null;
                    email: string;
                }[];
            };
            meta: object;
        }>;
        getById: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                userId: number;
            };
            output: {
                id: number;
                name: string | null;
                email: string;
            };
            meta: object;
        }>;
    }>>;
    timestamp: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        submit: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
            };
            output: {
                status: import("./db/schema").TimestampStatus;
                message: string;
                timestampId: number;
            };
            meta: object;
        }>;
        getStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileId: number;
            };
            output: {
                hasTimestamp: boolean;
                status: null;
                submittedAt: null;
                confirmedAt: null;
                bitcoinBlockHeight: null;
                bitcoinTimestamp: null;
                contentHash: null;
            } | {
                hasTimestamp: boolean;
                status: import("./db/schema").TimestampStatus;
                submittedAt: Date;
                confirmedAt: Date | null;
                bitcoinBlockHeight: number | null;
                bitcoinTimestamp: Date | null;
                contentHash: string;
            };
            meta: object;
        }>;
        verify: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileId: number;
            };
            output: {
                verified: boolean;
                status: import("./db/schema").TimestampStatus;
                message: string;
                timestamp?: undefined;
                bitcoinBlockHeight?: undefined;
                bitcoinBlockHash?: undefined;
                attestations?: undefined;
            } | {
                verified: boolean;
                status: import("./db/schema").TimestampStatus;
                timestamp: Date | undefined;
                bitcoinBlockHeight: number | undefined;
                bitcoinBlockHash: string | undefined;
                attestations: import("./_core/timestamp/otsClient").OTSAttestation[];
                message?: undefined;
            };
            meta: object;
        }>;
        downloadProof: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileId: number;
            };
            output: {
                proof: string;
                filename: string;
                contentHash: string;
                status: import("./db/schema").TimestampStatus;
            };
            meta: object;
        }>;
        retry: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
            };
            output: {
                status: import("./db/schema").TimestampStatus;
                message: string;
                retryCount: number;
            };
            meta: object;
        }>;
        batchStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                fileIds: number[];
            };
            output: {
                fileId: number;
                status: "pending" | "confirmed" | "failed" | "confirming" | "skipped" | null;
                confirmedAt: Date | null;
            }[];
            meta: object;
        }>;
        isEnabled: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                enabled: boolean;
            };
            meta: object;
        }>;
        generateLegalPdf: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileId: number;
            };
            output: {
                pdf: string;
                filename: string;
                mimeType: string;
            };
            meta: object;
        }>;
    }>>;
    shamirRecovery: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        getStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                isConfigured: boolean;
                threshold: number;
                totalShares: number;
                distribution: null;
                masterKeyVersion: number;
                createdAt: null;
                configId?: undefined;
            } | {
                isConfigured: boolean;
                configId: string;
                threshold: number;
                totalShares: number;
                distribution: {
                    server: number;
                    email: number;
                    trusted_contact: number;
                    external: number;
                };
                masterKeyVersion: number;
                createdAt: Date;
            };
            meta: object;
        }>;
        setupRecovery: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                threshold: number;
                distribution: {
                    server: number;
                    email: number;
                    trustedContacts: number[];
                    external: number;
                };
                masterKeyVersion: number;
                shares: {
                    index: number;
                    encryptedShare: string;
                    shareType: "email" | "server" | "trusted_contact" | "external";
                    encryptionMethod: string;
                    integrityTag: string;
                    recipientUserId?: number | undefined;
                    recipientEmail?: string | undefined;
                }[];
                emailRecipients?: string[] | undefined;
            };
            output: import("./_core/shamirRecovery").SetupResultResponse;
            meta: object;
        }>;
        revokeAll: import("@trpc/server").TRPCMutationProcedure<{
            input: Record<string, never>;
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        getMyExternalShares: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                shares: {
                    index: number;
                    shareString: string;
                    qrData: string;
                    createdAt: Date;
                }[];
            };
            meta: object;
        }>;
        getHeldShares: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                shares: import("./_core/shamirRecovery").HeldShare[];
            };
            meta: object;
        }>;
        getPendingRecoveryRequests: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                requests: {
                    attemptId: number;
                    recoveryToken: string;
                    ownerUserId: number;
                    ownerEmail: string;
                    ownerName: string | null;
                    threshold: number;
                    collectedCount: number;
                    expiresAt: Date;
                    shareId: number;
                    canReleaseAt: Date;
                    canReleaseNow: boolean;
                    waitingPeriodHours: number;
                }[];
            };
            meta: object;
        }>;
        approveShareRelease: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                shareId: number;
                recoveryToken: string;
            };
            output: {
                success: boolean;
                message: string;
                alreadySubmitted: boolean;
                shareIndex?: undefined;
                encryptedShare?: undefined;
                encryptionMethod?: undefined;
                integrityTag?: undefined;
            } | {
                success: boolean;
                shareIndex: number;
                encryptedShare: string;
                encryptionMethod: string;
                integrityTag: string;
                message?: undefined;
                alreadySubmitted?: undefined;
            };
            meta: object;
        }>;
        revokeHeldShare: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                shareId: number;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        initiateRecovery: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                email: string;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        getRecoveryStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                recoveryToken: string;
            };
            output: import("./_core/shamirRecovery").RecoveryStatusResponse | null;
            meta: object;
        }>;
        submitShare: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                recoveryToken: string;
                shareIndex: number;
                shareData: string;
                shareType: "email" | "server" | "trusted_contact" | "external";
                integrityTag: string;
            };
            output: import("./_core/shamirRecovery").SubmitResultResponse;
            meta: object;
        }>;
        getServerShare: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                recoveryToken: string;
            };
            output: {
                available: boolean;
                shareIndex?: undefined;
                shareData?: undefined;
                integrityTag?: undefined;
            } | {
                available: boolean;
                shareIndex: number;
                shareData: string;
                integrityTag: string;
            };
            meta: object;
        }>;
        getCollectedShares: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                recoveryToken: string;
            };
            output: {
                shares: {
                    index: number;
                    data: string;
                }[];
                threshold: number;
            };
            meta: object;
        }>;
        completeRecovery: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                recoveryToken: string;
                newPbkdf2Salt: string;
                newRecoveryCodes: string[];
                newWrappedMasterKey: string;
                newPasswordHint?: string | undefined;
                kdfAlgorithm?: "pbkdf2" | "argon2id" | undefined;
                argon2Params?: {
                    type: "argon2id";
                    memoryCost: number;
                    timeCost: number;
                    parallelism: number;
                    hashLength: number;
                } | undefined;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
    }>>;
    hsm: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        generateKey: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                algorithm: "AES-256" | "AES-128" | "RSA-2048" | "RSA-4096" | "EC-P256" | "EC-P384" | "EC-P521";
                purpose: "wrap" | "encrypt" | "sign" | "derive" | ("wrap" | "encrypt" | "sign" | "derive")[];
                label: string;
                extractable?: boolean | undefined;
                parentKeyId?: string | undefined;
                metadata?: Record<string, string> | undefined;
            };
            output: import("./_core/hsm").HsmKeyInfoResponse;
            meta: object;
        }>;
        getKey: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                keyIdOrLabel: string;
            };
            output: import("./_core/hsm").HsmKeyInfoResponse;
            meta: object;
        }>;
        listKeys: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                status?: "active" | "rotating" | "retired" | "destroyed" | undefined;
                algorithm?: "AES-256" | "AES-128" | "RSA-2048" | "RSA-4096" | "EC-P256" | "EC-P384" | "EC-P521" | undefined;
                labelPrefix?: string | undefined;
                limit?: number | undefined;
                offset?: number | undefined;
            };
            output: {
                keys: import("./_core/hsm").HsmKeyInfoResponse[];
                total: number;
                limit: number;
                offset: number;
            };
            meta: object;
        }>;
        destroyKey: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                keyId: string;
                confirmDestruction: boolean;
            };
            output: {
                success: boolean;
                keyId: string;
            };
            meta: object;
        }>;
        rotateKey: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                keyId: string;
                newAlgorithm?: "AES-256" | "AES-128" | "RSA-2048" | "RSA-4096" | "EC-P256" | "EC-P384" | "EC-P521" | undefined;
            };
            output: {
                oldKey: import("./_core/hsm").HsmKeyInfoResponse;
                newKey: import("./_core/hsm").HsmKeyInfoResponse;
                gracePeriodEndsAt: Date;
            };
            meta: object;
        }>;
        queryAuditLog: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                since?: Date | undefined;
                until?: Date | undefined;
                operation?: "wrap" | "encrypt" | "sign" | "initialize" | "shutdown" | "generateKey" | "importKey" | "destroyKey" | "unwrap" | "decrypt" | "verify" | "rotateKey" | "getKey" | "listKeys" | undefined;
                keyId?: string | undefined;
                userId?: number | undefined;
                success?: boolean | undefined;
                limit?: number | undefined;
                offset?: number | undefined;
            };
            output: {
                entries: import("./_core/hsm").HsmAuditEntryResponse[];
                total: number;
                limit: number;
                offset: number;
            };
            meta: object;
        }>;
        getAuditSummary: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                period: string;
                since: Date;
                summary: {
                    operation: string;
                    success: boolean;
                    count: number;
                }[];
                recentFailures: import("./_core/hsm").HsmAuditEntryResponse[];
                totals: {
                    success: number;
                    failure: number;
                    total: number;
                };
            };
            meta: object;
        }>;
        getKeyAuditHistory: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                keyIdOrLabel: string;
                limit?: number | undefined;
                offset?: number | undefined;
            };
            output: {
                key: {
                    id: string;
                    label: string;
                    status: "active" | "rotating" | "retired" | "destroyed";
                };
                entries: import("./_core/hsm").HsmAuditEntryResponse[];
                total: number;
            };
            meta: object;
        }>;
        verifyAuditIntegrity: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                limit?: number | undefined;
                since?: Date | undefined;
                until?: Date | undefined;
            };
            output: never;
            meta: object;
        }>;
        getHealthStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: import("./_core/hsm").HsmHealthStatusResponse;
            meta: object;
        }>;
        getInitializationStatus: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: import("./_core/hsm").HsmInitializationStatusResponse;
            meta: object;
        }>;
        initializeHsm: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                confirmInitialization: boolean;
                notes?: string | undefined;
            };
            output: {
                success: boolean;
                message: string;
                keysCreated: ("stenvault-hsm-root" | "stenvault-server-master" | "stenvault-shamir-encryption" | "stenvault-hybrid-protection" | "stenvault-internal-secrets" | "stenvault-audit-signing")[];
            };
            meta: object;
        }>;
        protectSecret: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                secretName: string;
                secretType: "raw" | "symmetric" | "asymmetric-private";
                secretValue: string;
                description?: string | undefined;
                wrappingKeyId?: string | undefined;
            };
            output: {
                success: boolean;
                secretId: number;
                secretName: string;
                wrappingKeyLabel: string;
            };
            meta: object;
        }>;
        retrieveSecret: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                secretName: string;
            };
            output: {
                secretName: string;
                secretType: "raw" | "symmetric" | "asymmetric-private";
                value: string;
            };
            meta: object;
        }>;
        listProtectedSecrets: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                secrets: {
                    id: number;
                    secretName: string;
                    secretType: "raw" | "symmetric" | "asymmetric-private";
                    description: string | null;
                    status: "active" | "rotating" | "retired" | "destroyed";
                    version: number;
                    wrappingKeyLabel: string;
                    createdAt: Date;
                    lastAccessedAt: Date | null;
                }[];
                total: number;
            };
            meta: object;
        }>;
        isEnabled: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                enabled: boolean;
                provider: "aws-cloudhsm" | "azure-keyvault" | "yubihsm" | "hashicorp-vault" | "software" | null;
            };
            meta: object;
        }>;
    }>>;
    publicSend: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        deleteSend: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        listSendHistory: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                offset?: number | undefined;
                limit?: number | undefined;
            };
            output: {
                sessions: {
                    sessionId: string;
                    fileSize: number;
                    mimeType: string;
                    status: string;
                    downloadCount: number;
                    maxDownloads: number | null;
                    createdAt: string;
                    expiresAt: string;
                    isBundle: boolean;
                }[];
                total: number;
            };
            meta: object;
        }>;
        reportAbuse: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                reason: "other" | "malware" | "phishing" | "illegal_content" | "copyright";
                details?: string | undefined;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        claimDownload: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                password?: string | undefined;
            };
            output: {
                downloadUrl: string;
                encryptedMeta: string;
                metaIv: string;
                fileSize: number;
                totalParts: number;
                chunkSize: number;
                encryptionOverhead: number;
                chunkManifest: string | null;
                chunkHashes: string | null;
            };
            meta: object;
        }>;
        getPreview: import("@trpc/server").TRPCQueryProcedure<{
            input: {
                sessionId: string;
            };
            output: {
                encryptedMeta: string;
                metaIv: string;
                fileSize: number;
                mimeType: string;
                hasPassword: boolean;
                expiresAt: string;
                downloadsRemaining: number | null;
                encryptedThumbnail: string | null;
                thumbnailIv: string | null;
                encryptedSnippet: string | null;
                snippetIv: string | null;
                isBundle: boolean;
            };
            meta: object;
        }>;
        completeSend: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                parts: {
                    partNumber: number;
                    etag: string;
                }[];
                uploadSecret: string;
                chunkManifest?: string | undefined;
                chunkHashes?: string | undefined;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        initiateSend: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                fileSize: number;
                mimeType: string;
                encryptedMeta: string;
                metaIv: string;
                password?: string | undefined;
                expiresInHours?: number | undefined;
                maxDownloads?: number | null | undefined;
                turnstileToken?: string | undefined;
                encryptedThumbnail?: string | undefined;
                thumbnailIv?: string | undefined;
                encryptedSnippet?: string | undefined;
                snippetIv?: string | undefined;
                isBundle?: boolean | undefined;
                notifyOnDownload?: boolean | undefined;
                replyToSessionId?: string | undefined;
            };
            output: {
                sessionId: string;
                partUrls: {
                    partNumber: number;
                    url: string;
                    partSize: number;
                }[];
                expiresAt: string;
                uploadSecret: string;
            };
            meta: object;
        }>;
    }>>;
    localSend: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        createRoomCode: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                peerId: string;
            };
            output: {
                code: string;
            };
            meta: object;
        }>;
        joinRoomCode: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                peerId: string;
                code: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        leaveRoomCode: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                peerId: string;
                code: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        requestTransfer: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                peerId: string;
                receiverId: string;
                files: {
                    name: string;
                    size: number;
                    type: string;
                }[];
            };
            output: {
                sessionId: string;
            };
            meta: object;
        }>;
        respondTransfer: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                accept: boolean;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        cancelTransfer: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                peerId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        sendSignal: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                sessionId: string;
                peerId: string;
                type: "offer" | "answer" | "ice";
                data: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        registerReceiver: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                peerId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        unregisterReceiver: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                peerId: string;
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
        listReceivers: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: {
                peerId: string;
                displayName: string;
                browserName: string;
                osName: string;
            }[];
            meta: object;
        }>;
        reportAlternateIp: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                peerId: string;
            };
            output: {
                added: boolean;
                ipHash: string;
            };
            meta: object;
        }>;
    }>>;
    profile: import("@trpc/server").TRPCBuiltRouter<{
        ctx: import("./_core/context").TrpcContext;
        meta: object;
        errorShape: {
            message: string;
            data: {
                stack: undefined;
                code: import("@trpc/server").TRPC_ERROR_CODE_KEY;
                httpStatus: number;
                path?: string;
            };
            code: import("@trpc/server").TRPC_ERROR_CODE_NUMBER;
        };
        transformer: true;
    }, import("@trpc/server").TRPCDecorateCreateRouterOptions<{
        updateProfile: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                name: string;
            };
            output: {
                success: boolean;
                name: string;
            };
            meta: object;
        }>;
        requestEmailChange: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                newEmail: string;
                startLoginRequest: string;
            };
            output: {
                loginResponse: string;
                pendingNewEmail: string;
            };
            meta: object;
        }>;
        verifyPasswordForEmailChange: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                finishLoginRequest: string;
                newEmail: string;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        confirmEmailChange: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                otp: string;
            };
            output: {
                success: boolean;
                newEmail: string;
            };
            meta: object;
        }>;
        finalizeEmailChange: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                newEmail: string;
                registrationRecord: string;
            };
            output: {
                success: boolean;
                message: string;
            };
            meta: object;
        }>;
        preDeleteCheck: import("@trpc/server").TRPCQueryProcedure<{
            input: void;
            output: import("./_core/userDataPurge").PreDeleteCheck;
            meta: object;
        }>;
        deleteAccount: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                startLoginRequest: string;
            };
            output: {
                loginResponse: string;
            };
            meta: object;
        }>;
        deleteAccountFinish: import("@trpc/server").TRPCMutationProcedure<{
            input: {
                finishLoginRequest: string;
                confirmText: "DELETE";
            };
            output: {
                success: boolean;
            };
            meta: object;
        }>;
    }>>;
}>>;
export type AppRouter = typeof appRouter;
