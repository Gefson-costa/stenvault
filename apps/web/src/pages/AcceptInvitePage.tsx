/**
 * Accept Organization Invite Page
 *
 * Route: /invite/:code
 * Requires authentication (AuthGuard). Unauthenticated users redirect to login first.
 *
 * Key-in-URL flow: if the URL has #key=..., unwraps OMK from the invite blob,
 * re-wraps with personal MK, stores on server, and unlocks org vault immediately.
 */

import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { trpc } from "@/lib/trpc";
import { Building2, CheckCircle2, XCircle, Loader2, Lock, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useOrganizationContext } from "@/contexts/OrganizationContext";
import { useMasterKey } from "@/hooks/useMasterKey";
import { useOrgMasterKey } from "@/hooks/useOrgMasterKey";
import { unwrapOMKFromInvite, wrapOMKWithPersonalMK } from "@/hooks/orgMasterKeyCrypto";
import { toast } from "sonner";

type Status = "loading" | "success_with_key" | "success_no_key" | "needs_unlock" | "error";

export default function AcceptInvitePage() {
    const { code } = useParams<{ code: string }>();
    const navigate = useNavigate();
    const { switchToOrg, refreshOrganizations } = useOrganizationContext();
    const { isUnlocked, getCachedKey, deriveMasterKey, isDerivingKey } = useMasterKey();
    const { unlockOrgVault } = useOrgMasterKey();
    const storeWrappedOMK = trpc.orgKeys.storeWrappedOMKForSelf.useMutation();
    const acceptInvite = trpc.organizations.acceptInvite.useMutation();

    const [status, setStatus] = useState<Status>("loading");
    const [errorMessage, setErrorMessage] = useState("");
    const [orgId, setOrgId] = useState<number | null>(null);

    // Extract invite key from fragment on mount (before React clears it)
    const [inviteKeyFragment] = useState<string | null>(() => {
        const hash = window.location.hash;
        const match = hash.match(/^#key=([A-Za-z0-9_-]+)$/);
        return match?.[1] ?? null;
    });

    // Inline vault unlock state
    const [unlockPassword, setUnlockPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [unlockError, setUnlockError] = useState("");

    // Crypto state held between accept and unlock
    const [cryptoState, setCryptoState] = useState<{
        blob: string; keyVersion: number;
    } | null>(null);

    const completeCryptoFlow = async (
        blob: string, keyVersion: number, fragment: string, targetOrgId: number,
    ) => {
        try {
            const omk = await unwrapOMKFromInvite(blob, fragment);
            const personalMK = getCachedKey();
            if (!personalMK) throw new Error("Personal vault locked");

            const wrapped = await wrapOMKWithPersonalMK(omk, personalMK);
            await storeWrappedOMK.mutateAsync({
                organizationId: targetOrgId,
                omkEncrypted: wrapped,
                keyVersion,
            });

            await unlockOrgVault(targetOrgId);
            setStatus("success_with_key");
        } catch (err) {
            console.error("[AcceptInvite] Crypto flow failed:", err);
            setStatus("success_no_key");
        } finally {
            window.history.replaceState(null, "", window.location.pathname);
        }
    };

    useEffect(() => {
        if (!code) {
            setStatus("error");
            setErrorMessage("No invite code provided");
            return;
        }

        let cancelled = false;
        acceptInvite.mutateAsync({ inviteCode: code })
            .then(async (result) => {
                if (cancelled) return;
                setOrgId(result.organizationId);
                refreshOrganizations();

                if (result.omkWrappedForInvite && result.omkKeyVersion && inviteKeyFragment) {
                    if (isUnlocked) {
                        await completeCryptoFlow(
                            result.omkWrappedForInvite, result.omkKeyVersion,
                            inviteKeyFragment, result.organizationId,
                        );
                    } else {
                        setCryptoState({ blob: result.omkWrappedForInvite, keyVersion: result.omkKeyVersion });
                        setStatus("needs_unlock");
                    }
                } else {
                    setStatus("success_no_key");
                }
            })
            .catch((err: any) => {
                if (cancelled) return;
                setStatus("error");
                const msg = err.message || "Failed to accept invite";
                if (msg.includes("verify") || msg.includes("email")) {
                    setErrorMessage("Please verify your email, then click the invite link again.");
                } else {
                    setErrorMessage(msg);
                }
            });
        return () => { cancelled = true; };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [code]);

    const handleUnlockAndComplete = async (e: React.FormEvent) => {
        e.preventDefault();
        setUnlockError("");
        try {
            await deriveMasterKey(unlockPassword);
            if (cryptoState && orgId && inviteKeyFragment) {
                await completeCryptoFlow(cryptoState.blob, cryptoState.keyVersion, inviteKeyFragment, orgId);
            }
        } catch {
            setUnlockError("Incorrect password. Please try again.");
        }
    };

    const handleGoToOrg = async () => {
        if (orgId) {
            try {
                await switchToOrg(orgId);
                navigate("/home");
                return;
            } catch {
                toast.error("Could not switch to organization. Use the vault switcher to navigate manually.");
            }
        }
        navigate("/home");
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
            <div className="w-full max-w-md space-y-6 text-center">
                <div className="mx-auto w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center">
                    <Building2 className="w-8 h-8 text-primary" />
                </div>

                {status === "loading" && (
                    <>
                        <h1 className="text-2xl font-semibold">Accepting invite...</h1>
                        <Loader2 className="w-6 h-6 animate-spin mx-auto text-muted-foreground" />
                    </>
                )}

                {status === "success_with_key" && (
                    <>
                        <div className="mx-auto w-12 h-12 rounded-full bg-green-500/10 flex items-center justify-center">
                            <CheckCircle2 className="w-6 h-6 text-green-500" />
                        </div>
                        <h1 className="text-2xl font-semibold">You're all set</h1>
                        <p className="text-muted-foreground">
                            You've joined the organization and your encryption keys are ready.
                        </p>
                        <Button onClick={handleGoToOrg} className="mt-4">Go to organization</Button>
                    </>
                )}

                {status === "success_no_key" && (
                    <>
                        <div className="mx-auto w-12 h-12 rounded-full bg-green-500/10 flex items-center justify-center">
                            <CheckCircle2 className="w-6 h-6 text-green-500" />
                        </div>
                        <h1 className="text-2xl font-semibold">Invite accepted</h1>
                        <p className="text-muted-foreground">
                            You've joined the organization. An admin will grant you encryption access shortly.
                        </p>
                        <Button onClick={handleGoToOrg} className="mt-4">Go to organization</Button>
                    </>
                )}

                {status === "needs_unlock" && (
                    <>
                        <div className="mx-auto w-12 h-12 rounded-full bg-blue-500/10 flex items-center justify-center">
                            <Lock className="w-6 h-6 text-blue-500" />
                        </div>
                        <h1 className="text-2xl font-semibold">Invite accepted — Unlock your vault</h1>
                        <p className="text-muted-foreground">
                            Enter your Master Password to set up encryption for this organization.
                        </p>
                        <form onSubmit={handleUnlockAndComplete} className="space-y-4 text-left">
                            <div className="space-y-2">
                                <Label htmlFor="master-password">Master Password</Label>
                                <div className="relative">
                                    <Input
                                        id="master-password"
                                        type={showPassword ? "text" : "password"}
                                        value={unlockPassword}
                                        onChange={(e) => setUnlockPassword(e.target.value)}
                                        placeholder="Enter your master password"
                                        autoFocus
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowPassword(!showPassword)}
                                        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                                    >
                                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                    </button>
                                </div>
                                {unlockError && <p className="text-sm text-destructive">{unlockError}</p>}
                            </div>
                            <Button type="submit" className="w-full" disabled={isDerivingKey || !unlockPassword}>
                                {isDerivingKey ? (
                                    <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Unlocking...</>
                                ) : (
                                    "Unlock & Continue"
                                )}
                            </Button>
                        </form>
                    </>
                )}

                {status === "error" && (
                    <>
                        <div className="mx-auto w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
                            <XCircle className="w-6 h-6 text-destructive" />
                        </div>
                        <h1 className="text-2xl font-semibold">Invite failed</h1>
                        <p className="text-muted-foreground">{errorMessage}</p>
                        <Button variant="outline" onClick={() => navigate("/home")} className="mt-4">
                            Go to home
                        </Button>
                    </>
                )}
            </div>
        </div>
    );
}
