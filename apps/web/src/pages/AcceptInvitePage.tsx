/**
 * Accept Organization Invite Page
 *
 * Route: /invite/:code
 * Requires authentication (AuthGuard). Unauthenticated users redirect to login first.
 * On success, redirects to /home with the org context switched.
 */

import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { trpc } from "@/lib/trpc";
import { Building2, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useOrganizationContext } from "@/contexts/OrganizationContext";

type Status = "loading" | "success" | "error";

export default function AcceptInvitePage() {
    const { code } = useParams<{ code: string }>();
    const navigate = useNavigate();
    const { switchToOrg, refreshOrganizations } = useOrganizationContext();

    const [status, setStatus] = useState<Status>("loading");
    const [errorMessage, setErrorMessage] = useState("");
    const [orgId, setOrgId] = useState<number | null>(null);

    const acceptInvite = trpc.organizations.acceptInvite.useMutation();

    useEffect(() => {
        if (!code) {
            setStatus("error");
            setErrorMessage("No invite code provided");
            return;
        }

        acceptInvite.mutateAsync({ inviteCode: code })
            .then((result) => {
                setStatus("success");
                setOrgId(result.organizationId);
                refreshOrganizations();
            })
            .catch((err: any) => {
                setStatus("error");
                setErrorMessage(err.message || "Failed to accept invite");
            });
        // Run once on mount
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [code]);

    const handleGoToOrg = async () => {
        if (orgId) {
            try {
                await switchToOrg(orgId);
            } catch { /* ignore */ }
        }
        navigate("/home");
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
            <div className="w-full max-w-md space-y-6 text-center">
                {/* Icon */}
                <div className="mx-auto w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center">
                    <Building2 className="w-8 h-8 text-primary" />
                </div>

                {status === "loading" && (
                    <>
                        <h1 className="text-2xl font-semibold">Accepting invite...</h1>
                        <Loader2 className="w-6 h-6 animate-spin mx-auto text-muted-foreground" />
                    </>
                )}

                {status === "success" && (
                    <>
                        <div className="mx-auto w-12 h-12 rounded-full bg-green-500/10 flex items-center justify-center">
                            <CheckCircle2 className="w-6 h-6 text-green-500" />
                        </div>
                        <h1 className="text-2xl font-semibold">Invite accepted</h1>
                        <p className="text-muted-foreground">
                            You've joined the organization. Your encryption keys will be set up once an admin distributes them.
                        </p>
                        <Button onClick={handleGoToOrg} className="mt-4">
                            Go to organization
                        </Button>
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
