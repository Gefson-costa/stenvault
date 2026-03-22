/**
 * Shamir Recovery Section Component
 *
 * Allows users to set up and manage Shamir Secret Sharing for master key recovery.
 * Supports server, email, trusted contacts, and external (QR) share distribution.
 *
 * @module components/settings/ShamirRecoverySection
 */

import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import {
    Loader2,
    Shield,
    ShieldCheck,
    ShieldAlert,
    AlertTriangle,
    QrCode,
    Key,
    Users,
    Mail,
    Server,
    Info,
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ShamirSetupDialog } from "./ShamirSetupDialog";
import { ShamirRevokeDialog } from "./ShamirRevokeDialog";
import { ShamirExternalSharesDialog } from "./ShamirExternalSharesDialog";

export function ShamirRecoverySection() {
    // Status queries
    const {
        data: status,
        isLoading: statusLoading,
        refetch: refetchStatus,
    } = trpc.shamirRecovery.getStatus.useQuery();

    const { data: encryptionStatus } =
        trpc.encryption.getMasterKeyStatus.useQuery();

    // Dialog open states
    const [setupOpen, setSetupOpen] = useState(false);
    const [revokeOpen, setRevokeOpen] = useState(false);
    const [viewExternalOpen, setViewExternalOpen] = useState(false);

    const hasEncryptionSetup = encryptionStatus?.isConfigured ?? false;

    const handleSetupClick = () => {
        if (!hasEncryptionSetup) {
            toast.error("Please set up your encryption password first");
            return;
        }
        setSetupOpen(true);
    };

    const handleSetupClose = () => {
        setSetupOpen(false);
    };

    const handleSetupSuccess = () => {
        refetchStatus();
    };

    const handleRevokeSuccess = () => {
        refetchStatus();
    };

    if (statusLoading) {
        return (
            <Card>
                <CardContent className="flex items-center justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </CardContent>
            </Card>
        );
    }

    const isConfigured = status?.isConfigured;

    return (
        <>
            <Card
                className={`border-2 ${
                    isConfigured
                        ? "border-purple-100 dark:border-purple-900"
                        : "border-gray-100 dark:border-gray-800"
                } shadow-sm`}
            >
                <CardHeader>
                    <div className="flex flex-wrap items-center justify-between gap-3">
                        <div className="flex items-center gap-3 min-w-0">
                            <div
                                className={`p-2 rounded-lg shrink-0 ${
                                    isConfigured
                                        ? "bg-purple-100 dark:bg-purple-900"
                                        : "bg-gray-100 dark:bg-gray-800"
                                }`}
                            >
                                {isConfigured ? (
                                    <ShieldCheck className="w-6 h-6 text-purple-600 dark:text-purple-400" />
                                ) : (
                                    <Shield className="w-6 h-6 text-gray-600 dark:text-gray-400" />
                                )}
                            </div>
                            <div className="min-w-0">
                                <CardTitle>
                                    Social Recovery
                                </CardTitle>
                                <CardDescription>
                                    {isConfigured
                                        ? `Split recovery enabled (${status.threshold}-of-${status.totalShares} shares required)`
                                        : "Split your recovery key among trusted locations"}
                                </CardDescription>
                            </div>
                        </div>
                        {isConfigured ? (
                            <div className="flex flex-wrap gap-2">
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => setViewExternalOpen(true)}
                                >
                                    <QrCode className="mr-2 h-4 w-4" />
                                    View QR Codes
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => setRevokeOpen(true)}
                                    className="text-red-600 border-red-200 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                                >
                                    <ShieldAlert className="mr-2 h-4 w-4" />
                                    Revoke
                                </Button>
                            </div>
                        ) : (
                            <Button
                                variant="default"
                                size="sm"
                                onClick={handleSetupClick}
                                disabled={!hasEncryptionSetup}
                            >
                                <Key className="mr-2 h-4 w-4" />
                                Set Up Recovery
                            </Button>
                        )}
                    </div>
                </CardHeader>
                {isConfigured && status.distribution && (
                    <CardContent>
                        <div className="bg-purple-50 dark:bg-purple-950/30 p-4 rounded-lg space-y-3">
                            <div className="flex items-center gap-4 text-sm text-purple-900 dark:text-purple-100">
                                <div className="flex items-center gap-2">
                                    <Server className="h-4 w-4" />
                                    <span>
                                        {status.distribution.server} Server
                                    </span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Mail className="h-4 w-4" />
                                    <span>
                                        {status.distribution.email} Email
                                    </span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Users className="h-4 w-4" />
                                    <span>
                                        {status.distribution.trusted_contact ||
                                            0}{" "}
                                        Contacts
                                    </span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <QrCode className="h-4 w-4" />
                                    <span>
                                        {status.distribution.external} External
                                    </span>
                                </div>
                            </div>
                            <p className="text-xs text-purple-700 dark:text-purple-300">
                                You need any {status.threshold} shares from
                                different sources to recover your master key.
                            </p>
                        </div>
                    </CardContent>
                )}
                {!isConfigured && (
                    <CardContent>
                        {!hasEncryptionSetup ? (
                            <Alert>
                                <AlertTriangle className="h-4 w-4" />
                                <AlertTitle>Setup Required</AlertTitle>
                                <AlertDescription>
                                    You need to set up your encryption password
                                    first before configuring Shamir recovery.
                                </AlertDescription>
                            </Alert>
                        ) : (
                            <Alert>
                                <Info className="h-4 w-4" />
                                <AlertTitle>Why use Shamir Recovery?</AlertTitle>
                                <AlertDescription>
                                    Split your master key into multiple shares
                                    stored in different locations. You'll need a
                                    minimum number of shares to recover,
                                    providing both security and redundancy.
                                </AlertDescription>
                            </Alert>
                        )}
                    </CardContent>
                )}
            </Card>

            {/* Setup Dialog */}
            <ShamirSetupDialog
                open={setupOpen}
                onClose={handleSetupClose}
                onSuccess={handleSetupSuccess}
            />

            {/* View External Shares Dialog */}
            <ShamirExternalSharesDialog
                open={viewExternalOpen}
                onOpenChange={setViewExternalOpen}
            />

            {/* Revoke Dialog */}
            <ShamirRevokeDialog
                open={revokeOpen}
                onOpenChange={setRevokeOpen}
                onSuccess={handleRevokeSuccess}
            />
        </>
    );
}
