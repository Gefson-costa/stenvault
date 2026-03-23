/**
 * Shamir Setup Dialog Component
 *
 * 5-step wizard: password -> config -> processing -> external -> complete
 * Handles master key splitting into Shamir shares with configurable distribution.
 *
 * @module components/settings/ShamirSetupDialog
 */

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Loader2,
    AlertTriangle,
    QrCode,
    Key,
    Mail,
    Server,
    Download,
    Copy,
    Check,
    Plus,
    Minus,
    Info,
    Lock,
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Slider } from "@/components/ui/slider";
import { Separator } from "@/components/ui/separator";
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip";
import { prepareRecoveryShares } from "@/lib/platform/webShamirRecoveryProvider";
import { useMasterKey } from "@/hooks/useMasterKey";
import { deriveRawMasterKeyBytes } from "@/hooks/masterKeyCrypto";
import { QRCodeSVG } from "qrcode.react";

interface ShareDistribution {
    server: number;
    email: number;
    trustedContacts: number[];
    external: number;
}

interface ExternalShareDisplay {
    index: number;
    qrData: string;
    shareString: string;
}

interface ShamirSetupDialogProps {
    open: boolean;
    onClose: () => void;
    onSuccess: () => void;
}

export function ShamirSetupDialog({
    open,
    onClose,
    onSuccess,
}: ShamirSetupDialogProps) {
    // Setup state
    const [encryptionPassword, setEncryptionPassword] = useState("");
    const [threshold, setThreshold] = useState(3);
    const [distribution, setDistribution] = useState<ShareDistribution>({
        server: 1,
        email: 1,
        trustedContacts: [],
        external: 2,
    });
    const [emailRecipient, setEmailRecipient] = useState("");
    const [setupStep, setSetupStep] = useState<
        "password" | "config" | "processing" | "external" | "complete"
    >("password");
    const [externalShares, setExternalShares] = useState<ExternalShareDisplay[]>(
        []
    );
    const [copiedShare, setCopiedShare] = useState<number | null>(null);
    const [isUnlocking, setIsUnlocking] = useState(false);

    const { deriveMasterKey, config } = useMasterKey();

    // Get current encryption config for masterKeyVersion
    const { data: encryptionConfig } = trpc.encryption.getEncryptionConfig.useQuery();

    // Mutations
    const setupMutation = trpc.shamirRecovery.setupRecovery.useMutation({
        onSuccess: () => {
            toast.success("Shamir recovery configured successfully!");
            setSetupStep("complete");
            onSuccess();
        },
        onError: (error) => {
            toast.error(error.message);
            setSetupStep("config");
        },
    });

    // Calculated values
    const totalShares =
        distribution.server +
        distribution.email +
        distribution.trustedContacts.length +
        distribution.external;

    const isValidConfig =
        threshold >= 2 &&
        threshold <= totalShares &&
        totalShares >= 2 &&
        totalShares <= 255;

    const handleClose = () => {
        setSetupStep("password");
        setExternalShares([]);
        setThreshold(3);
        setDistribution({
            server: 1,
            email: 1,
            trustedContacts: [],
            external: 2,
        });
        setEmailRecipient("");
        setEncryptionPassword("");
        onClose();
    };

    const handleUnlockAndContinue = async () => {
        if (!encryptionPassword) {
            toast.error("Enter your encryption password");
            return;
        }

        setIsUnlocking(true);

        try {
            // Derive master key -- if password is wrong, unwrap fails with OperationError
            await deriveMasterKey(encryptionPassword);
            setSetupStep("config");
        } catch (error) {
            console.error("Unlock error:", error);
            toast.error("Invalid password. Please try again.");
        } finally {
            setIsUnlocking(false);
        }
    };

    const handleSetupSubmit = async () => {
        if (!encryptionPassword) {
            toast.error("Password required");
            return;
        }

        if (!isValidConfig) {
            toast.error("Invalid configuration");
            return;
        }

        setSetupStep("processing");

        let masterKeyBytes: Uint8Array | null = null;
        try {
            // Ensure vault is unlocked (caches non-extractable bundle)
            await deriveMasterKey(encryptionPassword);

            // Shamir splitting genuinely needs raw bytes — re-derive transiently
            if (!config?.salt || !config.argon2Params || !config.masterKeyEncrypted) {
                throw new Error('Encryption configuration not available');
            }
            const saltBytes = new Uint8Array(
                Uint8Array.from(atob(config.salt), c => c.charCodeAt(0))
            );
            masterKeyBytes = await deriveRawMasterKeyBytes(
                encryptionPassword,
                saltBytes,
                config.argon2Params as import('@stenvault/shared/platform/crypto').Argon2Params,
                config.masterKeyEncrypted
            );

            // Generate config ID
            const configId =
                window.crypto.randomUUID().replace(/-/g, "") +
                window.crypto.randomUUID().replace(/-/g, "");

            // Split the master key into shares
            const { shares } = await prepareRecoveryShares(
                masterKeyBytes,
                totalShares,
                threshold,
                configId
            );

            // Prepare shares for API
            let shareIndex = 0;
            const apiShares: Array<{
                index: number;
                encryptedShare: string;
                shareType:
                    | "server"
                    | "email"
                    | "trusted_contact"
                    | "external";
                encryptionMethod: string;
                integrityTag: string;
                recipientUserId?: number;
                recipientEmail?: string;
            }> = [];

            const externalSharesDisplay: ExternalShareDisplay[] = [];

            // Server shares
            for (let i = 0; i < distribution.server; i++) {
                const share = shares[shareIndex];
                if (share) {
                    apiShares.push({
                        index: share.index,
                        encryptedShare: share.data, // Server encrypts it
                        shareType: "server",
                        encryptionMethod: "server-aes-gcm",
                        integrityTag: share.hmac,
                    });
                }
                shareIndex++;
            }

            // Email shares
            for (let i = 0; i < distribution.email; i++) {
                const share = shares[shareIndex];
                if (share) {
                    apiShares.push({
                        index: share.index,
                        encryptedShare: share.data,
                        shareType: "email",
                        encryptionMethod: "email-token-aes-gcm",
                        integrityTag: share.hmac,
                        recipientEmail: emailRecipient || undefined,
                    });
                }
                shareIndex++;
            }

            // External shares
            for (let i = 0; i < distribution.external; i++) {
                const share = shares[shareIndex];
                if (share) {
                    const shareString = `shamir:v1:${share.index}/${threshold}/${totalShares}:${share.data}`;
                    const qrData = `${shareString}|${share.hmac}`;

                    apiShares.push({
                        index: share.index,
                        encryptedShare: share.data,
                        shareType: "external",
                        encryptionMethod: "none-hmac",
                        integrityTag: share.hmac,
                    });

                    externalSharesDisplay.push({
                        index: share.index,
                        shareString,
                        qrData,
                    });
                }
                shareIndex++;
            }

            setExternalShares(externalSharesDisplay);

            // Send to server
            await setupMutation.mutateAsync({
                threshold,
                distribution: {
                    server: distribution.server,
                    email: distribution.email,
                    trustedContacts: distribution.trustedContacts,
                    external: distribution.external,
                },
                masterKeyVersion: encryptionConfig?.masterKeyVersion ?? 1,
                shares: apiShares,
                emailRecipients: emailRecipient ? [emailRecipient] : undefined,
            });

            if (externalSharesDisplay.length > 0) {
                setSetupStep("external");
            }
        } catch (error) {
            console.error("Setup error:", error);
            toast.error(
                error instanceof Error ? error.message : "Setup failed"
            );
            setSetupStep("config");
        } finally {
            if (masterKeyBytes) masterKeyBytes.fill(0);
        }
    };

    const copyShareString = async (shareString: string, index: number) => {
        await navigator.clipboard.writeText(shareString);
        setCopiedShare(index);
        setTimeout(() => setCopiedShare(null), 2000);
        toast.success("Share copied to clipboard!");
    };

    const downloadShareAsFile = (share: ExternalShareDisplay) => {
        const blob = new Blob([share.shareString], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `recovery-share-${share.index}.txt`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success("Share downloaded!");
    };

    const adjustDistribution = (
        type: "server" | "email" | "external",
        delta: number
    ) => {
        setDistribution((prev) => ({
            ...prev,
            [type]: Math.max(0, Math.min(10, prev[type] + delta)),
        }));
    };

    return (
        <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
            <DialogContent className="max-w-lg">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <Key className="w-5 h-5" />
                        Set Up Shamir Recovery
                    </DialogTitle>
                    <DialogDescription>
                        {setupStep === "password" &&
                            "Enter your encryption password to unlock your master key."}
                        {setupStep === "config" &&
                            "Configure how your master key will be split and distributed."}
                        {setupStep === "processing" &&
                            "Setting up recovery shares..."}
                        {setupStep === "external" &&
                            "Save your external recovery shares in a safe place."}
                        {setupStep === "complete" &&
                            "Recovery setup complete!"}
                    </DialogDescription>
                </DialogHeader>

                {setupStep === "password" && (
                    <div className="space-y-4">
                        <Alert>
                            <Lock className="h-4 w-4" />
                            <AlertTitle>Unlock Required</AlertTitle>
                            <AlertDescription>
                                Your encryption password is needed to access and
                                split your master key securely.
                            </AlertDescription>
                        </Alert>

                        <div className="space-y-2">
                            <Label htmlFor="encryption-password">
                                Encryption Password
                            </Label>
                            <Input
                                id="encryption-password"
                                type="password"
                                value={encryptionPassword}
                                onChange={(e) =>
                                    setEncryptionPassword(e.target.value)
                                }
                                placeholder="Enter your encryption password"
                                onKeyDown={(e) => {
                                    if (e.key === "Enter") {
                                        handleUnlockAndContinue();
                                    }
                                }}
                            />
                        </div>

                        <DialogFooter>
                            <Button variant="outline" onClick={handleClose}>
                                Cancel
                            </Button>
                            <Button
                                onClick={handleUnlockAndContinue}
                                disabled={!encryptionPassword || isUnlocking}
                            >
                                {isUnlocking ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Unlocking...
                                    </>
                                ) : (
                                    "Continue"
                                )}
                            </Button>
                        </DialogFooter>
                    </div>
                )}

                {setupStep === "config" && (
                    <div className="space-y-6">
                        {/* Threshold Configuration */}
                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <Label className="text-base font-medium">
                                    Recovery Threshold (K)
                                </Label>
                                <TooltipProvider>
                                    <Tooltip>
                                        <TooltipTrigger>
                                            <Info className="h-4 w-4 text-muted-foreground" />
                                        </TooltipTrigger>
                                        <TooltipContent>
                                            <p className="max-w-xs">
                                                Minimum shares needed to
                                                recover. Higher = more secure
                                                but harder to recover.
                                            </p>
                                        </TooltipContent>
                                    </Tooltip>
                                </TooltipProvider>
                            </div>
                            <div className="flex items-center gap-4">
                                <Slider
                                    value={[threshold]}
                                    onValueChange={([v]) =>
                                        setThreshold(v ?? 2)
                                    }
                                    min={2}
                                    max={Math.max(2, totalShares)}
                                    step={1}
                                    className="flex-1"
                                />
                                <span className="w-12 text-center font-mono text-lg">
                                    {threshold}
                                </span>
                            </div>
                            <p className="text-sm text-muted-foreground">
                                {threshold} of {totalShares} shares required to
                                recover
                            </p>
                            {threshold <= 2 && (
                                <Alert className="border-amber-500/50 bg-amber-500/10">
                                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                                    <AlertDescription className="text-sm text-amber-700 dark:text-amber-400">
                                        A low threshold means fewer shares are needed to recover your account.
                                        Consider using 3 or higher for better security.
                                    </AlertDescription>
                                </Alert>
                            )}
                        </div>

                        <Separator />

                        {/* Share Distribution */}
                        <div className="space-y-4">
                            <Label className="text-base font-medium">
                                Share Distribution
                            </Label>

                            {/* Server Shares */}
                            <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                                <div className="flex items-center gap-3">
                                    <Server className="h-5 w-5 text-blue-600" />
                                    <div>
                                        <p className="font-medium">
                                            Server Storage
                                        </p>
                                        <p className="text-xs text-muted-foreground">
                                            Encrypted and stored on our servers
                                        </p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Button
                                        variant="outline"
                                        size="icon"
                                        className="h-8 w-8"
                                        onClick={() =>
                                            adjustDistribution("server", -1)
                                        }
                                        disabled={distribution.server <= 0}
                                    >
                                        <Minus className="h-4 w-4" />
                                    </Button>
                                    <span className="w-8 text-center font-mono">
                                        {distribution.server}
                                    </span>
                                    <Button
                                        variant="outline"
                                        size="icon"
                                        className="h-8 w-8"
                                        onClick={() =>
                                            adjustDistribution("server", 1)
                                        }
                                        disabled={distribution.server >= 10}
                                    >
                                        <Plus className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>

                            {/* Email Shares */}
                            <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                                <div className="flex items-center gap-3">
                                    <Mail className="h-5 w-5 text-green-600" />
                                    <div>
                                        <p className="font-medium">
                                            Email Backup
                                        </p>
                                        <p className="text-xs text-muted-foreground">
                                            Stored securely, delivered via email during recovery
                                        </p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Button
                                        variant="outline"
                                        size="icon"
                                        className="h-8 w-8"
                                        onClick={() =>
                                            adjustDistribution("email", -1)
                                        }
                                        disabled={distribution.email <= 0}
                                    >
                                        <Minus className="h-4 w-4" />
                                    </Button>
                                    <span className="w-8 text-center font-mono">
                                        {distribution.email}
                                    </span>
                                    <Button
                                        variant="outline"
                                        size="icon"
                                        className="h-8 w-8"
                                        onClick={() =>
                                            adjustDistribution("email", 1)
                                        }
                                        disabled={distribution.email >= 10}
                                    >
                                        <Plus className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>

                            {/* External Shares */}
                            <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                                <div className="flex items-center gap-3">
                                    <QrCode className="h-5 w-5 text-purple-600" />
                                    <div>
                                        <p className="font-medium">
                                            External (QR/Paper)
                                        </p>
                                        <p className="text-xs text-muted-foreground">
                                            Print or save as QR codes
                                        </p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Button
                                        variant="outline"
                                        size="icon"
                                        className="h-8 w-8"
                                        onClick={() =>
                                            adjustDistribution("external", -1)
                                        }
                                        disabled={distribution.external <= 0}
                                    >
                                        <Minus className="h-4 w-4" />
                                    </Button>
                                    <span className="w-8 text-center font-mono">
                                        {distribution.external}
                                    </span>
                                    <Button
                                        variant="outline"
                                        size="icon"
                                        className="h-8 w-8"
                                        onClick={() =>
                                            adjustDistribution("external", 1)
                                        }
                                        disabled={distribution.external >= 10}
                                    >
                                        <Plus className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>
                        </div>

                        {/* Email Recipient */}
                        {distribution.email > 0 && (
                            <div className="space-y-2">
                                <Label htmlFor="email-recipient">
                                    Recovery Email (optional)
                                </Label>
                                <Input
                                    id="email-recipient"
                                    type="email"
                                    placeholder="Leave blank to use your account email"
                                    value={emailRecipient}
                                    onChange={(e) =>
                                        setEmailRecipient(e.target.value)
                                    }
                                />
                                <p className="text-xs text-muted-foreground">
                                    A confirmation will be sent now. The actual share will be delivered when you initiate recovery.
                                </p>
                            </div>
                        )}

                        {/* Validation Warning */}
                        {!isValidConfig && (
                            <Alert variant="destructive">
                                <AlertTriangle className="h-4 w-4" />
                                <AlertDescription>
                                    {totalShares < 2
                                        ? "You need at least 2 shares total."
                                        : threshold > totalShares
                                          ? "Threshold cannot exceed total shares."
                                          : "Invalid configuration."}
                                </AlertDescription>
                            </Alert>
                        )}

                        <DialogFooter>
                            <Button variant="outline" onClick={handleClose}>
                                Cancel
                            </Button>
                            <Button
                                onClick={handleSetupSubmit}
                                disabled={
                                    !isValidConfig || setupMutation.isPending
                                }
                            >
                                Create Shares
                            </Button>
                        </DialogFooter>
                    </div>
                )}

                {setupStep === "processing" && (
                    <div className="flex flex-col items-center justify-center py-12 gap-4">
                        <Loader2 className="h-12 w-12 animate-spin text-purple-600" />
                        <p className="text-muted-foreground">
                            Generating and distributing shares...
                        </p>
                    </div>
                )}

                {setupStep === "external" && externalShares.length > 0 && (
                    <div className="space-y-4">
                        <Alert>
                            <AlertTriangle className="h-4 w-4" />
                            <AlertTitle>Important!</AlertTitle>
                            <AlertDescription>
                                Save these QR codes in secure locations. They are
                                shown ONCE and cannot be recovered from the
                                server.
                            </AlertDescription>
                        </Alert>

                        <div className="space-y-4">
                            {externalShares.map((share) => (
                                <div
                                    key={share.index}
                                    className="p-4 border rounded-lg space-y-3"
                                >
                                    <div className="flex items-center justify-between">
                                        <span className="font-medium">
                                            Share #{share.index}
                                        </span>
                                        <div className="flex gap-2">
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={() =>
                                                    copyShareString(
                                                        share.shareString,
                                                        share.index
                                                    )
                                                }
                                            >
                                                {copiedShare ===
                                                share.index ? (
                                                    <Check className="h-4 w-4" />
                                                ) : (
                                                    <Copy className="h-4 w-4" />
                                                )}
                                            </Button>
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={() =>
                                                    downloadShareAsFile(share)
                                                }
                                            >
                                                <Download className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                    <div className="flex justify-center bg-muted p-4 rounded-lg">
                                        <QRCodeSVG
                                            value={share.qrData}
                                            size={192}
                                            bgColor="transparent"
                                            fgColor="currentColor"
                                        />
                                    </div>
                                    <code className="block text-xs bg-muted p-2 rounded overflow-x-auto">
                                        {share.shareString}
                                    </code>
                                </div>
                            ))}
                        </div>

                        <DialogFooter>
                            <Button onClick={handleClose}>
                                I've Saved My Shares
                            </Button>
                        </DialogFooter>
                    </div>
                )}

                {setupStep === "complete" && externalShares.length === 0 && (
                    <div className="flex flex-col items-center justify-center py-8 gap-4">
                        <div className="p-4 bg-green-100 dark:bg-green-900 rounded-full">
                            <Check className="h-8 w-8 text-green-600 dark:text-green-400" />
                        </div>
                        <p className="text-center text-muted-foreground">
                            Your recovery shares have been created and
                            distributed.
                        </p>
                        <Button onClick={handleClose}>Done</Button>
                    </div>
                )}
            </DialogContent>
        </Dialog>
    );
}
