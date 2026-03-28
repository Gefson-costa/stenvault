import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Loader2,
    Mail,
    MailCheck,
    Shield,
    ShieldCheck,
    ShieldAlert,
    Copy,
    Check,
    AlertTriangle,
    QrCode,
    Key,
    Lock,
    Trash2,
    Download,
    Fingerprint,
} from "lucide-react";
import { browserSupportsWebAuthn, startRegistration as startPasskeyRegistration } from "@simplewebauthn/browser";
import { clearMasterKeyCache, clearDeviceWrappedMK } from "@/hooks/useMasterKey";
import { ShamirRecoverySection } from "./ShamirRecoverySection";
import { TrustedContactsSection } from "./TrustedContactsSection";
import { SignatureKeysSection } from "./SignatureKeysSection";
import { RecoveryCodesSection } from "./RecoveryCodesSection";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { useAuth } from "@/_core/hooks/useAuth";
import { startLogin, finishLogin, startRegistration, finishRegistration } from "@/lib/opaqueClient";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import {
    Alert,
    AlertDescription,
    AlertTitle,
} from "@/components/ui/alert";
import { useTheme } from "@/contexts/ThemeContext";
import { QRCodeSVG } from "qrcode.react";

/**
 * SecuritySettings Component
 * 
 * Displays email verification status, MFA setup, and password management.
 * 
 * @component
 */
export function SecuritySettings() {
    const { user } = useAuth();
    const { theme } = useTheme();
    const resendVerificationMutation = trpc.auth.sendVerificationEmail.useMutation();

    // MFA State
    const [mfaSetupOpen, setMfaSetupOpen] = useState(false);
    const [mfaDisableOpen, setMfaDisableOpen] = useState(false);
    const [mfaSecret, setMfaSecret] = useState("");
    const [mfaSetupId, setMfaSetupId] = useState("");
    const [qrCodeUrl, setQrCodeUrl] = useState("");
    const [verificationCode, setVerificationCode] = useState("");
    const [backupCodes, setBackupCodes] = useState<string[]>([]);
    const [disableTotpCode, setDisableTotpCode] = useState("");
    const [copiedCode, setCopiedCode] = useState<number | null>(null);

    // Password Change State
    const [passwordChangeOpen, setPasswordChangeOpen] = useState(false);
    const [currentPassword, setCurrentPassword] = useState("");
    const [newPassword, setNewPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");

    // Encryption Reset State
    const [resetEncryptionOpen, setResetEncryptionOpen] = useState(false);
    const [resetConfirmText, setResetConfirmText] = useState("");
    const deleteMasterKeyMutation = trpc.encryption.deleteMasterKey.useMutation();

    // Recovery status for reset dialog context
    const { data: masterKeyStatus } = trpc.encryption.getMasterKeyStatus.useQuery();
    const { data: shamirStatus } = trpc.shamirRecovery.getStatus.useQuery();

    // MFA Queries & Mutations
    const { data: mfaStatus, refetch: refetchMfaStatus } = trpc.mfa.getStatus.useQuery();

    const setupMfaMutation = trpc.mfa.setup.useMutation({
        onSuccess: (data) => {
            setMfaSecret(data.secret);
            setQrCodeUrl(data.qrCodeUrl);
            if (data.setupId) setMfaSetupId(data.setupId);
            toast.success("QR Code generated! Scan it with your authenticator app.");
        },
        onError: (error) => toast.error(error.message),
    });

    const verifyMfaMutation = trpc.mfa.verify.useMutation({
        onSuccess: (data) => {
            setBackupCodes(data.backupCodes);
            toast.success("Two-step login enabled!");
            refetchMfaStatus();
        },
        onError: (error) => toast.error(error.message),
    });

    const disableMfaMutation = trpc.mfa.disable.useMutation({
        onSuccess: () => {
            setMfaDisableOpen(false);
            setDisableTotpCode("");
            toast.success("Two-step login disabled");
            refetchMfaStatus();
        },
        onError: (error) => toast.error(error.message),
    });

    // Passkey State
    const [passkeyRegisterOpen, setPasskeyRegisterOpen] = useState(false);
    const [passkeyDeleteOpen, setPasskeyDeleteOpen] = useState<number | null>(null);
    const [passkeyFriendlyName, setPasskeyFriendlyName] = useState("");
    const [isRegisteringPasskey, setIsRegisteringPasskey] = useState(false);

    // Passkey Queries & Mutations
    const { data: passkeys, refetch: refetchPasskeys } = trpc.passkeys.list.useQuery();
    const generateRegOptionsMutation = trpc.passkeys.generateRegistrationOptions.useMutation();
    const verifyRegMutation = trpc.passkeys.verifyRegistration.useMutation();
    const deletePasskeyMutation = trpc.passkeys.delete.useMutation();

    // OPAQUE Password Change Mutations
    const opaqueChangeStartMutation = trpc.auth.opaqueChangePasswordStart.useMutation();
    const opaqueChangeFinishMutation = trpc.auth.opaqueChangePasswordFinish.useMutation();
    const opaqueRegisterStartMutation = trpc.auth.opaqueRegisterStart.useMutation();
    const [isChangingPassword, setIsChangingPassword] = useState(false);

    const handleSetupMfa = async () => {
        setupMfaMutation.mutate();
        setMfaSetupOpen(true);
    };

    const handleVerifyMfa = async () => {
        if (verificationCode.length !== 6) {
            toast.error("Enter a 6-digit code");
            return;
        }
        verifyMfaMutation.mutate({
            token: verificationCode,
            setupId: mfaSetupId,
        });
    };

    const handleDisableMfa = async () => {
        if (!disableTotpCode || disableTotpCode.length !== 6) {
            toast.error("Enter a 6-digit authenticator code");
            return;
        }
        disableMfaMutation.mutate({ totpCode: disableTotpCode });
    };

    const copyBackupCode = async (code: string, index: number) => {
        await navigator.clipboard.writeText(code);
        setCopiedCode(index);
        setTimeout(() => setCopiedCode(null), 2000);
        toast.success("Code copied!");
    };

    const handleCloseSetup = () => {
        setMfaSetupOpen(false);
        setMfaSecret("");
        setMfaSetupId("");
        setQrCodeUrl("");
        setVerificationCode("");
        setBackupCodes([]);
    };

    const handleRegisterPasskey = async () => {
        try {
            setIsRegisteringPasskey(true);
            const { options, challengeId } = await generateRegOptionsMutation.mutateAsync({
                friendlyName: passkeyFriendlyName || undefined,
            });

            const credential = await startPasskeyRegistration({ optionsJSON: options });

            await verifyRegMutation.mutateAsync({ challengeId, credential: credential as any });
            toast.success("Passkey registered!");
            setPasskeyRegisterOpen(false);
            setPasskeyFriendlyName("");
            refetchPasskeys();
        } catch (error: any) {
            if (error?.name === "NotAllowedError") return;
            toast.error(error?.message || "Failed to register passkey");
        } finally {
            setIsRegisteringPasskey(false);
        }
    };

    const handleDeletePasskey = async (id: number) => {
        try {
            await deletePasskeyMutation.mutateAsync({ passkeyId: id });
            toast.success("Passkey removed");
            setPasskeyDeleteOpen(null);
            refetchPasskeys();
        } catch (error: any) {
            toast.error(error?.message || "Failed to remove passkey");
        }
    };

    const handleResendVerification = async () => {
        try {
            await resendVerificationMutation.mutateAsync({ email: user?.email || "" });
            toast.success("Verification email resent! Please check your inbox.");
        } catch (error: any) {
            toast.error(error.message || "Error sending email");
        }
    };

    const handleChangePassword = async () => {
        if (!currentPassword) {
            toast.error("Enter your current password");
            return;
        }
        if (newPassword.length < 12) {
            toast.error("New password must be at least 12 characters");
            return;
        }
        if (newPassword !== confirmPassword) {
            toast.error("Passwords do not match");
            return;
        }

        try {
            setIsChangingPassword(true);

            // Step 1: Start OPAQUE login with current password to prove knowledge
            const clientLogin = await startLogin(currentPassword);
            const step1 = await opaqueChangeStartMutation.mutateAsync({
                startLoginRequest: clientLogin.startLoginRequest,
            });

            // Step 2: Finish OPAQUE login (proves current password)
            const clientFinish = await finishLogin(
                currentPassword,
                clientLogin.clientLoginState,
                step1.loginResponse
            );
            if (!clientFinish) {
                throw new Error("Current password is incorrect");
            }

            // Step 3: Create new OPAQUE registration with new password
            const clientReg = await startRegistration(newPassword);
            const regStep = await opaqueRegisterStartMutation.mutateAsync({
                email: user?.email || "",
                registrationRequest: clientReg.registrationRequest,
            });
            const regFinish = await finishRegistration(
                newPassword,
                clientReg.clientRegistrationState,
                regStep.registrationResponse
            );

            // Step 5: Send proof of current password + new OPAQUE record to server
            // NOTE: Login password and encryption password are independent.
            // Changing the login password must NOT touch the Master Key wrapping.
            await opaqueChangeFinishMutation.mutateAsync({
                finishLoginRequest: clientFinish.finishLoginRequest,
                newRegistrationRecord: regFinish.registrationRecord,
            });

            // Step 7: Invalidate Device-KEK + UES — force re-auth on all devices
            clearMasterKeyCache();
            clearDeviceWrappedMK();
            try {
                const { clearUES } = await import("@/lib/uesManager");
                clearUES();
            } catch {
                // UES module may not be available in all environments
            }

            toast.success("Password changed successfully!");
            setPasswordChangeOpen(false);
            setCurrentPassword("");
            setNewPassword("");
            setConfirmPassword("");
        } catch (error: any) {
            toast.error(error?.message || "Failed to change password");
        } finally {
            setIsChangingPassword(false);
        }
    };

    const handleResetEncryption = async () => {
        try {
            await deleteMasterKeyMutation.mutateAsync();
            clearMasterKeyCache();
            clearDeviceWrappedMK();
            localStorage.removeItem('stenvault_ues_v1');
            toast.success('Encryption reset. Reloading...');
            setTimeout(() => window.location.reload(), 1000);
        } catch (error: any) {
            toast.error(error.message || 'Failed to reset encryption');
        }
    };

    return (
        <div className="space-y-6">
            {/* Email Verification Status */}
            <Card className={`border-2 ${user?.emailVerified ? 'border-green-100 dark:border-green-900' : 'border-amber-100 dark:border-amber-900'} shadow-sm`}>
                <CardHeader>
                    <div className="flex items-start justify-between gap-4">
                        <div className="flex items-center gap-3 min-w-0">
                            <div
                                className="p-2 rounded-lg shrink-0"
                                style={{
                                    backgroundColor: user?.emailVerified
                                        ? `${theme.semantic.success}15`
                                        : `${theme.semantic.warning}15`
                                }}
                            >
                                <MailCheck
                                    className="w-6 h-6"
                                    style={{
                                        color: user?.emailVerified
                                            ? theme.semantic.success
                                            : theme.semantic.warning
                                    }}
                                />
                            </div>
                            <div className="min-w-0">
                                <CardTitle>Email Verification</CardTitle>
                                <CardDescription>
                                    {user?.emailVerified
                                        ? 'Your email has been verified successfully'
                                        : 'Verify your email to increase account security'}
                                </CardDescription>
                            </div>
                        </div>
                        {user?.emailVerified ? (
                            <Badge
                                variant="secondary"
                                style={{
                                    backgroundColor: `${theme.semantic.success}15`,
                                    color: theme.semantic.success
                                }}
                            >
                                Verified
                            </Badge>
                        ) : (
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={handleResendVerification}
                                disabled={resendVerificationMutation.isPending}
                                className="border-amber-200 text-amber-700 hover:bg-amber-50 dark:border-amber-800 dark:text-amber-400 dark:hover:bg-amber-950"
                            >
                                {resendVerificationMutation.isPending ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Sending...
                                    </>
                                ) : (
                                    <>
                                        <Mail className="mr-2 h-4 w-4" />
                                        Resend Email
                                    </>
                                )}
                            </Button>
                        )}
                    </div>
                </CardHeader>
            </Card>

            {/* MFA Card */}
            <Card className={`border-2 ${mfaStatus?.enabled ? 'border-blue-100 dark:border-blue-900' : 'border-gray-100 dark:border-gray-800'} shadow-sm`
            }>
                <CardHeader>
                    <div className="flex items-start justify-between gap-4">
                        <div className="flex items-center gap-3 min-w-0">
                            <div className={`p-2 rounded-lg shrink-0 ${mfaStatus?.enabled ? 'bg-blue-100 dark:bg-blue-900' : 'bg-gray-100 dark:bg-gray-800'}`}>
                                {mfaStatus?.enabled ? (
                                    <ShieldCheck className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                                ) : (
                                    <Shield className="w-6 h-6 text-gray-600 dark:text-gray-400" />
                                )}
                            </div>
                            <div className="min-w-0">
                                <CardTitle>Two-Step Login</CardTitle>
                                <CardDescription>
                                    {mfaStatus?.enabled
                                        ? 'Active — you\'ll need your authenticator app to sign in'
                                        : 'Require a code from your phone in addition to your password'}
                                </CardDescription>
                            </div>
                        </div>
                        {mfaStatus?.enabled ? (
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setMfaDisableOpen(true)}
                                className="text-red-600 border-red-200 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                            >
                                <ShieldAlert className="mr-2 h-4 w-4" />
                                Disable
                            </Button>
                        ) : (
                            <Button
                                variant="default"
                                size="sm"
                                onClick={handleSetupMfa}
                                disabled={setupMfaMutation.isPending}
                            >
                                {setupMfaMutation.isPending ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Setting up...
                                    </>
                                ) : (
                                    <>
                                        <Shield className="mr-2 h-4 w-4" />
                                        Enable
                                    </>
                                )}
                            </Button>
                        )}
                    </div>
                </CardHeader>
                {mfaStatus?.enabled && (
                    <CardContent>
                        <div className="bg-blue-50 dark:bg-blue-950/30 p-4 rounded-lg">
                            <p className="text-sm text-blue-900 dark:text-blue-100">
                                <strong>Protected:</strong> You'll need to enter a code from your authenticator app each time you sign in.
                            </p>
                        </div>
                    </CardContent>
                )}
            </Card>

            {/* Passkeys (WebAuthn) */}
            {browserSupportsWebAuthn() && (
                <Card>
                    <CardHeader>
                        <div className="flex items-start justify-between gap-4">
                            <div className="flex items-center gap-3 min-w-0">
                                <div className="p-2 rounded-lg bg-indigo-50 dark:bg-indigo-950 shrink-0">
                                    <Fingerprint className="w-6 h-6 text-indigo-600 dark:text-indigo-400" />
                                </div>
                                <div className="min-w-0">
                                    <CardTitle>Passkeys</CardTitle>
                                    <CardDescription>
                                        Sign in with biometrics or security keys instead of a password
                                    </CardDescription>
                                </div>
                            </div>
                            <div className="flex items-center gap-2">
                                {passkeys && passkeys.length > 0 && (
                                    <Badge variant="secondary">{passkeys.length}</Badge>
                                )}
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => setPasskeyRegisterOpen(true)}
                                >
                                    <Fingerprint className="mr-2 h-4 w-4" />
                                    Add Passkey
                                </Button>
                            </div>
                        </div>
                    </CardHeader>
                    {passkeys && passkeys.length > 0 && (
                        <CardContent>
                            <div className="space-y-3">
                                {passkeys.map((pk) => (
                                    <div
                                        key={pk.id}
                                        className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50"
                                    >
                                        <div className="flex items-center gap-3 min-w-0">
                                            <Fingerprint className="h-5 w-5 text-slate-400 shrink-0" />
                                            <div className="min-w-0">
                                                <p className="text-sm font-medium truncate">
                                                    {pk.friendlyName || "Unnamed passkey"}
                                                </p>
                                                <p className="text-xs text-slate-500">
                                                    Added {new Date(pk.createdAt).toLocaleDateString()}
                                                    {pk.lastUsedAt && ` \u00b7 Last used ${new Date(pk.lastUsedAt).toLocaleDateString()}`}
                                                    {pk.backedUp && " \u00b7 Synced"}
                                                </p>
                                            </div>
                                        </div>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => setPasskeyDeleteOpen(pk.id)}
                                            className="text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950"
                                        >
                                            <Trash2 className="h-4 w-4" />
                                        </Button>
                                    </div>
                                ))}
                            </div>
                        </CardContent>
                    )}
                </Card>
            )}

            {/* Password Change */}
            <Card>
                <CardHeader>
                    <div className="flex items-start justify-between gap-4">
                        <div className="flex items-center gap-3 min-w-0">
                            <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 shrink-0">
                                <Lock className="w-6 h-6 text-gray-600 dark:text-gray-400" />
                            </div>
                            <div className="min-w-0">
                                <CardTitle>Password</CardTitle>
                                <CardDescription>
                                    Change your account password
                                </CardDescription>
                            </div>
                        </div>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setPasswordChangeOpen(true)}
                        >
                            <Key className="mr-2 h-4 w-4" />
                            Change Password
                        </Button>
                    </div>
                </CardHeader>
            </Card>

            {/* Recovery Codes (Phase 4.3 NEW_DAY) */}
            <RecoveryCodesSection />

            {/* Trusted Contacts — shares held for others */}
            <TrustedContactsSection />

            {/* Shamir Master Key Recovery */}
            <ShamirRecoverySection />

            {/* File Signatures (Phase 3.4 Sovereign) */}
            <SignatureKeysSection />

            {/* MFA Setup Dialog */}
            <Dialog open={mfaSetupOpen} onOpenChange={(open) => !open && handleCloseSetup()}>
                <DialogContent className="max-w-md max-h-[85vh] overflow-y-auto">
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <QrCode className="w-5 h-5" />
                            Set Up Two-Step Login
                        </DialogTitle>
                        <DialogDescription>
                            {backupCodes.length > 0
                                ? "Save these backup codes in a safe place"
                                : qrCodeUrl
                                    ? "Scan the QR code with your authenticator app and enter the generated code"
                                    : "Generating QR code..."}
                        </DialogDescription>
                    </DialogHeader>

                    <div className="space-y-4">
                        {backupCodes.length > 0 ? (
                            /* Backup Codes Display */
                            <>
                                <Alert>
                                    <AlertTriangle className="h-4 w-4" />
                                    <AlertTitle>Important!</AlertTitle>
                                    <AlertDescription>
                                        These codes are only shown ONCE. Store them in a safe place.
                                        You can use them to access your account if you lose access to your authenticator app.
                                    </AlertDescription>
                                </Alert>
                                <div className="grid grid-cols-2 gap-2 p-4 bg-muted rounded-lg max-h-64 overflow-y-auto">
                                    {backupCodes.map((code, index) => (
                                        <div
                                            key={index}
                                            className="flex items-center justify-between p-2 bg-background rounded border font-mono text-sm"
                                        >
                                            <span>{code}</span>
                                            <Button
                                                variant="ghost"
                                                size="icon"
                                                className="h-6 w-6"
                                                onClick={() => copyBackupCode(code, index)}
                                            >
                                                {copiedCode === index ? (
                                                    <Check className="h-3 w-3 text-green-600" />
                                                ) : (
                                                    <Copy className="h-3 w-3" />
                                                )}
                                            </Button>
                                        </div>
                                    ))}
                                </div>
                                <div className="flex gap-2">
                                    <Button
                                        variant="outline"
                                        className="flex-1"
                                        onClick={() => {
                                            navigator.clipboard.writeText(backupCodes.join("\n"));
                                            toast.success("All codes copied to clipboard");
                                        }}
                                    >
                                        <Copy className="h-4 w-4 mr-2" />
                                        Copy all
                                    </Button>
                                    <Button
                                        variant="outline"
                                        className="flex-1"
                                        onClick={() => {
                                            const content = [
                                                "StenVault - Two-Step Login Backup Codes",
                                                `Generated: ${new Date().toLocaleDateString()}`,
                                                "",
                                                "Keep these codes safe. Each can only be used once.",
                                                "",
                                                ...backupCodes.map((code, i) => `${i + 1}. ${code}`),
                                            ].join("\n");
                                            const blob = new Blob([content], { type: "text/plain" });
                                            const url = URL.createObjectURL(blob);
                                            const a = document.createElement("a");
                                            a.href = url;
                                            a.download = "stenvault-backup-codes.txt";
                                            a.click();
                                            URL.revokeObjectURL(url);
                                        }}
                                    >
                                        <Download className="h-4 w-4 mr-2" />
                                        Download
                                    </Button>
                                </div>
                                <Button
                                    onClick={handleCloseSetup}
                                    className="w-full"
                                >
                                    Finish
                                </Button>
                            </>
                        ) : qrCodeUrl ? (
                            /* QR Code and Verification */
                            <>
                                <div className="flex flex-col items-center gap-4 p-4 bg-muted rounded-lg">
                                    {/* Manual entry — primary on mobile (can't scan own screen) */}
                                    <div className="w-full">
                                        <p className="text-sm font-medium mb-2 text-center">Enter this code in your authenticator app:</p>
                                        <div className="flex items-center gap-2">
                                            <code className="flex-1 text-xs bg-background px-3 py-2 rounded border break-all text-center font-mono">
                                                {mfaSecret}
                                            </code>
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={() => {
                                                    navigator.clipboard.writeText(mfaSecret);
                                                    toast.success("Secret key copied to clipboard");
                                                }}
                                            >
                                                <Copy className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>

                                    {/* QR Code — secondary (useful when setting up from desktop) */}
                                    <div className="bg-white p-4 rounded-lg">
                                        <QRCodeSVG value={qrCodeUrl} size={192} />
                                    </div>
                                    <p className="text-xs text-muted-foreground text-center">
                                        Or scan this QR code from another device
                                    </p>
                                </div>

                                <div className="space-y-2">
                                    <Label htmlFor="verification-code">Verification Code</Label>
                                    <Input
                                        id="verification-code"
                                        type="text"
                                        placeholder="000000"
                                        maxLength={6}
                                        value={verificationCode}
                                        onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ''))}
                                        className="text-center text-lg tracking-widest font-mono"
                                    />
                                    <p className="text-xs text-muted-foreground">
                                        Enter the 6-digit code from your authenticator app
                                    </p>
                                </div>

                                <DialogFooter>
                                    <Button
                                        variant="outline"
                                        onClick={handleCloseSetup}
                                    >
                                        Cancel
                                    </Button>
                                    <Button
                                        onClick={handleVerifyMfa}
                                        disabled={verificationCode.length !== 6 || verifyMfaMutation.isPending}
                                    >
                                        {verifyMfaMutation.isPending ? (
                                            <>
                                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                                Verifying...
                                            </>
                                        ) : (
                                            "Verify and Activate"
                                        )}
                                    </Button>
                                </DialogFooter>
                            </>
                        ) : (
                            <div className="flex items-center justify-center p-8">
                                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                            </div>
                        )}
                    </div>
                </DialogContent>
            </Dialog>

            {/* MFA Disable Dialog */}
            <Dialog open={mfaDisableOpen} onOpenChange={setMfaDisableOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2 text-red-600">
                            <ShieldAlert className="w-5 h-5" />
                            Disable Two-Step Login
                        </DialogTitle>
                        <DialogDescription>
                            Enter a code from your authenticator app to confirm. Your account will only be protected by your password.
                        </DialogDescription>
                    </DialogHeader>

                    <div className="space-y-4">
                        <Alert variant="destructive">
                            <AlertTriangle className="h-4 w-4" />
                            <AlertTitle>Warning</AlertTitle>
                            <AlertDescription>
                                Without two-step login, anyone with your password can access your account.
                            </AlertDescription>
                        </Alert>

                        <div className="space-y-2">
                            <Label htmlFor="disable-totp">Authenticator Code</Label>
                            <Input
                                id="disable-totp"
                                type="text"
                                inputMode="numeric"
                                maxLength={6}
                                value={disableTotpCode}
                                onChange={(e) => setDisableTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                placeholder="Enter 6-digit code"
                            />
                        </div>
                    </div>

                    <DialogFooter>
                        <Button
                            variant="outline"
                            onClick={() => {
                                setMfaDisableOpen(false);
                                setDisableTotpCode("");
                            }}
                        >
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={handleDisableMfa}
                            disabled={disableTotpCode.length !== 6 || disableMfaMutation.isPending}
                        >
                            {disableMfaMutation.isPending ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Disabling...
                                </>
                            ) : (
                                "Disable Two-Step Login"
                            )}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Reset Encryption */}
            <Card className="border-2 border-red-200 dark:border-red-900 shadow-sm">
                <CardHeader>
                    <div className="flex items-start justify-between gap-4">
                        <div className="flex items-center gap-3 min-w-0">
                            <div className="p-2 rounded-lg bg-red-100 dark:bg-red-950 shrink-0">
                                <Trash2 className="w-6 h-6 text-red-600 dark:text-red-400" />
                            </div>
                            <div className="min-w-0">
                                <CardTitle>Start Over</CardTitle>
                                <CardDescription>
                                    Erase your encryption keys and start fresh. You will lose access to all existing files.
                                </CardDescription>
                            </div>
                        </div>
                        <Button
                            variant="destructive"
                            size="sm"
                            className="shrink-0"
                            onClick={() => setResetEncryptionOpen(true)}
                        >
                            Reset
                        </Button>
                    </div>
                </CardHeader>
            </Card>

            {/* Reset Encryption Dialog */}
            <Dialog open={resetEncryptionOpen} onOpenChange={(open) => {
                if (!open) {
                    setResetEncryptionOpen(false);
                    setResetConfirmText("");
                }
            }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2 text-red-600">
                            <AlertTriangle className="w-5 h-5" />
                            Start Over
                        </DialogTitle>
                        <DialogDescription>
                            This will erase your encryption keys. All your current files will become permanently inaccessible. You'll set up a new master password afterwards.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4">
                        <Alert variant="destructive">
                            <AlertTriangle className="h-4 w-4" />
                            <AlertTitle>This action cannot be undone</AlertTitle>
                            <AlertDescription className="space-y-2">
                                <p>Type <strong>RESET</strong> to confirm.</p>
                                {(masterKeyStatus?.recoveryCodesRemaining ?? 0) > 0 && (
                                    <p>You have {masterKeyStatus?.recoveryCodesRemaining} recovery code{masterKeyStatus?.recoveryCodesRemaining !== 1 ? 's' : ''} remaining — these will stop working.</p>
                                )}
                                {shamirStatus?.isConfigured && (
                                    <p>Your shared recovery ({shamirStatus.threshold} of {shamirStatus.totalShares} trusted contacts needed) will stop working.</p>
                                )}
                            </AlertDescription>
                        </Alert>
                        <Input
                            value={resetConfirmText}
                            onChange={(e) => setResetConfirmText(e.target.value)}
                            placeholder='Type "RESET" to confirm'
                        />
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => { setResetEncryptionOpen(false); setResetConfirmText(""); }}>
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={handleResetEncryption}
                            disabled={resetConfirmText !== "RESET" || deleteMasterKeyMutation.isPending}
                        >
                            {deleteMasterKeyMutation.isPending ? (
                                <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Resetting...</>
                            ) : (
                                "Erase and Start Over"
                            )}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Password Change Dialog */}
            <Dialog open={passwordChangeOpen} onOpenChange={(open) => {
                if (!open) {
                    setPasswordChangeOpen(false);
                    setCurrentPassword("");
                    setNewPassword("");
                    setConfirmPassword("");
                }
            }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <Lock className="w-5 h-5" />
                            Change Password
                        </DialogTitle>
                        <DialogDescription>
                            Enter your current password and choose a new password.
                        </DialogDescription>
                    </DialogHeader>

                    <div className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="current-password">Current Password</Label>
                            <Input
                                id="current-password"
                                type="password"
                                value={currentPassword}
                                onChange={(e) => setCurrentPassword(e.target.value)}
                                placeholder="Enter your current password"
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="new-password">New Password</Label>
                            <Input
                                id="new-password"
                                type="password"
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                placeholder="Enter new password (min. 12 characters)"
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="confirm-password">Confirm New Password</Label>
                            <Input
                                id="confirm-password"
                                type="password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                placeholder="Confirm new password"
                            />
                            {confirmPassword && newPassword !== confirmPassword && (
                                <p className="text-sm text-red-500">Passwords do not match</p>
                            )}
                        </div>
                    </div>

                    <DialogFooter>
                        <Button
                            variant="outline"
                            onClick={() => {
                                setPasswordChangeOpen(false);
                                setCurrentPassword("");
                                setNewPassword("");
                                setConfirmPassword("");
                            }}
                        >
                            Cancel
                        </Button>
                        <Button
                            onClick={handleChangePassword}
                            disabled={
                                !currentPassword ||
                                newPassword.length < 12 ||
                                newPassword !== confirmPassword ||
                                isChangingPassword
                            }
                        >
                            {isChangingPassword ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Changing...
                                </>
                            ) : (
                                "Change Password"
                            )}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Passkey Register Dialog */}
            <Dialog open={passkeyRegisterOpen} onOpenChange={(open) => {
                if (!open) {
                    setPasskeyRegisterOpen(false);
                    setPasskeyFriendlyName("");
                }
            }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <Fingerprint className="w-5 h-5" />
                            Register Passkey
                        </DialogTitle>
                        <DialogDescription>
                            Add a passkey to sign in with biometrics or a security key.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="passkey-name">Name (optional)</Label>
                            <Input
                                id="passkey-name"
                                value={passkeyFriendlyName}
                                onChange={(e) => setPasskeyFriendlyName(e.target.value)}
                                placeholder='e.g. "MacBook Pro" or "iPhone"'
                                maxLength={100}
                            />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => { setPasskeyRegisterOpen(false); setPasskeyFriendlyName(""); }}>
                            Cancel
                        </Button>
                        <Button onClick={handleRegisterPasskey} disabled={isRegisteringPasskey}>
                            {isRegisteringPasskey ? (
                                <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Registering...</>
                            ) : (
                                "Register"
                            )}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Passkey Delete Confirmation Dialog */}
            <Dialog open={passkeyDeleteOpen !== null} onOpenChange={(open) => { if (!open) setPasskeyDeleteOpen(null); }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Remove Passkey</DialogTitle>
                        <DialogDescription>
                            Are you sure you want to remove this passkey? You will no longer be able to sign in with it.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setPasskeyDeleteOpen(null)}>
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={() => passkeyDeleteOpen !== null && handleDeletePasskey(passkeyDeleteOpen)}
                            disabled={deletePasskeyMutation.isPending}
                        >
                            {deletePasskeyMutation.isPending ? (
                                <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Removing...</>
                            ) : (
                                "Remove"
                            )}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}

