/**
 * SignatureKeysSection Component
 *
 * Settings section for managing hybrid signature keys (Ed25519 + ML-DSA-65).
 * Allows generating, viewing, rotating keys and setting "sign by default".
 */

import { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import {
    Loader2,
    Shield,
    ShieldCheck,
    Copy,
    Check,
    RefreshCw,
    AlertTriangle,
    History,
    Eye,
    EyeOff,
    KeyRound,
} from "lucide-react";
import { useSignatureKeys } from "@/hooks/useSignatureKeys";
import { useMasterKey } from "@/hooks/useMasterKey";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// ============ localStorage helpers ============

const SIGN_BY_DEFAULT_KEY = "stenvault_sign_by_default";

export function getSignByDefault(): boolean {
    try {
        return localStorage.getItem(SIGN_BY_DEFAULT_KEY) === "true";
    } catch {
        return false;
    }
}

export function setSignByDefault(value: boolean): void {
    try {
        localStorage.setItem(SIGN_BY_DEFAULT_KEY, String(value));
    } catch {
        // localStorage unavailable
    }
}

// ============ Component ============

export function SignatureKeysSection() {
    const {
        keyInfo,
        isLoading,
        generateKeyPair,
        isPending,
        refetch,
        keyHistory,
        isLoadingHistory,
    } = useSignatureKeys();
    const { deriveMasterKey, isCached, getCachedKey } = useMasterKey();

    const [isGenerating, setIsGenerating] = useState(false);
    const [rotateOpen, setRotateOpen] = useState(false);
    const [historyOpen, setHistoryOpen] = useState(false);
    const [copiedFingerprint, setCopiedFingerprint] = useState(false);
    const [signByDefault, setSignByDefaultState] = useState(getSignByDefault);

    // Password modal state
    const [passwordModalOpen, setPasswordModalOpen] = useState(false);
    const [passwordModalPassword, setPasswordModalPassword] = useState("");
    const [passwordModalShowPassword, setPasswordModalShowPassword] = useState(false);
    const [passwordModalError, setPasswordModalError] = useState<string | null>(null);
    const [passwordModalAction, setPasswordModalAction] = useState<"generate" | "rotate">("generate");

    const openPasswordModal = useCallback((action: "generate" | "rotate") => {
        setPasswordModalAction(action);
        setPasswordModalPassword("");
        setPasswordModalShowPassword(false);
        setPasswordModalError(null);
        setPasswordModalOpen(true);
    }, []);

    const executeWithMasterKey = useCallback(async (masterKey: CryptoKey | import('@/hooks/masterKeyCrypto').MasterKeyBundle, action: "generate" | "rotate") => {
        setIsGenerating(true);
        try {
            await generateKeyPair(masterKey);
            await refetch();
            if (action === "rotate") {
                toast.success("Verification keys replaced successfully");
            }
        } catch {
            toast.error(action === "rotate" ? "Failed to replace verification keys" : "Failed to set up file verification");
        } finally {
            setIsGenerating(false);
        }
    }, [generateKeyPair, refetch]);

    const handlePasswordModalSubmit = useCallback(async () => {
        if (!passwordModalPassword.trim()) {
            setPasswordModalError("Please enter your Encryption Password");
            return;
        }
        setPasswordModalError(null);
        try {
            const masterKey = await deriveMasterKey(passwordModalPassword);
            setPasswordModalOpen(false);
            await executeWithMasterKey(masterKey, passwordModalAction);
        } catch {
            setPasswordModalError("Incorrect password. Please try again.");
        }
    }, [passwordModalPassword, deriveMasterKey, executeWithMasterKey, passwordModalAction]);

    const handleGenerate = useCallback(async () => {
        if (isCached) {
            const cached = getCachedKey();
            if (cached) {
                await executeWithMasterKey(cached, "generate");
                return;
            }
        }
        openPasswordModal("generate");
    }, [isCached, getCachedKey, executeWithMasterKey, openPasswordModal]);

    const handleRotate = useCallback(async () => {
        setRotateOpen(false);
        if (isCached) {
            const cached = getCachedKey();
            if (cached) {
                await executeWithMasterKey(cached, "rotate");
                return;
            }
        }
        openPasswordModal("rotate");
    }, [isCached, getCachedKey, executeWithMasterKey, openPasswordModal]);

    const handleCopyFingerprint = useCallback(async () => {
        if (!keyInfo.fingerprint) return;
        await navigator.clipboard.writeText(keyInfo.fingerprint);
        setCopiedFingerprint(true);
        setTimeout(() => setCopiedFingerprint(false), 2000);
        toast.success("Key ID copied!");
    }, [keyInfo.fingerprint]);

    const handleSignByDefaultToggle = useCallback((checked: boolean) => {
        setSignByDefaultState(checked);
        setSignByDefault(checked);
        toast.success(checked ? "Auto-verification enabled" : "Auto-verification disabled");
    }, []);

    if (isLoading) {
        return (
            <Card>
                <CardContent className="flex items-center justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </CardContent>
            </Card>
        );
    }

    const hasKeys = keyInfo.hasKeyPair;

    return (
        <>
            <Card
                className={`border-2 ${
                    hasKeys
                        ? "border-indigo-100 dark:border-indigo-900"
                        : "border-gray-100 dark:border-gray-800"
                } shadow-sm`}
            >
                <CardHeader>
                    <div className="flex items-start justify-between gap-4">
                        <div className="flex items-center gap-3 min-w-0">
                            <div
                                className={`p-2 rounded-lg shrink-0 ${
                                    hasKeys
                                        ? "bg-indigo-100 dark:bg-indigo-900"
                                        : "bg-gray-100 dark:bg-gray-800"
                                }`}
                            >
                                {hasKeys ? (
                                    <ShieldCheck className="w-6 h-6 text-indigo-600 dark:text-indigo-400" />
                                ) : (
                                    <Shield className="w-6 h-6 text-gray-600 dark:text-gray-400" />
                                )}
                            </div>
                            <div className="min-w-0">
                                <CardTitle>File Verification</CardTitle>
                                <CardDescription>
                                    {hasKeys
                                        ? "Your files are signed — any tampering will be detected"
                                        : "Prove your files are authentic and haven't been altered"}
                                </CardDescription>
                            </div>
                        </div>
                        {hasKeys ? (
                            <div className="flex gap-2 shrink-0">
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => setHistoryOpen(true)}
                                >
                                    <History className="mr-2 h-4 w-4" />
                                    History
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => setRotateOpen(true)}
                                    disabled={isGenerating || isPending}
                                >
                                    <RefreshCw className="mr-2 h-4 w-4" />
                                    Replace Keys
                                </Button>
                            </div>
                        ) : (
                            <Button
                                variant="default"
                                size="sm"
                                onClick={handleGenerate}
                                disabled={isGenerating || isPending}
                            >
                                {isGenerating || isPending ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Generating...
                                    </>
                                ) : (
                                    <>
                                        <Shield className="mr-2 h-4 w-4" />
                                        Set Up
                                    </>
                                )}
                            </Button>
                        )}
                    </div>
                </CardHeader>
                {hasKeys && (
                    <CardContent>
                        <div className="bg-indigo-50 dark:bg-indigo-950/30 p-4 rounded-lg space-y-3">
                            {/* Fingerprint */}
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2 text-sm text-indigo-900 dark:text-indigo-100">
                                    <span className="text-muted-foreground">Key ID:</span>
                                    <code className="font-mono text-xs bg-indigo-100 dark:bg-indigo-900/50 px-2 py-0.5 rounded">
                                        {keyInfo.fingerprint?.slice(0, 16)}...
                                    </code>
                                    <Button
                                        variant="ghost"
                                        size="icon"
                                        className="h-6 w-6"
                                        onClick={handleCopyFingerprint}
                                    >
                                        {copiedFingerprint ? (
                                            <Check className="h-3 w-3 text-green-600" />
                                        ) : (
                                            <Copy className="h-3 w-3" />
                                        )}
                                    </Button>
                                </div>
                                <Badge
                                    variant="secondary"
                                    className="bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300"
                                >
                                    v{keyInfo.keyVersion}
                                </Badge>
                            </div>

                            {/* Sign by default toggle */}
                            <div className="flex items-center justify-between pt-2 border-t border-indigo-200 dark:border-indigo-800">
                                <div>
                                    <Label
                                        htmlFor="sign-by-default"
                                        className="text-sm font-medium text-indigo-900 dark:text-indigo-100 cursor-pointer"
                                    >
                                        Verify new uploads automatically
                                    </Label>
                                    <p className="text-xs text-indigo-700 dark:text-indigo-300">
                                        Sign every file you upload so others can confirm it's from you
                                    </p>
                                </div>
                                <Switch
                                    id="sign-by-default"
                                    checked={signByDefault}
                                    onCheckedChange={handleSignByDefaultToggle}
                                />
                            </div>
                        </div>
                    </CardContent>
                )}
                {!hasKeys && (
                    <CardContent>
                        <div className="bg-muted/50 p-4 rounded-lg">
                            <p className="text-sm text-muted-foreground">
                                File verification lets you prove that a file was uploaded by you
                                and hasn't been modified. Your verification keys are protected
                                by your master password.
                            </p>
                        </div>
                    </CardContent>
                )}
            </Card>

            {/* Rotate Confirmation Dialog */}
            <Dialog open={rotateOpen} onOpenChange={setRotateOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <RefreshCw className="w-5 h-5" />
                            Replace Verification Keys
                        </DialogTitle>
                        <DialogDescription>
                            Create new verification keys. Files you already signed can
                            still be verified.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-3">
                        <div className="flex items-start gap-2 p-3 bg-amber-50 dark:bg-amber-950/30 rounded-lg text-sm text-amber-800 dark:text-amber-200">
                            <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
                            <p>
                                New uploads will be signed with the new keys. Previously
                                signed files will still pass verification.
                            </p>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setRotateOpen(false)}>
                            Cancel
                        </Button>
                        <Button onClick={handleRotate} disabled={isGenerating || isPending}>
                            {isGenerating || isPending ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Rotating...
                                </>
                            ) : (
                                "Replace Keys"
                            )}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Key History Dialog */}
            <Dialog open={historyOpen} onOpenChange={setHistoryOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <History className="w-5 h-5" />
                            Verification Key History
                        </DialogTitle>
                        <DialogDescription>
                            Previous and current keys used to verify your files.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                        {isLoadingHistory ? (
                            <div className="flex items-center justify-center py-8">
                                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                            </div>
                        ) : keyHistory && keyHistory.length > 0 ? (
                            keyHistory.map((kp) => (
                                <div
                                    key={kp.id}
                                    className="flex items-center justify-between p-3 rounded-lg border"
                                >
                                    <div className="space-y-1">
                                        <div className="flex items-center gap-2">
                                            <span className="text-sm font-medium">
                                                Version {kp.keyVersion}
                                            </span>
                                            {kp.isActive && (
                                                <Badge
                                                    variant="secondary"
                                                    className="bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300 text-xs"
                                                >
                                                    Active
                                                </Badge>
                                            )}
                                        </div>
                                        <div className="flex items-center gap-3 text-xs text-muted-foreground">
                                            <span>{kp.algorithm}</span>
                                            {kp.fingerprint && (
                                                <code className="font-mono">
                                                    {kp.fingerprint.slice(0, 16)}...
                                                </code>
                                            )}
                                        </div>
                                        <p className="text-xs text-muted-foreground">
                                            Created {new Date(kp.createdAt).toLocaleDateString()}
                                        </p>
                                    </div>
                                </div>
                            ))
                        ) : (
                            <p className="text-sm text-muted-foreground text-center py-4">
                                No key history available.
                            </p>
                        )}
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setHistoryOpen(false)}>
                            Close
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Password Modal */}
            <Dialog open={passwordModalOpen} onOpenChange={setPasswordModalOpen}>
                <DialogContent className="sm:max-w-md">
                    <DialogHeader className="text-center">
                        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-amber-500/10">
                            <Shield className="h-7 w-7 text-amber-500" />
                        </div>
                        <DialogTitle className="text-xl">
                            {passwordModalAction === "rotate" ? "Replace Verification Keys" : "Set Up File Verification"}
                        </DialogTitle>
                        <DialogDescription>
                            Enter your Encryption Password to continue. Your password never leaves this device.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-4">
                        <div className="space-y-2">
                            <Label htmlFor="sig-password">Encryption Password</Label>
                            <div className="relative">
                                <Input
                                    id="sig-password"
                                    type={passwordModalShowPassword ? "text" : "password"}
                                    placeholder="Enter your Encryption Password"
                                    value={passwordModalPassword}
                                    onChange={(e) => setPasswordModalPassword(e.target.value)}
                                    onKeyDown={(e) => {
                                        if (e.key === "Enter") handlePasswordModalSubmit();
                                    }}
                                    disabled={isGenerating}
                                    className={cn("pr-10", passwordModalError && "border-red-500 focus-visible:ring-red-500")}
                                    autoFocus
                                />
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="icon"
                                    className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7"
                                    onClick={() => setPasswordModalShowPassword(!passwordModalShowPassword)}
                                    tabIndex={-1}
                                    aria-label={passwordModalShowPassword ? "Hide password" : "Show password"}
                                >
                                    {passwordModalShowPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                                </Button>
                            </div>
                        </div>
                        {passwordModalError && (
                            <div className="flex items-center gap-2 text-sm text-red-500">
                                <AlertTriangle className="h-4 w-4 shrink-0" />
                                <span>{passwordModalError}</span>
                            </div>
                        )}
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setPasswordModalOpen(false)}>
                            Cancel
                        </Button>
                        <Button
                            onClick={handlePasswordModalSubmit}
                            disabled={isGenerating || !passwordModalPassword.trim()}
                            disableAnimation
                        >
                            {isGenerating ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    {passwordModalAction === "rotate" ? "Replacing..." : "Setting up..."}
                                </>
                            ) : (
                                <>
                                    <KeyRound className="mr-2 h-4 w-4" />
                                    Continue
                                </>
                            )}
                        </Button>
                    </DialogFooter>
                    <div className="rounded-lg bg-muted/50 p-3 text-xs text-muted-foreground">
                        <p>
                            <strong>Zero-Knowledge:</strong> Your Encryption Password is used only on
                            this device to derive encryption keys. It is never sent to our servers.
                        </p>
                    </div>
                </DialogContent>
            </Dialog>
        </>
    );
}
