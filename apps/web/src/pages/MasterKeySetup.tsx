/**
 * MasterKeySetup Page (Phase 1.2 NEW_DAY)
 *
 * Onboarding page for new users to configure their Master Key.
 * Generates recovery codes and guides user through secure setup.
 *
 * Flow:
 * 1. User enters new Master Password (with confirmation)
 * 2. Client generates Master Key, recovery codes, KEK
 * 3. Shows recovery codes for user to save
 * 4. User confirms they saved the codes
 * 5. Setup completes, vault is unlocked
 */

import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Eye, EyeOff, Copy, Check, AlertTriangle, Loader2, KeyRound, Download, Users, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useMasterKey } from '@/hooks/useMasterKey';
import { PasswordStrengthMeter } from '@/components/auth/PasswordStrengthMeter';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { toast } from 'sonner';
import { trpc } from '@/lib/trpc';
import {
    generateAndStoreUES,
    exportUESForServer,
} from '@/lib/uesManager';
import {
    getDeviceFingerprintHash,
    getDeviceName,
    getBrowserInfo,
} from '@/lib/deviceEntropy';

type SetupStep = 'password' | 'recovery' | 'complete';

export default function MasterKeySetup() {
    const setLocation = useNavigate();
    const { setupMasterKey, isDerivingKey, isConfigured, getCachedKey } = useMasterKey();

    // Form state
    const [step, setStep] = useState<SetupStep>('password');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [passwordHint, setPasswordHint] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirm, setShowConfirm] = useState(false);

    // Hybrid KEM error dialog
    const [hybridKemError, setHybridKemError] = useState(false);

    // Recovery codes state
    const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
    const [copiedAll, setCopiedAll] = useState(false);
    const [savedConfirmed, setSavedConfirmed] = useState(false);
    const [shamirDismissed, setShamirDismissed] = useState(false);
    const redirectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    // Validation
    const passwordMinLength = 12;
    const passwordsMatch = password === confirmPassword;
    const passwordValid = password.length >= passwordMinLength;
    const canProceed = passwordValid && passwordsMatch;

    // Device registration mutation
    const registerDeviceMutation = trpc.devices.registerTrustedDevice.useMutation();

    // Handle setup
    const handleSetup = async () => {
        if (!canProceed) return;

        try {
            const result = await setupMasterKey(password, passwordHint || undefined);
            if (result.success) {
                // Phase 3 UES: Generate and register trusted device
                try {
                    // 1. Generate UES and store locally
                    const uesData = await generateAndStoreUES();
                    if (import.meta.env.DEV) console.log('[UES] Generated and stored locally');

                    // 2. Get device info for server registration
                    const [fingerprint, deviceName, browserInfo] = await Promise.all([
                        getDeviceFingerprintHash(),
                        Promise.resolve(getDeviceName()),
                        Promise.resolve(getBrowserInfo()),
                    ]);

                    // 3. Export UES encrypted with Master Key for server storage
                    // After setupMasterKey, the key is cached so we can retrieve it
                    const cachedMasterKey = getCachedKey();
                    if (cachedMasterKey) {
                        const exported = await exportUESForServer(uesData.ues, cachedMasterKey);

                        // 4. Register this device as trusted
                        await registerDeviceMutation.mutateAsync({
                            deviceFingerprint: fingerprint,
                            deviceName,
                            platform: 'web',
                            browserInfo,
                            uesEncrypted: exported.uesEncrypted,
                            uesEncryptionIv: exported.uesIv,
                        });

                        if (import.meta.env.DEV) console.log('[UES] Device registered as trusted');
                    } else {
                        if (import.meta.env.DEV) console.warn('[UES] Master Key not cached after setup, skipping device registration');
                    }
                } catch (uesError) {
                    // UES is optional enhancement - don't block setup
                    if (import.meta.env.DEV) console.warn('[UES] Failed to setup UES (non-critical):', uesError);
                }

                setRecoveryCodes(result.recoveryCodesPlain);
                setStep('recovery');
            }
        } catch (err: any) {
            if (err?.code === 'HYBRID_KEM_UNAVAILABLE') {
                setHybridKemError(true);
            }
            // Other errors handled by the hook
        }
    };

    // Copy all recovery codes
    const handleCopyAll = async () => {
        const text = recoveryCodes.join('\n');
        await navigator.clipboard.writeText(text);
        setCopiedAll(true);
        toast.success('Recovery codes copied to clipboard');
        setTimeout(() => setCopiedAll(false), 3000);
    };

    // Download recovery codes as file
    const handleDownload = () => {
        const content = [
            '=== StenVault Recovery Codes ===',
            '',
            'These are your ONLY recovery option. We cannot reset your password.',
            'Each code can only be used once.',
            '',
            ...recoveryCodes.map((code, i) => `${i + 1}. ${code}`),
            '',
            `Generated: ${new Date().toISOString()}`,
        ].join('\n');

        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'stenvault-recovery-codes.txt';
        a.click();
        URL.revokeObjectURL(url);
        toast.success('Recovery codes downloaded');
    };

    // Complete setup
    const handleComplete = () => {
        if (!savedConfirmed) {
            toast.error('Please confirm you have saved the recovery codes');
            return;
        }
        setStep('complete');
    };

    // Prevent accidental tab close during recovery code step
    useEffect(() => {
        if (step === 'complete') return;
        const handler = (e: BeforeUnloadEvent) => { e.preventDefault(); };
        window.addEventListener('beforeunload', handler);
        return () => window.removeEventListener('beforeunload', handler);
    }, [step]);

    // Fallback auto-redirect 15s after reaching complete step
    useEffect(() => {
        if (step !== 'complete') return;
        redirectTimerRef.current = setTimeout(() => setLocation('/'), 15000);
        return () => {
            if (redirectTimerRef.current) clearTimeout(redirectTimerRef.current);
        };
    }, [step, setLocation]);

    // If already configured, redirect (via useEffect to avoid calling setLocation during render)
    useEffect(() => {
        if (isConfigured) {
            setLocation('/');
        }
    }, [isConfigured, setLocation]);

    if (isConfigured) {
        return null;
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
            <div className="w-full max-w-lg">
                {/* Header */}
                <div className="text-center mb-8">
                    <div className="flex justify-center gap-2 mb-4">
                        {(['password', 'recovery', 'complete'] as const).map((s, i) => (
                            <div key={s} className={cn(
                                'w-2 h-2 rounded-full transition-colors duration-300',
                                i <= (['password', 'recovery', 'complete'] as const).indexOf(step) ? 'bg-emerald-400' : 'bg-slate-600'
                            )} />
                        ))}
                    </div>
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-emerald-500/10 mb-4">
                        <Shield className="w-8 h-8 text-emerald-400" />
                    </div>
                    <h1 className="text-2xl font-bold text-white mb-2">
                        {step === 'password' && 'Create Your Encryption Password'}
                        {step === 'recovery' && 'Save Your Recovery Codes'}
                        {step === 'complete' && 'Setup Complete!'}
                    </h1>
                    <p className="text-slate-400">
                        {step === 'password' && (<>You just created your login credentials. Now create an <span className="font-semibold text-slate-300">encryption password</span> — this protects your files and never reaches our servers. Even we can&apos;t access your data without it.</>)}
                        {step === 'recovery' && 'These codes can recover your account if you forget your password.'}
                        {step === 'complete' && 'One more thing before you go...'}
                    </p>
                </div>

                {/* Card */}
                <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-2xl p-6 shadow-xl">
                    {/* Step 1: Password */}
                    {step === 'password' && (
                        <div className="space-y-6">
                            {/* Password field */}
                            <div className="space-y-2">
                                <Label htmlFor="password" className="text-slate-200">
                                    Encryption Password
                                </Label>
                                <div className="relative">
                                    <Input
                                        id="password"
                                        type={showPassword ? 'text' : 'password'}
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        placeholder="Create your encryption password..."
                                        size="lg"
                                        className="pr-12 bg-slate-900/50 border-slate-600 text-white placeholder:text-slate-500"
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowPassword(!showPassword)}
                                        className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-slate-400 hover:text-slate-300"
                                        aria-label={showPassword ? "Hide password" : "Show password"}
                                    >
                                        {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                                    </button>
                                </div>

                                <PasswordStrengthMeter password={password} />
                            </div>

                            {/* Confirm password */}
                            <div className="space-y-2">
                                <Label htmlFor="confirm" className="text-slate-200">
                                    Confirm Password
                                </Label>
                                <div className="relative">
                                    <Input
                                        id="confirm"
                                        type={showConfirm ? 'text' : 'password'}
                                        value={confirmPassword}
                                        onChange={(e) => setConfirmPassword(e.target.value)}
                                        placeholder="Confirm your password..."
                                        size="lg"
                                        className={cn(
                                            'pr-12 bg-slate-900/50 border-slate-600 text-white placeholder:text-slate-500',
                                            confirmPassword && !passwordsMatch && 'border-red-500',
                                            confirmPassword && passwordsMatch && 'border-emerald-500/50'
                                        )}
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowConfirm(!showConfirm)}
                                        className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-slate-400 hover:text-slate-300"
                                        aria-label={showConfirm ? "Hide password" : "Show password"}
                                    >
                                        {showConfirm ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                                    </button>
                                </div>
                                {confirmPassword && !passwordsMatch && (
                                    <p className="text-xs text-red-400">Passwords do not match</p>
                                )}
                                {confirmPassword && passwordsMatch && (
                                    <p className="text-xs text-emerald-400 flex items-center gap-1">
                                        <Check className="w-3 h-3" /> Passwords match
                                    </p>
                                )}
                            </div>

                            {/* Password hint (optional) */}
                            <div className="space-y-2">
                                <Label htmlFor="hint" className="text-slate-200">
                                    Password Hint <span className="text-slate-500">(optional)</span>
                                </Label>
                                <Input
                                    id="hint"
                                    type="text"
                                    value={passwordHint}
                                    onChange={(e) => setPasswordHint(e.target.value)}
                                    placeholder="A hint to help you remember..."
                                    className="bg-slate-900/50 border-slate-600 text-white placeholder:text-slate-500"
                                    maxLength={255}
                                />
                            </div>

                            {/* Warning */}
                            <div className="flex items-start gap-3 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
                                <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                                <div className="text-sm text-amber-200/80">
                                    <p className="font-medium text-amber-200 mb-1">Important</p>
                                    <p>This password cannot be recovered. If you forget it, you'll need to use your recovery codes.</p>
                                </div>
                            </div>

                            {/* Submit */}
                            <Button
                                onClick={handleSetup}
                                disabled={!canProceed || isDerivingKey}
                                className="w-full bg-emerald-600 hover:bg-emerald-500 text-white"
                            >
                                {isDerivingKey ? (
                                    <>
                                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                        Generating your encryption keys...
                                    </>
                                ) : (
                                    <>
                                        <KeyRound className="w-4 h-4 mr-2" />
                                        Create Encryption Password
                                    </>
                                )}
                            </Button>
                        </div>
                    )}

                    {/* Step 2: Recovery Codes */}
                    {step === 'recovery' && (
                        <div className="space-y-6">
                            {/* Codes grid */}
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                {recoveryCodes.map((code, index) => (
                                    <div
                                        key={index}
                                        className="flex items-center justify-between bg-slate-900/50 border border-slate-600 rounded-lg px-3 py-2"
                                    >
                                        <span className="text-slate-500 text-sm mr-2">{index + 1}.</span>
                                        <code className="font-mono text-emerald-400 text-sm tracking-wider">{code}</code>
                                    </div>
                                ))}
                            </div>

                            {/* Actions */}
                            <div className="flex gap-2">
                                <Button
                                    variant="outline"
                                    size="lg"
                                    onClick={handleCopyAll}
                                    className="flex-1 border-slate-600 text-slate-200 hover:bg-slate-700"
                                >
                                    {copiedAll ? (
                                        <Check className="w-4 h-4 mr-2 text-emerald-400" />
                                    ) : (
                                        <Copy className="w-4 h-4 mr-2" />
                                    )}
                                    {copiedAll ? 'Copied!' : 'Copy All'}
                                </Button>
                                <Button
                                    variant="outline"
                                    size="lg"
                                    onClick={handleDownload}
                                    className="flex-1 border-slate-600 text-slate-200 hover:bg-slate-700"
                                >
                                    <Download className="w-4 h-4 mr-2" />
                                    Download
                                </Button>
                            </div>

                            {/* Warning */}
                            <div className="flex items-start gap-3 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                                <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                                <div className="text-sm text-red-200/80">
                                    <p className="font-medium text-red-200 mb-1">Why this matters</p>
                                    <p>We use zero-knowledge encryption, which means we can't see or reset your password. These codes are your <span className="font-semibold text-red-200">only backup</span>. Save them in a password manager or print them.</p>
                                </div>
                            </div>

                            {/* Confirmation checkbox */}
                            <div className="flex items-center gap-3">
                                <Checkbox
                                    id="confirm-saved"
                                    checked={savedConfirmed}
                                    onCheckedChange={(checked) => setSavedConfirmed(checked === true)}
                                    className="border-slate-500 data-[state=checked]:bg-emerald-600 data-[state=checked]:border-emerald-600"
                                />
                                <label
                                    htmlFor="confirm-saved"
                                    className="text-sm text-slate-300 cursor-pointer"
                                >
                                    I've saved my recovery codes — I understand they can't be regenerated
                                </label>
                            </div>

                            {/* Complete */}
                            <Button
                                onClick={handleComplete}
                                disabled={!savedConfirmed}
                                className="w-full bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50"
                            >
                                <Check className="w-4 h-4 mr-2" />
                                Complete Setup
                            </Button>
                        </div>
                    )}

                    {/* Step 3: Complete + Shamir nudge */}
                    {step === 'complete' && (
                        <div className="text-center py-8 space-y-6">
                            <div>
                                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-emerald-500/20 mb-4">
                                    <Check className="w-8 h-8 text-emerald-400" />
                                </div>
                                <p className="text-lg font-medium text-white">Your vault is ready!</p>
                            </div>

                            {!shamirDismissed ? (
                                <>
                                    <div className="flex items-start gap-3 p-4 bg-indigo-500/10 border border-indigo-500/20 rounded-lg text-left">
                                        <Users className="w-5 h-5 text-indigo-400 flex-shrink-0 mt-0.5" />
                                        <div className="text-sm text-slate-300">
                                            <p className="font-medium text-indigo-300 mb-1">Want extra protection?</p>
                                            <p>Split your recovery key among trusted contacts so no single person — including you — holds the full key.</p>
                                        </div>
                                    </div>
                                    <div className="flex gap-3">
                                        <Button
                                            onClick={() => {
                                                if (redirectTimerRef.current) clearTimeout(redirectTimerRef.current);
                                                setLocation('/settings?tab=security');
                                            }}
                                            className="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white"
                                        >
                                            <Users className="w-4 h-4 mr-2" />
                                            Set Up Now
                                        </Button>
                                        <Button
                                            variant="outline"
                                            onClick={() => {
                                                if (redirectTimerRef.current) clearTimeout(redirectTimerRef.current);
                                                setShamirDismissed(true);
                                                setTimeout(() => setLocation('/'), 1500);
                                            }}
                                            className="flex-1 border-slate-600 text-slate-300 hover:bg-slate-700"
                                        >
                                            I'll set this up in Settings
                                        </Button>
                                    </div>
                                </>
                            ) : (
                                <div className="flex flex-col items-center gap-2">
                                    <p className="text-slate-400">Redirecting to dashboard...</p>
                                    <Loader2 className="w-5 h-5 animate-spin text-emerald-400" />
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {/* Footer */}
                <p className="text-center text-slate-500 text-xs mt-6">
                    Your password never leaves this device. We use zero-knowledge encryption.
                </p>
            </div>

            {/* Hybrid KEM Error Dialog */}
            <Dialog open={hybridKemError} onOpenChange={setHybridKemError}>
                <DialogContent className="max-w-md">
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <AlertTriangle className="w-5 h-5 text-amber-500" />
                            Setup Issue
                        </DialogTitle>
                        <DialogDescription>
                            We couldn't initialize your vault's encryption on this browser.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4">
                        <p className="text-sm text-slate-400">
                            This is usually a temporary issue. Try:
                        </p>
                        <ol className="list-decimal list-inside space-y-1.5 text-sm text-slate-300">
                            <li>Refresh the page and try again</li>
                            <li>Use a different browser (Chrome or Firefox)</li>
                            <li>Check your internet connection</li>
                        </ol>
                        <p className="text-xs text-slate-500">
                            Still not working? Contact support with code: HYBRID_KEM_UNAVAILABLE
                        </p>
                    </div>
                    <DialogFooter className="gap-2 sm:gap-0">
                        <Button variant="outline" onClick={() => window.location.reload()}>
                            <RefreshCw className="w-4 h-4 mr-2" />
                            Reload Page
                        </Button>
                        <Button onClick={() => setHybridKemError(false)}>
                            Try Again
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
