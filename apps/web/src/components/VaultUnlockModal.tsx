/**
 * VaultUnlockModal Component (Phase 1.1 NEW_DAY)
 *
 * Modal presented after login when the vault is locked.
 * Allows user to unlock their vault by entering their Master Password.
 * 
 * Zero-Knowledge: Password is never sent to server, only used locally
 * to derive KEK and unwrap the Master Key.
 */

import { useState, useCallback, useEffect } from 'react';
import { Shield, ShieldCheck, Eye, EyeOff, Loader2, KeyRound, AlertCircle } from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { cn } from '@/lib/utils';
import { useMasterKey } from '@/hooks/useMasterKey';
import { toast } from 'sonner';

interface VaultUnlockModalProps {
    /** Whether the modal is open */
    isOpen: boolean;
    /** Callback when vault is successfully unlocked */
    onUnlock: () => void;
    /** Callback to close the modal without unlocking */
    onClose?: () => void;
    /** Callback for forgot password flow (recovery codes) */
    onForgotPassword?: () => void;
}

export function VaultUnlockModal({
    isOpen,
    onUnlock,
    onClose,
    onForgotPassword,
}: VaultUnlockModalProps) {
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [showSlowHint, setShowSlowHint] = useState(false);

    const { deriveMasterKey, isDerivingKey, isUnlocked, config } = useMasterKey();

    // Show slow-path hint after 1s of key derivation
    useEffect(() => {
        if (!isDerivingKey) {
            setShowSlowHint(false);
            return;
        }
        const timer = setTimeout(() => setShowSlowHint(true), 1000);
        return () => clearTimeout(timer);
    }, [isDerivingKey]);

    // Reset state when modal opens
    useEffect(() => {
        if (isOpen) {
            setPassword('');
            setShowPassword(false);
            setError(null);
        }
    }, [isOpen]);

    // Auto-close modal if already unlocked
    useEffect(() => {
        if (isOpen && isUnlocked) {
            onUnlock();
        }
    }, [isOpen, isUnlocked, onUnlock]);

    const handleUnlock = useCallback(async () => {
        if (import.meta.env.DEV) console.log('[VaultUnlock] handleUnlock called', { passwordLength: password.length, isDerivingKey, configLoaded: !!config });

        if (!password.trim()) {
            setError('Please enter your Encryption Password');
            return;
        }

        setError(null);

        try {
            if (import.meta.env.DEV) console.log('[VaultUnlock] Calling deriveMasterKey...');
            await deriveMasterKey(password);
            if (import.meta.env.DEV) console.log('[VaultUnlock] deriveMasterKey succeeded');
            toast.success('Vault unlocked');
            onUnlock();
        } catch (err) {
            console.error('[VaultUnlock] Failed to unlock:', err);

            // Provide user-friendly error messages
            let errorMessage: string;
            if (err instanceof Error) {
                if (err.message.includes('OperationError')) {
                    errorMessage = 'Incorrect Encryption Password. Please try again.';
                } else if (err.message.includes('not configured')) {
                    errorMessage = 'Encryption not configured. Please set up your encryption first.';
                } else {
                    errorMessage = err.message;
                }
            } else {
                errorMessage = 'Failed to unlock vault. Please try again.';
            }

            setError(errorMessage);
            toast.error('Unlock failed', { description: errorMessage });
        }
    }, [password, deriveMasterKey, onUnlock, isDerivingKey, config]);

    const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !isDerivingKey) {
            handleUnlock();
        }
    }, [handleUnlock, isDerivingKey]);

    return (
        <Dialog open={isOpen} onOpenChange={(open) => { if (!open && onClose) onClose(); }}>
            <DialogContent
                className="sm:max-w-md"
                showCloseButton={!!onClose}
                onInteractOutside={(e) => { if (!onClose) e.preventDefault(); }}
                onEscapeKeyDown={(e) => { if (!onClose) e.preventDefault(); }}
            >
                <DialogHeader className="text-center">
                    <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-amber-500/10">
                        <Shield className="h-7 w-7 text-amber-500" />
                    </div>
                    <DialogTitle className="text-xl font-sans">Unlock Your Vault</DialogTitle>
                    <DialogDescription className="text-sm text-muted-foreground">
                        Enter your Encryption Password to access your encrypted files.
                        Your password never leaves this device.
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-4">
                    {/* Password Input */}
                    <div className="space-y-2">
                        <Label htmlFor="master-password">Encryption Password</Label>
                        <div className="relative">
                            <Input
                                id="master-password"
                                type={showPassword ? 'text' : 'password'}
                                placeholder="Enter your Encryption Password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                onKeyDown={handleKeyDown}
                                disabled={isDerivingKey}
                                className={cn(
                                    'pr-10',
                                    error && 'border-red-500 focus-visible:ring-red-500'
                                )}
                                autoFocus
                            />
                            <Button
                                type="button"
                                variant="ghost"
                                size="icon"
                                className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7"
                                onClick={() => setShowPassword(!showPassword)}
                                disabled={isDerivingKey}
                                tabIndex={-1}
                                aria-label={showPassword ? "Hide password" : "Show password"}
                            >
                                {showPassword ? (
                                    <EyeOff className="h-4 w-4" />
                                ) : (
                                    <Eye className="h-4 w-4" />
                                )}
                            </Button>
                        </div>
                    </div>

                    {/* Error Message */}
                    {error && (
                        <div className="flex items-center gap-2 text-sm text-red-500 animate-in fade-in slide-in-from-top-1">
                            <AlertCircle className="h-4 w-4 flex-shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}

                    {/* Password Hint — only shown after a failed attempt */}
                    {error && config?.passwordHint && (
                        <p className="text-xs text-muted-foreground">
                            <KeyRound className="inline h-3 w-3 mr-1" />
                            Hint: {config.passwordHint}
                        </p>
                    )}

                    {/* Unlock Button - disableAnimation avoids framer-motion click issues */}
                    <Button
                        type="button"
                        onClick={handleUnlock}
                        disabled={isDerivingKey || !password.trim()}
                        disableAnimation
                        className="w-full"
                    >
                        {isDerivingKey ? (
                            <div className="flex flex-col items-center gap-1">
                                <div className="flex items-center">
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    {showSlowHint ? 'Deriving encryption key...' : 'Unlocking...'}
                                </div>
                            </div>
                        ) : (
                            <>
                                <ShieldCheck className="mr-2 h-4 w-4" />
                                Unlock Vault
                            </>
                        )}
                    </Button>

                    {isDerivingKey && showSlowHint && (
                        <p className="text-xs text-center text-slate-500 -mt-1">
                            This is normal for first login. Future unlocks will be faster.
                        </p>
                    )}

                    {/* Forgot Password Link */}
                    {onForgotPassword && (
                        <div className="text-center pt-1">
                            <button
                                type="button"
                                onClick={onForgotPassword}
                                className="text-sm text-amber-600 dark:text-amber-400 hover:text-amber-700 dark:hover:text-amber-300 underline underline-offset-4 transition-colors"
                                disabled={isDerivingKey}
                            >
                                Forgot your password? Use a recovery code
                            </button>
                        </div>
                    )}
                </div>

            </DialogContent>
        </Dialog>
    );
}
