/**
 * SigningPanel Component (Phase 3.4 Sovereign)
 *
 * Provides UI for enabling file signing during upload.
 * When enabled, prompts user for master password to derive signing keys.
 *
 * Features:
 * - Toggle to enable/disable signing
 * - Password prompt for master key derivation
 * - Session caching of master key (user only enters password once)
 * - Shows signing status and key info
 * - Smooth animations for state transitions (Framer Motion)
 */

import { useState, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Lock, Shield, ShieldCheck, Key, Loader2, Eye, EyeOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { cn } from '@/lib/utils';
import { useSignatureKeys } from '@/hooks/useSignatureKeys';
import { useMasterKey } from '@/hooks/useMasterKey';
import type { HybridSignatureSecretKey } from '@stenvault/shared/platform/crypto';

// ============ Animation Variants ============

const fadeInUp = {
  initial: { opacity: 0, y: -10 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -10 },
};

const fadeIn = {
  initial: { opacity: 0 },
  animate: { opacity: 1 },
  exit: { opacity: 0 },
};

// ============ Types ============

// Re-export from types for convenience
export type { SigningState } from '../types';

interface SigningPanelProps {
  signingState: import('../types').SigningState;
  onEnableChange: (enabled: boolean) => void;
  onKeysReady: (
    secretKey: HybridSignatureSecretKey,
    fingerprint: string,
    keyVersion: number
  ) => void;
  onKeysClear: () => void;
  className?: string;
}

// ============ Component ============

export function SigningPanel({
  signingState,
  onEnableChange,
  onKeysReady,
  onKeysClear,
  className,
}: SigningPanelProps) {
  const [showPasswordPrompt, setShowPasswordPrompt] = useState(false);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);

  // Hooks for signature keys and master key
  const { keyInfo, isLoading: isLoadingKeys, getSecretKey } = useSignatureKeys();
  const { config: encryptionConfig, deriveMasterKey, isCached, getCachedKey } = useMasterKey();

  // Check if user has both signature keys and master key wrapping
  const canSign = keyInfo.hasKeyPair && encryptionConfig?.isConfigured && encryptionConfig?.masterKeyEncrypted;

  // Auto-unlock with cached key if available
  const unlockWithCachedKey = useCallback(async () => {
    const cachedKey = getCachedKey();
    if (!cachedKey || !keyInfo.fingerprint || !keyInfo.keyVersion) return false;

    try {
      const secretKey = await getSecretKey(cachedKey);
      onKeysReady(secretKey, keyInfo.fingerprint, keyInfo.keyVersion);
      return true;
    } catch {
      // Cache might be invalid, let user re-enter password
      return false;
    }
  }, [getCachedKey, getSecretKey, keyInfo, onKeysReady]);

  // Handle toggle change
  const handleToggle = useCallback(
    async (enabled: boolean) => {
      onEnableChange(enabled);

      if (enabled && canSign && !signingState.keysReady) {
        // Try cached key first
        if (isCached) {
          const unlocked = await unlockWithCachedKey();
          if (unlocked) return;
        }
        // Show password prompt to unlock signing keys
        setShowPasswordPrompt(true);
      } else if (!enabled) {
        // Clear keys when disabled
        setShowPasswordPrompt(false);
        onKeysClear();
      }
    },
    [canSign, signingState.keysReady, onEnableChange, onKeysClear, isCached, unlockWithCachedKey]
  );

  // Handle password submit to unlock signing keys
  const handleUnlock = useCallback(async () => {
    if (!password.trim()) {
      setUnlockError('Please enter your master password');
      return;
    }

    setIsUnlocking(true);
    setUnlockError(null);

    try {
      // Derive master key from password
      const masterKey = await deriveMasterKey(password);

      // Get signature secret key using master key
      const secretKey = await getSecretKey(masterKey);

      // Signal keys are ready
      onKeysReady(secretKey, keyInfo.fingerprint!, keyInfo.keyVersion!);

      // Clear password from memory
      setPassword('');
      setShowPasswordPrompt(false);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message.includes('unwrap')
            ? 'Incorrect password. Please try again.'
            : error.message
          : 'Failed to unlock signing keys';
      setUnlockError(message);
    } finally {
      setIsUnlocking(false);
    }
  }, [password, deriveMasterKey, getSecretKey, keyInfo, onKeysReady]);

  // Clear password on unmount
  useEffect(() => {
    return () => {
      setPassword('');
    };
  }, []);

  // If user doesn't have signature keys, show nothing — avoid noise
  if (!canSign) {
    return null;
  }

  return (
    <div className={cn('rounded-lg border', className, signingState.enabled ? 'border-primary/50 bg-primary/5' : 'border-border')}>
      <div className="p-4">
        {/* Toggle */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {signingState.keysReady ? (
              <ShieldCheck className="h-5 w-5 text-green-500" />
            ) : (
              <Shield className="h-5 w-5 text-muted-foreground" />
            )}
            <div>
              <Label htmlFor="signing-toggle" className="text-sm font-medium cursor-pointer">
                Sign Files
              </Label>
              <p className="text-xs text-muted-foreground">
                Add hybrid signature (Ed25519 + ML-DSA-65)
              </p>
            </div>
          </div>
          <Switch
            id="signing-toggle"
            checked={signingState.enabled}
            onCheckedChange={handleToggle}
            disabled={isLoadingKeys}
          />
        </div>

        {/* Status when enabled */}
        <AnimatePresence mode="wait">
          {signingState.enabled && signingState.keysReady && (
            <motion.div
              key="status"
              {...fadeIn}
              transition={{ duration: 0.2 }}
              className="mt-3 flex items-center gap-2 text-xs text-green-600"
            >
              <Key className="h-3 w-3" />
              <span>
                Signing enabled (Key: {keyInfo.fingerprint?.slice(0, 8)}...){isCached && ' • Session cached'}
              </span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Password prompt */}
        <AnimatePresence mode="wait">
          {showPasswordPrompt && !signingState.keysReady && (
            <motion.div
              key="password-prompt"
              {...fadeInUp}
              transition={{ duration: 0.2 }}
              className="mt-4 space-y-3 border-t pt-4"
            >
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Lock className="h-4 w-4" />
                <span>Enter your master password to unlock signing keys</span>
              </div>

              <div className="relative">
                <Input
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Master password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleUnlock();
                  }}
                  className="pr-10"
                  disabled={isUnlocking}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </Button>
              </div>

              <AnimatePresence>
                {unlockError && (
                  <motion.p
                    {...fadeIn}
                    transition={{ duration: 0.15 }}
                    className="text-xs text-destructive"
                  >
                    {unlockError}
                  </motion.p>
                )}
              </AnimatePresence>

              <div className="flex gap-2">
                <Button
                  size="sm"
                  onClick={handleUnlock}
                  disabled={isUnlocking || !password.trim()}
                >
                  {isUnlocking && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Unlock
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setShowPasswordPrompt(false);
                    setPassword('');
                    onEnableChange(false);
                  }}
                  disabled={isUnlocking}
                >
                  Cancel
                </Button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Error display */}
        <AnimatePresence>
          {signingState.error && (
            <motion.div
              {...fadeIn}
              transition={{ duration: 0.15 }}
              className="mt-3 text-xs text-destructive"
            >
              {signingState.error}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
