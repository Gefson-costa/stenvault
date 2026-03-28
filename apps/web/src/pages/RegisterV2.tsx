import { useState } from 'react';
import { trpc } from '@/lib/trpc';
import { startRegistration, finishRegistration } from '@/lib/opaqueClient';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, Loader2 } from 'lucide-react';
import { AuthLayout, AuthCard, AuthInput, AuthButton, AuthDivider, AuthLink } from '@/components/auth';
import { PasswordStrengthMeter } from '@/components/auth/PasswordStrengthMeter';

function getAndClearReturnUrl(): string {
    const url = sessionStorage.getItem('stenvault_return_url');
    sessionStorage.removeItem('stenvault_return_url');
    if (!url) return '/home';
    if (!url.startsWith('/') || url.startsWith('//')) return '/home';
    return url;
}

export default function RegisterV2() {
    const setLocation = useNavigate();
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [inviteCode, setInviteCode] = useState('');
    const [isRegistering, setIsRegistering] = useState(false);

    const { data: registrationStatus, isLoading: statusLoading } = trpc.auth.getRegistrationStatus.useQuery();
    const opaqueRegisterStartMutation = trpc.auth.opaqueRegisterStart.useMutation();
    const opaqueRegisterFinishMutation = trpc.auth.opaqueRegisterFinish.useMutation();
    const utils = trpc.useUtils();

    const handleRegister = async (e: React.FormEvent) => {
        e.preventDefault();

        if (password.length < 12) {
            toast.error('Password must be at least 12 characters long');
            return;
        }

        if (password !== confirmPassword) {
            toast.error('Passwords do not match');
            return;
        }

        try {
            setIsRegistering(true);

            // OPAQUE Step 1: Client generates registrationRequest
            const clientReg = await startRegistration(password);

            // OPAQUE Step 2: Send to server, get registrationResponse
            const step1 = await opaqueRegisterStartMutation.mutateAsync({
                email,
                registrationRequest: clientReg.registrationRequest,
            });

            // OPAQUE Step 3: Client finishes registration
            const clientFinish = await finishRegistration(
                password,
                clientReg.clientRegistrationState,
                step1.registrationResponse
            );

            // OPAQUE Step 4: Send registrationRecord to server, get tokens
            const result = await opaqueRegisterFinishMutation.mutateAsync({
                email,
                registrationRecord: clientFinish.registrationRecord,
                name: name || undefined,
                inviteCode: inviteCode.trim() || undefined,
            }) as any;

            // Server sets HttpOnly cookies in the response — no client-side storage needed

            toast.success('Account created! Please check your email to verify your account.', {
                duration: 5000,
            });

            await utils.auth.me.invalidate();
            setLocation(getAndClearReturnUrl());
        } catch (error: any) {
            const message = error.message || 'Registration failed';
            if (message.includes('already registered')) {
                toast.error('This email is already registered');
            } else if (message.includes('8 character') || message.includes('12 character')) {
                toast.error('Password must be at least 12 characters long');
            } else {
                toast.error(message);
            }
        } finally {
            setIsRegistering(false);
        }
    };

    if (statusLoading) return <AuthLayout><div className="flex justify-center py-20"><Loader2 className="animate-spin text-indigo-500" /></div></AuthLayout>;

    if (!registrationStatus?.isOpen) {
        return (
            <AuthLayout>
                <AuthCard title="Registration Closed" description="Public signups are currently disabled.">
                    <AuthButton variant="secondary" onClick={() => setLocation('/auth/login')}>Back to Sign In</AuthButton>
                </AuthCard>
            </AuthLayout>
        );
    }

    const requiresCode = !registrationStatus?.allowPublicRegistration || registrationStatus?.requireInviteCode;
    const isPending = isRegistering || opaqueRegisterStartMutation.isPending || opaqueRegisterFinishMutation.isPending;

    return (
        <AuthLayout>
            <AuthCard
                title="Create Account"
                description="Secure your digital assets with StenVault."
            >
                <form onSubmit={handleRegister} className="space-y-6">
                    {requiresCode && (
                        <AuthInput
                            id="inviteCode"
                            label="Invite Code"
                            value={inviteCode}
                            onChange={(e) => setInviteCode(e.target.value)}
                            placeholder="CLOUD-XXXX"
                            required
                        />
                    )}

                    <AuthInput
                        id="name"
                        label="Full Name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="John Doe"
                    />

                    <AuthInput
                        id="email"
                        type="email"
                        label="Email Address"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="name@gmail.com"
                        required
                    />

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-start">
                        <AuthInput
                            id="password"
                            type="password"
                            label="Login Password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Create a login password"
                            required
                        />
                        <AuthInput
                            id="confirmPassword"
                            type="password"
                            label="Confirm Password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            placeholder="••••••••"
                            required
                        />
                    </div>

                    <PasswordStrengthMeter password={password} />

                    <AuthButton
                        type="submit"
                        isLoading={isPending}
                        icon={<ArrowRight className="w-4 h-4" />}
                    >
                        Create Account
                    </AuthButton>
                </form>

                <AuthDivider text="Preference" />

                <div className="text-center">
                    <p className="text-[13px] text-slate-500">
                        Already have an account?{' '}
                        <AuthLink href="/auth/login" className="text-indigo-500">
                            Sign in here
                        </AuthLink>
                    </p>
                </div>
            </AuthCard>
        </AuthLayout>
    );
}
