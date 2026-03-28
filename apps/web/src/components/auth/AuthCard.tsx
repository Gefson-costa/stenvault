import { ReactNode, useState } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { cn } from '@/lib/utils';
import { LANDING_COLORS } from '@/components/landing-v3/constants';

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH CARD (Header & Container)
// ═══════════════════════════════════════════════════════════════════════════════

interface AuthCardProps {
    children: ReactNode;
    title: string;
    description?: string;
    className?: string;
}

export function AuthCard({
    children,
    title,
    description,
    className,
}: AuthCardProps) {
    return (
        <div className={cn(
            'relative space-y-8',
            className
        )}>
            {/* Header */}
            <div className="space-y-3 text-center sm:text-left">
                <h1 className="text-4xl font-bold text-white tracking-tighter bg-gradient-to-b from-white to-white/60 bg-clip-text text-transparent">
                    {title}
                </h1>
                {description && (
                    <p className="text-slate-400 font-light leading-relaxed text-sm sm:text-base">
                        {description}
                    </p>
                )}
            </div>

            {/* Content */}
            <div className="relative z-20">
                {children}
            </div>
        </div>
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH INPUT 
// ═══════════════════════════════════════════════════════════════════════════════

interface AuthInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
    label: string;
    error?: string;
    icon?: ReactNode;
    rightIcon?: ReactNode;
}

export function AuthInput({
    label,
    error,
    icon,
    rightIcon,
    className,
    id,
    type,
    ...props
}: AuthInputProps) {
    const [isFocused, setIsFocused] = useState(false);
    const [showPassword, setShowPassword] = useState(false);

    const isPassword = type === 'password';

    return (
        <div className="space-y-2.5">
            <label
                htmlFor={id}
                className="block text-xs uppercase tracking-[0.2em] font-bold text-slate-500 ml-1"
            >
                {label}
            </label>
            <div className="relative group">
                {/* Active Border Glow */}
                <div className={cn(
                    "absolute -inset-[1px] rounded-xl bg-gradient-to-r from-indigo-500/50 to-teal-500/50 opacity-0 transition-opacity duration-300 blur-[2px]",
                    isFocused && "opacity-100"
                )} />

                <input
                    id={id}
                    type={isPassword ? (showPassword ? 'text' : 'password') : type}
                    className={cn(
                        'relative w-full h-13 rounded-xl border border-white/[0.08] bg-white/[0.03] px-5 text-sm text-white',
                        'transition-all duration-300 outline-none placeholder:text-slate-600 focus-visible:ring-2 focus-visible:ring-indigo-500/50',
                        'focus:bg-slate-900/80',
                        isPassword && 'pr-12',
                        error && 'border-red-500/50',
                        className
                    )}
                    onFocus={() => setIsFocused(true)}
                    onBlur={() => setIsFocused(false)}
                    {...props}
                />

                {isPassword ? (
                    <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-slate-500 hover:text-slate-300 transition-colors z-30"
                        aria-label={showPassword ? "Hide password" : "Show password"}
                    >
                        {showPassword ? (
                            <EyeOff className="w-5 h-5" />
                        ) : (
                            <Eye className="w-5 h-5" />
                        )}
                    </button>
                ) : rightIcon ? (
                    <div className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 group-hover:text-slate-300 transition-colors">
                        {rightIcon}
                    </div>
                ) : null}
            </div>
            {error && <p className="text-xs text-red-400/80 font-medium ml-1">{error}</p>}
        </div>
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH BUTTON
// ═══════════════════════════════════════════════════════════════════════════════

interface AuthButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
    children: ReactNode;
    variant?: 'primary' | 'secondary' | 'ghost';
    isLoading?: boolean;
    icon?: ReactNode;
}

export function AuthButton({
    children,
    variant = 'primary',
    isLoading,
    icon,
    className,
    disabled,
    ...props
}: AuthButtonProps) {
    return (
        <button
            className={cn(
                'relative w-full h-13 rounded-xl font-bold text-sm transition-all duration-300',
                'flex items-center justify-center gap-2 overflow-hidden group focus-visible:ring-2 focus-visible:ring-indigo-500/50 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900',
                'disabled:opacity-50 disabled:cursor-not-allowed',

                variant === 'primary' && [
                    'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20',
                    'hover:bg-indigo-500 hover:shadow-indigo-500/40 hover:-translate-y-0.5',
                    'active:translate-y-0 active:brightness-90'
                ],

                variant === 'secondary' && [
                    'bg-white/[0.04] text-white border border-white/[0.08] backdrop-blur-md',
                    'hover:bg-white/[0.08] hover:border-white/[0.15]',
                ],

                variant === 'ghost' && 'bg-transparent text-slate-500 hover:text-white',

                className
            )}
            disabled={disabled || isLoading}
            {...props}
        >
            {/* Shimmer effect for primary button */}
            {variant === 'primary' && !isLoading && !disabled && (
                <div className="absolute inset-0 w-full h-full bg-gradient-to-r from-transparent via-white/10 to-transparent -translate-x-full group-hover:animate-shimmer" />
            )}

            {isLoading ? (
                <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    <span className="uppercase tracking-widest text-[11px]">Syncing...</span>
                </div>
            ) : (
                <div className="flex items-center gap-2">
                    <span className={variant === 'primary' ? 'uppercase tracking-widest text-[12px]' : ''}>
                        {children}
                    </span>
                    {icon && <span className="group-hover:translate-x-0.5 transition-transform">{icon}</span>}
                </div>
            )}
        </button>
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH DIVIDER
// ═══════════════════════════════════════════════════════════════════════════════

export function AuthDivider({ text = 'Validation' }: { text?: string }) {
    return (
        <div className="relative flex items-center py-6">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-white/[0.05] to-transparent" />
            <span className="px-4 text-[11px] uppercase tracking-[0.3em] text-slate-600 font-black">
                {text}
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-white/[0.05] to-transparent" />
        </div>
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH LINK
// ═══════════════════════════════════════════════════════════════════════════════

export function AuthLink({ href, children, className }: { href: string; children: ReactNode; className?: string }) {
    return (
        <a
            href={href}
            className={cn(
                'text-[12px] font-bold transition-all hover:text-indigo-400 hover:tracking-wider duration-300',
                className
            )}
            style={{ color: '#64748B' }}
        >
            {children}
        </a>
    );
}

export default AuthCard;
