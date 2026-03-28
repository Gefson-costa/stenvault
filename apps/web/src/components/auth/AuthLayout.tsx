import { ReactNode } from 'react';
import { motion } from 'framer-motion';
import { Shield, ArrowLeft, Cpu } from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { LANDING_COLORS } from '@/components/landing-v3/constants';

interface AuthLayoutProps {
    children: ReactNode;
    showBackLink?: boolean;
    backLinkUrl?: string;
    backLinkText?: string;
}

function AuthBackground() {
    return (
        <div className="fixed inset-0 overflow-hidden pointer-events-none bg-[#020617]">
            {/* Ambient Nebula Effect */}
            <div
                className="absolute top-[-20%] left-[-10%] w-[60%] h-[60%] rounded-full blur-[150px] opacity-[0.1]"
                style={{ background: `radial-gradient(circle, ${LANDING_COLORS.accent} 0%, transparent 70%)` }}
            />
            <div
                className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] rounded-full blur-[150px] opacity-[0.05]"
                style={{ background: `radial-gradient(circle, ${LANDING_COLORS.success} 0%, transparent 70%)` }}
            />

            {/* Subtle Grid Pattern with perspective */}
            <div
                className="absolute inset-0 opacity-[0.03]"
                style={{
                    backgroundImage: `linear-gradient(${LANDING_COLORS.accent} 1px, transparent 1px), linear-gradient(90deg, ${LANDING_COLORS.accent} 1px, transparent 1px)`,
                    backgroundSize: '100px 100px',
                    maskImage: 'radial-gradient(ellipse at center, black, transparent 80%)'
                }}
            />
        </div>
    );
}

function BrandLogo() {
    return (
        <Link to="/" className="inline-flex items-center gap-2 group">
            <div className="relative">
                <Shield className="w-8 h-8 text-indigo-500 transition-transform group-hover:scale-110" />
                <div className="absolute inset-0 bg-indigo-500 blur-lg opacity-20 group-hover:opacity-40 transition-opacity" />
            </div>
            <span className="text-2xl font-bold text-white tracking-tighter">
                Sten<span className="text-indigo-500">Vault</span>
            </span>
        </Link>
    );
}

export function AuthLayout({
    children,
    showBackLink = true,
    backLinkUrl = '/',
    backLinkText = 'Return to gateway',
}: AuthLayoutProps) {
    return (
        <div className="min-h-[100dvh] w-full flex flex-col items-center justify-center p-4 overflow-y-auto selection:bg-indigo-500/30 font-sans antialiased">
            <AuthBackground />

            <motion.div
                initial={{ opacity: 0, y: 5, scale: 0.99 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.5, ease: "easeOut" }}
                className="relative z-10 w-full max-w-[440px]"
            >
                {/* Header */}
                <div className="flex flex-col items-center mb-12 space-y-4">
                    <BrandLogo />
                    {showBackLink && (
                        <Link
                            to={backLinkUrl}
                            className="flex items-center gap-1.5 text-[12px] uppercase tracking-widest text-slate-500 hover:text-indigo-400 transition-colors font-medium"
                        >
                            <ArrowLeft className="w-3 h-3" />
                            <span>{backLinkText}</span>
                        </Link>
                    )}
                </div>

                {/* Glass Card Wrapper */}
                <div className="relative group">
                    {/* Decorative glow behind the card */}
                    <div className="absolute -inset-1 bg-gradient-to-r from-indigo-500/10 to-teal-500/10 rounded-[2rem] blur-2xl opacity-50 group-hover:opacity-100 transition duration-1000" />

                    <div className="relative bg-slate-950/40 backdrop-blur-3xl border border-white/[0.05] rounded-[2rem] p-8 sm:p-10 shadow-2xl overflow-hidden min-h-[400px]">
                        {/* Scanline effect */}
                        <div className="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent opacity-20" />

                        {children}
                    </div>
                </div>

                {/* Footer Minimalist */}
                <div className="mt-12 text-center">
                    <div className="inline-flex items-center gap-3 px-4 py-2 rounded-full border border-white/[0.03] bg-white/[0.01] backdrop-blur-sm">
                        <Cpu className="w-3.5 h-3.5 text-indigo-500" />
                        <span className="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-semibold">
                            Quantum-Resistant Encryption Active
                        </span>
                    </div>
                </div>
            </motion.div>
        </div>
    );
}

export default AuthLayout;
