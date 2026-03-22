/**
 * ═══════════════════════════════════════════════════════════════
 * WELCOME HEADER COMPONENT
 * ═══════════════════════════════════════════════════════════════
 *
 * Personalized greeting with time-of-day context and user info.
 * Part of the Home page redesign.
 * 
 * Enhanced with Aurora Design System:
 * - Theme-aware gradients and glow effects
 * - Dynamic colors based on current theme
 *
 * ═══════════════════════════════════════════════════════════════
 */

import { motion } from 'framer-motion';
import { Sun, Moon, Sunrise, Sunset } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useTheme } from '@/contexts/ThemeContext';

interface WelcomeHeaderProps {
    userName: string | null;
    className?: string;
}

function getTimeOfDay(): {
    greeting: string;
    icon: typeof Sun;
    iconColor: string;
    bgGradient: string;
} {
    const hour = new Date().getHours();

    if (hour >= 5 && hour < 12) {
        return {
            greeting: 'Good morning',
            icon: Sunrise,
            iconColor: 'text-amber-500',
            bgGradient: 'from-amber-500/10 via-orange-500/5 to-transparent',
        };
    } else if (hour >= 12 && hour < 17) {
        return {
            greeting: 'Good afternoon',
            icon: Sun,
            iconColor: 'text-yellow-500',
            bgGradient: 'from-yellow-500/10 via-amber-500/5 to-transparent',
        };
    } else if (hour >= 17 && hour < 21) {
        return {
            greeting: 'Good evening',
            icon: Sunset,
            iconColor: 'text-purple-500',
            bgGradient: 'from-purple-500/10 via-pink-500/5 to-transparent',
        };
    } else {
        return {
            greeting: 'Good night',
            icon: Moon,
            iconColor: 'text-indigo-400',
            bgGradient: 'from-indigo-500/10 via-blue-500/5 to-transparent',
        };
    }
}

export function WelcomeHeader({ userName, className }: WelcomeHeaderProps) {
    const { theme } = useTheme();
    const { greeting, icon: TimeIcon, iconColor, bgGradient } = getTimeOfDay();
    const displayName = userName || 'User';
    const currentDate = new Date().toLocaleDateString('en-US', {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
    });

    return (
        <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
            className={cn(
                'relative overflow-hidden rounded-2xl p-6 md:p-8',
                'bg-card/50 backdrop-blur-xl border border-border',
                className
            )}
        >
            {/* Background gradient layer */}
            <div
                className={cn(
                    'absolute inset-0 bg-gradient-to-br',
                    bgGradient,
                    'pointer-events-none'
                )}
            />

            {/* Content */}
            <div className="relative flex items-start gap-4">
                <motion.div
                    className={cn(
                        'p-3 rounded-xl',
                        'bg-gradient-to-br from-white/10 to-transparent',
                        'border border-white/10',
                        iconColor
                    )}
                    whileHover={{ scale: 1.05, rotate: 5 }}
                    transition={{ type: 'spring', stiffness: 400 }}
                >
                    <TimeIcon className="h-6 w-6" />
                </motion.div>

                <div className="flex-1 min-w-0">
                    <motion.h1
                        className="text-2xl md:text-3xl font-semibold tracking-tight text-foreground"
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: 0.1, duration: 0.4 }}
                    >
                        {greeting},{' '}
                        <span
                            className="font-bold"
                            style={{ color: theme.brand.primary }}
                        >
                            {displayName}
                        </span>
                    </motion.h1>

                    <motion.p
                        className="mt-1.5 text-sm md:text-base text-muted-foreground capitalize"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.2, duration: 0.4 }}
                    >
                        {currentDate}
                    </motion.p>

                    {/* Quick stats badge */}
                    <motion.div
                        className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium bg-primary/10 text-primary"
                        initial={{ opacity: 0, y: 5 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.3, duration: 0.4 }}
                    >
                        <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-primary" />
                        </span>
                        System active
                    </motion.div>
                </div>
            </div>
        </motion.div>
    );
}

