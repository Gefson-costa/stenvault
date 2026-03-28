/**
 * Header — Premium glassmorphism navigation with animated border glow
 */
import { useEffect, useState, useRef } from 'react';
import { Shield, Menu, X } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { gsap } from 'gsap';
import { useAuth } from '@/_core/hooks/useAuth';
import { LANDING_COLORS } from '../constants';
import { HEADER } from '../constants/copy';
import { getReducedMotion } from '@/hooks/useReducedMotion';

export function Header() {
    const setLocation = useNavigate();
    const { isAuthenticated } = useAuth();
    const [isScrolled, setIsScrolled] = useState(false);
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const borderRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleScroll = () => setIsScrolled(window.scrollY > 20);
        window.addEventListener('scroll', handleScroll, { passive: true });
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    // Animated border glow when scrolled
    useEffect(() => {
        if (!isScrolled || getReducedMotion() || !borderRef.current) return;

        const tween = gsap.to(borderRef.current, {
            backgroundPosition: '200% 0',
            duration: 4,
            ease: 'none',
            repeat: -1,
        });

        return () => { tween.kill(); };
    }, [isScrolled]);

    const closeMobileMenu = () => setIsMobileMenuOpen(false);

    return (
        <nav
            className={`fixed top-0 left-0 right-0 z-50 transition-all duration-500 ${
                isScrolled ? 'py-3 backdrop-blur-2xl' : 'py-5 md:py-6'
            }`}
            style={{
                backgroundColor: isScrolled
                    ? LANDING_COLORS.glassBg
                    : 'transparent',
                borderBottom: isScrolled
                    ? 'none'
                    : '1px solid transparent',
            }}
        >
            {/* Animated bottom border */}
            {isScrolled && (
                <div
                    ref={borderRef}
                    className="absolute bottom-0 left-0 right-0 h-px"
                    style={{
                        backgroundImage: `linear-gradient(90deg, transparent, ${LANDING_COLORS.glassBorder}, ${LANDING_COLORS.accent}30, ${LANDING_COLORS.glassBorder}, transparent)`,
                        backgroundSize: '200% 100%',
                    }}
                />
            )}

            <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
                {/* Logo */}
                <Link to="/" className="flex items-center gap-2.5 group">
                    <div className="relative">
                        <Shield className="w-5 h-5 text-indigo-400 transition-transform duration-300 group-hover:scale-110" />
                        <div className="absolute inset-0 bg-indigo-500 blur-lg opacity-20 group-hover:opacity-40 transition-opacity" />
                    </div>
                    <span className="font-bold text-lg tracking-tight text-white">
                        Sten<span className="text-indigo-400">Vault</span>
                    </span>
                </Link>

                {/* Desktop nav */}
                <div className="hidden md:flex items-center gap-8">
                    {HEADER.nav.map((link) =>
                        'isRoute' in link && link.isRoute ? (
                            <Link
                                key={link.href}
                                to={link.href}
                                className="text-sm text-slate-400 hover:text-white transition-colors duration-300"
                            >
                                {link.label}
                            </Link>
                        ) : (
                            <a
                                key={link.href}
                                href={link.href}
                                className="text-sm text-slate-400 hover:text-white transition-colors duration-300"
                            >
                                {link.label}
                            </a>
                        ),
                    )}
                </div>

                {/* Desktop auth */}
                <div className="hidden md:flex items-center gap-3">
                    {isAuthenticated ? (
                        <button
                            onClick={() => setLocation('/')}
                            className="px-5 py-2.5 rounded-xl bg-indigo-600 text-white text-sm font-semibold hover:bg-indigo-500 transition-colors shadow-lg shadow-indigo-600/20 cursor-pointer"
                        >
                            Dashboard
                        </button>
                    ) : (
                        <>
                            <button
                                onClick={() => setLocation('/auth/login')}
                                className="text-sm text-slate-400 hover:text-white transition-colors cursor-pointer"
                            >
                                Log in
                            </button>
                            <button
                                onClick={() => setLocation('/auth/register')}
                                className="px-5 py-2.5 rounded-xl text-white text-sm font-semibold transition-all cursor-pointer"
                                style={{
                                    backgroundColor: LANDING_COLORS.accent,
                                    boxShadow: `0 0 20px ${LANDING_COLORS.accentGlow}`,
                                }}
                            >
                                Get Started
                            </button>
                        </>
                    )}
                </div>

                {/* Mobile toggle */}
                <button
                    className="md:hidden text-white p-3 cursor-pointer"
                    onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                    aria-label={
                        isMobileMenuOpen ? 'Close menu' : 'Open menu'
                    }
                >
                    {isMobileMenuOpen ? (
                        <X className="w-5 h-5" />
                    ) : (
                        <Menu className="w-5 h-5" />
                    )}
                </button>
            </div>

            {/* Mobile menu */}
            {isMobileMenuOpen && (
                <div
                    className="md:hidden absolute top-full left-0 right-0 backdrop-blur-2xl p-6 flex flex-col gap-4"
                    style={{
                        backgroundColor: LANDING_COLORS.glassBg,
                        borderBottom: `1px solid ${LANDING_COLORS.glassBorder}`,
                    }}
                >
                    {HEADER.nav.map((link) =>
                        'isRoute' in link && link.isRoute ? (
                            <Link
                                key={link.href}
                                to={link.href}
                                className="text-sm text-slate-300 hover:text-white py-2"
                                onClick={closeMobileMenu}
                            >
                                {link.label}
                            </Link>
                        ) : (
                            <a
                                key={link.href}
                                href={link.href}
                                className="text-sm text-slate-300 hover:text-white py-2"
                                onClick={closeMobileMenu}
                            >
                                {link.label}
                            </a>
                        ),
                    )}
                    <div className="h-px bg-white/10 my-1" />
                    {isAuthenticated ? (
                        <button
                            onClick={() => {
                                setLocation('/');
                                closeMobileMenu();
                            }}
                            className="w-full py-3 rounded-xl bg-indigo-600 text-white font-semibold cursor-pointer"
                        >
                            Dashboard
                        </button>
                    ) : (
                        <>
                            <button
                                onClick={() => {
                                    setLocation('/auth/login');
                                    closeMobileMenu();
                                }}
                                className="w-full py-3 rounded-xl border border-white/10 text-white font-medium cursor-pointer"
                            >
                                Log in
                            </button>
                            <button
                                onClick={() => {
                                    setLocation('/auth/register');
                                    closeMobileMenu();
                                }}
                                className="w-full py-3 rounded-xl bg-indigo-600 text-white font-semibold cursor-pointer"
                            >
                                Get Started
                            </button>
                        </>
                    )}
                </div>
            )}
        </nav>
    );
}
