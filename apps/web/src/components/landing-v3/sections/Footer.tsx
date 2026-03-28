/**
 * Footer — Clean premium footer
 */
import { Shield } from 'lucide-react';
import { Link } from 'react-router-dom';
import { LANDING_COLORS } from '../constants';
import { FOOTER } from '../constants/copy';

export function Footer() {
    const year = new Date().getFullYear();

    return (
        <footer
            style={{
                backgroundColor: LANDING_COLORS.bg,
                borderTop: `1px solid ${LANDING_COLORS.border}`,
            }}
        >
            <div className="max-w-7xl mx-auto px-6 py-16 md:py-20">
                <div className="grid grid-cols-1 md:grid-cols-12 gap-12 md:gap-8">
                    {/* Brand */}
                    <div className="md:col-span-5">
                        <Link
                            to="/"
                            className="inline-flex items-center gap-2 mb-4 group"
                        >
                            <Shield className="w-4 h-4 text-indigo-400 transition-transform group-hover:scale-110" />
                            <span className="font-bold text-base tracking-tight text-white">
                                Sten
                                <span className="text-indigo-400">Vault</span>
                            </span>
                        </Link>
                        <p className="text-sm text-slate-400 max-w-xs">
                            {FOOTER.brand.tagline}
                        </p>
                    </div>

                    {/* Nav columns */}
                    {FOOTER.columns.map((col) => (
                        <div
                            key={col.title}
                            className="md:col-span-2"
                        >
                            <h4 className="text-xs tracking-wider uppercase text-slate-400 font-medium mb-4">
                                {col.title}
                            </h4>
                            <ul className="space-y-3">
                                {col.links.map((link) => (
                                    <li key={link.label}>
                                        {link.href.startsWith('/') ? (
                                            <Link
                                                to={link.href}
                                                className="text-sm text-slate-400 hover:text-slate-200 transition-colors duration-200"
                                            >
                                                {link.label}
                                            </Link>
                                        ) : (
                                            <a
                                                href={link.href}
                                                className="text-sm text-slate-400 hover:text-slate-200 transition-colors duration-200"
                                            >
                                                {link.label}
                                            </a>
                                        )}
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ))}
                </div>
            </div>

            {/* Copyright */}
            <div
                className="px-6 py-5"
                style={{
                    borderTop: `1px solid ${LANDING_COLORS.border}50`,
                }}
            >
                <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
                    <span className="text-xs text-slate-500">
                        &copy; {year} StenVault. All rights reserved.
                    </span>
                    <span className="text-xs text-slate-500">
                        Private by design. Not by promise.
                    </span>
                </div>
            </div>
        </footer>
    );
}
