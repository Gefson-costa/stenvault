/**
 * TimestampProofModal Component
 *
 * Premium blockchain timestamp verification and proof download experience.
 * Features a distinctive Bitcoin/crypto aesthetic with animated visualizations.
 */

import { useState, useEffect } from "react";
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
    Check,
    AlertCircle,
    Download,
    RefreshCw,
    Shield,
    ExternalLink,
    Loader2,
    Copy,
    CheckCircle2,
    Clock,
    FileDigit,
    Link2,
    Blocks,
    ShieldCheck,
    FileText,
    ChevronDown,
    Sparkles,
} from "lucide-react";
import { useTimestamp } from "@/hooks/useTimestamp";
import type { TimestampVerification } from "@stenvault/shared";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

interface TimestampProofModalProps {
    fileId: number;
    filename: string;
    open: boolean;
    onClose: () => void;
}

// Bitcoin orange gradient
const bitcoinGradient = "from-orange-500 via-amber-500 to-yellow-500";

export function TimestampProofModal({
    fileId,
    filename,
    open,
    onClose,
}: TimestampProofModalProps) {
    const {
        timestampInfo,
        isLoading,
        isEnabled,
        hasPlanAccess,
        submitTimestamp,
        verifyTimestamp,
        downloadProof,
        downloadLegalPdf,
        retryTimestamp,
        isPending,
    } = useTimestamp({ fileId, filename });

    const [verification, setVerification] = useState<TimestampVerification | null>(null);
    const [isVerifying, setIsVerifying] = useState(false);
    const [copiedHash, setCopiedHash] = useState(false);
    const [showDetails, setShowDetails] = useState(false);

    // Reset state when modal closes
    useEffect(() => {
        if (!open) {
            setVerification(null);
            setShowDetails(false);
        }
    }, [open]);

    const handleVerify = async () => {
        setIsVerifying(true);
        try {
            const result = await verifyTimestamp();
            setVerification(result);
        } finally {
            setIsVerifying(false);
        }
    };

    const handleCopyHash = async (hash: string) => {
        await navigator.clipboard.writeText(hash);
        setCopiedHash(true);
        setTimeout(() => setCopiedHash(false), 2000);
    };

    const formatDate = (date: Date | string | null) => {
        if (!date) return "—";
        const d = new Date(date);
        return d.toLocaleString(undefined, {
            year: "numeric",
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
        });
    };

    const truncateHash = (hash: string) => {
        if (!hash || hash.length < 16) return hash;
        return `${hash.slice(0, 8)}...${hash.slice(-8)}`;
    };

    if (!isEnabled) {
        return (
            <Dialog open={open} onOpenChange={onClose}>
                <DialogContent className="sm:max-w-md bg-gradient-to-br from-zinc-900 to-zinc-950 border-zinc-800 text-white">
                    <div className="flex flex-col items-center gap-4 py-8 text-center">
                        <div className="w-16 h-16 rounded-2xl bg-zinc-800 flex items-center justify-center">
                            <AlertCircle className="h-8 w-8 text-zinc-500" />
                        </div>
                        <div>
                            <p className="font-semibold text-lg">Service Unavailable</p>
                            <p className="text-sm text-zinc-400 mt-1">
                                Blockchain timestamping is not enabled.
                            </p>
                        </div>
                    </div>
                </DialogContent>
            </Dialog>
        );
    }

    return (
        <Dialog open={open} onOpenChange={onClose}>
            <DialogContent className="sm:max-w-lg p-0 overflow-hidden bg-gradient-to-br from-zinc-900 via-zinc-900 to-zinc-950 border-zinc-800 text-white">
                {/* Header with Bitcoin gradient accent */}
                <div className="relative">
                    <div className={cn(
                        "absolute inset-x-0 top-0 h-1 bg-gradient-to-r",
                        bitcoinGradient
                    )} />
                    <DialogHeader className="p-6 pb-0">
                        <DialogTitle className="flex items-center gap-3 text-xl font-bold">
                            <div className={cn(
                                "w-10 h-10 rounded-xl flex items-center justify-center",
                                "bg-gradient-to-br", bitcoinGradient
                            )}>
                                <Blocks className="h-5 w-5 text-white" />
                            </div>
                            <div>
                                <span className="text-white">Blockchain Proof</span>
                                <p className="text-xs font-normal text-zinc-500 mt-0.5 truncate max-w-[280px]">
                                    {filename}
                                </p>
                            </div>
                        </DialogTitle>
                    </DialogHeader>
                </div>

                <div className="p-6 pt-4">
                    {isLoading ? (
                        <LoadingState />
                    ) : !timestampInfo?.hasTimestamp ? (
                        <NoTimestampState
                            onSubmit={submitTimestamp}
                            isPending={isPending}
                            hasPlanAccess={hasPlanAccess}
                        />
                    ) : (
                        <motion.div
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="space-y-5"
                        >
                            {/* Status Card */}
                            <StatusCard
                                status={timestampInfo.status}
                                submittedAt={timestampInfo.submittedAt}
                                confirmedAt={timestampInfo.confirmedAt}
                                bitcoinBlockHeight={timestampInfo.bitcoinBlockHeight}
                                bitcoinTimestamp={timestampInfo.bitcoinTimestamp}
                                formatDate={formatDate}
                            />

                            {/* Content Hash Display */}
                            {timestampInfo.contentHash && (
                                <HashDisplay
                                    hash={timestampInfo.contentHash}
                                    onCopy={() => handleCopyHash(timestampInfo.contentHash!)}
                                    copied={copiedHash}
                                    truncate={truncateHash}
                                />
                            )}

                            {/* Verification Result */}
                            <AnimatePresence>
                                {verification && (
                                    <VerificationResult verification={verification} />
                                )}
                            </AnimatePresence>

                            {/* Action Buttons */}
                            <div className="flex flex-wrap gap-2 pt-2">
                                {timestampInfo.status === "confirmed" && (
                                    <>
                                        <ActionButton
                                            onClick={handleVerify}
                                            loading={isVerifying}
                                            icon={ShieldCheck}
                                            variant="primary"
                                        >
                                            Verify Proof
                                        </ActionButton>
                                        <ActionButton
                                            onClick={downloadProof}
                                            icon={Download}
                                        >
                                            Download .ots
                                        </ActionButton>
                                        <ActionButton
                                            onClick={downloadLegalPdf}
                                            loading={isPending}
                                            icon={FileText}
                                        >
                                            Legal PDF
                                        </ActionButton>
                                    </>
                                )}
                                {timestampInfo.status === "failed" && (
                                    <ActionButton
                                        onClick={retryTimestamp}
                                        loading={isPending}
                                        icon={RefreshCw}
                                        variant="warning"
                                    >
                                        Retry Timestamp
                                    </ActionButton>
                                )}
                            </div>

                            {/* Pending Info */}
                            {(timestampInfo.status === "pending" || timestampInfo.status === "confirming") && (
                                <PendingInfo status={timestampInfo.status} />
                            )}

                            {/* Expandable Info */}
                            <ExpandableInfo
                                open={showDetails}
                                onToggle={() => setShowDetails(!showDetails)}
                            />
                        </motion.div>
                    )}
                </div>
            </DialogContent>
        </Dialog>
    );
}

// Loading State
function LoadingState() {
    return (
        <div className="flex flex-col items-center justify-center py-12 gap-4">
            <div className="relative">
                <div className={cn(
                    "w-16 h-16 rounded-2xl bg-gradient-to-br animate-pulse",
                    bitcoinGradient,
                    "opacity-20"
                )} />
                <Loader2 className="h-8 w-8 text-orange-500 animate-spin absolute inset-0 m-auto" />
            </div>
            <p className="text-sm text-zinc-500">Loading timestamp data...</p>
        </div>
    );
}

// No Timestamp State
function NoTimestampState({
    onSubmit,
    isPending,
    hasPlanAccess,
}: {
    onSubmit: () => void;
    isPending: boolean;
    hasPlanAccess: boolean;
}) {
    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="flex flex-col items-center gap-5 py-8 text-center"
        >
            {/* Animated Bitcoin Icon */}
            <div className="relative">
                <motion.div
                    animate={{
                        boxShadow: [
                            "0 0 0 0 rgba(251, 146, 60, 0.4)",
                            "0 0 0 20px rgba(251, 146, 60, 0)",
                        ],
                    }}
                    transition={{ duration: 2, repeat: Infinity }}
                    className={cn(
                        "w-20 h-20 rounded-2xl flex items-center justify-center",
                        "bg-gradient-to-br", bitcoinGradient
                    )}
                >
                    <Blocks className="h-10 w-10 text-white" />
                </motion.div>
            </div>

            <div className="space-y-2">
                <h3 className="text-lg font-semibold text-white">
                    Create Blockchain Proof
                </h3>
                <p className="text-sm text-zinc-400 max-w-xs">
                    Anchor this file's existence to the Bitcoin blockchain.
                    Immutable, verifiable, forever.
                </p>
            </div>

            {hasPlanAccess ? (
                <>
                    <Button
                        onClick={onSubmit}
                        disabled={isPending}
                        className={cn(
                            "bg-gradient-to-r text-white font-semibold px-6",
                            bitcoinGradient,
                            "hover:opacity-90 transition-opacity"
                        )}
                    >
                        {isPending ? (
                            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        ) : (
                            <Sparkles className="h-4 w-4 mr-2" />
                        )}
                        Create Timestamp
                    </Button>

                    <p className="text-xs text-zinc-600">
                        Included with your plan • Takes 1-3 hours for Bitcoin confirmation
                    </p>
                </>
            ) : (
                <>
                    <div className="px-4 py-2 rounded-lg bg-zinc-800/50 border border-zinc-700/50">
                        <p className="text-sm text-zinc-400">
                            Blockchain timestamping requires a <span className="text-orange-400 font-medium">Pro</span> or <span className="text-orange-400 font-medium">Business</span> plan.
                        </p>
                    </div>

                    <Button
                        onClick={() => window.location.href = '/settings?tab=subscription'}
                        className={cn(
                            "bg-gradient-to-r text-white font-semibold px-6",
                            bitcoinGradient,
                            "hover:opacity-90 transition-opacity"
                        )}
                    >
                        <Sparkles className="h-4 w-4 mr-2" />
                        Upgrade to Pro
                    </Button>
                </>
            )}
        </motion.div>
    );
}

// Status Card
function StatusCard({
    status,
    submittedAt,
    confirmedAt,
    bitcoinBlockHeight,
    bitcoinTimestamp,
    formatDate,
}: {
    status: string | null;
    submittedAt: Date | string | null;
    confirmedAt: Date | string | null;
    bitcoinBlockHeight: number | null;
    bitcoinTimestamp: Date | string | null;
    formatDate: (date: Date | string | null) => string;
}) {
    const isConfirmed = status === "confirmed";
    const isPending = status === "pending" || status === "confirming";
    const isFailed = status === "failed";

    return (
        <div className={cn(
            "rounded-xl border p-4",
            isConfirmed && "border-green-500/30 bg-green-500/5",
            isPending && "border-orange-500/30 bg-orange-500/5",
            isFailed && "border-red-500/30 bg-red-500/5"
        )}>
            {/* Status Header */}
            <div className="flex items-center gap-3 mb-4">
                <div className={cn(
                    "w-10 h-10 rounded-lg flex items-center justify-center",
                    isConfirmed && "bg-green-500/20",
                    isPending && "bg-orange-500/20",
                    isFailed && "bg-red-500/20"
                )}>
                    {isConfirmed && <Check className="h-5 w-5 text-green-500" />}
                    {isPending && <Clock className="h-5 w-5 text-orange-500 animate-pulse" />}
                    {isFailed && <AlertCircle className="h-5 w-5 text-red-500" />}
                </div>
                <div>
                    <p className={cn(
                        "font-semibold",
                        isConfirmed && "text-green-400",
                        isPending && "text-orange-400",
                        isFailed && "text-red-400"
                    )}>
                        {isConfirmed && "Verified on Bitcoin"}
                        {isPending && "Awaiting Confirmation"}
                        {isFailed && "Timestamp Failed"}
                    </p>
                    <p className="text-xs text-zinc-500">
                        Submitted {formatDate(submittedAt)}
                    </p>
                </div>
            </div>

            {/* Details Grid */}
            {isConfirmed && (
                <div className="grid grid-cols-2 gap-3 text-sm">
                    <InfoCell
                        icon={CheckCircle2}
                        label="Confirmed"
                        value={formatDate(confirmedAt)}
                    />
                    <InfoCell
                        icon={Blocks}
                        label="Block Height"
                        value={bitcoinBlockHeight?.toLocaleString() || "—"}
                        link={bitcoinBlockHeight
                            ? `https://blockstream.info/block-height/${bitcoinBlockHeight}`
                            : undefined
                        }
                    />
                    <InfoCell
                        icon={Clock}
                        label="Block Time"
                        value={formatDate(bitcoinTimestamp)}
                        className="col-span-2"
                    />
                </div>
            )}
        </div>
    );
}

// Info Cell
function InfoCell({
    icon: Icon,
    label,
    value,
    link,
    className,
}: {
    icon: typeof Check;
    label: string;
    value: string;
    link?: string;
    className?: string;
}) {
    return (
        <div className={cn("bg-zinc-800/50 rounded-lg p-3", className)}>
            <div className="flex items-center gap-2 mb-1">
                <Icon className="h-3.5 w-3.5 text-zinc-500" />
                <span className="text-xs text-zinc-500">{label}</span>
            </div>
            {link ? (
                <a
                    href={link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm font-medium text-orange-400 hover:text-orange-300 flex items-center gap-1"
                >
                    {value}
                    <ExternalLink className="h-3 w-3" />
                </a>
            ) : (
                <span className="text-sm font-medium text-white">{value}</span>
            )}
        </div>
    );
}

// Hash Display
function HashDisplay({
    hash,
    onCopy,
    copied,
    truncate,
}: {
    hash: string;
    onCopy: () => void;
    copied: boolean;
    truncate: (hash: string) => string;
}) {
    return (
        <div className="bg-zinc-800/50 rounded-xl p-4 border border-zinc-700/50">
            <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                    <FileDigit className="h-4 w-4 text-zinc-500" />
                    <span className="text-xs font-medium text-zinc-400">
                        Content SHA-256
                    </span>
                </div>
                <button
                    onClick={onCopy}
                    className="text-xs text-zinc-500 hover:text-white transition-colors flex items-center gap-1"
                >
                    {copied ? (
                        <>
                            <Check className="h-3 w-3 text-green-500" />
                            <span className="text-green-500">Copied!</span>
                        </>
                    ) : (
                        <>
                            <Copy className="h-3 w-3" />
                            Copy
                        </>
                    )}
                </button>
            </div>
            <code className="text-sm font-mono text-orange-400 break-all">
                {truncate(hash)}
            </code>
        </div>
    );
}

// Verification Result
function VerificationResult({
    verification,
}: {
    verification: TimestampVerification;
}) {
    return (
        <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className={cn(
                "rounded-xl border p-4",
                verification.verified
                    ? "border-green-500/50 bg-green-500/10"
                    : "border-red-500/50 bg-red-500/10"
            )}
        >
            <div className="flex items-start gap-3">
                <div className={cn(
                    "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0",
                    verification.verified ? "bg-green-500/20" : "bg-red-500/20"
                )}>
                    {verification.verified ? (
                        <ShieldCheck className="h-4 w-4 text-green-500" />
                    ) : (
                        <AlertCircle className="h-4 w-4 text-red-500" />
                    )}
                </div>
                <div>
                    <p className={cn(
                        "font-semibold",
                        verification.verified ? "text-green-400" : "text-red-400"
                    )}>
                        {verification.verified
                            ? "Cryptographically Verified"
                            : "Verification Failed"}
                    </p>
                    {verification.message && (
                        <p className="text-sm text-zinc-400 mt-1">
                            {verification.message}
                        </p>
                    )}
                </div>
            </div>
        </motion.div>
    );
}

// Action Button
function ActionButton({
    onClick,
    loading,
    icon: Icon,
    variant = "default",
    children,
}: {
    onClick: () => void;
    loading?: boolean;
    icon: typeof Check;
    variant?: "default" | "primary" | "warning";
    children: React.ReactNode;
}) {
    return (
        <Button
            variant="outline"
            size="sm"
            onClick={onClick}
            disabled={loading}
            className={cn(
                "border-zinc-700 text-zinc-300 hover:text-white hover:bg-zinc-800",
                variant === "primary" && "border-orange-500/50 text-orange-400 hover:bg-orange-500/10",
                variant === "warning" && "border-red-500/50 text-red-400 hover:bg-red-500/10"
            )}
        >
            {loading ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
                <Icon className="h-4 w-4 mr-2" />
            )}
            {children}
        </Button>
    );
}

// Pending Info
function PendingInfo({ status }: { status: string }) {
    return (
        <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center gap-3 p-4 rounded-xl bg-orange-500/5 border border-orange-500/20"
        >
            <div className="relative">
                <Clock className="h-5 w-5 text-orange-500" />
                <motion.div
                    animate={{ scale: [1, 1.5, 1], opacity: [1, 0, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                    className="absolute inset-0 rounded-full bg-orange-500/30"
                />
            </div>
            <div>
                <p className="text-sm font-medium text-orange-400">
                    {status === "pending" ? "Submitted to Calendar Servers" : "Bitcoin Network Processing"}
                </p>
                <p className="text-xs text-zinc-500">
                    Confirmation typically takes 1-3 hours
                </p>
            </div>
        </motion.div>
    );
}

// Expandable Info
function ExpandableInfo({
    open,
    onToggle,
}: {
    open: boolean;
    onToggle: () => void;
}) {
    return (
        <div className="border-t border-zinc-800 pt-4">
            <button
                onClick={onToggle}
                className="flex items-center gap-2 text-sm text-zinc-500 hover:text-zinc-300 transition-colors w-full"
            >
                <ChevronDown className={cn(
                    "h-4 w-4 transition-transform",
                    open && "rotate-180"
                )} />
                What is blockchain timestamping?
            </button>
            <AnimatePresence>
                {open && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden"
                    >
                        <div className="pt-4 space-y-3 text-sm text-zinc-400">
                            <p>
                                <strong className="text-white">OpenTimestamps</strong> creates
                                cryptographic proof that your file existed at a specific point
                                in time, anchored in the Bitcoin blockchain.
                            </p>
                            <p>
                                The proof is <strong className="text-orange-400">tamper-evident</strong> and
                                can be independently verified by anyone using the .ots file.
                            </p>
                            <div className="flex items-start gap-2 p-3 rounded-lg bg-zinc-800/50">
                                <Link2 className="h-4 w-4 text-orange-500 mt-0.5 flex-shrink-0" />
                                <span className="text-xs">
                                    Verify independently at{" "}
                                    <a
                                        href="https://opentimestamps.org"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-orange-400 hover:underline"
                                    >
                                        opentimestamps.org
                                    </a>
                                </span>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

export default TimestampProofModal;
