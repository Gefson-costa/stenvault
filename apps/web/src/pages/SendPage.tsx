/**
 * SendPage - Premium Standalone Mini-Landing for Anonymous Encrypted File Sharing
 *
 * Design: Dark obsidian theme matching main landing, with GradientMesh,
 * SpotlightCards, and MagneticButtons for a world-class experience.
 *
 * Features:
 * - Multi-file + folder drop support
 * - QR code for sharing
 * - Auth-aware (5GB + 30d for logged-in users)
 * - Speed/ETA display during upload
 * - Resume interrupted upload banner
 */
import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { usePublicSend, type SendConfig } from "@/hooks/usePublicSend";
import { useAuth } from "@/_core/hooks/useAuth";
import { useTurnstile } from "@/hooks/useTurnstile";
import { trpc } from "@/lib/trpc";
import { formatBytes } from "@stenvault/shared";
import { readDroppedEntries } from "@/lib/directoryReader";
import { LANDING_COLORS } from "@/components/landing-v3/constants";
import { GradientMesh } from "@/components/landing-v3/components/GradientMesh";
import { SpotlightCard } from "@/components/landing-v3/components/SpotlightCard";
import { MagneticButton } from "@/components/landing-v3/components/MagneticButton";
import { toast } from "sonner";
import { QRCodeSVG } from "qrcode.react";
import {
  Upload,
  Shield,
  Copy,
  Check,
  Lock,
  Clock,
  Download,
  ArrowRight,
  Loader2,
  AlertCircle,
  RefreshCw,
  Eye,
  EyeOff,
  Zap,
  Server,
  FileIcon,
  QrCode,
  Share2,
  Files,
  Crown,
  Bell,
} from "lucide-react";

// Extracted modules
import { EXPIRY_OPTIONS_ANON, EXPIRY_OPTIONS_AUTH, HOW_IT_WORKS, COMPARISON, FAQ_ITEMS } from "./send/constants";
import { ComparisonCell } from "./send/ComparisonCell";
import { FAQItem } from "./send/FAQItem";
import { formatSize, formatSpeed, formatEta } from "./send/utils";

// ═══════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════

export default function SendPage() {
  const { state, progress, shareUrl, error, speed, eta, resumeAvailable, send, reset } =
    usePublicSend();
  const { user } = useAuth();
  const isAuthenticated = !!user;
  const { containerRef: turnstileRef, getToken: getTurnstileToken } = useTurnstile(
    import.meta.env.VITE_TURNSTILE_SITE_KEY,
  );

  // File state (multi-file)
  const [files, setFiles] = useState<File[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Cleanup copy timer on unmount
  useEffect(() => {
    return () => {
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    };
  }, []);

  // Config
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [expiresInHours, setExpiresInHours] = useState(24);
  const [maxDownloads, setMaxDownloads] = useState<string>("");
  const [copied, setCopied] = useState(false);
  const [showQR, setShowQR] = useState(false);
  const [notifyOnDownload, setNotifyOnDownload] = useState(false);

  // Reply chain tracking
  const replyToSessionId = new URLSearchParams(window.location.search).get("reply") || undefined;

  // Scroll state for nav
  const [isScrolled, setIsScrolled] = useState(false);

  // Plan-aware limits
  const { data: subscription } = trpc.stripe.getSubscription.useQuery(undefined, {
    enabled: isAuthenticated,
    staleTime: 60000,
  });
  const planMaxFileSize = subscription?.features?.publicSendMaxFileSize;
  const planMaxExpiryHours = subscription?.features?.publicSendMaxExpiryHours ?? (isAuthenticated ? 720 : 168);

  const maxSize = isAuthenticated && planMaxFileSize
    ? formatBytes(planMaxFileSize)
    : isAuthenticated ? "5 GB" : "2 GB";

  const expiryOptions = useMemo(() => {
    const base = isAuthenticated ? EXPIRY_OPTIONS_AUTH : EXPIRY_OPTIONS_ANON;
    if (!isAuthenticated || planMaxExpiryHours === -1) return base;
    return base.filter((opt) => opt.value <= planMaxExpiryHours);
  }, [isAuthenticated, planMaxExpiryHours]);

  const maxExpiryLabel = useMemo(() => {
    if (!isAuthenticated) return "7 days";
    if (planMaxExpiryHours === -1) return "30 days";
    const last = expiryOptions[expiryOptions.length - 1];
    return last?.label ?? "24 hours";
  }, [isAuthenticated, planMaxExpiryHours, expiryOptions]);

  // Reset expiry if selected value exceeds plan max
  useEffect(() => {
    if (planMaxExpiryHours !== -1 && expiresInHours > planMaxExpiryHours) {
      const maxAllowed = expiryOptions[expiryOptions.length - 1]?.value ?? 24;
      setExpiresInHours(maxAllowed);
    }
  }, [planMaxExpiryHours, expiryOptions, expiresInHours]);

  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 20);
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Drag handlers (multi-file + folder)
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const dropped = await readDroppedEntries(e.dataTransfer);
    if (dropped.length > 0) setFiles(dropped);
  }, []);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = Array.from(e.target.files ?? []);
    if (selected.length > 0) setFiles(selected);
  }, []);

  const handleSend = useCallback(async () => {
    if (files.length === 0) return;
    const turnstileToken = await getTurnstileToken();
    const config: SendConfig = {
      expiresInHours,
      ...(password ? { password } : {}),
      ...(maxDownloads ? { maxDownloads: parseInt(maxDownloads, 10) } : { maxDownloads: null }),
      turnstileToken,
      notifyOnDownload: isAuthenticated ? notifyOnDownload : undefined,
      replyToSessionId,
    };
    await send(files, config);
  }, [files, password, expiresInHours, maxDownloads, send, getTurnstileToken]);

  const handleCopy = useCallback(async () => {
    if (!shareUrl) return;
    await navigator.clipboard.writeText(shareUrl);
    setCopied(true);
    toast.success("Link copied to clipboard");
    if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    copyTimerRef.current = setTimeout(() => setCopied(false), 2000);
  }, [shareUrl]);

  const handleShare = useCallback(async () => {
    if (!shareUrl) return;
    if (navigator.share) {
      try {
        await navigator.share({
          title: "Encrypted file via StenVault Send",
          url: shareUrl,
        });
      } catch {
        // User cancelled or not supported
      }
    } else {
      handleCopy();
    }
  }, [shareUrl, handleCopy]);

  const handleReset = useCallback(() => {
    reset();
    setFiles([]);
    setPassword("");
    setShowPassword(false);
    setExpiresInHours(24);
    setMaxDownloads("");
    setCopied(false);
    setShowQR(false);
    setNotifyOnDownload(false);
  }, [reset]);

  const isActive = state === "encrypting" || state === "uploading" || state === "completing";
  const totalSize = files.reduce((sum, f) => sum + f.size, 0);

  // File display info
  const fileDisplayName =
    files.length === 0
      ? ""
      : files.length === 1
        ? files[0]!.name
        : `${files.length} files`;
  const fileDisplaySize = files.length > 0 ? formatSize(totalSize) : "";

  return (
    <div className="min-h-screen" style={{ backgroundColor: LANDING_COLORS.bg }}>
      <meta name="referrer" content="no-referrer" />

      {/* ═══════════ NAVIGATION ═══════════ */}
      <nav
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          isScrolled ? "py-3 border-b" : "py-5"
        }`}
        style={{
          backgroundColor: isScrolled ? `${LANDING_COLORS.bg}E6` : "transparent",
          borderColor: isScrolled ? `${LANDING_COLORS.border}40` : "transparent",
          backdropFilter: isScrolled ? "blur(16px)" : "none",
        }}
      >
        <div className="container mx-auto px-6 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 group">
            <Shield className="w-6 h-6 text-indigo-500" />
            <span className="text-lg font-bold" style={{ color: LANDING_COLORS.textPrimary }}>
              Sten<span className="text-indigo-500">Vault</span>
            </span>
            <span
              className="text-xs font-medium px-2 py-0.5 rounded-full"
              style={{
                backgroundColor: LANDING_COLORS.accentSubtle,
                color: LANDING_COLORS.accentHover,
              }}
            >
              Send
            </span>
          </Link>
          <div className="flex items-center gap-3">
            <Link
              to="/send/local"
              className="hidden sm:inline-flex items-center gap-1.5 text-sm font-medium transition-colors hover:text-emerald-400"
              style={{ color: LANDING_COLORS.textSecondary }}
            >
              <Zap className="w-3.5 h-3.5" />
              Local
            </Link>
            {isAuthenticated ? (
              <Link
                to="/home"
                className="hidden sm:inline-flex text-sm font-medium transition-colors hover:text-white"
                style={{ color: LANDING_COLORS.textSecondary }}
              >
                Dashboard
              </Link>
            ) : (
              <Link
                to="/auth/login"
                className="hidden sm:inline-flex text-sm font-medium transition-colors hover:text-white"
                style={{ color: LANDING_COLORS.textSecondary }}
              >
                Sign in
              </Link>
            )}
            {!isAuthenticated && (
              <MagneticButton as="a" href="/auth/register" size="sm" variant="primary">
                Get 5 GB free
                <ArrowRight className="w-4 h-4" />
              </MagneticButton>
            )}
          </div>
        </div>
      </nav>

      {/* ═══════════ HERO + DROPZONE ═══════════ */}
      <section className="relative min-h-screen flex items-center justify-center pt-24 pb-16 overflow-hidden">
        <GradientMesh variant="hero" />

        <div className="container mx-auto px-6 relative z-10">
          <div className="max-w-2xl mx-auto">
            {/* Reply indicator */}
            {replyToSessionId && (
              <div className="flex justify-center mb-4">
                <div
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-full border backdrop-blur-sm"
                  style={{
                    borderColor: `${LANDING_COLORS.success}30`,
                    backgroundColor: `${LANDING_COLORS.success}08`,
                  }}
                >
                  <ArrowRight className="w-3.5 h-3.5 text-emerald-400 rotate-180" />
                  <span className="text-xs font-semibold text-emerald-300">
                    Replying with a file
                  </span>
                </div>
              </div>
            )}

            {/* Badge */}
            <div className="flex justify-center mb-6">
              <div
                className="inline-flex items-center gap-2 px-4 py-2 rounded-full border backdrop-blur-sm"
                style={{
                  borderColor: `${LANDING_COLORS.accent}30`,
                  backgroundColor: `${LANDING_COLORS.accent}08`,
                }}
              >
                <Lock className="w-3.5 h-3.5 text-indigo-400" />
                <span className="text-xs font-semibold text-indigo-300">
                  End-to-end encrypted
                </span>
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              </div>
            </div>

            {/* Headline */}
            <h1
              className="text-4xl sm:text-5xl md:text-6xl font-black text-center tracking-tight leading-[1.1] mb-4"
              style={{ color: LANDING_COLORS.textPrimary }}
            >
              Send files.{" "}
              <span className="bg-gradient-to-r from-indigo-400 via-violet-400 to-purple-400 bg-clip-text text-transparent">
                Encrypted.
              </span>
            </h1>

            <p
              className="text-lg md:text-xl text-center font-light leading-relaxed mb-8 max-w-lg mx-auto"
              style={{ color: LANDING_COLORS.textSecondary }}
            >
              Zero-knowledge file sharing. No account needed.
              Your files are encrypted in your browser — we never see them.
            </p>

            {/* ═══════════ LOCAL SEND BANNER ═══════════ */}
            <Link
              to="/send/local"
              className="flex items-center gap-3 p-3.5 rounded-xl border mb-8 transition-all hover:scale-[1.005] group"
              style={{
                borderColor: `${LANDING_COLORS.success}25`,
                backgroundColor: `${LANDING_COLORS.success}06`,
              }}
            >
              <div
                className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                style={{ backgroundColor: `${LANDING_COLORS.success}12` }}
              >
                <Zap className="w-4.5 h-4.5 text-emerald-400" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold" style={{ color: LANDING_COLORS.textPrimary }}>
                  On the same WiFi?{" "}
                  <span className="text-emerald-400">Transfer directly</span>
                </p>
                <p className="text-xs" style={{ color: LANDING_COLORS.textMuted }}>
                  Device-to-device · LAN speed · Zero cloud
                </p>
              </div>
              <ArrowRight className="w-4 h-4 shrink-0 text-emerald-400 transition-transform group-hover:translate-x-0.5" />
            </Link>

            {/* ═══════════ UPLOAD CARD ═══════════ */}
            <div
              className="rounded-2xl border overflow-hidden backdrop-blur-xl"
              style={{
                backgroundColor: `${LANDING_COLORS.surface}B3`,
                borderColor: LANDING_COLORS.border,
              }}
            >
              <div className="p-6 sm:p-8">
                {/* Hidden Turnstile widget container */}
                <div ref={turnstileRef} className="hidden" />

                {/* Resume banner */}
                {resumeAvailable && state === "idle" && (
                  <div
                    className="flex items-center gap-3 p-3.5 rounded-xl mb-4 text-sm"
                    style={{
                      backgroundColor: `${LANDING_COLORS.accent}10`,
                      borderColor: `${LANDING_COLORS.accent}20`,
                    }}
                  >
                    <RefreshCw className="w-4 h-4 text-indigo-400 shrink-0" />
                    <span style={{ color: LANDING_COLORS.textSecondary }}>
                      An interrupted upload was found. Re-select the file to try again.
                    </span>
                  </div>
                )}

                {/* Auth-aware tier badge */}
                {isAuthenticated && state === "idle" && (
                  <div
                    className="flex items-center gap-2 px-3 py-2 rounded-lg mb-4"
                    style={{
                      backgroundColor: `${LANDING_COLORS.accent}08`,
                      border: `1px solid ${LANDING_COLORS.accent}20`,
                    }}
                  >
                    <Crown className="w-3.5 h-3.5 text-indigo-400" />
                    <span className="text-xs font-medium text-indigo-300">
                      Signed in — {maxSize} limit, up to {maxExpiryLabel}
                    </span>
                  </div>
                )}

                {/* ── IDLE / ERROR ── */}
                {(state === "idle" || state === "error") && (
                  <div className="space-y-6">
                    {/* Dropzone */}
                    <div
                      className={`relative border-2 border-dashed rounded-xl p-10 text-center cursor-pointer
                        transition-all duration-300 group ${
                          isDragging
                            ? "scale-[1.01]"
                            : files.length > 0
                              ? ""
                              : "hover:scale-[1.005]"
                        }`}
                      style={{
                        borderColor: isDragging
                          ? LANDING_COLORS.accent
                          : files.length > 0
                            ? `${LANDING_COLORS.accent}60`
                            : `${LANDING_COLORS.textMuted}30`,
                        backgroundColor: isDragging
                          ? `${LANDING_COLORS.accent}08`
                          : files.length > 0
                            ? `${LANDING_COLORS.accent}05`
                            : "transparent",
                      }}
                      onDragOver={handleDragOver}
                      onDragLeave={handleDragLeave}
                      onDrop={handleDrop}
                      onClick={() => fileInputRef.current?.click()}
                    >
                      <input
                        ref={fileInputRef}
                        type="file"
                        className="hidden"
                        multiple
                        onChange={handleFileSelect}
                      />

                      {files.length > 0 ? (
                        <div className="space-y-3">
                          <div
                            className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto"
                            style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
                          >
                            {files.length > 1 ? (
                              <Files className="w-7 h-7 text-indigo-400" />
                            ) : (
                              <FileIcon className="w-7 h-7 text-indigo-400" />
                            )}
                          </div>
                          <p
                            className="font-semibold truncate max-w-xs mx-auto"
                            style={{ color: LANDING_COLORS.textPrimary }}
                          >
                            {fileDisplayName}
                          </p>
                          <p className="text-sm" style={{ color: LANDING_COLORS.textSecondary }}>
                            {fileDisplaySize}
                            {files.length > 1 && ` (${files.length} files — will be zipped)`}
                          </p>
                          <p className="text-xs" style={{ color: LANDING_COLORS.textMuted }}>
                            Click or drop to change files
                          </p>
                        </div>
                      ) : (
                        <div className="space-y-3">
                          <div
                            className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto transition-transform duration-300 group-hover:scale-110"
                            style={{ backgroundColor: `${LANDING_COLORS.accent}10` }}
                          >
                            <Upload className="w-7 h-7 text-indigo-400" />
                          </div>
                          <p className="font-semibold" style={{ color: LANDING_COLORS.textPrimary }}>
                            Drop files here or{" "}
                            <span className="text-indigo-400">browse</span>
                          </p>
                          <p className="text-sm" style={{ color: LANDING_COLORS.textMuted }}>
                            Up to {maxSize} &middot; Any file type &middot; Folders supported
                          </p>
                        </div>
                      )}
                    </div>

                    {/* Error */}
                    {state === "error" && error && (
                      <div
                        className="flex items-center gap-2.5 p-3.5 rounded-xl text-sm"
                        style={{
                          backgroundColor: `${LANDING_COLORS.danger}10`,
                          color: LANDING_COLORS.danger,
                        }}
                      >
                        <AlertCircle className="w-4 h-4 shrink-0" />
                        {error}
                      </div>
                    )}

                    {/* Settings (shown when files selected) */}
                    {files.length > 0 && (
                      <div className="space-y-4">
                        {/* Password */}
                        <div className="space-y-2">
                          <label
                            className="flex items-center gap-1.5 text-xs font-medium"
                            style={{ color: LANDING_COLORS.textSecondary }}
                          >
                            <Lock className="w-3.5 h-3.5" />
                            Password protection (optional)
                          </label>
                          <div className="relative">
                            <input
                              type={showPassword ? "text" : "password"}
                              placeholder="Set a download password"
                              value={password}
                              onChange={(e) => setPassword(e.target.value)}
                              className="w-full h-10 rounded-lg border px-3 pr-10 text-sm outline-none transition-colors focus:ring-1"
                              style={{
                                backgroundColor: LANDING_COLORS.bg,
                                borderColor: LANDING_COLORS.border,
                                color: LANDING_COLORS.textPrimary,
                                // @ts-expect-error CSS custom property
                                "--tw-ring-color": LANDING_COLORS.accent,
                              }}
                            />
                            <button
                              type="button"
                              onClick={() => setShowPassword(!showPassword)}
                              className="absolute right-3 top-1/2 -translate-y-1/2 cursor-pointer"
                              style={{ color: LANDING_COLORS.textMuted }}
                              aria-label={showPassword ? "Hide password" : "Show password"}
                            >
                              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                          </div>
                        </div>

                        {/* Expiry + Download Limit */}
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <label
                              className="flex items-center gap-1.5 text-xs font-medium"
                              style={{ color: LANDING_COLORS.textSecondary }}
                            >
                              <Clock className="w-3.5 h-3.5" />
                              Expires after
                            </label>
                            <select
                              value={expiresInHours}
                              onChange={(e) => setExpiresInHours(parseInt(e.target.value, 10))}
                              className="w-full h-10 rounded-lg border px-3 text-sm outline-none transition-colors focus:ring-1 cursor-pointer"
                              style={{
                                backgroundColor: LANDING_COLORS.bg,
                                borderColor: LANDING_COLORS.border,
                                color: LANDING_COLORS.textPrimary,
                              }}
                            >
                              {expiryOptions.map((opt) => (
                                <option key={opt.value} value={opt.value}>
                                  {opt.label}
                                </option>
                              ))}
                            </select>
                          </div>

                          <div className="space-y-2">
                            <label
                              className="flex items-center gap-1.5 text-xs font-medium"
                              style={{ color: LANDING_COLORS.textSecondary }}
                            >
                              <Download className="w-3.5 h-3.5" />
                              Download limit
                            </label>
                            <input
                              type="number"
                              placeholder="Unlimited"
                              min={1}
                              max={1000}
                              value={maxDownloads}
                              onChange={(e) => setMaxDownloads(e.target.value)}
                              className="w-full h-10 rounded-lg border px-3 text-sm outline-none transition-colors focus:ring-1"
                              style={{
                                backgroundColor: LANDING_COLORS.bg,
                                borderColor: LANDING_COLORS.border,
                                color: LANDING_COLORS.textPrimary,
                              }}
                            />
                          </div>
                        </div>

                        {/* Notify on download toggle (auth only) */}
                        {isAuthenticated && (
                          <button
                            type="button"
                            onClick={() => setNotifyOnDownload(!notifyOnDownload)}
                            className="flex items-center justify-between w-full py-2 cursor-pointer group"
                          >
                            <span
                              className="flex items-center gap-2 text-sm font-medium"
                              style={{ color: LANDING_COLORS.textSecondary }}
                            >
                              <Bell className="w-4 h-4" />
                              Notify me on first download
                            </span>
                            <div
                              className="relative w-10 h-[22px] rounded-full transition-colors duration-200"
                              style={{
                                backgroundColor: notifyOnDownload
                                  ? LANDING_COLORS.accent
                                  : `${LANDING_COLORS.textMuted}40`,
                              }}
                            >
                              <div
                                className="absolute top-[3px] w-4 h-4 rounded-full bg-white shadow-sm transition-transform duration-200"
                                style={{
                                  transform: notifyOnDownload
                                    ? "translateX(22px)"
                                    : "translateX(3px)",
                                }}
                              />
                            </div>
                          </button>
                        )}

                        {/* Send Button */}
                        <MagneticButton
                          size="lg"
                          variant="primary"
                          className="w-full"
                          onClick={handleSend}
                          disabled={files.length === 0}
                        >
                          <Shield className="w-5 h-5" />
                          Encrypt & Send
                        </MagneticButton>
                      </div>
                    )}
                  </div>
                )}

                {/* ── ENCRYPTING / UPLOADING ── */}
                {isActive && (
                  <div className="space-y-8 py-6">
                    <div className="text-center space-y-3">
                      <div className="relative w-16 h-16 mx-auto">
                        <div
                          className="absolute inset-0 rounded-full animate-ping opacity-20"
                          style={{ backgroundColor: LANDING_COLORS.accent }}
                        />
                        <div
                          className="relative w-16 h-16 rounded-full flex items-center justify-center"
                          style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
                        >
                          <Loader2 className="w-8 h-8 animate-spin text-indigo-400" />
                        </div>
                      </div>
                      <p className="font-semibold text-lg" style={{ color: LANDING_COLORS.textPrimary }}>
                        {state === "encrypting" && "Encrypting your files..."}
                        {state === "uploading" && "Uploading encrypted data..."}
                        {state === "completing" && "Finalizing..."}
                      </p>
                      <p className="text-sm" style={{ color: LANDING_COLORS.textMuted }}>
                        Your files never leave your browser unencrypted
                      </p>
                    </div>

                    {/* Progress bar */}
                    <div className="space-y-2">
                      <div
                        className="h-2 rounded-full overflow-hidden"
                        style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
                      >
                        <div
                          className="h-full rounded-full transition-all duration-500 ease-out"
                          style={{
                            width: `${progress}%`,
                            background: `linear-gradient(90deg, ${LANDING_COLORS.accent}, #A78BFA)`,
                          }}
                        />
                      </div>
                      <div className="flex items-center justify-between">
                        <p className="text-sm font-medium" style={{ color: LANDING_COLORS.textSecondary }}>
                          {progress}%
                        </p>
                        {state === "uploading" && speed > 0 && (
                          <p className="text-xs" style={{ color: LANDING_COLORS.textMuted }}>
                            {formatSpeed(speed)}
                            {eta > 0 && ` · ${formatEta(eta)}`}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* ── DONE ── */}
                {state === "done" && shareUrl && (
                  <div className="space-y-8 py-4">
                    <div className="text-center space-y-3">
                      <div
                        className="w-16 h-16 rounded-full flex items-center justify-center mx-auto"
                        style={{ backgroundColor: `${LANDING_COLORS.success}15` }}
                      >
                        <Check className="w-8 h-8" style={{ color: LANDING_COLORS.success }} />
                      </div>
                      <p className="font-semibold text-lg" style={{ color: LANDING_COLORS.textPrimary }}>
                        {files.length > 1 ? "Files encrypted & uploaded" : "File encrypted & uploaded"}
                      </p>
                      <p className="text-sm" style={{ color: LANDING_COLORS.textSecondary }}>
                        Share this link — only people with it can decrypt the {files.length > 1 ? "files" : "file"}.
                      </p>
                    </div>

                    {/* Share link */}
                    <div className="space-y-3">
                      <div
                        className="flex items-center gap-2 rounded-xl border p-1"
                        style={{
                          backgroundColor: LANDING_COLORS.bg,
                          borderColor: LANDING_COLORS.border,
                        }}
                      >
                        <input
                          readOnly
                          value={shareUrl}
                          className="flex-1 bg-transparent px-3 text-xs font-mono outline-none truncate"
                          style={{ color: LANDING_COLORS.textPrimary }}
                          onClick={handleCopy}
                        />
                        <button
                          onClick={handleCopy}
                          className="shrink-0 flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all cursor-pointer"
                          style={{
                            backgroundColor: copied ? `${LANDING_COLORS.success}15` : LANDING_COLORS.accent,
                            color: copied ? LANDING_COLORS.success : "#fff",
                          }}
                        >
                          {copied ? (
                            <>
                              <Check className="w-4 h-4" /> Copied
                            </>
                          ) : (
                            <>
                              <Copy className="w-4 h-4" /> Copy link
                            </>
                          )}
                        </button>
                      </div>

                      {/* Action buttons */}
                      <div className="flex gap-2">
                        <button
                          onClick={() => setShowQR(!showQR)}
                          className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl border text-sm font-medium transition-colors cursor-pointer"
                          style={{
                            borderColor: LANDING_COLORS.border,
                            color: showQR ? LANDING_COLORS.accent : LANDING_COLORS.textSecondary,
                            backgroundColor: showQR ? `${LANDING_COLORS.accent}08` : "transparent",
                          }}
                          onMouseEnter={(e) => {
                            if (!showQR) e.currentTarget.style.backgroundColor = LANDING_COLORS.surface;
                          }}
                          onMouseLeave={(e) => {
                            if (!showQR) e.currentTarget.style.backgroundColor = "transparent";
                          }}
                        >
                          <QrCode className="w-4 h-4" />
                          QR Code
                        </button>
                        {typeof navigator.share === "function" && (
                          <button
                            onClick={handleShare}
                            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl border text-sm font-medium transition-colors cursor-pointer"
                            style={{
                              borderColor: LANDING_COLORS.border,
                              color: LANDING_COLORS.textSecondary,
                              backgroundColor: "transparent",
                            }}
                            onMouseEnter={(e) =>
                              (e.currentTarget.style.backgroundColor = LANDING_COLORS.surface)
                            }
                            onMouseLeave={(e) =>
                              (e.currentTarget.style.backgroundColor = "transparent")
                            }
                          >
                            <Share2 className="w-4 h-4" />
                            Share
                          </button>
                        )}
                      </div>

                      {/* QR Code */}
                      {showQR && (
                        <div className="flex justify-center py-4">
                          <div className="bg-white p-4 rounded-xl">
                            <QRCodeSVG value={shareUrl} size={224} level="M" />
                          </div>
                        </div>
                      )}

                      {/* Auth CTA (for anonymous users) */}
                      {!isAuthenticated && (
                        <div
                          className="flex items-center gap-3 p-3.5 rounded-xl text-sm"
                          style={{
                            backgroundColor: `${LANDING_COLORS.accent}08`,
                            border: `1px solid ${LANDING_COLORS.accent}15`,
                          }}
                        >
                          <Crown className="w-4 h-4 text-indigo-400 shrink-0" />
                          <span style={{ color: LANDING_COLORS.textSecondary }}>
                            <Link
                              to="/auth/register?ref=send"
                              className="text-indigo-400 font-medium hover:underline"
                            >
                              Sign up
                            </Link>{" "}
                            for free — keep your files truly private
                          </span>
                        </div>
                      )}

                      <button
                        onClick={handleReset}
                        className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border text-sm font-medium transition-colors cursor-pointer"
                        style={{
                          borderColor: LANDING_COLORS.border,
                          color: LANDING_COLORS.textSecondary,
                          backgroundColor: "transparent",
                        }}
                        onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = LANDING_COLORS.surface)}
                        onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
                      >
                        <RefreshCw className="w-4 h-4" />
                        Send another file
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Trust signals under card */}
            <div className="flex flex-wrap items-center justify-center gap-6 mt-6">
              {[
                { icon: Shield, label: "Zero-knowledge" },
                { icon: Lock, label: "AES-256-GCM" },
                { icon: Clock, label: "Auto-delete" },
                { icon: Server, label: "EU servers" },
              ].map(({ icon: Icon, label }) => (
                <span
                  key={label}
                  className="flex items-center gap-1.5 text-xs font-medium"
                  style={{ color: LANDING_COLORS.textMuted }}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {label}
                </span>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════ HOW IT WORKS ═══════════ */}
      <section className="py-24 md:py-32 px-6 relative">
        <div className="container mx-auto max-w-5xl">
          <div className="text-center mb-16">
            <span
              className="text-xs font-semibold tracking-widest uppercase"
              style={{ color: LANDING_COLORS.accent }}
            >
              How it works
            </span>
            <h2
              className="text-3xl sm:text-4xl md:text-5xl font-black tracking-tight mt-3 leading-[1.1]"
              style={{ color: LANDING_COLORS.textPrimary }}
            >
              Three steps to{" "}
              <span className="bg-gradient-to-r from-indigo-400 to-violet-400 bg-clip-text text-transparent">
                total privacy
              </span>
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {HOW_IT_WORKS.map((item) => (
              <SpotlightCard
                key={item.step}
                variant="glass"
                tilt
                spotlightColor={item.accent}
              >
                <div className="p-6 md:p-8 space-y-4">
                  <div className="flex items-center gap-3">
                    <span
                      className="text-xs font-bold tracking-widest"
                      style={{ color: item.accent }}
                    >
                      {item.step}
                    </span>
                    <div
                      className="h-px flex-1"
                      style={{ backgroundColor: `${item.accent}20` }}
                    />
                  </div>
                  <div
                    className="w-12 h-12 rounded-xl flex items-center justify-center"
                    style={{ backgroundColor: `${item.accent}15` }}
                  >
                    <item.icon className="w-6 h-6" style={{ color: item.accent }} />
                  </div>
                  <h3
                    className="text-lg font-bold"
                    style={{ color: LANDING_COLORS.textPrimary }}
                  >
                    {item.title}
                  </h3>
                  <p
                    className="text-sm leading-relaxed"
                    style={{ color: LANDING_COLORS.textSecondary }}
                  >
                    {item.description}
                  </p>
                </div>
              </SpotlightCard>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════ COMPARISON TABLE ═══════════ */}
      <section className="py-24 md:py-32 px-6 relative">
        <GradientMesh variant="subtle" />

        <div className="container mx-auto max-w-4xl relative z-10">
          <div className="text-center mb-16">
            <span
              className="text-xs font-semibold tracking-widest uppercase"
              style={{ color: LANDING_COLORS.accent }}
            >
              Comparison
            </span>
            <h2
              className="text-3xl sm:text-4xl md:text-5xl font-black tracking-tight mt-3 leading-[1.1]"
              style={{ color: LANDING_COLORS.textPrimary }}
            >
              Not all file sharing is{" "}
              <span className="bg-gradient-to-r from-indigo-400 to-emerald-400 bg-clip-text text-transparent">
                equal
              </span>
            </h2>
          </div>

          <div
            className="rounded-2xl border overflow-hidden backdrop-blur-xl"
            style={{
              backgroundColor: `${LANDING_COLORS.surface}80`,
              borderColor: LANDING_COLORS.border,
            }}
          >
            <div
              className="grid grid-cols-4 gap-4 px-6 py-4 border-b"
              style={{ borderColor: LANDING_COLORS.border }}
            >
              <div className="text-sm font-medium" style={{ color: LANDING_COLORS.textMuted }}>
                Feature
              </div>
              <div className="text-center">
                <span className="text-sm font-bold text-indigo-400">StenVault</span>
              </div>
              <div className="text-center">
                <span className="text-sm font-medium" style={{ color: LANDING_COLORS.textSecondary }}>
                  WeTransfer
                </span>
              </div>
              <div className="text-center">
                <span className="text-sm font-medium" style={{ color: LANDING_COLORS.textSecondary }}>
                  Wormhole
                </span>
              </div>
            </div>

            {COMPARISON.map((row, i) => (
              <div
                key={row.feature}
                className="grid grid-cols-4 gap-4 px-6 py-3.5 items-center transition-colors"
                style={{
                  backgroundColor: i % 2 === 0 ? "transparent" : `${LANDING_COLORS.bg}40`,
                }}
              >
                <div className="text-sm" style={{ color: LANDING_COLORS.textSecondary }}>
                  {row.feature}
                </div>
                <div className="text-center">
                  <ComparisonCell value={row.stenvault} />
                </div>
                <div className="text-center">
                  <ComparisonCell value={row.wetransfer} />
                </div>
                <div className="text-center">
                  <ComparisonCell value={row.wormhole} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════ FAQ ═══════════ */}
      <section className="py-24 md:py-32 px-6">
        <div className="container mx-auto max-w-2xl">
          <div className="text-center mb-16">
            <span
              className="text-xs font-semibold tracking-widest uppercase"
              style={{ color: LANDING_COLORS.accent }}
            >
              Questions
            </span>
            <h2
              className="text-3xl sm:text-4xl font-black tracking-tight mt-3"
              style={{ color: LANDING_COLORS.textPrimary }}
            >
              Frequently asked
            </h2>
          </div>

          <div>
            {FAQ_ITEMS.map((item) => (
              <FAQItem key={item.q} q={item.q} a={item.a} />
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════ CTA SECTION ═══════════ */}
      <section className="py-24 md:py-32 px-6 relative overflow-hidden">
        <div className="container mx-auto max-w-4xl relative z-10">
          <div
            className="relative p-10 md:p-16 lg:p-20 rounded-[2.5rem] border text-center overflow-hidden"
            style={{
              background: `linear-gradient(to bottom, ${LANDING_COLORS.surface}CC, ${LANDING_COLORS.bg}CC)`,
              borderColor: `${LANDING_COLORS.border}60`,
            }}
          >
            <GradientMesh variant="cta" />

            <div
              className="absolute inset-0 pointer-events-none"
              style={{
                backgroundImage: `radial-gradient(${LANDING_COLORS.accent} 1px, transparent 1px)`,
                backgroundSize: "40px 40px",
                opacity: 0.03,
              }}
            />

            <div className="relative z-10 space-y-6">
              <h2
                className="text-3xl sm:text-4xl md:text-5xl font-black tracking-tight leading-[1.1]"
                style={{ color: LANDING_COLORS.textPrimary }}
              >
                Want{" "}
                <span className="bg-gradient-to-r from-indigo-400 via-violet-400 to-purple-400 bg-clip-text text-transparent">
                  permanent
                </span>{" "}
                encrypted storage?
              </h2>
              <p
                className="text-lg font-light max-w-lg mx-auto leading-relaxed"
                style={{ color: LANDING_COLORS.textSecondary }}
              >
                Get 5 GB free — your files are encrypted before they leave your device. Not even we can see them.
              </p>

              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
                <MagneticButton as="a" href="/auth/register?ref=send" size="lg" variant="primary">
                  Create free account
                  <ArrowRight className="w-5 h-5" />
                </MagneticButton>
                <MagneticButton as="a" href="/" size="lg" variant="secondary">
                  Learn more
                </MagneticButton>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-6 pt-4">
                {[
                  "Quantum-safe protection",
                  "Password never sent to server",
                  "Encrypted filenames",
                  "Zero-knowledge architecture",
                ].map((feature) => (
                  <span
                    key={feature}
                    className="flex items-center gap-1.5 text-xs"
                    style={{ color: LANDING_COLORS.textMuted }}
                  >
                    <Check className="w-3.5 h-3.5 text-emerald-500" />
                    {feature}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════ FOOTER ═══════════ */}
      <footer className="py-8 px-6 border-t" style={{ borderColor: LANDING_COLORS.border }}>
        <div className="container mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-indigo-500" />
            <span className="text-sm font-medium" style={{ color: LANDING_COLORS.textMuted }}>
              StenVault Send
            </span>
          </div>
          <div className="flex items-center gap-6">
            <Link
              to="/send/local"
              className="text-xs transition-colors hover:text-indigo-400"
              style={{ color: LANDING_COLORS.textMuted }}
            >
              LAN Transfer
            </Link>
            <Link
              to="/"
              className="text-xs transition-colors hover:text-indigo-400"
              style={{ color: LANDING_COLORS.textMuted }}
            >
              Home
            </Link>
            <Link
              to="/auth/register"
              className="text-xs transition-colors hover:text-indigo-400"
              style={{ color: LANDING_COLORS.textMuted }}
            >
              Sign up
            </Link>
            <span className="text-xs" style={{ color: LANDING_COLORS.textMuted }}>
              &copy; {new Date().getFullYear()} StenVault
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
