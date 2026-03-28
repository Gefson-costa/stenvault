/**
 * ReceivePage - Premium Encrypted File Download (Receiver)
 *
 * Matches the dark obsidian theme of SendPage.
 * Extracts #key= from URL fragment, fetches preview, decrypts, downloads.
 *
 * Features:
 * - Thumbnail/snippet preview (encrypted, decrypted client-side)
 * - Bundle (zip) indicator with file manifest
 * - Save to Vault CTA (for authenticated users)
 * - Referral tracking (?ref=send)
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { useParams, Link } from "react-router-dom";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { toast } from "sonner";
import {
  fragmentToKey,
  decryptMetadata,
  decryptPublicSendStream,
  decryptThumbnail,
  decryptSnippet,
} from "@/lib/publicSendCrypto";
import { streamDownloadToDisk } from "@/lib/platform/streamingDownload";
import { useSaveToVault } from "@/hooks/useSaveToVault";
import { LANDING_COLORS } from "@/components/landing-v3/constants";
import { GradientMesh } from "@/components/landing-v3/components/GradientMesh";
import { MagneticButton } from "@/components/landing-v3/components/MagneticButton";
import { SpotlightCard } from "@/components/landing-v3/components/SpotlightCard";
import { formatBytes } from "@stenvault/shared";
import { formatSpeed, formatEta } from "@/pages/send/utils";
import {
  Download,
  Shield,
  Lock,
  Clock,
  AlertCircle,
  Check,
  CheckCircle2,
  Loader2,
  ArrowRight,
  FileIcon,
  Eye,
  EyeOff,
  Upload,
  Zap,
  Flag,
  Archive,
  ChevronDown,
  FolderDown,
  Image as ImageIcon,
  FileText,
  Server,
  Reply,
  Link2,
} from "lucide-react";

const ABUSE_REASON_LABELS: Record<string, string> = {
  malware: "Malware / Virus",
  phishing: "Phishing / Scam",
  illegal_content: "Illegal content",
  copyright: "Copyright violation",
  other: "Other",
};

type PageState = "loading" | "preview" | "password" | "downloading" | "decrypting" | "done" | "error" | "missing_key";

function getContextualError(msg: string): string {
  const lower = msg.toLowerCase();
  if (lower.includes('quota') || lower.includes('storage'))
    return 'Storage full \u2014 free up space or upgrade your plan';
  if (lower.includes('network') || lower.includes('fetch') || lower.includes('failed to fetch'))
    return 'Connection lost \u2014 check your internet and try again';
  if (lower.includes('expired') || lower.includes('404') || lower.includes('not found'))
    return 'This link has expired or been removed';
  return msg;
}

export default function ReceivePage() {
  const params = useParams<{ sessionId: string }>();
  const sessionId = params.sessionId || "";
  const { user } = useAuth();
  const isAuthenticated = !!user;
  const {
    saveToVault,
    state: saveState,
    progress: saveProgress,
    error: saveError,
    canSave,
    reset: resetSave,
  } = useSaveToVault();
  const decryptedBlobRef = useRef<Blob | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  /** Max file size for Save to Vault (100MB) — avoids holding huge files in memory */
  const SAVE_TO_VAULT_MAX_SIZE = 100 * 1024 * 1024;

  const [pageState, setPageState] = useState<PageState>("loading");
  const [error, setError] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [progress, setProgress] = useState(0);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileType, setFileType] = useState<string | null>(null);
  const [thumbnailUrl, setThumbnailUrl] = useState<string | null>(null);
  const [snippetText, setSnippetText] = useState<string | null>(null);
  const [isBundle, setIsBundle] = useState(false);
  const [manifest, setManifest] = useState<Array<{ name: string; size: number; type: string }> | null>(null);
  const [showManifest, setShowManifest] = useState(false);
  const [thumbnailFailed, setThumbnailFailed] = useState(false);
  const [keyInput, setKeyInput] = useState("");
  const [keyRetrigger, setKeyRetrigger] = useState(0);
  const keyRef = useRef<CryptoKey | null>(null);

  // Countdown timer
  const [timeRemaining, setTimeRemaining] = useState<string | null>(null);
  const [isExpiringSoon, setIsExpiringSoon] = useState(false);
  const [isExpiringSoonUrgent, setIsExpiringSoonUrgent] = useState(false);

  // Download speed tracking
  const [downloadSpeed, setDownloadSpeed] = useState(0);
  const [downloadEta, setDownloadEta] = useState(0);
  const speedSamplesRef = useRef<Array<{ bytes: number; time: number }>>([]);

  // Report abuse state
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportReason, setReportReason] = useState("malware");
  const [reportDetails, setReportDetails] = useState("");
  const [reportSubmitted, setReportSubmitted] = useState(false);
  const reportMutation = trpc.publicSend.reportAbuse.useMutation();

  // Scroll state for nav
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 20);
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Fetch preview
  const previewQuery = trpc.publicSend.getPreview.useQuery(
    { sessionId },
    { enabled: !!sessionId, retry: false },
  );

  const claimMutation = trpc.publicSend.claimDownload.useMutation();

  // Extract key from fragment and decrypt metadata + thumbnail/snippet
  useEffect(() => {
    if (!previewQuery.data) return;

    const fragment = window.location.hash.replace(/^#key=/, "");
    if (!fragment || fragment === window.location.hash) {
      setPageState("missing_key");
      return;
    }

    (async () => {
      try {
        const key = await fragmentToKey(fragment);
        keyRef.current = key;

        const meta = await decryptMetadata(
          previewQuery.data.encryptedMeta,
          previewQuery.data.metaIv,
          key,
        );
        setFileName(meta.name);
        setFileType(meta.type);
        setIsBundle(meta.isBundle ?? false);
        setManifest(meta.manifest?.files ?? null);

        // Decrypt thumbnail (best-effort)
        if (previewQuery.data.encryptedThumbnail && previewQuery.data.thumbnailIv) {
          try {
            const blob = await decryptThumbnail(
              previewQuery.data.encryptedThumbnail,
              previewQuery.data.thumbnailIv,
              key,
            );
            setThumbnailUrl(URL.createObjectURL(blob));
          } catch (err) {
            console.warn('[ReceivePage] Thumbnail decryption failed:', err);
            setThumbnailFailed(true);
          }
        }

        // Decrypt snippet (best-effort)
        if (previewQuery.data.encryptedSnippet && previewQuery.data.snippetIv) {
          try {
            const text = await decryptSnippet(
              previewQuery.data.encryptedSnippet,
              previewQuery.data.snippetIv,
              key,
            );
            setSnippetText(text);
          } catch (err) {
            console.warn('[ReceivePage] Snippet decryption failed:', err);
          }
        }

        if (previewQuery.data.hasPassword) {
          setPageState("password");
        } else {
          setPageState("preview");
        }
      } catch {
        setError("This link appears damaged — ask the sender to share it again");
        setPageState("error");
      }
    })();
  }, [previewQuery.data, keyRetrigger]);

  // Cleanup thumbnail URL
  useEffect(() => {
    return () => {
      if (thumbnailUrl) URL.revokeObjectURL(thumbnailUrl);
    };
  }, [thumbnailUrl]);

  // Countdown timer
  useEffect(() => {
    const expiresAt = previewQuery.data?.expiresAt;
    if (!expiresAt) return;

    const update = () => {
      const diff = new Date(expiresAt).getTime() - Date.now();
      if (diff <= 0) {
        setTimeRemaining("Expired");
        setIsExpiringSoon(true);
        setIsExpiringSoonUrgent(true);
        return;
      }
      const days = Math.floor(diff / 86400000);
      const hours = Math.floor((diff % 86400000) / 3600000);
      const mins = Math.floor((diff % 3600000) / 60000);
      const secs = Math.floor((diff % 60000) / 1000);

      if (days > 0) setTimeRemaining(`${days}d ${hours}h`);
      else if (hours > 0) setTimeRemaining(`${hours}h ${mins}m`);
      else if (mins > 0) setTimeRemaining(`${mins}m ${secs}s`);
      else setTimeRemaining(`${secs}s`);

      setIsExpiringSoon(diff < 86400000);
      setIsExpiringSoonUrgent(diff < 3600000);
    };
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [previewQuery.data?.expiresAt]);

  useEffect(() => {
    if (previewQuery.error) {
      setError(previewQuery.error.message);
      setPageState("error");
    }
  }, [previewQuery.error]);

  const handleDownload = useCallback(async () => {
    const key = keyRef.current;
    if (!key || !previewQuery.data) return;

    try {
      setPageState("downloading");
      setProgress(0);
      setDownloadSpeed(0);
      setDownloadEta(0);
      speedSamplesRef.current = [];

      const controller = new AbortController();
      abortControllerRef.current = controller;

      const claim = await claimMutation.mutateAsync({
        sessionId,
        ...(password ? { password } : {}),
      });

      const response = await fetch(claim.downloadUrl, { signal: controller.signal });
      if (!response.ok) throw new Error(`Download failed: ${response.status}`);
      if (!response.body) throw new Error("Browser does not support streaming downloads");

      const { fileSize, totalParts, chunkSize, encryptionOverhead } = claim;

      const decryptedStream = decryptPublicSendStream(response.body, {
        key,
        fileSize,
        totalParts,
        chunkSize,
        encryptionOverhead,
        // W3: Pass chunk manifest for integrity verification
        expectedChunkHashes: claim.chunkHashes,
        expectedManifest: claim.chunkManifest,
        // V2: derived chunk IVs (null = V1 legacy with prepended random IVs)
        chunkBaseIv: claim.chunkBaseIv,
        onProgress: (chunkIndex, total) => {
          setProgress(Math.round(((chunkIndex + 1) / total) * 100));
          const now = Date.now();
          const chunkBytes = chunkSize + encryptionOverhead;
          speedSamplesRef.current.push({ bytes: chunkBytes, time: now });
          if (speedSamplesRef.current.length > 5) speedSamplesRef.current.shift();
          const samples = speedSamplesRef.current;
          if (samples.length >= 2) {
            const first = samples[0]!;
            const last = samples[samples.length - 1]!;
            const elapsed = (last.time - first.time) / 1000;
            const totalBytes = samples.reduce((s, v) => s + v.bytes, 0);
            if (elapsed > 0) {
              const bps = totalBytes / elapsed;
              setDownloadSpeed(bps);
              const remaining = (total - chunkIndex - 1) * chunkBytes;
              setDownloadEta(remaining > 0 ? Math.ceil(remaining / bps) : 0);
            }
          }
        },
      });

      // If authenticated and file is small enough, tee the stream to capture
      // the decrypted blob for "Save to Vault" without re-downloading
      const canCapture = isAuthenticated && fileSize <= SAVE_TO_VAULT_MAX_SIZE;

      if (canCapture) {
        const [streamForDisk, streamForVault] = decryptedStream.tee();
        const capturePromise = new Response(streamForVault).blob().then((b) => {
          decryptedBlobRef.current = b;
        });

        await streamDownloadToDisk(streamForDisk, {
          filename: fileName || "download",
          mimeType: fileType || "application/octet-stream",
          totalSize: fileSize,
        });
        await capturePromise;
      } else {
        decryptedBlobRef.current = null;
        await streamDownloadToDisk(decryptedStream, {
          filename: fileName || "download",
          mimeType: fileType || "application/octet-stream",
          totalSize: fileSize,
        });
      }

      setPageState("done");
    } catch (err: any) {
      const msg = err?.message || "Download failed";
      if (msg.includes("Incorrect password")) {
        setError("Incorrect password");
        setPageState("password");
      } else if (err?.name === "AbortError") {
        setPageState(previewQuery.data?.hasPassword ? "password" : "preview");
      } else {
        setError(getContextualError(msg));
        setPageState("error");
      }
    }
  }, [sessionId, password, previewQuery.data, claimMutation, fileName, fileType]);

  const handleReportAbuse = useCallback(async () => {
    try {
      await reportMutation.mutateAsync({
        sessionId,
        reason: reportReason as any,
        details: reportDetails || undefined,
      });
      setReportSubmitted(true);
      setTimeout(() => {
        setShowReportModal(false);
        setReportSubmitted(false);
        setReportReason("malware");
        setReportDetails("");
      }, 2000);
    } catch (err: any) {
      toast.error(err?.message || "Failed to submit report");
    }
  }, [sessionId, reportReason, reportDetails, reportMutation]);

  const previewData = previewQuery.data;
  const isProcessing = pageState === "downloading" || pageState === "decrypting";

  // File icon component based on thumbnail/type
  const FilePreviewIcon = () => {
    if (thumbnailUrl) {
      return (
        <img
          src={thumbnailUrl}
          alt="Preview"
          className="w-14 h-14 rounded-2xl object-cover"
        />
      );
    }
    if (thumbnailFailed) {
      return (
        <div
          className="w-14 h-14 rounded-2xl flex flex-col items-center justify-center shrink-0"
          style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
        >
          <ImageIcon className="w-5 h-5 text-indigo-400/50" />
          <span className="text-[8px] mt-0.5" style={{ color: LANDING_COLORS.textMuted }}>
            No preview
          </span>
        </div>
      );
    }
    const IconComponent = isBundle ? Archive : FileIcon;
    return (
      <div
        className="w-14 h-14 rounded-2xl flex items-center justify-center shrink-0"
        style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
      >
        <IconComponent className="w-7 h-7 text-indigo-400" />
      </div>
    );
  };

  return (
    <div className="min-h-screen" style={{ backgroundColor: LANDING_COLORS.bg }}>
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
          <Link to="/" className="flex items-center gap-2">
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
          <MagneticButton as="a" href="/send?ref=send" size="sm" variant="primary">
            <Upload className="w-4 h-4" />
            Send a file
          </MagneticButton>
        </div>
      </nav>

      {/* ═══════════ MAIN CONTENT ═══════════ */}
      <section className="relative min-h-screen flex items-center justify-center pt-24 pb-16 overflow-hidden">
        <GradientMesh variant="default" />

        <div className="container mx-auto px-6 relative z-10">
          <div className="max-w-md mx-auto">
            {/* Trust Badge */}
            <div className="flex justify-center mb-6">
              <div
                className="inline-flex items-center gap-2 px-4 py-2 rounded-full border backdrop-blur-sm"
                style={{
                  borderColor: `${LANDING_COLORS.success}30`,
                  backgroundColor: `${LANDING_COLORS.success}08`,
                }}
              >
                <Lock className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-xs font-semibold text-emerald-300">
                  End-to-end encrypted
                </span>
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              </div>
            </div>

            <h1
              className="text-2xl sm:text-3xl font-black text-center tracking-tight leading-[1.1] mb-2"
              style={{ color: LANDING_COLORS.textPrimary }}
            >
              Encrypted File
            </h1>
            <p
              className="text-sm text-center mb-8"
              style={{ color: LANDING_COLORS.textSecondary }}
            >
              Only you and the sender can see this file
            </p>

            {/* ═══════════ CARD ═══════════ */}
            <div
              className="rounded-2xl border overflow-hidden backdrop-blur-xl"
              style={{
                backgroundColor: `${LANDING_COLORS.surface}B3`,
                borderColor: LANDING_COLORS.border,
              }}
            >
              <div className="p-6 sm:p-8">
                {/* ── LOADING ── */}
                {pageState === "loading" && (
                  <div className="flex flex-col items-center gap-4 py-12">
                    <div className="relative w-14 h-14">
                      <div
                        className="absolute inset-0 rounded-full animate-ping opacity-20"
                        style={{ backgroundColor: LANDING_COLORS.accent }}
                      />
                      <div
                        className="relative w-14 h-14 rounded-full flex items-center justify-center"
                        style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
                      >
                        <Loader2 className="w-7 h-7 animate-spin text-indigo-400" />
                      </div>
                    </div>
                    <p className="text-sm" style={{ color: LANDING_COLORS.textSecondary }}>
                      Loading file info...
                    </p>
                  </div>
                )}

                {/* ── MISSING KEY ── */}
                {pageState === "missing_key" && (
                  <div className="space-y-6 py-4">
                    <div className="text-center space-y-3">
                      <div
                        className="w-16 h-16 rounded-full flex items-center justify-center mx-auto"
                        style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
                      >
                        <Lock className="w-8 h-8 text-indigo-400" />
                      </div>
                      <p className="font-semibold text-lg" style={{ color: LANDING_COLORS.textPrimary }}>
                        Missing decryption key
                      </p>
                      <p className="text-sm" style={{ color: LANDING_COLORS.textSecondary }}>
                        Paste the full link or the key fragment below
                      </p>
                    </div>

                    <div className="space-y-3">
                      <input
                        type="text"
                        placeholder="Paste full link or key fragment"
                        value={keyInput}
                        onChange={(e) => setKeyInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && keyInput.trim()) {
                            const val = keyInput.trim();
                            const keyMatch = val.match(/#key=(.+)$/);
                            const extracted = keyMatch ? keyMatch[1] : val;
                            window.location.hash = `#key=${extracted}`;
                            setPageState("loading");
                            setKeyRetrigger((v) => v + 1);
                          }
                        }}
                        className="w-full h-10 rounded-lg border px-3 text-sm outline-none transition-colors focus:ring-1"
                        style={{
                          backgroundColor: LANDING_COLORS.bg,
                          borderColor: LANDING_COLORS.border,
                          color: LANDING_COLORS.textPrimary,
                        }}
                      />
                      <MagneticButton
                        size="lg"
                        variant="primary"
                        className="w-full"
                        disabled={!keyInput.trim()}
                        onClick={() => {
                          const val = keyInput.trim();
                          const keyMatch = val.match(/#key=(.+)$/);
                          const extracted = keyMatch ? keyMatch[1] : val;
                          window.location.hash = `#key=${extracted}`;
                          setPageState("loading");
                          setKeyRetrigger((v) => v + 1);
                        }}
                      >
                        <Lock className="w-5 h-5" />
                        Decrypt
                      </MagneticButton>
                    </div>
                  </div>
                )}

                {/* ── PREVIEW ── */}
                {pageState === "preview" && previewData && (
                  <div className="space-y-6">
                    {/* File info */}
                    <div className="flex items-center gap-4">
                      <FilePreviewIcon />
                      <div className="min-w-0">
                        <p
                          className="font-semibold truncate"
                          style={{ color: LANDING_COLORS.textPrimary }}
                        >
                          {fileName || "Encrypted file"}
                        </p>
                        <p className="text-sm" style={{ color: LANDING_COLORS.textSecondary }}>
                          {formatBytes(previewData.fileSize)}
                        </p>
                      </div>
                    </div>

                    {/* Thumbnail preview (full-width) */}
                    {thumbnailUrl && (
                      <div className="rounded-xl overflow-hidden border" style={{ borderColor: LANDING_COLORS.border }}>
                        <img
                          src={thumbnailUrl}
                          alt="File preview"
                          className="w-full max-h-48 object-cover"
                        />
                      </div>
                    )}

                    {/* Text snippet preview */}
                    {snippetText && !thumbnailUrl && (
                      <div
                        className="rounded-xl p-4 border"
                        style={{
                          backgroundColor: LANDING_COLORS.bg,
                          borderColor: LANDING_COLORS.border,
                        }}
                      >
                        <div className="flex items-center gap-2 mb-2">
                          <FileText className="w-3.5 h-3.5 text-indigo-400" />
                          <span className="text-xs font-medium" style={{ color: LANDING_COLORS.textMuted }}>
                            Preview
                          </span>
                        </div>
                        <pre
                          className="text-xs leading-relaxed whitespace-pre-wrap break-words max-h-32 overflow-y-auto font-mono"
                          style={{ color: LANDING_COLORS.textSecondary }}
                        >
                          {snippetText}
                        </pre>
                      </div>
                    )}

                    {/* Bundle manifest */}
                    {isBundle && manifest && manifest.length > 0 && (
                      <div>
                        <button
                          onClick={() => setShowManifest(!showManifest)}
                          className="flex items-center gap-2 text-xs font-medium cursor-pointer transition-colors hover:text-indigo-300"
                          style={{ color: LANDING_COLORS.textSecondary }}
                        >
                          <Archive className="w-3.5 h-3.5 text-indigo-400" />
                          ZIP archive · {manifest.length} files
                          <ChevronDown
                            className={`w-3.5 h-3.5 transition-transform ${showManifest ? "rotate-180" : ""}`}
                          />
                        </button>
                        {showManifest && (
                          <div
                            className="mt-2 rounded-lg border overflow-hidden"
                            style={{ borderColor: LANDING_COLORS.border }}
                          >
                            {manifest.map((f, i) => (
                              <div
                                key={i}
                                className="flex items-center justify-between px-3 py-2 text-xs"
                                style={{
                                  backgroundColor: i % 2 === 0 ? "transparent" : `${LANDING_COLORS.bg}40`,
                                }}
                              >
                                <span className="truncate" style={{ color: LANDING_COLORS.textPrimary }}>
                                  {f.name}
                                </span>
                                <span className="shrink-0 ml-2" style={{ color: LANDING_COLORS.textMuted }}>
                                  {formatBytes(f.size)}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Expiry warning */}
                    {isExpiringSoonUrgent && (
                      <div
                        className="flex items-center gap-2.5 p-3 rounded-xl text-sm font-medium"
                        style={{
                          backgroundColor: `${LANDING_COLORS.danger}10`,
                          color: LANDING_COLORS.danger,
                        }}
                      >
                        <AlertCircle className="w-4 h-4 shrink-0" />
                        This link expires soon — download now
                      </div>
                    )}

                    {/* Badges */}
                    <div className="flex flex-wrap gap-2">
                      <span
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium"
                        style={{
                          backgroundColor: isExpiringSoonUrgent
                            ? `${LANDING_COLORS.danger}10`
                            : isExpiringSoon
                              ? '#78350f15'
                              : `${LANDING_COLORS.accent}10`,
                          color: isExpiringSoonUrgent
                            ? LANDING_COLORS.danger
                            : isExpiringSoon
                              ? '#fbbf24'
                              : LANDING_COLORS.textSecondary,
                        }}
                      >
                        <Clock className="w-3.5 h-3.5" />
                        {timeRemaining ? `Expires in ${timeRemaining}` : `Expires ${new Date(previewData.expiresAt).toLocaleDateString()}`}
                      </span>
                      {previewData.downloadsRemaining !== null && (
                        <span
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium"
                          style={{
                            backgroundColor: `${LANDING_COLORS.accent}10`,
                            color: LANDING_COLORS.textSecondary,
                          }}
                        >
                          <Download className="w-3.5 h-3.5 text-indigo-400" />
                          {previewData.downloadsRemaining} downloads left
                        </span>
                      )}
                      <span
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium"
                        style={{
                          backgroundColor: `${LANDING_COLORS.success}10`,
                          color: LANDING_COLORS.success,
                        }}
                      >
                        <Shield className="w-3.5 h-3.5" />
                        Encrypted
                      </span>
                    </div>

                    <MagneticButton
                      size="lg"
                      variant="primary"
                      className="w-full"
                      onClick={handleDownload}
                    >
                      <Download className="w-5 h-5" />
                      Download & Decrypt
                    </MagneticButton>
                    {isAuthenticated && previewData.fileSize > 100 * 1024 * 1024 && (
                      <p className="text-xs text-center" style={{ color: LANDING_COLORS.textMuted }}>
                        Files over 100 MB can be downloaded but not saved directly to your vault.
                      </p>
                    )}
                  </div>
                )}

                {/* ── PASSWORD ── */}
                {pageState === "password" && (
                  <div className="space-y-6">
                    <div className="flex items-center gap-4">
                      <FilePreviewIcon />
                      <div className="min-w-0">
                        <p
                          className="font-semibold truncate"
                          style={{ color: LANDING_COLORS.textPrimary }}
                        >
                          {fileName || "Encrypted file"}
                        </p>
                        <p className="text-sm" style={{ color: LANDING_COLORS.textSecondary }}>
                          {previewData ? formatBytes(previewData.fileSize) : ""}
                        </p>
                      </div>
                    </div>

                    {error && (
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

                    <div className="space-y-2">
                      <label
                        htmlFor="receive-file-password"
                        className="text-xs font-medium"
                        style={{ color: LANDING_COLORS.textSecondary }}
                      >
                        This file is password protected
                      </label>
                      <div className="relative">
                        <input
                          id="receive-file-password"
                          type={showPassword ? "text" : "password"}
                          placeholder="Enter password"
                          value={password}
                          onChange={(e) => {
                            setPassword(e.target.value);
                            setError(null);
                          }}
                          onKeyDown={(e) => e.key === "Enter" && handleDownload()}
                          required
                          aria-required="true"
                          aria-label="File password"
                          className="w-full h-10 rounded-lg border px-3 pr-10 text-sm outline-none transition-colors focus:ring-1"
                          style={{
                            backgroundColor: LANDING_COLORS.bg,
                            borderColor: LANDING_COLORS.border,
                            color: LANDING_COLORS.textPrimary,
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

                    <MagneticButton
                      size="lg"
                      variant="primary"
                      className="w-full"
                      onClick={handleDownload}
                      disabled={!password}
                    >
                      <Download className="w-5 h-5" />
                      Download & Decrypt
                    </MagneticButton>
                  </div>
                )}

                {/* ── DOWNLOADING / DECRYPTING ── */}
                {isProcessing && (
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
                        Downloading & decrypting...
                      </p>
                      <p className="text-sm" style={{ color: LANDING_COLORS.textMuted }}>
                        Decryption happens entirely in your browser
                      </p>
                    </div>

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
                      <p
                        className="text-center text-sm font-medium"
                        style={{ color: LANDING_COLORS.textSecondary }}
                      >
                        {progress}%
                        {downloadSpeed > 0 && (
                          <span className="ml-2 text-xs" style={{ color: LANDING_COLORS.textMuted }}>
                            {formatSpeed(downloadSpeed)}
                            {downloadEta > 0 && ` · ${formatEta(downloadEta)}`}
                          </span>
                        )}
                      </p>
                    </div>

                    <button
                      onClick={() => abortControllerRef.current?.abort()}
                      className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border text-sm font-medium transition-colors cursor-pointer"
                      style={{
                        borderColor: LANDING_COLORS.border,
                        color: LANDING_COLORS.textSecondary,
                        backgroundColor: "transparent",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = LANDING_COLORS.surface)}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
                    >
                      Cancel
                    </button>
                  </div>
                )}

                {/* ── DONE ── */}
                {pageState === "done" && (
                  <div className="space-y-6 py-4">
                    <div className="text-center space-y-3">
                      <div
                        className="w-16 h-16 rounded-full flex items-center justify-center mx-auto"
                        style={{ backgroundColor: `${LANDING_COLORS.success}15` }}
                      >
                        <Check className="w-8 h-8" style={{ color: LANDING_COLORS.success }} />
                      </div>
                      <p className="font-semibold text-lg" style={{ color: LANDING_COLORS.textPrimary }}>
                        File decrypted & saved
                      </p>
                      <p className="text-sm" style={{ color: LANDING_COLORS.textSecondary }}>
                        {fileName}
                      </p>
                    </div>

                    {/* Save to Vault — authenticated users with captured blob */}
                    {isAuthenticated && decryptedBlobRef.current && canSave && saveState === 'idle' && (
                      <MagneticButton
                        size="lg"
                        variant="primary"
                        className="w-full"
                        onClick={async () => {
                          const blob = decryptedBlobRef.current;
                          if (!blob) return;
                          const ok = await saveToVault(blob, fileName || "download", fileType || "application/octet-stream");
                          if (ok) {
                            toast.success("File saved to your vault");
                            decryptedBlobRef.current = null;
                          }
                        }}
                      >
                        <FolderDown className="w-5 h-5" />
                        Save to Vault
                      </MagneticButton>
                    )}

                    {/* Save to Vault — too large (>100MB, blob not captured) */}
                    {isAuthenticated && !decryptedBlobRef.current && canSave && saveState === 'idle' && (
                      <div
                        className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-medium"
                        style={{ color: LANDING_COLORS.textMuted }}
                        title="Files over 100 MB must be downloaded directly"
                      >
                        <FolderDown className="w-5 h-5 opacity-40" />
                        <span className="opacity-60">Save to Vault</span>
                        <span
                          className="text-[10px] px-1.5 py-0.5 rounded ml-1"
                          style={{ backgroundColor: `${LANDING_COLORS.surface}`, color: LANDING_COLORS.textMuted }}
                        >
                          100 MB max
                        </span>
                      </div>
                    )}

                    {/* Save to Vault — progress */}
                    {isAuthenticated && saveState !== 'idle' && saveState !== 'done' && saveState !== 'error' && (
                      <div className="space-y-3">
                        <div className="flex items-center justify-center gap-2 text-sm font-medium" style={{ color: LANDING_COLORS.textPrimary }}>
                          <Loader2 className="w-4 h-4 animate-spin text-indigo-400" />
                          {saveState === 'encrypting' ? 'Encrypting for your vault...' : saveState === 'uploading' ? 'Uploading to vault...' : 'Confirming...'}
                        </div>
                        <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}>
                          <div
                            className="h-full rounded-full transition-all duration-300 ease-out"
                            style={{ width: `${saveProgress}%`, background: `linear-gradient(90deg, ${LANDING_COLORS.accent}, #A78BFA)` }}
                          />
                        </div>
                      </div>
                    )}

                    {/* Save to Vault — done */}
                    {isAuthenticated && saveState === 'done' && (
                      <div className="space-y-2">
                        <div className="flex items-center justify-center gap-2 py-2.5 text-sm font-medium" style={{ color: LANDING_COLORS.success }}>
                          <Check className="w-4 h-4" />
                          Saved to your vault
                        </div>
                        <Link
                          to="/drive"
                          className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border text-sm font-medium transition-colors"
                          style={{
                            borderColor: LANDING_COLORS.border,
                            color: LANDING_COLORS.textSecondary,
                            backgroundColor: "transparent",
                          }}
                          onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = LANDING_COLORS.surface)}
                          onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
                        >
                          Go to Dashboard
                          <ArrowRight className="w-4 h-4" />
                        </Link>
                      </div>
                    )}

                    {/* Save to Vault — error */}
                    {isAuthenticated && saveState === 'error' && (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2 p-3 rounded-xl text-xs" style={{ backgroundColor: `${LANDING_COLORS.danger}10`, color: LANDING_COLORS.danger }}>
                          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                          {saveError || 'Failed to save'}
                        </div>
                        <button
                          onClick={resetSave}
                          className="w-full text-center text-xs font-medium cursor-pointer transition-colors hover:text-indigo-400"
                          style={{ color: LANDING_COLORS.textMuted }}
                        >
                          Try again
                        </button>
                      </div>
                    )}

                    <button
                      onClick={handleDownload}
                      className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border text-sm font-medium transition-colors cursor-pointer"
                      style={{
                        borderColor: LANDING_COLORS.border,
                        color: LANDING_COLORS.textSecondary,
                        backgroundColor: "transparent",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = LANDING_COLORS.surface)}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
                    >
                      <Download className="w-4 h-4" />
                      Download again
                    </button>
                  </div>
                )}

                {/* ── ERROR ── */}
                {pageState === "error" && (
                  <div className="space-y-4 py-8">
                    <div className="text-center space-y-3">
                      <div
                        className="w-16 h-16 rounded-full flex items-center justify-center mx-auto"
                        style={{ backgroundColor: `${LANDING_COLORS.danger}15` }}
                      >
                        <AlertCircle className="w-8 h-8" style={{ color: LANDING_COLORS.danger }} />
                      </div>
                      <p className="font-semibold text-lg" style={{ color: LANDING_COLORS.textPrimary }}>
                        Unable to access file
                      </p>
                      <p className="text-sm" style={{ color: LANDING_COLORS.textSecondary }}>
                        {error}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── REPORT ABUSE ── */}
                {pageState !== "loading" && (
                  <div
                    className="mt-4 pt-4 border-t"
                    style={{ borderColor: LANDING_COLORS.border }}
                  >
                    {!showReportModal ? (
                      <button
                        onClick={() => setShowReportModal(true)}
                        className="flex items-center gap-1.5 text-xs transition-colors cursor-pointer hover:text-red-400"
                        style={{ color: LANDING_COLORS.textMuted }}
                      >
                        <Flag className="w-3.5 h-3.5" />
                        Report abuse
                      </button>
                    ) : reportSubmitted ? (
                      <div className="flex items-center justify-center gap-2 py-4">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <p className="text-sm font-medium text-emerald-400">
                          Report submitted. Thank you.
                        </p>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        <p
                          className="text-xs font-medium"
                          style={{ color: LANDING_COLORS.textSecondary }}
                        >
                          Why are you reporting this file?
                        </p>
                        <select
                          value={reportReason}
                          onChange={(e) => setReportReason(e.target.value)}
                          className="w-full h-9 rounded-lg border px-3 text-sm outline-none cursor-pointer"
                          style={{
                            backgroundColor: LANDING_COLORS.bg,
                            borderColor: LANDING_COLORS.border,
                            color: LANDING_COLORS.textPrimary,
                          }}
                        >
                          {Object.entries(ABUSE_REASON_LABELS).map(([value, label]) => (
                            <option key={value} value={value}>
                              {label}
                            </option>
                          ))}
                        </select>
                        <textarea
                          placeholder="Additional details (optional)"
                          maxLength={500}
                          value={reportDetails}
                          onChange={(e) => setReportDetails(e.target.value)}
                          className="w-full h-20 rounded-lg border px-3 py-2 text-sm outline-none resize-none"
                          style={{
                            backgroundColor: LANDING_COLORS.bg,
                            borderColor: LANDING_COLORS.border,
                            color: LANDING_COLORS.textPrimary,
                          }}
                        />
                        <div className="flex gap-2">
                          <button
                            onClick={handleReportAbuse}
                            disabled={reportMutation.isPending}
                            className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer"
                            style={{
                              backgroundColor: `${LANDING_COLORS.danger}15`,
                              color: LANDING_COLORS.danger,
                            }}
                          >
                            {reportMutation.isPending ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Flag className="w-3.5 h-3.5" />
                            )}
                            Submit report
                          </button>
                          <button
                            onClick={() => setShowReportModal(false)}
                            className="px-4 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer"
                            style={{
                              color: LANDING_COLORS.textMuted,
                              backgroundColor: "transparent",
                            }}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* ═══════════ VIRAL CTAs (always visible) ═══════════ */}
            {pageState !== "loading" && (
              <div className="mt-8 space-y-4">
                {/* Reply with a file */}
                <a
                  href={`/send?reply=${sessionId}`}
                  className="flex items-center gap-3 p-4 rounded-xl border transition-all hover:scale-[1.01]"
                  style={{
                    borderColor: `${LANDING_COLORS.accent}30`,
                    backgroundColor: `${LANDING_COLORS.accent}08`,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = `${LANDING_COLORS.accent}60`;
                    e.currentTarget.style.backgroundColor = `${LANDING_COLORS.accent}12`;
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = `${LANDING_COLORS.accent}30`;
                    e.currentTarget.style.backgroundColor = `${LANDING_COLORS.accent}08`;
                  }}
                >
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
                    style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
                  >
                    <Reply className="w-5 h-5 text-indigo-400" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold" style={{ color: LANDING_COLORS.textPrimary }}>
                      Reply with a file
                    </p>
                    <p className="text-xs" style={{ color: LANDING_COLORS.textSecondary }}>
                      Send an encrypted file back
                    </p>
                  </div>
                  <ArrowRight className="w-4 h-4 ml-auto shrink-0 text-indigo-400" />
                </a>

                {/* Transfer locally (LAN) */}
                <Link
                  to="/send/local"
                  className="flex items-center gap-3 p-4 rounded-xl border transition-all hover:scale-[1.01] group"
                  style={{
                    borderColor: `${LANDING_COLORS.success}25`,
                    backgroundColor: `${LANDING_COLORS.success}06`,
                  }}
                >
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
                    style={{ backgroundColor: `${LANDING_COLORS.success}12` }}
                  >
                    <Zap className="w-5 h-5 text-emerald-400" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold" style={{ color: LANDING_COLORS.textPrimary }}>
                      On the same WiFi?{" "}
                      <span className="text-emerald-400">Transfer directly</span>
                    </p>
                    <p className="text-xs" style={{ color: LANDING_COLORS.textSecondary }}>
                      Device-to-device · LAN speed · Zero cloud
                    </p>
                  </div>
                  <ArrowRight className="w-4 h-4 ml-auto shrink-0 text-emerald-400 transition-transform group-hover:translate-x-0.5" />
                </Link>

                {/* Send your own files */}
                <SpotlightCard variant="glass" tilt spotlightColor={LANDING_COLORS.accent}>
                  <div className="p-5 sm:p-6 space-y-4 text-center">
                    <div
                      className="w-10 h-10 rounded-lg flex items-center justify-center mx-auto"
                      style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
                    >
                      <Zap className="w-5 h-5 text-indigo-400" />
                    </div>
                    <div>
                      <h3
                        className="text-base font-bold"
                        style={{ color: LANDING_COLORS.textPrimary }}
                      >
                        Want to send your own files?
                      </h3>
                      <p className="text-xs mt-1" style={{ color: LANDING_COLORS.textSecondary }}>
                        Free &middot; Encrypted &middot; No account required
                      </p>
                    </div>
                    <div className="flex flex-col sm:flex-row gap-2.5">
                      <MagneticButton as="a" href="/send?ref=receive" size="sm" variant="primary" className="flex-1">
                        <Upload className="w-4 h-4" />
                        Send Files Now
                      </MagneticButton>
                      {!isAuthenticated && (
                        <MagneticButton as="a" href="/auth/register?ref=send" size="sm" variant="secondary" className="flex-1">
                          <div className="text-center">
                            <div>Keep your files truly private</div>
                            <div className="text-[10px] opacity-70 font-normal">5 GB free, no credit card</div>
                          </div>
                        </MagneticButton>
                      )}
                    </div>
                  </div>
                </SpotlightCard>
              </div>
            )}

            {/* ═══════════ HOW IT WORKS (compact) ═══════════ */}
            {pageState !== "loading" && (
              <div
                className="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-3"
              >
                {[
                  { icon: Lock, label: "Encrypted in your browser" },
                  { icon: Link2, label: "Key never leaves the URL" },
                  { icon: Server, label: "Server sees only bytes" },
                ].map(({ icon: Icon, label }, i) => (
                  <div
                    key={label}
                    className="flex items-center gap-2 px-3 py-2.5 rounded-lg"
                    style={{ backgroundColor: `${LANDING_COLORS.surface}80` }}
                  >
                    <div
                      className="w-6 h-6 rounded flex items-center justify-center shrink-0"
                      style={{ backgroundColor: `${LANDING_COLORS.accent}10` }}
                    >
                      <Icon className="w-3.5 h-3.5 text-indigo-400" />
                    </div>
                    <span
                      className="text-xs font-medium"
                      style={{ color: LANDING_COLORS.textMuted }}
                    >
                      {label}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* ═══════════ FOOTER ═══════════ */}
      <footer className="py-8 px-6 border-t" style={{ borderColor: LANDING_COLORS.border }}>
        <div className="container mx-auto space-y-4">
          {/* Powered by badge */}
          <div className="flex justify-center">
            <div
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full border"
              style={{
                borderColor: LANDING_COLORS.border,
                backgroundColor: `${LANDING_COLORS.surface}60`,
              }}
            >
              <Shield className="w-3.5 h-3.5 text-indigo-500" />
              <span className="text-xs font-medium" style={{ color: LANDING_COLORS.textSecondary }}>
                Powered by <span className="text-indigo-400 font-semibold">StenVault</span> — Zero-Knowledge Encrypted
              </span>
            </div>
          </div>
          {/* Links */}
          <div className="flex items-center justify-center gap-6">
            <Link
              to="/send?ref=send"
              className="text-xs transition-colors hover:text-indigo-400"
              style={{ color: LANDING_COLORS.textMuted }}
            >
              Send a file
            </Link>
            <Link
              to="/send/local"
              className="text-xs transition-colors hover:text-emerald-400"
              style={{ color: LANDING_COLORS.textMuted }}
            >
              LAN Transfer
            </Link>
            <Link
              to="/auth/register?ref=send"
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
