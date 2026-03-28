/**
 * LocalSendPage — LAN Device-to-Device Transfer
 *
 * AirDrop-like experience in the browser. Zero cloud, zero cost, E2E encrypted.
 * Uses SSE for discovery + tRPC mutations for actions + WebRTC DataChannel for data.
 *
 * States: idle -> send | receive
 *   Send:    file drop zone (multi-file) + receiver list + transfer progress
 *   Receive: waiting animation + incoming request dialog + progress
 */

import { useState, useRef, useCallback, useEffect } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { LANDING_COLORS } from "@/components/landing-v3/constants";
import { GradientMesh } from "@/components/landing-v3/components/GradientMesh";
import { MagneticButton } from "@/components/landing-v3/components/MagneticButton";
import { formatBytes } from "@stenvault/shared";
import { trpc } from "@/lib/trpc";
import {
  useLocalSSE,
  type TransferRequest,
  type SignalData,
} from "@/hooks/useLocalSSE";
import { useLocalTransfer } from "@/hooks/useLocalTransfer";
import {
  Wifi,
  Upload,
  Download,
  Shield,
  ArrowLeft,
  ArrowRight,
  Check,
  X,
  Loader2,
  Globe,
  FileIcon,
  Zap,
  ShieldCheck,
  Lock,
} from "lucide-react";

import type { PageMode } from "./local-send/utils";
import { getDeviceIcon, isSafari, TWO_GB } from "./local-send/utils";
import { SafariWarning } from "./local-send/SafariWarning";
import { RoomCodeSection } from "./local-send/RoomCodeSection";
import { ResumableTransfersSection } from "./local-send/ResumableTransfersSection";
import { TransferProgressDisplay } from "./local-send/TransferProgressDisplay";

// ═══════════════════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════════════════

export default function LocalSendPage() {
  const [mode, setMode] = useState<PageMode>("idle");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [incomingRequest, setIncomingRequest] = useState<TransferRequest | null>(null);
  const [safariDismissed, setSafariDismissed] = useState(false);
  const [reRegisterKey, setReRegisterKey] = useState(0);
  const [showCancelConfirm, setShowCancelConfirm] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Scroll state for nav
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 20);
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Transfer hook
  const transfer = useLocalTransfer();

  // Re-register as receiver after transfer resets
  useEffect(() => {
    transfer.onReset.current = () => {
      if (mode === "receive") {
        setReRegisterKey((k) => k + 1);
      }
    };
    return () => {
      transfer.onReset.current = null;
    };
  }, [transfer, mode]);

  // SSE hook with callbacks
  const sse = useLocalSSE({
    onTransferRequest: (req) => {
      setIncomingRequest(req);
    },
    onTransferAccepted: (sessionId) => {
      transfer.handleSignal({
        sessionId,
        peerId: "",
        type: "offer",
        data: "",
      });
    },
    onTransferRejected: () => {
      toast.info("Transfer declined by receiver");
      transfer.reset();
      setSelectedFiles([]);
    },
    onTransferCancelled: (sessionId) => {
      transfer.handleTransferCancelled(sessionId);
      setIncomingRequest(null);
      toast.info("Transfer cancelled by peer");
    },
    onPeerLeft: (leftPeerId) => {
      // If the sender who sent us a request just left, clear the request
      if (incomingRequest?.senderId === leftPeerId) {
        setIncomingRequest(null);
        toast.info("Sender disconnected");
      }
    },
    onSignal: (signal: SignalData) => {
      transfer.handleSignal(signal);
    },
  });

  const totalSelectedSize = selectedFiles.reduce((sum, f) => sum + f.size, 0);
  const showSafariWarning = isSafari() && totalSelectedSize > TWO_GB && !safariDismissed;

  // Safari warning for incoming request (receiver side)
  const incomingTotalSize = incomingRequest
    ? incomingRequest.files.reduce((sum, f) => sum + f.size, 0)
    : 0;
  const showReceiverSafariWarning = isSafari() && incomingTotalSize > TWO_GB;

  // --- File selection (multi-file) ---
  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = e.target.files;
      if (files && files.length > 0) {
        setSelectedFiles((prev) => [...prev, ...Array.from(files)]);
      }
      // Reset input so same file can be selected again
      e.target.value = "";
    },
    [],
  );

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      setSelectedFiles((prev) => [...prev, ...Array.from(files)]);
    }
  }, []);

  const handleRemoveFile = useCallback((index: number) => {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
  }, []);

  // --- Send to receiver ---
  const handleSendTo = useCallback(
    (receiverId: string) => {
      if (selectedFiles.length === 0 || !sse.peerId) return;
      transfer.sendToReceiver(receiverId, selectedFiles, sse.peerId);
    },
    [selectedFiles, sse.peerId, transfer],
  );

  // --- Accept/Reject incoming ---
  const handleAccept = useCallback(() => {
    if (!incomingRequest || !sse.peerId) return;
    transfer.acceptTransfer(incomingRequest, sse.peerId);
    setIncomingRequest(null);
  }, [incomingRequest, sse.peerId, transfer]);

  const handleReject = useCallback(() => {
    if (!incomingRequest) return;
    transfer.rejectTransfer(incomingRequest.sessionId);
    setIncomingRequest(null);
  }, [incomingRequest, transfer]);

  const isTransferActive =
    transfer.state === "transferring" ||
    transfer.state === "connecting" ||
    transfer.state === "requesting" ||
    transfer.state === "waiting_accept";

  // --- Back to idle ---
  const handleBack = useCallback(() => {
    if (isTransferActive) {
      transfer.cancelTransfer();
    } else {
      transfer.reset();
    }
    setSelectedFiles([]);
    setIncomingRequest(null);
    setSafariDismissed(false);
    setShowCancelConfirm(false);
    setMode("idle");
  }, [transfer, isTransferActive]);

  // ═══════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════

  return (
    <div className="min-h-screen" style={{ backgroundColor: LANDING_COLORS.bg }}>
      {/* =========== NAVIGATION =========== */}
      <nav
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          isScrolled ? "py-3 border-b" : "py-4"
        }`}
        style={{
          backgroundColor: isScrolled ? `${LANDING_COLORS.bg}E6` : "transparent",
          borderColor: isScrolled ? `${LANDING_COLORS.border}40` : "transparent",
          backdropFilter: isScrolled ? "blur(16px)" : "none",
        }}
      >
        <div className="container mx-auto px-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            {mode !== "idle" && (
              <button
                onClick={() => {
                  if (transfer.state === "transferring") {
                    setShowCancelConfirm(true);
                  } else {
                    handleBack();
                  }
                }}
                className="p-1.5 rounded-lg transition-colors hover:bg-white/5 cursor-pointer"
                style={{ color: LANDING_COLORS.textSecondary }}
              >
                <ArrowLeft className="w-4 h-4" />
              </button>
            )}
            <Link to="/send" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
              <Shield className="w-6 h-6 text-indigo-500" />
              <span className="text-lg font-bold" style={{ color: LANDING_COLORS.textPrimary }}>
                Sten<span className="text-indigo-500">Vault</span>
              </span>
              <span
                className="text-xs font-medium px-2 py-0.5 rounded-full"
                style={{
                  backgroundColor: `${LANDING_COLORS.success}15`,
                  color: LANDING_COLORS.success,
                }}
              >
                Local
              </span>
            </Link>
          </div>
          <div className="flex items-center gap-3">
            <Link
              to="/send"
              className="hidden sm:inline-flex items-center gap-1.5 text-sm font-medium transition-colors hover:text-indigo-400"
              style={{ color: LANDING_COLORS.textSecondary }}
            >
              <Upload className="w-3.5 h-3.5" />
              Cloud Send
            </Link>
            <span
              className={`inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full border ${
                sse.connected
                  ? "border-emerald-500/20 bg-emerald-500/8 text-emerald-400"
                  : "border-amber-500/20 bg-amber-500/8 text-amber-400"
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  sse.connected ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
                }`}
              />
              {sse.connected ? "Connected" : sse.error ? "Reconnecting..." : "Connecting..."}
            </span>
          </div>
        </div>
      </nav>

      {/* =========== MAIN CONTENT =========== */}
      <section className="relative min-h-screen flex items-center justify-center pt-24 pb-16 overflow-hidden">
        <GradientMesh variant="default" />

        <div className="container mx-auto px-6 relative z-10">
          <div className="max-w-xl mx-auto">
            {/* ============= IDLE STATE ============= */}
            {mode === "idle" && (
              <>
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

                {/* Hero */}
                <h1
                  className="text-3xl sm:text-4xl font-black text-center tracking-tight leading-[1.1] mb-3"
                  style={{ color: LANDING_COLORS.textPrimary }}
                >
                  Transfer files{" "}
                  <span className="text-indigo-500">instantly</span>
                </h1>
                <p
                  className="text-sm sm:text-base text-center mb-10 max-w-md mx-auto"
                  style={{ color: LANDING_COLORS.textSecondary }}
                >
                  Direct device-to-device on the same WiFi.
                  Zero cloud. Zero cost. E2E encrypted.
                </p>

                {/* Mode selection card */}
                <div
                  className="rounded-2xl border overflow-hidden backdrop-blur-xl"
                  style={{
                    backgroundColor: `${LANDING_COLORS.surface}B3`,
                    borderColor: LANDING_COLORS.border,
                  }}
                >
                  <div className="p-6 sm:p-8">
                    <div className="grid grid-cols-2 gap-4">
                      {/* Send card */}
                      <button
                        onClick={() => setMode("send")}
                        className="group relative flex flex-col items-center gap-4 p-6 sm:p-8 rounded-xl border-2 transition-all duration-200 cursor-pointer"
                        style={{
                          borderColor: `${LANDING_COLORS.accent}20`,
                          backgroundColor: `${LANDING_COLORS.accent}05`,
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.borderColor = `${LANDING_COLORS.accent}60`;
                          e.currentTarget.style.backgroundColor = `${LANDING_COLORS.accent}10`;
                          e.currentTarget.style.transform = "translateY(-2px)";
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.borderColor = `${LANDING_COLORS.accent}20`;
                          e.currentTarget.style.backgroundColor = `${LANDING_COLORS.accent}05`;
                          e.currentTarget.style.transform = "translateY(0)";
                        }}
                      >
                        <div
                          className="w-14 h-14 rounded-2xl flex items-center justify-center"
                          style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
                        >
                          <Upload className="w-7 h-7 text-indigo-400" />
                        </div>
                        <div className="text-center">
                          <p
                            className="text-base font-bold mb-1"
                            style={{ color: LANDING_COLORS.textPrimary }}
                          >
                            Send
                          </p>
                          <p
                            className="text-xs leading-relaxed"
                            style={{ color: LANDING_COLORS.textMuted }}
                          >
                            Choose files and pick a nearby device
                          </p>
                        </div>
                        <ArrowRight
                          className="w-4 h-4 text-indigo-400 opacity-0 group-hover:opacity-100 transition-opacity absolute top-4 right-4"
                        />
                      </button>

                      {/* Receive card */}
                      <button
                        onClick={() => setMode("receive")}
                        className="group relative flex flex-col items-center gap-4 p-6 sm:p-8 rounded-xl border-2 transition-all duration-200 cursor-pointer"
                        style={{
                          borderColor: `${LANDING_COLORS.success}20`,
                          backgroundColor: `${LANDING_COLORS.success}05`,
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.borderColor = `${LANDING_COLORS.success}60`;
                          e.currentTarget.style.backgroundColor = `${LANDING_COLORS.success}10`;
                          e.currentTarget.style.transform = "translateY(-2px)";
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.borderColor = `${LANDING_COLORS.success}20`;
                          e.currentTarget.style.backgroundColor = `${LANDING_COLORS.success}05`;
                          e.currentTarget.style.transform = "translateY(0)";
                        }}
                      >
                        <div
                          className="w-14 h-14 rounded-2xl flex items-center justify-center"
                          style={{ backgroundColor: `${LANDING_COLORS.success}15` }}
                        >
                          <Download className="w-7 h-7 text-emerald-400" />
                        </div>
                        <div className="text-center">
                          <p
                            className="text-base font-bold mb-1"
                            style={{ color: LANDING_COLORS.textPrimary }}
                          >
                            Receive
                          </p>
                          <p
                            className="text-xs leading-relaxed"
                            style={{ color: LANDING_COLORS.textMuted }}
                          >
                            Make this device visible to senders
                          </p>
                        </div>
                        <ArrowRight
                          className="w-4 h-4 text-emerald-400 opacity-0 group-hover:opacity-100 transition-opacity absolute top-4 right-4"
                        />
                      </button>
                    </div>
                  </div>

                  {/* Feature strip inside card */}
                  <div
                    className="border-t px-6 py-4"
                    style={{ borderColor: LANDING_COLORS.border }}
                  >
                    <div className="flex items-center justify-center gap-6 sm:gap-8">
                      {[
                        { icon: Zap, label: "LAN speed", color: "text-amber-400" },
                        { icon: ShieldCheck, label: "E2E encrypted", color: "text-emerald-400" },
                        { icon: Globe, label: "Works everywhere", color: "text-indigo-400" },
                      ].map(({ icon: Icon, label, color }) => (
                        <span
                          key={label}
                          className="flex items-center gap-1.5 text-xs font-medium"
                          style={{ color: LANDING_COLORS.textMuted }}
                        >
                          <Icon className={`w-3.5 h-3.5 ${color}`} />
                          {label}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* How it works */}
                <div className="mt-8 grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {[
                    { icon: Wifi, label: "Discovers devices on your WiFi" },
                    { icon: Lock, label: "Unique encryption for every transfer" },
                    { icon: Shield, label: "Data never leaves your network" },
                  ].map(({ icon: Icon, label }) => (
                    <div
                      key={label}
                      className="flex items-center gap-2.5 px-3.5 py-3 rounded-xl"
                      style={{ backgroundColor: `${LANDING_COLORS.surface}80` }}
                    >
                      <div
                        className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
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
              </>
            )}

            {/* ============= SEND MODE ============= */}
            {mode === "send" && (
              <>
                <h2
                  className="text-2xl sm:text-3xl font-black text-center tracking-tight mb-2"
                  style={{ color: LANDING_COLORS.textPrimary }}
                >
                  Send files
                </h2>
                <p
                  className="text-sm text-center mb-8"
                  style={{ color: LANDING_COLORS.textSecondary }}
                >
                  Select files and pick a nearby device
                </p>

                {/* Main card */}
                <div
                  className="rounded-2xl border overflow-hidden backdrop-blur-xl"
                  style={{
                    backgroundColor: `${LANDING_COLORS.surface}B3`,
                    borderColor: LANDING_COLORS.border,
                  }}
                >
                  <div className="p-6 sm:p-8">
                    {/* File drop zone / file list */}
                    {selectedFiles.length === 0 ? (
                      <div
                        className="border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all hover:border-indigo-500/40"
                        style={{ borderColor: `${LANDING_COLORS.border}80` }}
                        onClick={() => fileInputRef.current?.click()}
                        onDrop={handleDrop}
                        onDragOver={(e) => e.preventDefault()}
                      >
                        <div
                          className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4"
                          style={{ backgroundColor: `${LANDING_COLORS.accent}10` }}
                        >
                          <Upload className="w-7 h-7 text-indigo-400" />
                        </div>
                        <p className="text-sm font-medium" style={{ color: LANDING_COLORS.textSecondary }}>
                          Drop files here or{" "}
                          <span className="text-indigo-400 underline underline-offset-2">browse</span>
                        </p>
                        <p className="text-xs mt-1.5" style={{ color: LANDING_COLORS.textMuted }}>
                          Any file type, any size — up to 100 files
                        </p>
                        <input
                          ref={fileInputRef}
                          type="file"
                          multiple
                          className="hidden"
                          onChange={handleFileSelect}
                        />
                      </div>
                    ) : (
                      <div>
                        {/* File list */}
                        <div
                          className="space-y-1.5 max-h-48 overflow-y-auto rounded-xl border p-2"
                          style={{
                            borderColor: `${LANDING_COLORS.accent}25`,
                            backgroundColor: `${LANDING_COLORS.accent}05`,
                          }}
                        >
                          {selectedFiles.map((file, idx) => (
                            <div
                              key={`${file.name}-${idx}`}
                              className="flex items-center gap-3 px-3 py-2 rounded-lg"
                              style={{ backgroundColor: `${LANDING_COLORS.bg}40` }}
                            >
                              <FileIcon className="w-4 h-4 text-indigo-400 shrink-0" />
                              <span
                                className="text-sm truncate flex-1"
                                style={{ color: LANDING_COLORS.textPrimary }}
                              >
                                {file.name}
                              </span>
                              <span className="text-xs shrink-0" style={{ color: LANDING_COLORS.textMuted }}>
                                {formatBytes(file.size)}
                              </span>
                              {transfer.state === "idle" && (
                                <button
                                  onClick={() => handleRemoveFile(idx)}
                                  className="p-0.5 rounded hover:bg-white/10 cursor-pointer"
                                  style={{ color: LANDING_COLORS.textMuted }}
                                >
                                  <X className="w-3.5 h-3.5" />
                                </button>
                              )}
                            </div>
                          ))}
                        </div>

                        {/* Summary bar */}
                        <div className="flex items-center justify-between mt-2.5 px-1">
                          <span className="text-xs font-medium" style={{ color: LANDING_COLORS.textMuted }}>
                            {selectedFiles.length} file{selectedFiles.length > 1 ? "s" : ""} — {formatBytes(totalSelectedSize)}
                          </span>
                          {transfer.state === "idle" && (
                            <button
                              onClick={() => fileInputRef.current?.click()}
                              className="text-xs font-medium text-indigo-400 hover:text-indigo-300 transition-colors cursor-pointer"
                            >
                              + Add more
                            </button>
                          )}
                        </div>

                        <input
                          ref={fileInputRef}
                          type="file"
                          multiple
                          className="hidden"
                          onChange={handleFileSelect}
                        />
                      </div>
                    )}

                    {/* Safari >2GB warning */}
                    {showSafariWarning && (
                      <SafariWarning onDismiss={() => setSafariDismissed(true)} />
                    )}

                    {/* Receiver list — always visible in send mode */}
                    {transfer.state === "idle" && (
                      <div className="mt-6">
                        <h3
                          className="text-xs font-semibold uppercase tracking-wider mb-3"
                          style={{ color: LANDING_COLORS.textMuted }}
                        >
                          Nearby devices ({sse.receivers.length})
                        </h3>
                        {sse.receivers.length === 0 ? (
                          <div className="text-center py-8">
                            <Loader2 className="w-6 h-6 animate-spin mx-auto mb-3 text-indigo-400" />
                            <p className="text-sm" style={{ color: LANDING_COLORS.textMuted }}>
                              Waiting for a device to enter <span className="text-emerald-400">Receive</span> mode...
                            </p>
                          </div>
                        ) : (
                          <div className="space-y-2">
                            {sse.receivers.map((r) => {
                              const DeviceIcon = getDeviceIcon(r.osName);
                              return (
                                <button
                                  key={r.peerId}
                                  onClick={() => handleSendTo(r.peerId)}
                                  disabled={selectedFiles.length === 0}
                                  className="w-full flex items-center gap-3 p-3.5 rounded-xl border transition-all hover:border-indigo-500/40 cursor-pointer group disabled:opacity-50 disabled:cursor-not-allowed"
                                  style={{
                                    borderColor: LANDING_COLORS.border,
                                    backgroundColor: "transparent",
                                  }}
                                  onMouseEnter={(e) => {
                                    e.currentTarget.style.backgroundColor = `${LANDING_COLORS.accent}05`;
                                  }}
                                  onMouseLeave={(e) => {
                                    e.currentTarget.style.backgroundColor = "transparent";
                                  }}
                                >
                                  <div
                                    className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                                    style={{ backgroundColor: `${LANDING_COLORS.accent}10` }}
                                  >
                                    <DeviceIcon className="w-4 h-4 text-indigo-400" />
                                  </div>
                                  <span className="font-medium text-sm flex-1 text-left" style={{ color: LANDING_COLORS.textPrimary }}>
                                    {r.displayName}
                                  </span>
                                  <ArrowRight className="w-4 h-4 text-indigo-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                                </button>
                              );
                            })}
                          </div>
                        )}

                        {/* Room code section */}
                        <RoomCodeSection peerId={sse.peerId} />
                      </div>
                    )}

                    {/* Transfer progress (sender) */}
                    {transfer.state !== "idle" && (
                      <div className="mt-6">
                        <TransferProgressDisplay
                          transfer={transfer}
                          role="send"
                          showCancelConfirm={showCancelConfirm}
                          setShowCancelConfirm={setShowCancelConfirm}
                        />
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}

            {/* ============= RECEIVE MODE ============= */}
            {mode === "receive" && (
              <>
                <h2
                  className="text-2xl sm:text-3xl font-black text-center tracking-tight mb-2"
                  style={{ color: LANDING_COLORS.textPrimary }}
                >
                  Receive files
                </h2>
                <p
                  className="text-sm text-center mb-8"
                  style={{ color: LANDING_COLORS.textSecondary }}
                >
                  This device is visible to senders on your network
                </p>

                {/* Auto-register as receiver */}
                <ReceiverRegistration peerId={sse.peerId} reRegisterKey={reRegisterKey} />

                {/* Main card */}
                <div
                  className="rounded-2xl border overflow-hidden backdrop-blur-xl"
                  style={{
                    backgroundColor: `${LANDING_COLORS.surface}B3`,
                    borderColor: LANDING_COLORS.border,
                  }}
                >
                  <div className="p-6 sm:p-8">
                    {/* Incoming request dialog */}
                    {incomingRequest && transfer.state === "idle" && (
                      <div>
                        <div className="flex items-center gap-3 mb-5">
                          <div
                            className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0"
                            style={{ backgroundColor: `${LANDING_COLORS.accent}15` }}
                          >
                            <Download className="w-5 h-5 text-indigo-400" />
                          </div>
                          <div>
                            <p className="font-semibold text-sm" style={{ color: LANDING_COLORS.textPrimary }}>
                              Incoming transfer
                            </p>
                            <p className="text-xs" style={{ color: LANDING_COLORS.textSecondary }}>
                              from <span className="text-indigo-400 font-medium">{incomingRequest.senderName}</span>
                              {incomingRequest.files.length > 1 && (
                                <span className="ml-1.5" style={{ color: LANDING_COLORS.textMuted }}>
                                  ({incomingRequest.files.length} files, {formatBytes(incomingTotalSize)})
                                </span>
                              )}
                            </p>
                          </div>
                        </div>

                        <div className="space-y-1.5 mb-6 max-h-40 overflow-y-auto">
                          {incomingRequest.files.map((f, i) => (
                            <div
                              key={i}
                              className="flex items-center gap-3 p-3 rounded-lg"
                              style={{ backgroundColor: `${LANDING_COLORS.bg}60` }}
                            >
                              <FileIcon className="w-4 h-4 text-indigo-400 shrink-0" />
                              <span className="text-sm truncate flex-1" style={{ color: LANDING_COLORS.textPrimary }}>
                                {f.name}
                              </span>
                              <span className="text-xs shrink-0" style={{ color: LANDING_COLORS.textMuted }}>
                                {formatBytes(f.size)}
                              </span>
                            </div>
                          ))}
                        </div>

                        {/* Safari >2GB warning (receiver) */}
                        {showReceiverSafariWarning && (
                          <SafariWarning className="mb-4" />
                        )}

                        <div className="flex gap-3">
                          <MagneticButton variant="primary" size="md" className="flex-1" onClick={handleAccept}>
                            <Check className="w-4 h-4" />
                            Accept
                          </MagneticButton>
                          <MagneticButton variant="ghost" size="md" onClick={handleReject}>
                            <X className="w-4 h-4" />
                            Decline
                          </MagneticButton>
                        </div>
                      </div>
                    )}

                    {/* Waiting state */}
                    {!incomingRequest && transfer.state === "idle" && (
                      <div className="text-center py-8">
                        <div className="relative w-20 h-20 mx-auto mb-6">
                          <div
                            className="absolute inset-0 rounded-full animate-ping opacity-15"
                            style={{ backgroundColor: LANDING_COLORS.success }}
                          />
                          <div
                            className="absolute inset-2 rounded-full animate-ping opacity-10"
                            style={{ backgroundColor: LANDING_COLORS.success, animationDelay: "0.5s" }}
                          />
                          <div
                            className="relative w-full h-full rounded-full flex items-center justify-center"
                            style={{ backgroundColor: `${LANDING_COLORS.success}12` }}
                          >
                            <Download className="w-9 h-9 text-emerald-400" />
                          </div>
                        </div>
                        <p className="text-sm font-medium" style={{ color: LANDING_COLORS.textSecondary }}>
                          Waiting for a sender...
                        </p>
                        {sse.displayName && (
                          <p className="text-xs mt-2" style={{ color: LANDING_COLORS.textMuted }}>
                            Showing as <span className="text-emerald-400 font-medium">{sse.displayName}</span>
                          </p>
                        )}

                        {/* Resumable transfers */}
                        {transfer.resumableTransfers.length > 0 && (
                          <ResumableTransfersSection
                            transfers={transfer.resumableTransfers}
                            onDiscard={transfer.discardResumable}
                          />
                        )}

                        {/* Room code section */}
                        <RoomCodeSection peerId={sse.peerId} />
                      </div>
                    )}

                    {/* Transfer progress (receiver) */}
                    {transfer.state !== "idle" && (
                      <TransferProgressDisplay
                        transfer={transfer}
                        role="receive"
                        showCancelConfirm={showCancelConfirm}
                        setShowCancelConfirm={setShowCancelConfirm}
                      />
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </section>

      {/* =========== FOOTER =========== */}
      <footer className="py-8 px-6 border-t" style={{ borderColor: LANDING_COLORS.border }}>
        <div className="container mx-auto space-y-4">
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
                Powered by <span className="text-indigo-400 font-semibold">StenVault</span> — End-to-End Encrypted
              </span>
            </div>
          </div>
          <div className="flex items-center justify-center gap-6">
            <Link
              to="/send"
              className="text-xs transition-colors hover:text-indigo-400"
              style={{ color: LANDING_COLORS.textMuted }}
            >
              Cloud Send
            </Link>
            <Link
              to="/auth/register?ref=local-send"
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

// ═══════════════════════════════════════════════════════════════════
// SUB-COMPONENTS (kept here — uses tRPC hooks directly)
// ═══════════════════════════════════════════════════════════════════

/**
 * Auto-registers as receiver when mounted.
 * Unregisters on unmount. Re-registers when reRegisterKey changes.
 */
function ReceiverRegistration({ peerId, reRegisterKey = 0 }: { peerId: string | null; reRegisterKey?: number }) {
  const registerMut = trpc.localSend.registerReceiver.useMutation({
    onError: (err) => {
      toast.error("Failed to register as receiver: " + err.message);
    },
  });
  const unregisterMut = trpc.localSend.unregisterReceiver.useMutation();

  useEffect(() => {
    if (!peerId) return;

    registerMut.mutate({ peerId });

    return () => {
      unregisterMut.mutate({ peerId });
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [peerId, reRegisterKey]);

  return null;
}
