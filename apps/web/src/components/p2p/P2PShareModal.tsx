/**
 * P2P Share Modal
 * Modal for creating a P2P file sharing session (sender side).
 * 
 * Refactored to use modular subcomponents for better maintainability.
 */
import { useCallback, useEffect, useRef } from "react";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Loader2, Wifi } from "lucide-react";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { useP2PTransfer } from "@/hooks/p2p";
import type { P2PShareModalProps } from "./types";

// Modular subcomponents
import {
    FileInfoCard,
    RecipientInput,
    EncryptionSelector,
    ShamirConfig,
    ExpirationSlider,
    ActiveSessionView,
    useShareModalState,
} from "./P2PShareModal/index";

export function P2PShareModal({
    open,
    onOpenChange,
    fileId,
    fileName,
    fileSize
}: P2PShareModalProps) {
    // Form state hook
    const modalState = useShareModalState();

    // Track if we've already started the transfer
    const transferStartedRef = useRef(false);

    // P2P transfer hook
    const {
        connectionState,
        transferState,
        createSession,
        cancelTransfer,
        startFileTransfer,
        isLoading,
        error,
        peerFingerprint,
        localFingerprint,
    } = useP2PTransfer();

    // tRPC utilities for fetching file
    const trpcUtils = trpc.useUtils();

    /**
     * Handle session creation
     */
    const handleCreateSession = useCallback(async () => {
        // Reset transfer tracking for new session
        transferStartedRef.current = false;

        try {
            // Generate Shamir shares if needed
            await modalState.generateShamirShares();

            const result = await createSession({
                fileId,
                recipientEmail: modalState.recipientEmail || undefined,
                encryptionMethod: modalState.encryptionMethod,
                splitShares: modalState.isShamir ? modalState.shamirTotalShares : 1,
                expiresInMinutes: modalState.expiresInMinutes,
            });

            modalState.setShareUrl(result.shareUrl);

            if (modalState.isShamir) {
                toast.success("P2P session created with Shamir's Secret Sharing! Distribute the shares securely.");
            } else {
                toast.success("P2P session created! Share the link with your recipient.");
            }
        } catch (err) {
            const message = err instanceof Error ? err.message : "Failed to create session";
            toast.error(message);
        }
    }, [createSession, fileId, modalState]);

    /**
     * Auto-start file transfer when recipient connects
     */
    useEffect(() => {
        // Only start if:
        // 1. Connection state is "connected" 
        // 2. We haven't already started
        // 3. Session is active
        if (connectionState === "connected" && !transferStartedRef.current && modalState.isSessionActive) {
            transferStartedRef.current = true;

            // Fetch the file and start transfer
            (async () => {
                try {
                    toast.info("Recipient connected! Starting file transfer...");

                    // Get download URL for the file
                    const { url } = await trpcUtils.files.getDownloadUrl.fetch({ fileId });

                    // Fetch the file content
                    const response = await fetch(url);
                    if (!response.ok) {
                        throw new Error(`Failed to fetch file: ${response.status}`);
                    }

                    // Convert to File object
                    const blob = await response.blob();
                    const file = new File([blob], fileName, { type: blob.type });

                    // Start the P2P transfer
                    await startFileTransfer(file);

                } catch (err) {
                    const message = err instanceof Error ? err.message : "Failed to start transfer";
                    toast.error(message);
                    console.error("[P2P] Auto-transfer error:", err);
                }
            })();
        }
    }, [connectionState, modalState.isSessionActive, fileId, fileName, startFileTransfer, trpcUtils]);

    /**
     * Handle modal close with different behavior based on state:
     * - idle: close directly
     * - waiting/connecting: offer to minimize to Quantum Mesh (session continues)
     * - transferring: require confirmation to cancel
     * - completed/failed: close directly
     */
    const handleClose = useCallback(() => {
        // States where we can close directly
        if (connectionState === "idle" || connectionState === "completed" || connectionState === "failed") {
            modalState.reset();
            transferStartedRef.current = false;
            onOpenChange(false);
            return;
        }

        // Waiting for recipient - offer to minimize instead of cancel
        if (connectionState === "creating" || connectionState === "waiting" || connectionState === "connecting") {
            const shouldMinimize = confirm(
                "The session is waiting for a recipient.\n\n" +
                "Click OK to minimize (session continues in background)\n" +
                "Click Cancel to stay on this screen"
            );

            if (shouldMinimize) {
                // Just close the modal, session continues
                onOpenChange(false);
                toast.info("Session continues in Quantum Mesh", {
                    description: "Open the Quantum Mesh page to monitor the session",
                    action: {
                        label: "Open",
                        onClick: () => window.location.href = "/quantum-mesh",
                    },
                });
            }
            return;
        }

        // Active transfer - require confirmation to cancel
        if (connectionState === "connected" || connectionState === "transferring") {
            if (!confirm("A transfer is in progress. Cancel it?")) return;
            cancelTransfer();
            modalState.reset();
            transferStartedRef.current = false;
            onOpenChange(false);
            return;
        }

        // Fallback for any other state
        modalState.reset();
        transferStartedRef.current = false;
        onOpenChange(false);
    }, [connectionState, cancelTransfer, modalState, onOpenChange]);

    return (
        <Dialog open={open} onOpenChange={handleClose}>
            <DialogContent className={`max-w-[92vw] ${modalState.isShamir && modalState.isSessionActive ? "sm:max-w-2xl" : "sm:max-w-md"}`}>
                {/* Header */}
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <div className="p-2 rounded-lg bg-gradient-to-br from-purple-500/20 to-blue-500/20">
                            <Wifi className="h-5 w-5 text-purple-500" />
                        </div>
                        <div>
                            <span>Quantum Mesh Network</span>
                            <Badge variant="secondary" className="ml-2 text-xs">P2P</Badge>
                        </div>
                    </DialogTitle>
                    <DialogDescription>
                        Share directly peer-to-peer. The server never sees your file.
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-6 py-4">
                    {/* File info - always visible */}
                    <FileInfoCard fileName={fileName} fileSize={fileSize} />

                    {!modalState.isSessionActive ? (
                        /* === SESSION CREATION FORM === */
                        <>
                            <RecipientInput
                                value={modalState.recipientEmail}
                                onChange={modalState.setRecipientEmail}
                            />

                            <EncryptionSelector
                                value={modalState.encryptionMethod}
                                onChange={modalState.setEncryptionMethod}
                            />

                            {modalState.isShamir && (
                                <ShamirConfig
                                    totalShares={modalState.shamirTotalShares}
                                    threshold={modalState.shamirThreshold}
                                    onTotalSharesChange={modalState.setShamirTotalShares}
                                    onThresholdChange={modalState.setShamirThreshold}
                                />
                            )}

                            <ExpirationSlider
                                value={modalState.expiresInMinutes}
                                onChange={modalState.setExpiresInMinutes}
                            />

                            {/* Error display */}
                            {error && (
                                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30">
                                    <p className="text-sm text-red-500">{error}</p>
                                </div>
                            )}

                            {/* Create button */}
                            <Button
                                onClick={handleCreateSession}
                                disabled={isLoading}
                                className="w-full bg-gradient-to-r from-purple-500 to-blue-500 hover:from-purple-600 hover:to-blue-600"
                            >
                                {isLoading ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Creating session...
                                    </>
                                ) : (
                                    <>
                                        <Wifi className="mr-2 h-4 w-4" />
                                        Create P2P Session
                                    </>
                                )}
                            </Button>
                        </>
                    ) : (
                        /* === ACTIVE SESSION VIEW === */
                        <ActiveSessionView
                            shareUrl={modalState.shareUrl!}
                            connectionState={connectionState}
                            transferState={transferState}
                            fileName={fileName}
                            isShamir={modalState.isShamir}
                            shamirShares={modalState.shamirShares}
                            peerFingerprint={peerFingerprint ?? undefined}
                            localFingerprint={localFingerprint ?? undefined}
                            onCancel={cancelTransfer}
                            onClose={handleClose}
                        />
                    )}
                </div>
            </DialogContent>
        </Dialog>
    );
}
