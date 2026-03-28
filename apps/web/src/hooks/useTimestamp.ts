/**
 * useTimestamp Hook
 *
 * Provides access to OpenTimestamps blockchain proof of existence features.
 * Handles submitting files for timestamping, checking status, verification,
 * and downloading proof files.
 */

import { useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { downloadBase64File } from "@/lib/platform";
import type {
    TimestampStatus,
    FileTimestampInfo,
    TimestampVerification,
} from "@stenvault/shared";

interface UseTimestampOptions {
    /** File ID to manage timestamps for */
    fileId?: number;
    /** Decrypted filename (for zero-knowledge download naming) */
    filename?: string;
    /** Callback when timestamp status changes */
    onStatusChange?: (status: TimestampStatus | null) => void;
}

interface UseTimestampReturn {
    /** Current timestamp info for the file */
    timestampInfo: FileTimestampInfo | null;
    /** Whether timestamp data is loading */
    isLoading: boolean;
    /** Whether timestamping service is enabled */
    isEnabled: boolean;
    /** Whether user's plan includes timestamp access */
    hasPlanAccess: boolean;
    /** Submit file for timestamping */
    submitTimestamp: () => Promise<void>;
    /** Verify the timestamp proof */
    verifyTimestamp: () => Promise<TimestampVerification | null>;
    /** Download the OTS proof file */
    downloadProof: () => Promise<void>;
    /** Download legal PDF certificate */
    downloadLegalPdf: () => Promise<void>;
    /** Retry a failed timestamp */
    retryTimestamp: () => Promise<void>;
    /** Whether a mutation is in progress */
    isPending: boolean;
}

/**
 * Hook for managing OpenTimestamps blockchain proofs
 */
export function useTimestamp(options: UseTimestampOptions = {}): UseTimestampReturn {
    const { fileId, filename, onStatusChange } = options;
    const utils = trpc.useUtils();

    // Check if OTS is enabled
    const { data: enabledData } = trpc.timestamp.isEnabled.useQuery(undefined, {
        staleTime: 5 * 60 * 1000, // Cache for 5 minutes
    });
    const isEnabled = enabledData?.enabled ?? false;
    const hasPlanAccess = enabledData?.hasPlanAccess ?? false;

    // Get timestamp status for the file
    const {
        data: statusData,
        isLoading,
        refetch: refetchStatus,
    } = trpc.timestamp.getStatus.useQuery(
        { fileId: fileId! },
        {
            enabled: !!fileId && isEnabled,
            staleTime: 30 * 1000, // Refresh every 30 seconds
            refetchInterval: (query) => {
                // Poll more frequently if pending
                const data = query.state.data;
                if (data?.status === "pending" || data?.status === "confirming") {
                    return 60 * 1000; // Every minute
                }
                return false; // Don't poll if confirmed/failed
            },
        }
    );

    // Submit mutation
    const submitMutation = trpc.timestamp.submit.useMutation({
        onSuccess: (result) => {
            toast.success(result.message);
            onStatusChange?.(result.status);
            refetchStatus();
        },
        onError: (error) => {
            toast.error(error.message || "Failed to submit timestamp");
        },
    });

    // Retry mutation
    const retryMutation = trpc.timestamp.retry.useMutation({
        onSuccess: (result) => {
            toast.success(result.message);
            onStatusChange?.("pending");
            refetchStatus();
        },
        onError: (error) => {
            toast.error(error.message || "Failed to retry timestamp");
        },
    });

    // Legal PDF mutation
    const legalPdfMutation = trpc.timestamp.generateLegalPdf.useMutation({
        onError: (error) => {
            toast.error(error.message || "Failed to generate PDF");
        },
    });

    // Submit timestamp
    const submitTimestamp = useCallback(async () => {
        if (!fileId) {
            toast.error("No file selected");
            return;
        }
        if (!isEnabled) {
            toast.error("Timestamping service is disabled");
            return;
        }
        await submitMutation.mutateAsync({ fileId });
    }, [fileId, isEnabled, submitMutation]);

    // Verify timestamp
    const verifyTimestamp = useCallback(async (): Promise<TimestampVerification | null> => {
        if (!fileId) {
            toast.error("No file selected");
            return null;
        }
        try {
            const result = await utils.timestamp.verify.fetch({ fileId });
            if (result.verified) {
                toast.success("Timestamp verified on Bitcoin blockchain");
            }
            return result as TimestampVerification;
        } catch (error) {
            const message = error instanceof Error ? error.message : "Verification failed";
            toast.error(message);
            return null;
        }
    }, [fileId, utils]);

    // Download proof
    const downloadProof = useCallback(async () => {
        if (!fileId) {
            toast.error("No file selected");
            return;
        }
        try {
            const result = await utils.timestamp.downloadProof.fetch({ fileId, displayName: filename });

            // Use platform-agnostic download provider
            const downloadResult = await downloadBase64File(
                result.proof,
                result.filename,
                "application/octet-stream"
            );

            if (downloadResult.success) {
                toast.success(`Downloaded ${result.filename}`);
            } else {
                toast.error(downloadResult.error || "Failed to download proof");
            }
        } catch (error) {
            const message = error instanceof Error ? error.message : "Failed to download proof";
            toast.error(message);
        }
    }, [fileId, filename, utils]);

    // Download legal PDF
    const downloadLegalPdf = useCallback(async () => {
        if (!fileId) {
            toast.error("No file selected");
            return;
        }
        try {
            const result = await legalPdfMutation.mutateAsync({ fileId, displayName: filename });

            // Use platform-agnostic download provider
            const downloadResult = await downloadBase64File(
                result.pdf,
                result.filename,
                result.mimeType
            );

            if (downloadResult.success) {
                toast.success(`Downloaded ${result.filename}`);
            } else {
                toast.error(downloadResult.error || "Failed to download PDF");
            }
        } catch {
            // Error already handled by mutation onError
        }
    }, [fileId, filename, legalPdfMutation]);

    // Retry timestamp
    const retryTimestamp = useCallback(async () => {
        if (!fileId) {
            toast.error("No file selected");
            return;
        }
        await retryMutation.mutateAsync({ fileId });
    }, [fileId, retryMutation]);

    const timestampInfo: FileTimestampInfo | null = statusData
        ? {
              hasTimestamp: statusData.hasTimestamp,
              status: statusData.status,
              submittedAt: statusData.submittedAt,
              confirmedAt: statusData.confirmedAt,
              bitcoinBlockHeight: statusData.bitcoinBlockHeight,
              bitcoinTimestamp: statusData.bitcoinTimestamp,
              contentHash: statusData.contentHash,
          }
        : null;

    return {
        timestampInfo,
        isLoading,
        isEnabled,
        hasPlanAccess,
        submitTimestamp,
        verifyTimestamp,
        downloadProof,
        downloadLegalPdf,
        retryTimestamp,
        isPending: submitMutation.isPending || retryMutation.isPending || legalPdfMutation.isPending,
    };
}

/**
 * Hook for batch timestamp status (efficient for file lists)
 */
export function useBatchTimestampStatus(fileIds: number[]) {
    const { data: enabledData } = trpc.timestamp.isEnabled.useQuery(undefined, {
        staleTime: 5 * 60 * 1000,
    });
    const isEnabled = enabledData?.enabled ?? false;

    const { data, isLoading } = trpc.timestamp.batchStatus.useQuery(
        { fileIds },
        {
            enabled: isEnabled && fileIds.length > 0,
            staleTime: 30 * 1000,
        }
    );

    // Create a map for quick lookup
    const statusMap = new Map<number, TimestampStatus | null>();
    if (data) {
        for (const item of data) {
            statusMap.set(item.fileId, item.status);
        }
    }

    return {
        isEnabled,
        isLoading,
        getStatus: (fileId: number) => statusMap.get(fileId) ?? null,
        statusMap,
    };
}
