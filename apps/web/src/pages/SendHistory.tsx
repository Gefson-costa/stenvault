/**
 * SendHistory - View past send sessions for authenticated users.
 *
 * Shows file size, MIME type, status, download count, dates.
 * Cannot reconstruct share URLs (zero-knowledge — key is never stored on server).
 */
import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { formatBytes } from "@stenvault/shared";
import { toast } from "sonner";
import {
  Send,
  FileIcon,
  Archive,
  Clock,
  Download,
  AlertTriangle,
  CheckCircle,
  Upload,
  Loader2,
  ChevronLeft,
  ChevronRight,
  Info,
  Image,
  Film,
  Music,
  FileText,
  Code,
  MoreHorizontal,
  Trash2,
  RefreshCw,
} from "lucide-react";
import { Link } from "react-router-dom";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const PAGE_SIZE = 20;

function getMimeIcon(mimeType: string) {
  if (mimeType.startsWith("image/")) return Image;
  if (mimeType.startsWith("video/")) return Film;
  if (mimeType.startsWith("audio/")) return Music;
  if (mimeType.startsWith("text/")) return FileText;
  if (mimeType === "application/pdf") return FileText;
  if (mimeType.includes("json") || mimeType.includes("xml") || mimeType.includes("javascript"))
    return Code;
  if (mimeType === "application/zip" || mimeType.includes("archive")) return Archive;
  return FileIcon;
}

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { icon: typeof CheckCircle; label: string; className: string }> = {
    ready: {
      icon: CheckCircle,
      label: "Active",
      className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    },
    uploading: {
      icon: Upload,
      label: "Uploading",
      className: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    },
    expired: {
      icon: Clock,
      label: "Expired",
      className: "bg-slate-500/10 text-slate-400 border-slate-500/20",
    },
    deleted: {
      icon: AlertTriangle,
      label: "Deleted",
      className: "bg-red-500/10 text-red-400 border-red-500/20",
    },
  };

  const { icon: Icon, label, className } = config[status] ?? config.expired!;

  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium border ${className}`}
    >
      <Icon className="w-3 h-3" />
      {label}
    </span>
  );
}

function formatRelativeDate(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

function formatExpiresIn(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = date.getTime() - now.getTime();

  if (diffMs <= 0) return "Expired";

  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 60) return `${diffMins}m left`;
  if (diffHours < 24) return `${diffHours}h left`;
  return `${diffDays}d left`;
}

function formatDownloadCount(downloadCount: number, maxDownloads: number | null): string {
  if (maxDownloads === null) return `${downloadCount}`;
  return `${downloadCount} / ${maxDownloads}`;
}

export default function SendHistory() {
  const [page, setPage] = useState(0);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const utils = trpc.useUtils();
  const { data, isLoading, error, refetch } = trpc.publicSend.listSendHistory.useQuery(
    { offset: page * PAGE_SIZE, limit: PAGE_SIZE },
    { refetchInterval: 30000 },
  );

  const deleteMutation = trpc.publicSend.deleteSend.useMutation({
    onSuccess: () => {
      toast.success("Send deleted successfully");
      setDeleteTarget(null);
      utils.publicSend.listSendHistory.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const sessions = useMemo(() => data?.sessions ?? [], [data?.sessions]);
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  const handleDelete = useCallback(() => {
    if (deleteTarget) {
      deleteMutation.mutate({ sessionId: deleteTarget });
    }
  }, [deleteTarget, deleteMutation]);

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Send History</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Your encrypted file shares
          </p>
        </div>
        <Link
          to="/send"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          <Send className="w-4 h-4" />
          New Send
        </Link>
      </div>

      {/* Zero-knowledge banner */}
      <div className="flex items-start gap-3 p-4 rounded-xl bg-amber-500/5 border border-amber-500/10">
        <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="font-medium text-amber-300">Share links are not stored</p>
          <p className="text-muted-foreground mt-0.5">
            Encryption keys are never sent to our servers. Save your share links when you create them
            — they cannot be reconstructed.
          </p>
        </div>
      </div>

      {/* Content */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      ) : error ? (
        <div className="flex flex-col items-center justify-center py-20 space-y-3">
          <AlertTriangle className="w-8 h-8 text-destructive" />
          <p className="text-sm text-muted-foreground">{error.message}</p>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Retry
          </Button>
        </div>
      ) : sessions.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 space-y-4">
          <div className="w-16 h-16 rounded-2xl bg-muted/50 flex items-center justify-center">
            <Send className="w-8 h-8 text-muted-foreground" />
          </div>
          <div className="text-center">
            <p className="font-medium">No sends yet</p>
            <p className="text-sm text-muted-foreground mt-1">
              Files you send while logged in will appear here.
            </p>
          </div>
          <Link
            to="/send"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
          >
            <Send className="w-4 h-4" />
            Send your first file
          </Link>
        </div>
      ) : (
        <>
          {/* Mobile card layout */}
          <div className="space-y-3 sm:hidden">
            {sessions.map((session) => {
              const MimeIcon = getMimeIcon(session.mimeType);
              const isExpired = new Date(session.expiresAt) < new Date();
              const effectiveStatus = isExpired ? "expired" : session.status;
              const canDelete = effectiveStatus === "ready" || effectiveStatus === "uploading";

              return (
                <div
                  key={session.sessionId}
                  className="rounded-xl border p-4 space-y-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                        <MimeIcon className="w-4.5 h-4.5 text-primary" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-medium truncate">
                          {session.isBundle ? "File bundle" : "Encrypted file"}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {formatBytes(session.fileSize)}
                          {session.isBundle && " (multiple files)"}
                        </p>
                      </div>
                    </div>
                    {canDelete && (
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <button className="p-1.5 rounded-lg hover:bg-muted/50 transition-colors">
                            <MoreHorizontal className="w-4 h-4 text-muted-foreground" />
                          </button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem
                            className="text-destructive focus:text-destructive"
                            onClick={() => setDeleteTarget(session.sessionId)}
                          >
                            <Trash2 className="w-4 h-4 mr-2" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <StatusBadge status={effectiveStatus} />
                    <div className="flex items-center gap-3 text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Download className="w-3 h-3" />
                        {formatDownloadCount(session.downloadCount, session.maxDownloads)}
                      </span>
                      <span>{formatRelativeDate(session.createdAt)}</span>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    <span className={isExpired ? "text-muted-foreground" : "text-foreground"}>
                      {formatExpiresIn(session.expiresAt)}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Desktop table */}
          <div className="rounded-xl border overflow-hidden hidden sm:block">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-muted/30">
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">
                    File
                  </th>
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">
                    Status
                  </th>
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3 hidden md:table-cell">
                    Downloads
                  </th>
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3 hidden lg:table-cell">
                    Created
                  </th>
                  <th className="text-right text-xs font-medium text-muted-foreground px-4 py-3">
                    Expires
                  </th>
                  <th className="w-10 px-2 py-3" />
                </tr>
              </thead>
              <tbody>
                {sessions.map((session) => {
                  const MimeIcon = getMimeIcon(session.mimeType);
                  const isExpired = new Date(session.expiresAt) < new Date();
                  const effectiveStatus = isExpired ? "expired" : session.status;
                  const canDelete = effectiveStatus === "ready" || effectiveStatus === "uploading";

                  return (
                    <tr
                      key={session.sessionId}
                      className="border-b last:border-0 hover:bg-muted/20 transition-colors"
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                            <MimeIcon className="w-4.5 h-4.5 text-primary" />
                          </div>
                          <div className="min-w-0">
                            <p className="text-sm font-medium truncate">
                              {session.isBundle ? "File bundle" : "Encrypted file"}
                            </p>
                            <p className="text-xs text-muted-foreground">
                              {formatBytes(session.fileSize)}
                              {session.isBundle && " (multiple files)"}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={effectiveStatus} />
                      </td>
                      <td className="px-4 py-3 hidden md:table-cell">
                        <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
                          <Download className="w-3.5 h-3.5" />
                          {formatDownloadCount(session.downloadCount, session.maxDownloads)}
                        </div>
                      </td>
                      <td className="px-4 py-3 hidden lg:table-cell">
                        <span className="text-sm text-muted-foreground">
                          {formatRelativeDate(session.createdAt)}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span
                          className={`text-sm ${isExpired ? "text-muted-foreground" : "text-foreground"}`}
                        >
                          {formatExpiresIn(session.expiresAt)}
                        </span>
                      </td>
                      <td className="px-2 py-3">
                        {canDelete && (
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <button className="p-1.5 rounded-lg hover:bg-muted/50 transition-colors">
                                <MoreHorizontal className="w-4 h-4 text-muted-foreground" />
                              </button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem
                                className="text-destructive focus:text-destructive"
                                onClick={() => setDeleteTarget(session.sessionId)}
                              >
                                <Trash2 className="w-4 h-4 mr-2" />
                                Delete
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="p-2 rounded-lg border hover:bg-muted/50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                  className="p-2 rounded-lg border hover:bg-muted/50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Delete confirmation dialog */}
      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete send?</DialogTitle>
            <DialogDescription>
              This will permanently delete the encrypted file from our servers. Anyone with the share
              link will no longer be able to download it. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
