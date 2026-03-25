import { useState, useEffect, useRef, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Upload,
  Download,
  CheckCircle2,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  X,
  Loader2,
  Lock,
  Shield,
  Eye,
} from 'lucide-react';
import { Progress } from '@/components/ui/progress';
import { CircularProgress } from '@/components/ui/progress';
import { useIsMobile } from '@/hooks/useMobile';
import {
  useOperationStore,
  type BackgroundOperation,
  type OperationStatus,
} from '@/stores/operationStore';

// ============ Status Helpers ============

const STATUS_LABELS: Record<OperationStatus, string> = {
  pending: 'Waiting...',
  encrypting: 'Encrypting...',
  uploading: 'Uploading...',
  downloading: 'Downloading encrypted file...',
  decrypting: 'Decrypting on your device...',
  completed: 'Encrypted & secure',
  error: 'Failed',
  cancelled: 'Cancelled',
};

/** Statuses that represent a cancellable in-flight operation */
const CANCELLABLE_STATUSES: ReadonlySet<OperationStatus> = new Set([
  'pending', 'encrypting', 'uploading', 'downloading', 'decrypting',
]);

function StatusIcon({ status }: { status: OperationStatus }) {
  switch (status) {
    case 'encrypting':
    case 'decrypting':
      return <Lock className="h-3.5 w-3.5 text-primary animate-pulse" />;
    case 'uploading':
      return <Upload className="h-3.5 w-3.5 text-primary" />;
    case 'downloading':
      return <Download className="h-3.5 w-3.5 text-primary" />;
    case 'completed':
      return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />;
    case 'error':
      return <AlertCircle className="h-3.5 w-3.5 text-destructive" />;
    case 'cancelled':
      return <X className="h-3.5 w-3.5 text-muted-foreground" />;
    default:
      return <Loader2 className="h-3.5 w-3.5 text-muted-foreground animate-spin" />;
  }
}

function TypeIcon({ type }: { type: 'upload' | 'download' | 'preview' }) {
  if (type === 'upload') return <Shield className="h-3.5 w-3.5 text-muted-foreground" />;
  if (type === 'preview') return <Eye className="h-3.5 w-3.5 text-muted-foreground" />;
  return <Download className="h-3.5 w-3.5 text-muted-foreground" />;
}

// ============ Operation Row ============

function OperationRow({
  op,
  onDismiss,
  onCancel,
}: {
  op: BackgroundOperation;
  onDismiss: (id: string) => void;
  onCancel: (id: string) => void;
}) {
  const isActive = CANCELLABLE_STATUSES.has(op.status);
  const isTerminal = op.status === 'completed' || op.status === 'error' || op.status === 'cancelled';
  const truncatedName =
    op.filename.length > 28 ? op.filename.slice(0, 25) + '...' : op.filename;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.2 }}
      className="px-3 py-2 border-b border-border/50 last:border-b-0"
    >
      <div className="flex items-center gap-2">
        <TypeIcon type={op.type} />
        <span className="text-xs font-medium text-foreground truncate flex-1" title={op.filename}>
          {truncatedName}
        </span>
        <StatusIcon status={op.status} />
        {isActive && (
          <button
            onClick={() => onCancel(op.id)}
            className="text-muted-foreground hover:text-destructive transition-colors p-0.5"
            title="Cancel"
          >
            <X className="h-3 w-3" />
          </button>
        )}
        {isTerminal && (
          <button
            onClick={() => onDismiss(op.id)}
            className="text-muted-foreground hover:text-foreground transition-colors p-0.5"
          >
            <X className="h-3 w-3" />
          </button>
        )}
      </div>

      {isActive && (
        <div className="mt-1.5 flex items-center gap-2">
          <Progress value={op.progress} size="xs" className="flex-1" />
          <span className="text-[10px] text-muted-foreground tabular-nums w-8 text-right">
            {op.progress}%
          </span>
        </div>
      )}

      {op.status === 'error' && op.error && (
        <p className="text-[10px] text-destructive mt-1 truncate" title={op.error}>
          {op.error}
        </p>
      )}

      {isActive && (
        <p className="text-[10px] text-muted-foreground mt-0.5">
          {STATUS_LABELS[op.status]}
        </p>
      )}
    </motion.div>
  );
}

// ============ Panel ============

const AUTO_MINIMIZE_DELAY = 3000;
const COMPLETED_FADE_DELAY = 5000;

export function BackgroundOperationsPanel() {
  const operations = useOperationStore((s) => s.operations);
  const removeOperation = useOperationStore((s) => s.removeOperation);
  const cancelOperation = useOperationStore((s) => s.cancelOperation);
  const clearCompleted = useOperationStore((s) => s.clearCompleted);

  const [expanded, setExpanded] = useState(false);
  const [userMinimized, setUserMinimized] = useState(false);
  const isMobile = useIsMobile();
  const prevActiveCountRef = useRef(0);
  const autoMinimizeTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const completedTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const activeOps = operations.filter((op) => op.status !== 'completed' && op.status !== 'error');
  const activeCount = activeOps.length;

  const aggregateProgress =
    activeOps.length > 0
      ? Math.round(activeOps.reduce((sum, op) => sum + op.progress, 0) / activeOps.length)
      : 0;

  // Auto-expand when a new operation starts (unless user explicitly minimized)
  useEffect(() => {
    if (activeCount > prevActiveCountRef.current && !userMinimized) {
      setExpanded(true);
    }
    prevActiveCountRef.current = activeCount;
  }, [activeCount, userMinimized]);

  // Auto-minimize after all ops complete
  useEffect(() => {
    if (activeCount === 0 && operations.length > 0) {
      autoMinimizeTimerRef.current = setTimeout(() => {
        setExpanded(false);
      }, AUTO_MINIMIZE_DELAY);
    }
    return () => {
      if (autoMinimizeTimerRef.current) clearTimeout(autoMinimizeTimerRef.current);
    };
  }, [activeCount, operations.length]);

  // Auto-remove completed operations after fade delay
  useEffect(() => {
    const completedOps = operations.filter((op) => op.status === 'completed' || op.status === 'cancelled');
    for (const op of completedOps) {
      if (!completedTimersRef.current.has(op.id)) {
        const timer = setTimeout(() => {
          removeOperation(op.id);
          completedTimersRef.current.delete(op.id);
        }, COMPLETED_FADE_DELAY);
        completedTimersRef.current.set(op.id, timer);
      }
    }

    // Clean timers for ops that no longer exist
    for (const [id, timer] of completedTimersRef.current.entries()) {
      if (!operations.find((op) => op.id === id)) {
        clearTimeout(timer);
        completedTimersRef.current.delete(id);
      }
    }
  }, [operations, removeOperation]);

  // Cleanup timers on unmount
  useEffect(() => {
    return () => {
      for (const timer of completedTimersRef.current.values()) {
        clearTimeout(timer);
      }
    };
  }, []);

  const handleToggle = useCallback(() => {
    setExpanded((prev) => {
      const next = !prev;
      if (!next) setUserMinimized(true);
      else setUserMinimized(false);
      return next;
    });
  }, []);

  const handleDismiss = useCallback(
    (id: string) => {
      removeOperation(id);
    },
    [removeOperation],
  );

  const handleCancel = useCallback(
    (id: string) => {
      cancelOperation(id);
    },
    [cancelOperation],
  );

  // Nothing to show
  if (operations.length === 0) return null;

  const positionClasses = isMobile
    ? 'fixed bottom-[72px] right-3 left-3 z-40'
    : 'fixed bottom-4 right-4 z-40 w-[360px]';

  return (
    <AnimatePresence>
      <motion.div
        key="bg-ops-panel"
        initial={{ opacity: 0, y: 20, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 20, scale: 0.95 }}
        transition={{ duration: 0.2 }}
        className={positionClasses}
      >
        <div className="bg-background/95 backdrop-blur-lg border border-border/60 rounded-xl shadow-xl overflow-hidden">
          {/* Header / Pill */}
          <button
            onClick={handleToggle}
            className="w-full flex items-center gap-2.5 px-3 py-2 hover:bg-muted/50 transition-colors"
          >
            {activeCount > 0 ? (
              <CircularProgress value={aggregateProgress} size={24} strokeWidth={3} />
            ) : (
              <CheckCircle2 className="h-5 w-5 text-emerald-500" />
            )}

            <div className="flex-1 text-left">
              <span className="text-xs font-medium text-foreground">
                {activeCount > 0
                  ? `${activeCount} operation${activeCount > 1 ? 's' : ''} in progress`
                  : 'All operations complete'}
              </span>
              {activeCount > 0 && (
                <span className="text-[10px] text-muted-foreground ml-2 tabular-nums">
                  {aggregateProgress}%
                </span>
              )}
            </div>

            {expanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronUp className="h-4 w-4 text-muted-foreground" />
            )}
          </button>

          {/* Expanded list */}
          <AnimatePresence>
            {expanded && (
              <motion.div
                key="ops-list"
                initial={{ height: 0 }}
                animate={{ height: 'auto' }}
                exit={{ height: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="max-h-[240px] overflow-y-auto">
                  <AnimatePresence mode="popLayout">
                    {operations.map((op) => (
                      <OperationRow key={op.id} op={op} onDismiss={handleDismiss} onCancel={handleCancel} />
                    ))}
                  </AnimatePresence>
                </div>

                {operations.some((op) => op.status === 'completed' || op.status === 'cancelled') && (
                  <div className="px-3 py-1.5 border-t border-border/50">
                    <button
                      onClick={clearCompleted}
                      className="text-[10px] text-muted-foreground hover:text-foreground transition-colors"
                    >
                      Clear completed
                    </button>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>
    </AnimatePresence>
  );
}
