import { create } from 'zustand';
import { useEffect } from 'react';

/**
 * Background Operations Store
 *
 * Tracks upload/download operations globally so the user sees progress
 * even when navigating away from the originating page.
 * Ephemeral — no persist middleware (operations don't survive page reload).
 */

// ============ Types ============

export type OperationType = 'upload' | 'download' | 'preview';

export type OperationStatus =
  | 'pending'
  | 'encrypting'
  | 'uploading'
  | 'downloading'
  | 'decrypting'
  | 'completed'
  | 'error'
  | 'cancelled';

export interface BackgroundOperation {
  id: string;
  type: OperationType;
  filename: string;
  status: OperationStatus;
  /** 0–100 */
  progress: number;
  error?: string;
  createdAt: number;
  completedAt?: number;
  /** Controller to abort this operation's in-flight work */
  abortController?: AbortController;
}

interface OperationStore {
  // State
  operations: BackgroundOperation[];

  // Actions
  addOperation: (op: Pick<BackgroundOperation, 'type' | 'filename'> & { id?: string; status?: OperationStatus; abortController?: AbortController }) => string;
  updateProgress: (id: string, update: { status?: OperationStatus; progress?: number }) => void;
  completeOperation: (id: string) => void;
  failOperation: (id: string, error: string) => void;
  cancelOperation: (id: string) => void;
  removeOperation: (id: string) => void;
  clearCompleted: () => void;
}

export const useOperationStore = create<OperationStore>()((set) => ({
  operations: [],

  addOperation: (op) => {
    const id = op.id ?? crypto.randomUUID();
    set((state) => ({
      operations: [
        ...state.operations,
        {
          id,
          type: op.type,
          filename: op.filename,
          status: op.status ?? 'pending',
          progress: 0,
          createdAt: Date.now(),
          abortController: op.abortController,
        },
      ],
    }));
    return id;
  },

  updateProgress: (id, update) => {
    set((state) => ({
      operations: state.operations.map((op) =>
        op.id === id
          ? {
              ...op,
              ...(update.status !== undefined && { status: update.status }),
              ...(update.progress !== undefined && { progress: update.progress }),
            }
          : op,
      ),
    }));
  },

  completeOperation: (id) => {
    set((state) => ({
      operations: state.operations.map((op) =>
        op.id === id
          ? { ...op, status: 'completed' as const, progress: 100, completedAt: Date.now() }
          : op,
      ),
    }));
  },

  failOperation: (id, error) => {
    set((state) => ({
      operations: state.operations.map((op) =>
        op.id === id ? { ...op, status: 'error' as const, error } : op,
      ),
    }));
  },

  cancelOperation: (id) => {
    set((state) => ({
      operations: state.operations.map((op) => {
        if (op.id !== id) return op;
        // Signal abort to any in-flight work
        op.abortController?.abort();
        return { ...op, status: 'cancelled' as const, completedAt: Date.now() };
      }),
    }));
  },

  removeOperation: (id) => {
    set((state) => ({
      operations: state.operations.filter((op) => op.id !== id),
    }));
  },

  clearCompleted: () => {
    set((state) => ({
      operations: state.operations.filter((op) => op.status !== 'completed' && op.status !== 'cancelled'),
    }));
  },
}));

// ============ Selectors ============

const TERMINAL_STATUSES: ReadonlySet<OperationStatus> = new Set(['completed', 'error', 'cancelled']);

export const useActiveOperations = () =>
  useOperationStore((s) =>
    s.operations.filter((op) => !TERMINAL_STATUSES.has(op.status)),
  );

export const useHasActiveOperations = () =>
  useOperationStore((s) =>
    s.operations.some((op) => !TERMINAL_STATUSES.has(op.status)),
  );

export const useOperationCount = () =>
  useOperationStore((s) => ({
    total: s.operations.length,
    active: s.operations.filter((op) => !TERMINAL_STATUSES.has(op.status)).length,
    completed: s.operations.filter((op) => op.status === 'completed').length,
    error: s.operations.filter((op) => op.status === 'error').length,
  }));

/** Non-React check for active operations (callable from module-level timers) */
export function getHasActiveOperations(): boolean {
  return useOperationStore.getState().operations.some(
    (op) => !TERMINAL_STATUSES.has(op.status),
  );
}

/**
 * Hook: warn before closing/navigating away while operations are active.
 * Mount once in the app shell (DashboardLayout or AuthenticatedShell).
 */
export function useBeforeUnloadWarning(): void {
  const hasActive = useHasActiveOperations();
  useEffect(() => {
    if (!hasActive) return;
    const handler = (e: BeforeUnloadEvent) => { e.preventDefault(); };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [hasActive]);
}

/** Get the most recent createdAt among active (non-terminal) operations */
export function getLastActiveOperationStartTime(): number | null {
  const ops = useOperationStore.getState().operations.filter(
    (op) => !TERMINAL_STATUSES.has(op.status),
  );
  if (ops.length === 0) return null;
  return Math.max(...ops.map((op) => op.createdAt));
}
