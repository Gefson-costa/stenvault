/**
 * Operation Store Tests
 *
 * Tests the Zustand background operations store:
 * - Adding, updating, completing, failing, removing operations
 * - Selectors for active/completed/error counts
 * - clearCompleted behavior
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { useOperationStore, getHasActiveOperations, getLastActiveOperationStartTime } from './operationStore';

function getState() {
    return useOperationStore.getState();
}

describe('Operation Store', () => {
    beforeEach(() => {
        useOperationStore.setState({ operations: [] });
    });

    // ============ addOperation ============

    describe('addOperation', () => {
        it('should add an operation with defaults', () => {
            const id = getState().addOperation({ type: 'upload', filename: 'test.pdf' });

            const ops = getState().operations;
            expect(ops).toHaveLength(1);
            const op = ops[0]!;
            expect(op.id).toBe(id);
            expect(op.type).toBe('upload');
            expect(op.filename).toBe('test.pdf');
            expect(op.status).toBe('pending');
            expect(op.progress).toBe(0);
            expect(op.createdAt).toBeGreaterThan(0);
        });

        it('should accept custom id and status', () => {
            const id = getState().addOperation({
                id: 'custom-id',
                type: 'download',
                filename: 'report.xlsx',
                status: 'downloading',
            });

            expect(id).toBe('custom-id');
            expect(getState().operations[0]!.status).toBe('downloading');
        });

        it('should add multiple operations', () => {
            getState().addOperation({ type: 'upload', filename: 'a.txt' });
            getState().addOperation({ type: 'download', filename: 'b.txt' });

            expect(getState().operations).toHaveLength(2);
        });
    });

    // ============ updateProgress ============

    describe('updateProgress', () => {
        it('should update progress value', () => {
            const id = getState().addOperation({ type: 'upload', filename: 'file.bin' });
            getState().updateProgress(id, { progress: 42 });

            expect(getState().operations[0]!.progress).toBe(42);
        });

        it('should update status', () => {
            const id = getState().addOperation({ type: 'upload', filename: 'file.bin' });
            getState().updateProgress(id, { status: 'uploading' });

            expect(getState().operations[0]!.status).toBe('uploading');
        });

        it('should update both status and progress', () => {
            const id = getState().addOperation({ type: 'upload', filename: 'file.bin' });
            getState().updateProgress(id, { status: 'encrypting', progress: 75 });

            const op = getState().operations[0]!;
            expect(op.status).toBe('encrypting');
            expect(op.progress).toBe(75);
        });

        it('should not affect other operations', () => {
            const id1 = getState().addOperation({ type: 'upload', filename: 'a.txt' });
            const id2 = getState().addOperation({ type: 'upload', filename: 'b.txt' });
            getState().updateProgress(id1, { progress: 50 });

            expect(getState().operations.find(o => o.id === id2)!.progress).toBe(0);
        });
    });

    // ============ completeOperation ============

    describe('completeOperation', () => {
        it('should mark operation as completed with 100% progress', () => {
            const id = getState().addOperation({ type: 'upload', filename: 'file.bin' });
            getState().completeOperation(id);

            const op = getState().operations[0]!;
            expect(op.status).toBe('completed');
            expect(op.progress).toBe(100);
            expect(op.completedAt).toBeGreaterThan(0);
        });
    });

    // ============ failOperation ============

    describe('failOperation', () => {
        it('should mark operation as error with message', () => {
            const id = getState().addOperation({ type: 'upload', filename: 'file.bin' });
            getState().failOperation(id, 'Network error');

            const op = getState().operations[0]!;
            expect(op.status).toBe('error');
            expect(op.error).toBe('Network error');
        });
    });

    // ============ removeOperation ============

    describe('removeOperation', () => {
        it('should remove an operation by id', () => {
            const id = getState().addOperation({ type: 'upload', filename: 'file.bin' });
            getState().removeOperation(id);

            expect(getState().operations).toHaveLength(0);
        });

        it('should only remove the target operation', () => {
            getState().addOperation({ type: 'upload', filename: 'a.txt' });
            const id2 = getState().addOperation({ type: 'upload', filename: 'b.txt' });
            getState().removeOperation(id2);

            expect(getState().operations).toHaveLength(1);
            expect(getState().operations[0]!.filename).toBe('a.txt');
        });
    });

    // ============ clearCompleted ============

    describe('clearCompleted', () => {
        it('should remove only completed operations', () => {
            const id1 = getState().addOperation({ type: 'upload', filename: 'done.txt' });
            getState().addOperation({ type: 'upload', filename: 'active.txt', status: 'uploading' });
            const id3 = getState().addOperation({ type: 'download', filename: 'failed.txt' });

            getState().completeOperation(id1);
            getState().failOperation(id3, 'err');

            getState().clearCompleted();

            const ops = getState().operations;
            expect(ops).toHaveLength(2);
            expect(ops.map(o => o.filename)).toEqual(['active.txt', 'failed.txt']);
        });

        it('should do nothing when no completed operations', () => {
            getState().addOperation({ type: 'upload', filename: 'active.txt', status: 'uploading' });
            getState().clearCompleted();

            expect(getState().operations).toHaveLength(1);
        });
    });

    // ============ getHasActiveOperations (non-React) ============

    describe('getHasActiveOperations', () => {
        it('returns false when no operations exist', () => {
            expect(getHasActiveOperations()).toBe(false);
        });

        it('returns true when active operations exist', () => {
            getState().addOperation({ type: 'upload', filename: 'a.txt', status: 'uploading' });
            expect(getHasActiveOperations()).toBe(true);
        });

        it('returns false when all operations are terminal', () => {
            const id1 = getState().addOperation({ type: 'upload', filename: 'a.txt' });
            const id2 = getState().addOperation({ type: 'download', filename: 'b.txt' });
            getState().completeOperation(id1);
            getState().failOperation(id2, 'err');
            expect(getHasActiveOperations()).toBe(false);
        });
    });

    // ============ Selectors (tested via getState) ============

    describe('selectors', () => {
        it('should filter active operations correctly', () => {
            const id1 = getState().addOperation({ type: 'upload', filename: 'a.txt', status: 'uploading' });
            getState().addOperation({ type: 'download', filename: 'b.txt', status: 'downloading' });
            const id3 = getState().addOperation({ type: 'upload', filename: 'c.txt' });

            getState().completeOperation(id1);
            getState().failOperation(id3, 'err');

            const ops = getState().operations;
            const activeOps = ops.filter(
                (op) => op.status !== 'completed' && op.status !== 'error',
            );
            expect(activeOps).toHaveLength(1);
            expect(activeOps[0]!.filename).toBe('b.txt');
        });

        it('should compute correct operation counts', () => {
            const id1 = getState().addOperation({ type: 'upload', filename: 'a.txt', status: 'uploading' });
            getState().addOperation({ type: 'download', filename: 'b.txt', status: 'downloading' });
            const id3 = getState().addOperation({ type: 'upload', filename: 'c.txt' });

            getState().completeOperation(id1);
            getState().failOperation(id3, 'err');

            const ops = getState().operations;
            expect(ops).toHaveLength(3);
            expect(ops.filter((op) => op.status !== 'completed' && op.status !== 'error')).toHaveLength(1);
            expect(ops.filter((op) => op.status === 'completed')).toHaveLength(1);
            expect(ops.filter((op) => op.status === 'error')).toHaveLength(1);
        });
    });

    // ============ getLastActiveOperationStartTime ============

    describe('getLastActiveOperationStartTime', () => {
        it('should return null when no operations exist', () => {
            expect(getLastActiveOperationStartTime()).toBeNull();
        });

        it('should return null when all operations are terminal', () => {
            const id = getState().addOperation({ type: 'upload', filename: 'a.txt' });
            getState().completeOperation(id);

            expect(getLastActiveOperationStartTime()).toBeNull();
        });

        it('should return createdAt of the only active operation', () => {
            getState().addOperation({ type: 'upload', filename: 'a.txt', status: 'uploading' });

            const result = getLastActiveOperationStartTime();
            expect(result).toBeTypeOf('number');
            expect(result).toBeGreaterThan(0);
        });

        it('should return the most recent createdAt among active operations', () => {
            getState().addOperation({ type: 'upload', filename: 'a.txt', status: 'uploading' });

            // Manually set a second operation with a later timestamp
            const id2 = getState().addOperation({ type: 'download', filename: 'b.txt', status: 'downloading' });

            const result = getLastActiveOperationStartTime();
            const op2 = getState().operations.find(op => op.id === id2);
            expect(result).toBe(op2!.createdAt);
        });

        it('should ignore completed operations', () => {
            const id1 = getState().addOperation({ type: 'upload', filename: 'a.txt', status: 'uploading' });
            getState().addOperation({ type: 'download', filename: 'b.txt', status: 'downloading' });
            getState().completeOperation(id1);

            const result = getLastActiveOperationStartTime();
            const activeOps = getState().operations.filter(op => op.status !== 'completed');
            expect(result).toBe(activeOps[0]!.createdAt);
        });
    });
});
