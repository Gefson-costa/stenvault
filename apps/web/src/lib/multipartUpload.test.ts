/**
 * Multipart Upload Tests
 *
 * Tests large file upload logic:
 * - Part calculation correctness (all bytes accounted for)
 * - ETag parsing (with/without quotes)
 * - Progress tracking accuracy
 * - Threshold detection
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    shouldUseMultipart,
    calculateParts,
    uploadPart,
    performMultipartUpload,
} from './multipartUpload';

vi.mock('@/lib/debugLogger', () => ({ debugLog: vi.fn() }));

// ============ XHR Mock Helper ============

function createMockXhr(opts: {
    status?: number;
    etag?: string | null;
    triggerError?: boolean;
    progressEvents?: { loaded: number; total: number }[];
} = {}) {
    const handlers: Record<string, Function> = {};
    const uploadHandlers: Record<string, Function> = {};

    const xhr = {
        open: vi.fn(),
        send: vi.fn(() => {
            // Fire progress events
            if (opts.progressEvents) {
                for (const evt of opts.progressEvents) {
                    uploadHandlers['progress']?.({ lengthComputable: true, ...evt });
                }
            }

            if (opts.triggerError) {
                handlers['error']?.();
            } else {
                xhr.status = opts.status ?? 200;
                handlers['load']?.();
            }
        }),
        status: 0,
        upload: {
            addEventListener: vi.fn((event: string, handler: Function) => {
                uploadHandlers[event] = handler;
            }),
        },
        addEventListener: vi.fn((event: string, handler: Function) => {
            handlers[event] = handler;
        }),
        getResponseHeader: vi.fn((header: string) => {
            if (header === 'ETag') return opts.etag ?? null;
            return null;
        }),
    };

    return xhr;
}

describe('Multipart Upload', () => {

    // ============ shouldUseMultipart ============

    describe('shouldUseMultipart', () => {
        const THRESHOLD = 500 * 1024 * 1024; // 500MB

        it('should return true when file exceeds threshold', () => {
            expect(shouldUseMultipart(THRESHOLD + 1, THRESHOLD)).toBe(true);
        });

        it('should return false when file equals threshold', () => {
            expect(shouldUseMultipart(THRESHOLD, THRESHOLD)).toBe(false);
        });

        it('should return false when file is smaller', () => {
            expect(shouldUseMultipart(1024, THRESHOLD)).toBe(false);
        });

        it('should return false for empty file', () => {
            expect(shouldUseMultipart(0, THRESHOLD)).toBe(false);
        });
    });

    // ============ calculateParts ============

    describe('calculateParts', () => {
        it('should calculate single part for small file', () => {
            const parts = calculateParts(100, 1000);
            expect(parts).toEqual([{ start: 0, end: 100, partNumber: 1 }]);
        });

        it('should calculate exact split', () => {
            const parts = calculateParts(300, 100);
            expect(parts).toEqual([
                { start: 0, end: 100, partNumber: 1 },
                { start: 100, end: 200, partNumber: 2 },
                { start: 200, end: 300, partNumber: 3 },
            ]);
        });

        it('should handle remainder in last part', () => {
            const parts = calculateParts(250, 100);
            expect(parts).toEqual([
                { start: 0, end: 100, partNumber: 1 },
                { start: 100, end: 200, partNumber: 2 },
                { start: 200, end: 250, partNumber: 3 },
            ]);
        });

        it('should account for all bytes (no loss)', () => {
            const fileSize = 1_073_741_824; // 1GB
            const partSize = 100 * 1024 * 1024; // 100MB
            const parts = calculateParts(fileSize, partSize);

            const totalBytes = parts.reduce((sum, p) => sum + (p.end - p.start), 0);
            expect(totalBytes).toBe(fileSize);
        });

        it('should have contiguous ranges (no gaps)', () => {
            const parts = calculateParts(500, 120);

            for (let i = 1; i < parts.length; i++) {
                expect(parts[i]!.start).toBe(parts[i - 1]!.end);
            }
            expect(parts[0]!.start).toBe(0);
            expect(parts[parts.length - 1]!.end).toBe(500);
        });

        it('should number parts starting from 1', () => {
            const parts = calculateParts(300, 100);
            expect(parts.map(p => p.partNumber)).toEqual([1, 2, 3]);
        });

        it('should return empty array for zero-size file', () => {
            const parts = calculateParts(0, 100);
            expect(parts).toEqual([]);
        });

        it('should handle file size equal to part size', () => {
            const parts = calculateParts(100, 100);
            expect(parts).toEqual([{ start: 0, end: 100, partNumber: 1 }]);
        });

        it('should handle very large file (5GB)', () => {
            const fileSize = 5 * 1024 * 1024 * 1024; // 5GB
            const partSize = 100 * 1024 * 1024; // 100MB
            const parts = calculateParts(fileSize, partSize);

            expect(parts.length).toBe(Math.ceil(fileSize / partSize));
            const totalBytes = parts.reduce((sum, p) => sum + (p.end - p.start), 0);
            expect(totalBytes).toBe(fileSize);
        });
    });

    // ============ uploadPart ============

    describe('uploadPart', () => {
        afterEach(() => {
            vi.restoreAllMocks();
        });

        function stubXhr(opts: Parameters<typeof createMockXhr>[0]) {
            const xhr = createMockXhr(opts);
            // Return object from constructor so `new` uses it directly
            vi.stubGlobal('XMLHttpRequest', function() { return xhr; });
            return xhr;
        }

        it('should resolve with ETag on success (quotes stripped)', async () => {
            stubXhr({ status: 200, etag: '"abc123"' });

            const blob = new Blob(['hello world']);
            const etag = await uploadPart(blob, 0, 5, 'https://r2.example.com/upload');
            expect(etag).toBe('abc123');

            vi.unstubAllGlobals();
        });

        it('should handle ETag without quotes', async () => {
            stubXhr({ status: 200, etag: 'no-quotes' });

            const blob = new Blob(['data']);
            const etag = await uploadPart(blob, 0, 4, 'https://example.com');
            expect(etag).toBe('no-quotes');

            vi.unstubAllGlobals();
        });

        it('should reject when no ETag in response', async () => {
            stubXhr({ status: 200, etag: null });

            const blob = new Blob(['data']);
            await expect(uploadPart(blob, 0, 4, 'https://example.com'))
                .rejects.toThrow('No ETag in response');

            vi.unstubAllGlobals();
        });

        it('should reject on HTTP error', async () => {
            stubXhr({ status: 403 });

            const blob = new Blob(['data']);
            await expect(uploadPart(blob, 0, 4, 'https://example.com'))
                .rejects.toThrow('Part upload failed: 403');

            vi.unstubAllGlobals();
        });

        it('should reject on network error', async () => {
            stubXhr({ triggerError: true });

            const blob = new Blob(['data']);
            await expect(uploadPart(blob, 0, 4, 'https://example.com'))
                .rejects.toThrow('Part upload failed - network error');

            vi.unstubAllGlobals();
        });

        it('should call onProgress callback', async () => {
            const onProgress = vi.fn();
            stubXhr({
                status: 200,
                etag: '"etag"',
                progressEvents: [{ loaded: 50, total: 100 }],
            });

            const blob = new Blob(['x'.repeat(100)]);
            await uploadPart(blob, 0, 100, 'https://example.com', onProgress);

            expect(onProgress).toHaveBeenCalledWith(50, 100);

            vi.unstubAllGlobals();
        });

        it('should use PUT method with correct URL', async () => {
            const xhr = stubXhr({ status: 200, etag: '"etag"' });

            const blob = new Blob(['data']);
            await uploadPart(blob, 0, 4, 'https://r2.example.com/presigned-url');

            expect(xhr.open).toHaveBeenCalledWith('PUT', 'https://r2.example.com/presigned-url');

            vi.unstubAllGlobals();
        });
    });

    // ============ performMultipartUpload ============

    describe('performMultipartUpload', () => {
        afterEach(() => {
            vi.unstubAllGlobals();
            vi.restoreAllMocks();
        });

        function stubXhrSequence() {
            let callIndex = 0;
            vi.stubGlobal('XMLHttpRequest', function() {
                const partNum = ++callIndex;
                return createMockXhr({ status: 200, etag: `"etag-part-${partNum}"` });
            });
        }

        it('should upload all parts and return results', async () => {
            stubXhrSequence();

            const blob = new Blob(['x'.repeat(300)]);
            const results = await performMultipartUpload(blob, {
                partSize: 100,
                getPartUrl: vi.fn().mockResolvedValue('https://r2.example.com/upload'),
            });

            expect(results).toHaveLength(3);
            expect(results.map(r => r.partNumber)).toEqual([1, 2, 3]);
            expect(results.map(r => r.etag)).toEqual(['etag-part-1', 'etag-part-2', 'etag-part-3']);
        });

        it('should call getPartUrl with correct partNumber and size', async () => {
            stubXhrSequence();

            const getPartUrl = vi.fn().mockResolvedValue('https://example.com/upload');
            const blob = new Blob(['x'.repeat(250)]);

            await performMultipartUpload(blob, { partSize: 100, getPartUrl });

            expect(getPartUrl).toHaveBeenCalledWith(1, 100);
            expect(getPartUrl).toHaveBeenCalledWith(2, 100);
            expect(getPartUrl).toHaveBeenCalledWith(3, 50);
        });

        it('should report initial progress at 0%', async () => {
            stubXhrSequence();

            const onProgress = vi.fn();
            const blob = new Blob(['x'.repeat(200)]);

            await performMultipartUpload(blob, {
                partSize: 100,
                getPartUrl: vi.fn().mockResolvedValue('https://example.com/upload'),
                onProgress,
            });

            expect(onProgress).toHaveBeenCalledWith(
                expect.objectContaining({ phase: 'uploading', percentage: 0, bytesUploaded: 0 })
            );
        });

        it('should report completing phase at 100%', async () => {
            stubXhrSequence();

            const onProgress = vi.fn();
            const blob = new Blob(['x'.repeat(100)]);

            await performMultipartUpload(blob, {
                partSize: 100,
                getPartUrl: vi.fn().mockResolvedValue('https://example.com/upload'),
                onProgress,
            });

            const lastCall = onProgress.mock.calls[onProgress.mock.calls.length - 1]![0];
            expect(lastCall.phase).toBe('completing');
            expect(lastCall.percentage).toBe(100);
            expect(lastCall.bytesUploaded).toBe(100);
            expect(lastCall.totalBytes).toBe(100);
        });

        it('should handle single-part file', async () => {
            stubXhrSequence();

            const blob = new Blob(['small']);
            const results = await performMultipartUpload(blob, {
                partSize: 1000,
                getPartUrl: vi.fn().mockResolvedValue('https://example.com/upload'),
            });

            expect(results).toHaveLength(1);
            expect(results[0]!.partNumber).toBe(1);
        });

        it('should abort remaining parts when one part fails (early abort)', async () => {
            let callIndex = 0;
            // Use delayed getPartUrl to force proper async interleaving
            // so the abort flag can propagate between workers
            const getPartUrl = vi.fn().mockImplementation(async () => {
                await new Promise(r => setTimeout(r, 1));
                return 'https://example.com/upload';
            });

            vi.stubGlobal('XMLHttpRequest', function() {
                const partNum = ++callIndex;
                // Part 2 fails with 403
                if (partNum === 2) {
                    return createMockXhr({ status: 403 });
                }
                return createMockXhr({ status: 200, etag: `"etag-${partNum}"` });
            });

            // 10 parts with 3 workers — after part 2 fails, remaining should be aborted
            const blob = new Blob(['x'.repeat(1000)]);

            await expect(performMultipartUpload(blob, {
                partSize: 100,
                getPartUrl,
            })).rejects.toThrow('Part upload failed: 403');

            // With the abort flag, fewer parts should be attempted than total (10)
            expect(getPartUrl.mock.calls.length).toBeLessThan(10);
        });

        it('should throw first error when multiple parts fail', async () => {
            vi.stubGlobal('XMLHttpRequest', function() {
                return createMockXhr({ status: 500 });
            });

            const blob = new Blob(['x'.repeat(300)]);

            await expect(performMultipartUpload(blob, {
                partSize: 100,
                getPartUrl: vi.fn().mockResolvedValue('https://example.com/upload'),
            })).rejects.toThrow('Part upload failed: 500');
        });
    });
});
