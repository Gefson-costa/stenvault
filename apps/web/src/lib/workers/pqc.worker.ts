/**
 * PQC Web Worker — Isolates liboqs WASM memory from the main thread
 *
 * All ML-KEM-768 and ML-DSA-65 operations run in this worker so that
 * XSS on the main thread cannot read the WASM linear memory buffer
 * (which contains PQC private keys during active operations).
 *
 * Security model:
 * - Main thread sends only public keys / ciphertexts / messages
 * - Worker returns results via postMessage (Transferable for zero-copy)
 * - WASM instance destroyed in `finally` after each operation
 * - Worker context is a separate JS execution environment
 *
 * @module pqc.worker
 */

// ============ Dynamic Import Types ============

interface MLKEM768Module {
    generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array };
    encapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array };
    decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
    destroy(): void;
}

interface MLDSA65Module {
    generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array };
    sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
    destroy(): void;
}

// ============ Factory Cache ============

let createMLKEM768Fn: (() => Promise<MLKEM768Module>) | null = null;
let mlkem768LoadAttempted = false;

let createMLDSA65Fn: (() => Promise<MLDSA65Module>) | null = null;
let mldsa65LoadAttempted = false;

async function getMLKEM768Factory(): Promise<(() => Promise<MLKEM768Module>) | null> {
    if (mlkem768LoadAttempted) return createMLKEM768Fn;
    mlkem768LoadAttempted = true;

    try {
        const { createMLKEM768 } = await import('@openforge-sh/liboqs');
        createMLKEM768Fn = () => createMLKEM768() as unknown as Promise<MLKEM768Module>;
        return createMLKEM768Fn;
    } catch {
        return null;
    }
}

async function getMLDSA65Factory(): Promise<(() => Promise<MLDSA65Module>) | null> {
    if (mldsa65LoadAttempted) return createMLDSA65Fn;
    mldsa65LoadAttempted = true;

    try {
        const { createMLDSA65 } = await import('@openforge-sh/liboqs');
        createMLDSA65Fn = () => createMLDSA65() as unknown as Promise<MLDSA65Module>;
        return createMLDSA65Fn;
    } catch {
        return null;
    }
}

// ============ Message Types ============

export type PQCRequest =
    | { id: string; op: 'mlkem768-generateKeyPair' }
    | { id: string; op: 'mlkem768-encapsulate'; publicKey: Uint8Array }
    | { id: string; op: 'mlkem768-decapsulate'; ciphertext: Uint8Array; secretKey: Uint8Array }
    | { id: string; op: 'mldsa65-generateKeyPair' }
    | { id: string; op: 'mldsa65-sign'; message: Uint8Array; secretKey: Uint8Array }
    | { id: string; op: 'mldsa65-verify'; message: Uint8Array; signature: Uint8Array; publicKey: Uint8Array };

export type PQCResponse =
    | { id: string; op: string; error: string }
    | { id: string; op: 'mlkem768-generateKeyPair'; publicKey: Uint8Array; secretKey: Uint8Array }
    | { id: string; op: 'mlkem768-encapsulate'; ciphertext: Uint8Array; sharedSecret: Uint8Array }
    | { id: string; op: 'mlkem768-decapsulate'; sharedSecret: Uint8Array }
    | { id: string; op: 'mldsa65-generateKeyPair'; publicKey: Uint8Array; secretKey: Uint8Array }
    | { id: string; op: 'mldsa65-sign'; signature: Uint8Array }
    | { id: string; op: 'mldsa65-verify'; valid: boolean }
    | { type: 'ready' };

// ============ Helpers ============

function requireFactory<T>(factory: T | null, name: string): T {
    if (!factory) {
        throw new Error(`${name} WASM not available in PQC Worker`);
    }
    return factory;
}

// ============ Worker Message Handler ============

self.onmessage = async (event: MessageEvent<PQCRequest>) => {
    const { id, op } = event.data;

    try {
        switch (op) {
            // ---- ML-KEM-768 ----

            case 'mlkem768-generateKeyPair': {
                const factory = requireFactory(await getMLKEM768Factory(), 'ML-KEM-768');
                const instance = await factory();
                try {
                    const { publicKey, secretKey } = instance.generateKeyPair();
                    // Copy before destroy — WASM memory is freed in finally
                    const pub = new Uint8Array(publicKey);
                    const sec = new Uint8Array(secretKey);
                    (self as unknown as Worker).postMessage(
                        { id, op, publicKey: pub, secretKey: sec } satisfies PQCResponse,
                        { transfer: [pub.buffer, sec.buffer] }
                    );
                } finally {
                    instance.destroy();
                }
                break;
            }

            case 'mlkem768-encapsulate': {
                const { publicKey } = event.data as Extract<PQCRequest, { op: 'mlkem768-encapsulate' }>;
                const factory = requireFactory(await getMLKEM768Factory(), 'ML-KEM-768');
                const instance = await factory();
                try {
                    const result = instance.encapsulate(publicKey);
                    const ct = new Uint8Array(result.ciphertext);
                    const ss = new Uint8Array(result.sharedSecret);
                    (self as unknown as Worker).postMessage(
                        { id, op, ciphertext: ct, sharedSecret: ss } satisfies PQCResponse,
                        { transfer: [ct.buffer, ss.buffer] }
                    );
                } finally {
                    instance.destroy();
                }
                break;
            }

            case 'mlkem768-decapsulate': {
                const { ciphertext, secretKey } = event.data as Extract<PQCRequest, { op: 'mlkem768-decapsulate' }>;
                const factory = requireFactory(await getMLKEM768Factory(), 'ML-KEM-768');
                const instance = await factory();
                try {
                    const result = instance.decapsulate(ciphertext, secretKey);
                    const ss = new Uint8Array(result);
                    (self as unknown as Worker).postMessage(
                        { id, op, sharedSecret: ss } satisfies PQCResponse,
                        { transfer: [ss.buffer] }
                    );
                } finally {
                    instance.destroy();
                }
                break;
            }

            // ---- ML-DSA-65 ----

            case 'mldsa65-generateKeyPair': {
                const factory = requireFactory(await getMLDSA65Factory(), 'ML-DSA-65');
                const instance = await factory();
                try {
                    const { publicKey, secretKey } = instance.generateKeyPair();
                    const pub = new Uint8Array(publicKey);
                    const sec = new Uint8Array(secretKey);
                    (self as unknown as Worker).postMessage(
                        { id, op, publicKey: pub, secretKey: sec } satisfies PQCResponse,
                        { transfer: [pub.buffer, sec.buffer] }
                    );
                } finally {
                    instance.destroy();
                }
                break;
            }

            case 'mldsa65-sign': {
                const { message, secretKey } = event.data as Extract<PQCRequest, { op: 'mldsa65-sign' }>;
                const factory = requireFactory(await getMLDSA65Factory(), 'ML-DSA-65');
                const instance = await factory();
                try {
                    const result = instance.sign(message, secretKey);
                    const sig = new Uint8Array(result);
                    (self as unknown as Worker).postMessage(
                        { id, op, signature: sig } satisfies PQCResponse,
                        { transfer: [sig.buffer] }
                    );
                } finally {
                    instance.destroy();
                }
                break;
            }

            case 'mldsa65-verify': {
                const { message, signature, publicKey } = event.data as Extract<PQCRequest, { op: 'mldsa65-verify' }>;
                const factory = requireFactory(await getMLDSA65Factory(), 'ML-DSA-65');
                const instance = await factory();
                try {
                    const valid = instance.verify(message, signature, publicKey);
                    (self as unknown as Worker).postMessage(
                        { id, op, valid } satisfies PQCResponse
                    );
                } finally {
                    instance.destroy();
                }
                break;
            }

            default:
                self.postMessage({ id, op, error: `Unknown PQC operation: ${op}` });
        }
    } catch (error) {
        self.postMessage({
            id,
            op,
            error: error instanceof Error ? error.message : 'PQC Worker operation failed',
        });
    }
};

// Signal readiness
self.postMessage({ type: 'ready' });
