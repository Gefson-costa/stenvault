# StenVault

Zero-knowledge encrypted cloud storage. All cryptography runs client-side — the server stores ciphertext and cannot read files, filenames, or passwords.

This repository is the open-source web client. The backend is proprietary (open-core model).

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

[stenvault.app](https://stenvault.app) · [Security Whitepaper](https://github.com/Gefson-costa/stenvault/blob/main/SECURITY_WHITEPAPER.md) · [Audit repo](https://github.com/Gefson-costa/stenvault-audit) · [RAG integration](https://github.com/Gefson-costa/stenvault-rag)

![StenVault vault interface](docs/assets/screenshot.png)

## Threat model

StenVault assumes the server is untrusted. A compromised server, a malicious operator, or a subpoena should yield nothing useful. Specifically:

- The server never receives plaintext file contents, filenames, or passwords
- Authentication uses OPAQUE (RFC 9807) — the server verifies credentials without ever seeing them
- File keys are generated per-file and wrapped client-side; the server transports ciphertext only
- Encrypted filenames prevent metadata leakage at the storage layer
- Password changes re-wrap the master key without re-encrypting files

The post-quantum layer (V4) additionally protects against harvest-now-decrypt-later attacks targeting files encrypted today.

For full cryptographic flows, database schemas, and architectural decisions, see the [security whitepaper](https://github.com/Gefson-costa/stenvault/blob/main/SECURITY_WHITEPAPER.md).

## Cryptography

NIST finalized FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) in August 2024. This client implements both in hybrid mode alongside the classical algorithms they replace:

| Primitive | Classical | Post-Quantum | Purpose |
|-----------|-----------|--------------|---------|
| Key encapsulation | X25519 ECDH | ML-KEM-768 (FIPS 203) | Per-file key wrapping |
| Digital signatures | Ed25519 | ML-DSA-65 (FIPS 204) | File integrity |
| Password auth | — | — | OPAQUE (RFC 9807) |
| File encryption | AES-256-GCM | — | Content encryption |
| Key derivation | Argon2id (47 MiB, OWASP 2024) | — | Password → KEK |

File format: [CVEF v1.2](https://github.com/Gefson-costa/stenvault/blob/main/SECURITY_WHITEPAPER.md#21-cvef-file-format) (Crypto Vault Encrypted File) — binary format with versioned metadata headers and algorithm identifiers for forward compatibility. Each file declares what it needs for decryption, so future algorithm transitions don't break existing files.

## Key hierarchy

```
Password → Argon2id (47 MiB) → KEK → AES-KW → Master Key (32 bytes)
                                                    ├─ File keys
                                                    ├─ Filename keys
                                                    └─ Key pair wrapping
```

Per-file (V4 hybrid PQC):

```
Random File Key (32 bytes)
       │
┌──────┴──────┐
X25519-ECDH  ML-KEM-768
└──────┬──────┘
   HKDF-SHA256 → Hybrid KEK
       │
   AES-KW Wrap → Wrapped FK
       │
   AES-256-GCM(FK, file)
```

## Features

StenVault extends beyond encrypted storage into a zero-knowledge platform:

- **Shamir recovery** — K-of-N threshold splitting of the master key across trusted contacts. No single point of failure for account recovery.
- **Public Send** (`/send`) — share an encrypted file with anyone, no account needed. The decryption key lives in the URL fragment (`#key=...`), never sent to the server.
- **P2P transfers** — browser-to-browser via WebRTC, with optional Shamir splitting.
- **E2E chat** — encrypted messaging between users with hybrid key exchange.
- **Proof-of-existence** — file hash anchoring to Bitcoin via OpenTimestamps.

## Source map

If you are auditing the cryptography:

| File | What it does |
|------|-------------|
| `apps/web/src/lib/fileCrypto.ts` | AES-256-GCM file encryption |
| `apps/web/src/lib/hybridFileCrypto.ts` | V4 hybrid PQC encryption |
| `apps/web/src/lib/streamingCrypto.ts` | Chunked streaming for large files |
| `apps/web/src/lib/opaqueClient.ts` | OPAQUE zero-knowledge auth |
| `apps/web/src/hooks/useMasterKey.ts` | Argon2id derivation, key wrapping |
| `apps/web/src/hooks/masterKeyCrypto.ts` | AES-KW wrap/unwrap |
| `apps/web/src/lib/platform/webHybridKemProvider.ts` | ML-KEM-768 + X25519 |
| `apps/web/src/lib/platform/webHybridSignatureProvider.ts` | ML-DSA-65 + Ed25519 |
| `apps/web/src/lib/pqcWorkerClient.ts` | Promise API for the PQC Web Worker |
| `apps/web/src/lib/workers/pqc.worker.ts` | Dedicated Web Worker — isolates all WASM memory from main thread |

## Structure

```
apps/web/                         React 19 + Vite 7
  src/lib/
    fileCrypto.ts                 AES-256-GCM encryption
    hybridFileCrypto.ts           V4 hybrid PQC
    streamingCrypto.ts            Chunked streaming
    publicSendCrypto.ts           /send crypto
    opaqueClient.ts               OPAQUE auth
    platform/
      webHybridKemProvider.ts     ML-KEM-768
      webHybridSignatureProvider.ts  ML-DSA-65
    workers/
      pqc.worker.ts               PQC WASM isolated in Web Worker
  src/hooks/
    useMasterKey.ts               Key derivation & wrapping
    masterKeyCrypto.ts            AES-KW operations
    useE2ECrypto.ts               Chat crypto

packages/shared/                  Types, CVEF format, crypto utils
packages/api-types/               Generated API types
```

## Stack

React 19, TypeScript (strict), Vite 7, TailwindCSS 4, Wouter, TanStack Query, Zustand, WebCrypto API, [@stenvault/pqc-wasm](https://www.npmjs.com/package/@stenvault/pqc-wasm) (RustCrypto WASM), @serenity-kit/opaque, Vitest.

## Building and testing

This is the client only — a StenVault backend is required for full operation. The cryptographic code can be audited and tested independently:

```bash
pnpm install
pnpm test          # 3,900+ tests across 145 files
pnpm build
```

The full system (client + backend) exposes a 26-router tRPC API. See the [security whitepaper](https://github.com/Gefson-costa/stenvault/blob/main/SECURITY_WHITEPAPER.md) for the complete architecture.

## Contributing

Crypto audits and security reviews are the most useful contributions. Bug reports and PRs welcome.

## Ecosystem

| Project | Purpose |
|---------|---------|
| **StenVault** (this repo) | Zero-knowledge encrypted cloud storage (open-source client) |
| [StenVault Audit](https://github.com/Gefson-costa/stenvault-audit) | Automated security audit pipeline — tree-sitter AST + AI triage |
| [StenVault RAG](https://github.com/Gefson-costa/stenvault-rag) | Local codebase search and Q&A over the StenVault source |

## Security

Report vulnerabilities to [security@stenvault.app](mailto:security@stenvault.app). Do not open public issues for security bugs.

## License

[GPL-3.0](LICENSE). The backend is proprietary — this repo covers the client and shared libraries.
