# StenVault Security Whitepaper

**Version 2.0 — March 2026**
**Classification: Public**

---

## Table of Contents

- [1. Introduction](#1-introduction)
- [2. Security Principles](#2-security-principles)
- [3. Threat Model](#3-threat-model)
- [4. Cryptographic Primitives](#4-cryptographic-primitives)
- [5. Key Management](#5-key-management)
- [6. Authentication](#6-authentication)
- [7. File Encryption](#7-file-encryption)
- [8. File Sharing](#8-file-sharing)
- [9. Key Recovery](#9-key-recovery)
- [10. Transport and Web Security](#10-transport-and-web-security)
- [11. Supply Chain Security](#11-supply-chain-security)
- [12. Post-Quantum Readiness](#12-post-quantum-readiness)
- [13. Limitations and Known Considerations](#13-limitations-and-known-considerations)
- [14. Audit and Compliance](#14-audit-and-compliance)
- [Appendix A: Cryptographic Constants](#appendix-a-cryptographic-constants)
- [Appendix B: Glossary](#appendix-b-glossary)
- [Appendix C: Standards and References](#appendix-c-standards-and-references)
- [Appendix D: Document History](#appendix-d-document-history)

---

## 1. Introduction

### 1.1 Purpose

This document describes the cryptographic architecture, threat model, and security properties of StenVault — a zero-knowledge encrypted cloud storage platform. It is intended for security auditors, researchers, and anyone evaluating StenVault's security posture.

StenVault is designed so that even the platform operator cannot access user data. All encryption and decryption operations execute exclusively on the client device. The server stores only ciphertext and can never derive plaintext file contents, filenames, or user passwords.

### 1.2 Scope

This whitepaper covers the open-source web client. The backend API is proprietary (open-core model). The complete client source code is available for independent review at [github.com/StenVault/stenvault](https://github.com/StenVault/stenvault).

**In scope**: client-side encryption, key derivation, key management, authentication protocol flows, post-quantum cryptography, recovery mechanisms, and web security controls.

**Out of scope**: server-side implementation, database internals, infrastructure configuration, and deployment architecture. The server is treated as an untrusted transport layer throughout this document.

### 1.3 Document Conventions

- Algorithm names reference their governing standard (e.g., "AES-256-GCM per NIST SP 800-38D")
- Key sizes are stated in bytes unless otherwise noted
- "Client" refers to the web application running in the user's browser
- "Server" refers to the backend API and storage infrastructure

---

## 2. Security Principles

### 2.1 Zero-Knowledge Architecture

The server never possesses the information necessary to decrypt user data. Encryption keys are derived from the user's password on the client device. The server stores wrapped (encrypted) keys and ciphertext — it cannot perform decryption at any point.

The term "zero-knowledge" as used in this document refers specifically to file contents, filenames, folder names, and user passwords. The server necessarily observes certain operational metadata (see [§3.4](#34-what-the-server-observes)).

### 2.2 Client-Side Encryption

All cryptographic operations — key derivation, encryption, decryption, signing, and verification — execute in the user's browser. Plaintext data never leaves the client device. The server receives only ciphertext and cryptographic metadata (public keys, KDF salts, initialization vectors).

### 2.3 Hybrid Post-Quantum Cryptography

StenVault combines classical algorithms (X25519, Ed25519) with NIST-standardized post-quantum algorithms (ML-KEM-768, ML-DSA-65) in a hybrid construction. An attacker must break both the classical and post-quantum component to compromise a file. This protects against harvest-now-decrypt-later attacks targeting data encrypted today.

### 2.4 Defense in Depth

Security does not depend on any single mechanism:

- **Password compromise** is mitigated by Argon2id's memory-hardness and OPAQUE's zero-knowledge property
- **Server compromise** is mitigated by client-side encryption — the server stores only ciphertext
- **Algorithm compromise** is mitigated by the hybrid construction — classical and post-quantum algorithms protect each other
- **Device compromise** is mitigated by per-device key isolation and revocable device trust
- **Key loss** is mitigated by recovery codes and Shamir secret sharing

### 2.5 Open Source Transparency

The complete client-side codebase, including all cryptographic implementations, is open source and available for independent review. Security through obscurity is not relied upon.

---

## 3. Threat Model

### 3.1 Adversary Classes

| Adversary | Capabilities | Assumed? |
|-----------|-------------|:---:|
| Passive network observer | Can observe encrypted traffic between client and server | Yes |
| Active network attacker | Can intercept, modify, or replay network traffic (mitigated by TLS 1.3) | Yes |
| Malicious server operator | Has full access to the server, database, and stored data | Yes |
| Compromised database | Attacker has obtained a full database dump | Yes |
| Quantum computer (future) | Can run Shor's algorithm against classical asymmetric cryptography | Yes |
| Compromised client device | Has full access to the browser and OS during an active session | No |
| Physical coercion | Can compel the user to reveal their password | No |

StenVault is designed to protect user data against all adversaries marked "Yes." Adversaries marked "No" represent fundamental limitations of any client-side encryption system.

### 3.2 Security Goals

| Goal | Description | Mechanism |
|------|-------------|-----------|
| **Confidentiality** | File contents, filenames, and passwords are never accessible to the server | Client-side AES-256-GCM encryption, OPAQUE authentication |
| **Integrity** | Tampering with encrypted data is detected before decryption | GCM authentication tags, hybrid digital signatures |
| **Authenticity** | File origin can be cryptographically verified | Ed25519 + ML-DSA-65 dual signatures |
| **Forward secrecy** | Compromise of one file key does not affect other files | Per-file ephemeral key exchange |
| **Post-quantum resistance** | Data encrypted today remains secure against future quantum computers | Hybrid KEM (X25519 + ML-KEM-768) |

### 3.3 Trust Assumptions

1. **The client device is trusted** during an active session. The browser and operating system are assumed to be uncompromised while the vault is unlocked.
2. **The server is honest-but-curious.** StenVault is designed so that a fully compromised server cannot access user data. The server may attempt to read stored data but is assumed to follow the protocol (it does not serve malicious client code).
3. **TLS 1.3 is functional.** Network transport relies on TLS 1.3 with HSTS preload. A TLS compromise would expose traffic metadata but not file contents, which are encrypted before transmission.
4. **Cryptographic primitives are sound.** StenVault relies on peer-reviewed, standardized algorithms. The hybrid approach mitigates the impact if any single primitive is broken.
5. **The browser's CSPRNG is reliable.** Key material is generated using `crypto.getRandomValues`, which relies on the operating system's entropy source.

### 3.4 What the Server Observes

The zero-knowledge property applies to file contents, filenames, and passwords. The server necessarily observes the following operational metadata:

- User email addresses and IP addresses
- File sizes (before and after encryption)
- Upload and download timestamps
- Access frequency and patterns
- Number of files and total storage consumption
- Public keys (X25519, ML-KEM-768, Ed25519, ML-DSA-65)
- KDF salts, initialization vectors, and encryption version identifiers
- OPAQUE registration records (which do not contain the password)

Full metadata encryption (including file sizes) would require significant padding overhead and is not currently implemented.

### 3.5 Trust Boundary

```
┌───────────────────────────────────────────────────────────────────────┐
│                       ZERO-KNOWLEDGE BOUNDARY                          │
│                                                                        │
│  ┌──── CLIENT (TRUSTED) ────────────────────────────────────────────┐ │
│  │                                                                   │ │
│  │  Plaintext files and filenames                                    │ │
│  │  User password (never transmitted)                                │ │
│  │  Master Key (non-extractable, in memory only)                     │ │
│  │  Per-file encryption keys (ephemeral)                             │ │
│  │  Hybrid secret keys (X25519 + ML-KEM-768)                        │ │
│  │  Signature secret keys (Ed25519 + ML-DSA-65)                     │ │
│  │  Chat messages (decrypted)                                        │ │
│  │                                                                   │ │
│  └─────────────────────────────┬─────────────────────────────────────┘ │
│                                │                                       │
│                    HTTPS (TLS 1.3) — ciphertext only                   │
│                                │                                       │
│  ┌──── SERVER (UNTRUSTED) ─────┴────────────────────────────────────┐ │
│  │                                                                   │ │
│  │  Encrypted file blobs (AES-256-GCM ciphertext)                    │ │
│  │  Encrypted filenames (ciphertext)                                  │ │
│  │  Wrapped master key (AES-KW ciphertext)                           │ │
│  │  Encrypted secret keys (wrapped with Master Key)                   │ │
│  │  Public keys, KDF salts, IVs, encryption version                  │ │
│  │  File sizes, MIME types, timestamps                                │ │
│  │  OPAQUE registration record (not password-equivalent)              │ │
│  │                                                                   │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

Even if the server's database and object storage are completely compromised, an attacker obtains only encrypted data. The decryption keys exist only in the user's browser memory during an active session, derived from a password the server never sees.

---

## 4. Cryptographic Primitives

All cryptographic operations use standardized, peer-reviewed algorithms. No proprietary or novel cryptographic constructions are used.

### 4.1 Symmetric Encryption

**AES-256-GCM** (NIST SP 800-38D) is used for all symmetric encryption — file contents, filenames, thumbnails, and key wrapping of large post-quantum keys. GCM mode provides authenticated encryption in a single pass: confidentiality via CTR-mode encryption and integrity via a 128-bit authentication tag. Any modification to the ciphertext causes decryption to fail.

- Key size: 256 bits (32 bytes)
- IV size: 96 bits (12 bytes), generated from the browser's CSPRNG
- Authentication tag: 128 bits (16 bytes)

### 4.2 Key Derivation from Passwords

**Argon2id** (RFC 9106) derives encryption keys from user passwords. Argon2id is the winner of the Password Hashing Competition (2015) and is recommended by OWASP (2024 guidelines). The `id` variant combines data-dependent and data-independent memory access, providing resistance against both side-channel attacks and time-memory tradeoff attacks.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Memory cost | 47,104 KiB (46 MiB) | High enough to deter GPU/ASIC attacks; low enough for mobile browsers (~500ms) |
| Time cost | 1 iteration | Memory cost provides the primary defense; additional iterations add marginal benefit |
| Parallelism | 1 | Single-threaded for consistent performance across devices |
| Output length | 32 bytes | Matches AES-256 key length |

At 46 MiB memory per evaluation, an attacker attempting a brute-force attack would require approximately 46 TB of memory to run one million parallel evaluations. This makes large-scale password cracking economically impractical even with specialized hardware.

### 4.3 Key Derivation from Shared Secrets

**HKDF-SHA256** (RFC 5869) derives keys from Diffie-Hellman shared secrets and other high-entropy inputs. HKDF is used to combine classical and post-quantum shared secrets in the hybrid construction, and to derive filename encryption keys from the Master Key.

### 4.4 Key Wrapping

**AES-KW** (RFC 3394) wraps keys with other keys. AES-KW adds an 8-byte integrity check, ensuring that key material is not silently corrupted. It is used to wrap the Master Key with the KEK, and to wrap per-file encryption keys with the hybrid KEK.

AES-KW is designed for keys up to approximately 64 bytes. Post-quantum secret keys exceed this limit and are handled separately (see [§5.5](#55-key-storage-and-protection)).

### 4.5 Classical Asymmetric Cryptography

**X25519** (RFC 7748) provides elliptic curve Diffie-Hellman key agreement. Each file uses an ephemeral X25519 keypair, providing forward secrecy at the file level.

**Ed25519** (RFC 8032) provides digital signatures for file integrity and non-repudiation. Ed25519 is constant-time, preventing timing side-channel attacks.

### 4.6 Post-Quantum Cryptography

**ML-KEM-768** (FIPS 203) provides lattice-based key encapsulation, resistant to attacks by quantum computers. ML-KEM-768 operates at NIST Security Level 3 (roughly equivalent to AES-192 against quantum adversaries).

**ML-DSA-65** (FIPS 204) provides lattice-based digital signatures, also at NIST Security Level 3. Both standards were finalized by NIST in August 2024.

Post-quantum operations are implemented in WebAssembly (compiled from auditable Rust source using the RustCrypto `ml-kem` and `ml-dsa` crates) and execute in a dedicated Web Worker to isolate secret key material from the main browser thread (see [§11](#11-supply-chain-security)).

### 4.7 Hybrid Construction Rationale

StenVault never uses a post-quantum algorithm alone. Every post-quantum operation is paired with a classical counterpart:

| Operation | Classical | Post-Quantum | Combined via |
|-----------|-----------|-------------|--------------|
| Key exchange | X25519 ECDH | ML-KEM-768 Encapsulate | HKDF-SHA256 |
| Digital signature | Ed25519 | ML-DSA-65 | Both must verify |

This hybrid approach is motivated by two observations:

1. **ML-KEM-768 and ML-DSA-65 are new.** While they passed extensive NIST evaluation, they lack decades of real-world cryptanalysis. If a flaw is discovered in lattice-based schemes, the classical algorithms still protect the data.

2. **X25519 and Ed25519 are vulnerable to quantum attacks.** Shor's algorithm can break elliptic curve cryptography on a sufficiently powerful quantum computer. ML-KEM-768 and ML-DSA-65 are designed to resist such attacks.

An attacker must break both the classical and the post-quantum component to compromise a file's confidentiality or forge a signature. If either class of algorithm is compromised, the other maintains protection.

---

## 5. Key Management

### 5.1 Key Hierarchy

StenVault uses a layered key hierarchy that separates authentication credentials from encryption keys. Password changes do not require re-encrypting stored files — only the key wrapping changes.

```
User Password (never leaves the browser)
│
├── Argon2id(password, salt) ──► KEK (Key Encryption Key, 32 bytes)
│                                  │
│                                  └── AES-KW Unwrap ──► Master Key (32 bytes)
│                                                          │
│                                                          ├── Filename keys (HKDF derived)
│                                                          ├── Folder name keys (HKDF derived)
│                                                          ├── Thumbnail keys (HKDF derived)
│                                                          ├── X25519 secret key (AES-KW wrapped)
│                                                          ├── ML-KEM-768 secret key (AES-GCM encrypted)
│                                                          ├── Ed25519 secret key (AES-KW wrapped)
│                                                          ├── ML-DSA-65 secret key (AES-GCM encrypted)
│                                                          └── Organization Master Key (AES-KW wrapped)
│
└── [UES fast path] ──► Device-KEK (password + device entropy, lower Argon2id cost)
                          └── AES-KW Unwrap ──► same Master Key
```

### 5.2 Master Key

The Master Key is a 32-byte random value generated once during initial encryption setup using the browser's CSPRNG. It is the root of the key hierarchy — all other keys are either derived from it (via HKDF) or wrapped by it (via AES-KW or AES-256-GCM).

The Master Key is never stored in plaintext. It is always wrapped (encrypted) with the KEK before transmission to the server. At rest on the server, only the wrapped form exists.

### 5.3 Key Encryption Key (KEK)

The KEK is derived from the user's password via Argon2id. It exists only in memory during the derivation process and is used solely to unwrap (decrypt) the Master Key. The KEK is not stored anywhere.

When a user changes their password, a new KEK is derived from the new password and wraps the same Master Key. The server stores the newly wrapped Master Key. No file re-encryption is required.

### 5.4 Per-File Encryption Keys

Each file is encrypted with a unique, randomly generated 32-byte file key. This key is then wrapped using the hybrid KEM construction (X25519 + ML-KEM-768 → HKDF → AES-KW). The wrapped file key is stored in the file's CVEF header.

Ephemeral key exchange per file ensures that compromise of one file key does not reveal any other file's contents.

### 5.5 Key Storage and Protection

**Runtime protection**: The Master Key is imported as a non-extractable `CryptoKey` object via the WebCrypto API (`extractable: false`). Raw key bytes are zeroed immediately after import. Even JavaScript code running in the same page context cannot read the raw key material — it can only invoke cryptographic operations through the WebCrypto API.

**Post-quantum key sizes**: ML-KEM-768 secret keys (2,400 bytes) and ML-DSA-65 secret keys (4,032 bytes) exceed the capacity of AES-KW, which is designed for keys up to approximately 64 bytes.

| Key | Size | Wrapping method |
|-----|:---:|----------------|
| X25519 secret | 32 bytes | AES-KW (RFC 3394) |
| Ed25519 secret | 32 bytes | AES-KW (RFC 3394) |
| ML-KEM-768 secret | 2,400 bytes | AES-256-GCM with separate random IV |
| ML-DSA-65 secret | 4,032 bytes | AES-256-GCM with separate random IV |

Both methods provide confidentiality and integrity — AES-KW via its 8-byte integrity check, AES-GCM via its 16-byte authentication tag.

**Post-quantum Web Worker isolation**: All ML-KEM-768 and ML-DSA-65 operations execute in a dedicated Web Worker. Post-quantum secret keys never exist in the main browser thread's memory. This provides a security boundary against cross-site scripting (XSS) attacks — even if an attacker achieves JavaScript execution in the main thread, they cannot access the Web Worker's linear memory.

### 5.6 Key Rotation

Password changes re-wrap the Master Key with a new KEK. The Master Key itself does not change, so no files need re-encryption. This completes in milliseconds regardless of the number of stored files.

Hybrid key pair rotation (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65) can be triggered by the user. New key pairs are generated and wrapped with the Master Key. Previously encrypted files remain accessible via the old key pair, which is retained in wrapped form.

---

## 6. Authentication

### 6.1 OPAQUE Protocol (RFC 9807)

StenVault uses OPAQUE (Oblivious Pseudo-Random Function with Asymmetric Password-Authenticated Key Exchange), a zero-knowledge password authentication protocol standardized in RFC 9807. The server never sees, receives, or processes the user's password in any form — not as plaintext, not as a hash, and not as any password-equivalent token.

### 6.2 How OPAQUE Works

**Registration** (one-time setup):

1. The client blinds the password using an Oblivious Pseudo-Random Function (OPRF) and sends the blinded value to the server
2. The server evaluates the OPRF with its private key and returns the result
3. The client derives a registration record from the unblinded result and sends it to the server
4. The server stores the registration record, which contains no password-equivalent information

**Login** (each session):

1. The client sends a blinded OPRF request to the server
2. The server evaluates the OPRF using the stored registration record and returns the result along with its public key
3. The client unblinds the result, derives session keys, and sends a proof to the server
4. The server verifies the proof and issues session tokens
5. Both parties achieve mutual authentication — the server proved it holds the correct record, and the client proved it knows the correct password

The password never crosses the network in any form. Even an attacker who intercepts every packet cannot extract the password. Even if the server's database is fully compromised, the stored registration record cannot be used for an offline dictionary attack without the server's private OPRF key.

### 6.3 Multi-Factor Authentication

StenVault supports two-factor authentication using Time-based One-Time Passwords (TOTP, RFC 6238):

- A random 32-byte TOTP secret is generated and encrypted before database storage
- 10 backup codes are generated, stored as HMAC-SHA256 digests, and compared using constant-time comparison to prevent timing attacks
- On login with MFA enabled, a short-lived challenge token is issued; full session tokens are granted only after TOTP verification
- Anti-replay protection prevents reuse of a TOTP code within its validity window (per RFC 6238 Section 5.2)

### 6.4 Session Management

Sessions use a two-token architecture:

- **Access tokens** are short-lived and delivered as HttpOnly cookies (with `Secure` and `SameSite` attributes). They are not accessible to JavaScript, preventing exfiltration via XSS.
- **Refresh tokens** are single-use with rotation and delivered as HttpOnly cookies. Each refresh operation invalidates the previous token and issues a new one.

**Token theft detection**: Each login creates a "token family" — a chain of refresh tokens linked by a family identifier. If a previously-rotated token is reused (indicating that a stolen token is being replayed), the entire token family is revoked and all sessions for the user are terminated. This ensures that token theft is detected on the first use by either the attacker or the legitimate user that creates a mismatch.

If the token revocation store is unavailable, the system fails **closed** — tokens cannot be verified as non-revoked, so they are rejected. This prevents an infrastructure outage from creating a window where revoked tokens are accepted.

### 6.5 Device Trust and Approval

New devices undergo an approval workflow before gaining fast-path vault unlock:

1. User logs in on a new device; slow-path Argon2id derivation is used
2. The new device registers as "pending" in the device registry
3. An existing approved device is notified and approves the new device
4. The approving device generates a **fresh** device entropy seed for the new device (it never shares its own)
5. The new device stores the encrypted seed and uses the fast-path derivation going forward

Each device has a unique entropy seed. Compromise of one device does not affect others. Users can revoke device trust at any time.

---

## 7. File Encryption

### 7.1 Encryption Flow

All files are encrypted using the V4 Hybrid PQC construction:

```
1. Generate random file key (32 bytes) from CSPRNG

2. Key exchange (hybrid):
   a. Generate ephemeral X25519 keypair
   b. ECDH(ephemeral secret, recipient X25519 public) → classical shared secret (32 bytes)
   c. ML-KEM-768.Encapsulate(recipient ML-KEM public) → PQ shared secret (32 bytes) + PQ ciphertext (1,088 bytes)
   d. HKDF-SHA256(classical ‖ PQ, context) → hybrid KEK (32 bytes)

3. Key wrapping:
   AES-KW(hybrid KEK, file key) → wrapped file key (40 bytes)

4. File encryption:
   AES-256-GCM(file key, IV, plaintext) → ciphertext + authentication tag

5. Output:
   CVEF header (metadata JSON) + ciphertext
```

**Decryption** reverses the process: the recipient uses their own X25519 and ML-KEM-768 secret keys to reconstruct the hybrid KEK, unwraps the file key, and decrypts the ciphertext. The GCM authentication tag is verified before any plaintext is returned.

### 7.2 Chunked Encryption for Large Files

Files above 100 MB are split into 64 KiB chunks for streaming encryption and decryption:

- Each chunk is encrypted independently with AES-256-GCM using the same file key
- Each chunk uses a unique initialization vector derived deterministically from a base IV and the chunk index, preventing IV reuse
- Each chunk's GCM authentication tag is verified before the decrypted plaintext is written to disk
- Peak memory consumption during decryption is approximately 128 KB regardless of file size

The client uses a tiered streaming approach to write decrypted data directly to disk:

- **Tier 1**: Native file system access API (available in Chromium-based browsers) provides a writable file stream with a native save dialog
- **Tier 2**: A Service Worker intercepts download requests and streams decrypted chunks via a `ReadableStream` (available in Firefox and Safari)
- **Tier 3**: For browsers without streaming support, the file is decrypted into a memory buffer and downloaded as a blob

Files under 100 MB are encrypted and decrypted as a single AES-256-GCM operation, as the WebCrypto API requires the complete ciphertext for non-chunked GCM decryption.

### 7.3 Encrypted File Format (CVEF)

CVEF (Crypto Vault Encrypted File) is the binary format for all encrypted files. Each file is self-describing — the header declares every algorithm and parameter needed for decryption, enabling forward-compatible algorithm transitions without breaking existing files.

```
Offset    Size         Field
──────    ──────────   ────────────────────────────────
0x00      4 bytes      Magic: "CVEF" (0x43 0x56 0x45 0x46)
0x04      1 byte       Format version: 1
0x05      4 bytes      Metadata length (big-endian uint32)
0x09      N bytes      Metadata JSON (UTF-8 encoded)
0x09+N    remainder    Encrypted data (AES-256-GCM)
```

The metadata JSON contains:

- Format version (`"1.2"` or `"1.3"`)
- Algorithm identifiers (`"AES-256-GCM"`, `"argon2id"`, `"aes-kw"`, `"ml-kem-768"`)
- KDF parameters (memory cost, time cost, parallelism)
- Salt and initialization vector (Base64 encoded)
- Post-quantum key exchange parameters:
  - Classical ciphertext (ephemeral X25519 public key, 32 bytes)
  - PQ ciphertext (ML-KEM-768 encapsulation, 1,088 bytes)
  - Wrapped file key (AES-KW output, 40 bytes)
- Chunking parameters (if applicable): chunk count, chunk size, per-chunk IVs
- Signature parameters (v1.3): algorithm identifier, signer fingerprint, classical signature (Ed25519, 64 bytes), post-quantum signature (ML-DSA-65, 3,309 bytes)

Maximum metadata size is validated at 2 MB during parsing. Typical header overhead is approximately 1.8 KB for v1.2 and 6.2 KB for v1.3 with signatures.

### 7.4 Filename Encryption

Filenames are encrypted client-side to prevent metadata leakage at the storage layer:

1. A per-file filename key is derived via HKDF-SHA256 from the Master Key with the file identifier as context
2. The filename is encrypted with AES-256-GCM using the derived key and a random IV
3. The server stores the encrypted filename and IV; a server-side placeholder is used for internal operations
4. The client decrypts filenames on the fly and caches the results locally

If decryption fails (e.g., the Master Key is unavailable), the client displays a safe placeholder without exposing encrypted data.

### 7.5 Hybrid Digital Signatures

Files can be signed using both Ed25519 and ML-DSA-65 (CVEF v1.3). Both signatures must verify for a file to be considered authentic. Signing contexts (domain separators) prevent cross-protocol signature reuse:

| Context | Usage |
|---------|-------|
| `FILE` | File content integrity |
| `TIMESTAMP` | Proof-of-existence |
| `SHARE` | Share link integrity |

---

## 8. File Sharing

### 8.1 Authenticated Sharing

When a user shares a file with another StenVault user, the file key is re-encrypted for the recipient's hybrid key pair:

1. The sender extracts the file key from the CVEF header using their own secret keys
2. The sender performs a hybrid key exchange with the recipient's public keys (X25519 + ML-KEM-768)
3. The file key is wrapped with the resulting hybrid KEK and stored as share metadata
4. The recipient uses their own secret keys to unwrap the file key and decrypt the file

The server facilitates the share metadata exchange but never has access to the file key.

### 8.2 Public Send (Anonymous Sharing)

Public Send enables encrypted file sharing with anyone, without requiring the recipient to have a StenVault account:

1. The sender's client generates a random AES-256-GCM key (32 bytes) from the CSPRNG
2. The file is encrypted in 5 MiB chunks and uploaded
3. A share URL is generated: `https://stenvault.app/send/<session>#key=<base64url>`
4. **The decryption key is placed in the URL fragment.** Per RFC 3986 Section 3.5, URL fragments are never transmitted to the server — they are processed entirely by the client
5. The session has a configurable time-to-live (1 hour, 24 hours, or 7 days), after which the encrypted blob is deleted
6. The recipient visits the URL; the client extracts the key from the fragment and decrypts locally

The server never possesses the encryption key at any point in this flow. Even if the server is compromised, stored Public Send files cannot be decrypted.

---

## 9. Key Recovery

### 9.1 Recovery Codes

At encryption setup, 10 recovery codes are generated in `XXXX-XXXX` format:

- Displayed to the user once and never stored in plaintext on the server
- Stored as HMAC-SHA256 digests using a deterministic salt combined with a server secret
- Compared using constant-time comparison to prevent timing side-channel attacks
- Used codes are removed from the stored set atomically

A recovery code allows the user to reset their password and generate a new Master Key. **This is a destructive operation** — existing encrypted files become inaccessible because the old Master Key is lost. The user is explicitly warned of this consequence before proceeding.

### 9.2 Shamir Secret Sharing

Shamir Secret Sharing enables threshold recovery of the Master Key, providing social recovery without single points of failure.

**Mathematical foundation**: Based on polynomial interpolation over GF(2^8) (Galois Field with 256 elements). A random polynomial of degree K-1 is generated with the Master Key bytes as the constant term. N shares are evaluated from this polynomial. Any K shares reconstruct the secret via Lagrange interpolation. Fewer than K shares reveal zero information about the secret — this is information-theoretically secure, not merely computationally secure.

**Share distribution**: Shares can be distributed via multiple channels:

| Channel | Protection |
|---------|------------|
| Server-held share | Encrypted with a server-derived key (AES-256-GCM) |
| Email | Encrypted with a recovery token (AES-256-GCM) |
| Trusted contact | Encrypted with an ECDH shared secret (AES-256-GCM) |
| External (QR code or paper) | Base64 with HMAC integrity tag |

**Recovery flow**:

1. A recovery session is created with a 24-hour expiry
2. The user submits shares one at a time from their various channels
3. Each share is decrypted and validated
4. When threshold K is reached, polynomial interpolation reconstructs the Master Key
5. All collected shares are cleared from the database after recovery

Unlike recovery codes, Shamir recovery is non-destructive — the original Master Key is reconstructed, and all existing files remain accessible.

---

## 10. Transport and Web Security

### 10.1 TLS and Transport

All client-server communication requires TLS 1.3. HSTS is enabled with `preload` and `includeSubDomains` directives, instructing browsers to never make unencrypted connections.

File contents are encrypted client-side before transmission, providing a second layer of protection independent of TLS. Even if TLS were compromised, an attacker would obtain only ciphertext.

### 10.2 CSRF Protection

Cross-Site Request Forgery is prevented using the double-submit cookie pattern:

1. The client obtains a CSRF token from a dedicated endpoint (delivered as a cookie)
2. The client includes the token in a custom header on every mutating request
3. The server validates that the header value matches the cookie value
4. Tokens have a time-to-live and are rotated periodically

### 10.3 Content Security Policy

The Content Security Policy restricts the client application to loading only same-origin resources:

- **Scripts**: Same-origin only, with `wasm-unsafe-eval` required for post-quantum WASM modules. No `unsafe-inline` or `unsafe-eval`.
- **Connections**: Same-origin, HTTPS, and WSS only
- **Objects**: Blocked entirely (`object-src 'none'`)
- **Frames**: Blocked entirely (`frame-ancestors 'none'`) to prevent clickjacking
- **Form actions**: Same-origin only
- **Insecure requests**: Automatically upgraded (`upgrade-insecure-requests`)

No external scripts are loaded. All assets are bundled and served from the same origin.

### 10.4 Additional Security Headers

| Header | Value | Purpose |
|--------|-------|---------|
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload` | Enforce HTTPS |
| X-Frame-Options | `DENY` | Prevent clickjacking |
| X-Content-Type-Options | `nosniff` | Prevent MIME-type sniffing |
| Referrer-Policy | `no-referrer` | Prevent leaking URL fragments (protects Public Send keys) |
| Permissions-Policy | Disables geolocation, microphone, camera, payment | Reduce browser API surface |

### 10.5 Master Key Runtime Protection

The Master Key is imported into the WebCrypto API as a non-extractable `CryptoKey` object. The raw key bytes are zeroed immediately after import. This means:

- JavaScript code (including XSS payloads) can use the key for cryptographic operations through the WebCrypto API
- JavaScript code **cannot** read, copy, or exfiltrate the raw key bytes
- The key exists only in the browser's internal cryptographic module, not in JavaScript-accessible memory

Post-quantum secret keys are additionally isolated in a Web Worker, providing a separate memory space that is inaccessible from the main browser thread.

---

## 11. Supply Chain Security

In a client-side encryption architecture, the served application code is the security boundary. A compromised build pipeline or dependency could exfiltrate keys. StenVault implements multiple layers of defense:

**Dependency integrity**:
- Frozen lockfile enforcement in CI — no ad-hoc dependency resolution changes
- Exact version pinning for all cryptographic dependencies (no semver ranges)
- Automated dependency audit as a blocking CI gate
- Trust policy preventing silent downgrades to older versions
- Release cooldown period before adopting new package versions

**Build integrity**:
- Strict build policies prevent dependency build scripts from arbitrary execution
- Content Security Policy blocks any externally injected scripts at runtime

**Post-quantum WASM supply chain**:
- The ML-KEM-768 and ML-DSA-65 WASM module (`@stenvault/pqc-wasm`) is self-owned — compiled from auditable Rust source (RustCrypto crates)
- Published with SLSA provenance for supply chain verification
- Rust's `ZeroizeOnDrop` trait automatically zeroes all secret key material in WASM memory when it goes out of scope
- All PQC operations are isolated in a dedicated Web Worker, preventing the main thread from accessing WASM linear memory

These controls reduce but do not eliminate supply chain risk. Certificate transparency and reproducible builds are planned future mitigations.

---

## 12. Post-Quantum Readiness

### 12.1 The Harvest-Now-Decrypt-Later Threat

Adversaries with long time horizons (nation-states, well-funded organizations) may be collecting encrypted data today with the intention of decrypting it when quantum computers become available. Files encrypted with only classical algorithms (RSA, ECC) will be vulnerable to Shor's algorithm.

StenVault's hybrid approach ensures that data encrypted today is protected against this threat. Even if a quantum computer becomes available, the ML-KEM-768 component of the hybrid key exchange prevents decryption.

### 12.2 NIST Standards Compliance

StenVault uses the NIST-standardized post-quantum algorithms:

- **ML-KEM-768** (FIPS 203, finalized August 2024) for key encapsulation
- **ML-DSA-65** (FIPS 204, finalized August 2024) for digital signatures

Both operate at NIST Security Level 3, providing security roughly equivalent to AES-192 against quantum adversaries.

### 12.3 Algorithm Agility

The CVEF file format is designed for algorithm agility. Each encrypted file's header declares the algorithms and parameters used for encryption. This means:

- If NIST standardizes stronger PQC algorithms in the future, StenVault can adopt them for new files without breaking existing ones
- Existing files always declare their own decryption requirements
- Format version identifiers (v1.2, v1.3) enable backward-compatible additions

---

## 13. Limitations and Known Considerations

StenVault is transparent about its limitations. This section documents what the system cannot protect against and where known trade-offs exist.

### 13.1 Compromised Client Device

If an attacker has full access to the browser or operating system while the vault is unlocked, they can read decrypted files from memory. This is a fundamental limitation of any client-side encryption system. Auto-lock mitigates this for unattended sessions by clearing the Master Key from memory after a configurable inactivity period.

### 13.2 Browser-Based Cryptography

All cryptographic operations rely on the browser's WebCrypto API and the operating system's CSPRNG:

- If the browser's `crypto.getRandomValues` implementation is flawed, key generation is compromised
- WebCrypto's AES-GCM decryption requires the entire ciphertext for non-chunked operations (files under 100 MB), limiting streaming to chunked files
- WASM modules are required for post-quantum algorithms, as browsers do not yet natively support ML-KEM or ML-DSA

### 13.3 No Perfect Forward Secrecy for Stored Files

V4 encryption uses ephemeral X25519 keys per file, providing file-level forward secrecy. However, all file keys are ultimately protected by the user's long-term hybrid key pair. If the long-term secret keys are compromised (requiring compromise of the Master Key), all files encrypted with that key pair are vulnerable. This is inherent to any system where files must be retrievable across sessions.

### 13.4 Metadata Leakage

The server observes file sizes, upload/download timestamps, access frequency, and the number of files. Filenames and file contents are encrypted, but operational metadata is not. An adversary who compromises the server can build a profile of user activity patterns without accessing file contents.

### 13.5 Weak Passwords

Argon2id significantly slows brute-force password attacks, but it cannot protect against trivially weak passwords. StenVault enforces password strength requirements at registration, but the ultimate security of the key hierarchy depends on the user choosing a sufficiently strong password.

### 13.6 Server-Served Code Trust

The client application is served by the server. If the server is compromised and serves malicious client code, it could exfiltrate keys before encryption occurs. This is a fundamental limitation of web applications (as opposed to locally installed software). Mitigations include Content Security Policy, supply chain controls (see [§11](#11-supply-chain-security)), and open-source availability for review. Certificate transparency and reproducible builds are planned.

### 13.7 Account Recovery Trade-offs

Recovery codes enable password reset but at the cost of losing access to existing files (new Master Key is generated). Shamir recovery preserves existing files but requires the user to have distributed shares in advance. Users who lose both their password and all recovery mechanisms permanently lose access to their data — this is by design in a zero-knowledge system.

---

## 14. Audit and Compliance

### 14.1 Current Audit Status

StenVault has not yet undergone a formal, independent security audit by a third-party firm. The cryptographic architecture is designed following NIST, IETF, and OWASP standards, and the source code is available for independent review. A third-party audit is planned.

### 14.2 Open Source Review

The complete client-side source code is publicly available at [github.com/StenVault/stenvault](https://github.com/StenVault/stenvault). This includes all cryptographic implementations, key management logic, and authentication flows. Security researchers and auditors are encouraged to review the code and report findings.

### 14.3 Standards Compliance

StenVault's cryptographic choices are aligned with:

- **OWASP 2024 Password Storage Cheat Sheet** — Argon2id with recommended parameters
- **NIST SP 800-38D** — AES-GCM authenticated encryption
- **NIST FIPS 203/204** — Post-quantum key encapsulation and digital signatures
- **RFC 9807** — OPAQUE zero-knowledge password authentication
- **RFC 3394** — AES Key Wrap for key management
- **RFC 9106** — Argon2 password hashing

### 14.4 Responsible Disclosure

Security vulnerabilities should be reported to [security@stenvault.app](mailto:security@stenvault.app). Do not open public issues for security findings. Reports will be acknowledged and addressed according to severity.

---

## Appendix A: Cryptographic Constants

| Constant | Value |
|----------|-------|
| AES-256-GCM key | 32 bytes (256 bits) |
| AES-256-GCM initialization vector | 12 bytes (96 bits) |
| AES-256-GCM authentication tag | 16 bytes (128 bits) |
| Argon2id memory cost | 47,104 KiB (46 MiB) |
| Argon2id time cost | 1 iteration |
| Argon2id parallelism | 1 |
| Argon2id output length | 32 bytes |
| X25519 public key | 32 bytes |
| X25519 secret key | 32 bytes |
| ML-KEM-768 public key | 1,184 bytes |
| ML-KEM-768 secret key | 2,400 bytes |
| ML-KEM-768 ciphertext | 1,088 bytes |
| ML-KEM-768 shared secret | 32 bytes |
| Ed25519 public key | 32 bytes |
| Ed25519 secret key | 32 bytes |
| Ed25519 signature | 64 bytes |
| ML-DSA-65 public key | 1,952 bytes |
| ML-DSA-65 secret key | 4,032 bytes |
| ML-DSA-65 signature | 3,309 bytes |
| AES-KW wrapped key overhead | +8 bytes |
| HKDF-SHA256 output | 32 bytes |
| CVEF magic bytes | `0x43 0x56 0x45 0x46` ("CVEF") |
| CVEF fixed header size | 9 bytes |
| Streaming chunk size | 65,536 bytes (64 KiB) |
| Public Send chunk size | 5,242,880 bytes (5 MiB) |
| Shamir field | GF(2^8) = 256 elements |
| Key fingerprint | SHA-256, first 16 bytes, hex encoded (32 characters) |

---

## Appendix B: Glossary

| Term | Definition |
|------|-----------|
| **AES-256-GCM** | Advanced Encryption Standard with 256-bit key in Galois/Counter Mode. Provides authenticated encryption — confidentiality and integrity in a single operation. |
| **AES-KW** | AES Key Wrap (RFC 3394). Encrypts a key with another key, adding an 8-byte integrity check. |
| **Argon2id** | Memory-hard password hashing function. Winner of the Password Hashing Competition (2015). The `id` variant resists both side-channel and time-memory tradeoff attacks. |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator. In browsers, `crypto.getRandomValues`. |
| **CVEF** | Crypto Vault Encrypted File. Self-describing binary format with versioned metadata header and encrypted payload. |
| **ECDH** | Elliptic Curve Diffie-Hellman. Key agreement protocol that derives a shared secret from two parties' key pairs. |
| **Ed25519** | Edwards-curve Digital Signature Algorithm on Curve25519 (RFC 8032). Constant-time signatures. |
| **GF(2^8)** | Galois Field with 256 elements. Finite field used for Shamir Secret Sharing arithmetic. |
| **HKDF** | HMAC-based Key Derivation Function (RFC 5869). Derives cryptographic keys from high-entropy inputs. |
| **HMAC** | Hash-based Message Authentication Code. Provides message integrity and authenticity. |
| **IV** | Initialization Vector. Random value ensuring identical plaintexts produce different ciphertexts. |
| **KEK** | Key Encryption Key. Derived from the user's password; used solely to wrap/unwrap the Master Key. |
| **KEM** | Key Encapsulation Mechanism. Asymmetric primitive for establishing shared secrets. |
| **Master Key** | The root 32-byte encryption key from which all other keys are derived or wrapped. |
| **ML-DSA-65** | Module-Lattice Digital Signature Algorithm at NIST Security Level 3 (FIPS 204). Post-quantum. |
| **ML-KEM-768** | Module-Lattice Key Encapsulation Mechanism at NIST Security Level 3 (FIPS 203). Post-quantum. |
| **OPAQUE** | Oblivious Pseudo-Random Function with Asymmetric PAKE (RFC 9807). Zero-knowledge password authentication. |
| **OPRF** | Oblivious Pseudo-Random Function. Core primitive of OPAQUE; allows PRF evaluation without revealing input. |
| **PQC** | Post-Quantum Cryptography. Algorithms designed to resist attacks by quantum computers. |
| **Shamir Secret Sharing** | Information-theoretically secure scheme that splits a secret into N shares, requiring K to reconstruct. |
| **UES** | User Entropy Seed. Device-specific secret that supplements the password for fast vault unlock. |
| **X25519** | Elliptic curve Diffie-Hellman key agreement on Curve25519 (RFC 7748). |
| **Zero-Knowledge** | Architecture where the service provider cannot access user data by design, not merely by policy. |

---

## Appendix C: Standards and References

### IETF RFCs

| RFC | Title |
|-----|-------|
| RFC 2104 | HMAC: Keyed-Hashing for Message Authentication |
| RFC 3394 | AES Key Wrap Algorithm |
| RFC 3986 | Uniform Resource Identifier (URI): Generic Syntax |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) |
| RFC 6238 | TOTP: Time-Based One-Time Password Algorithm |
| RFC 7519 | JSON Web Token (JWT) |
| RFC 7748 | Elliptic Curves for Security |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm (EdDSA) |
| RFC 9106 | Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications |
| RFC 9807 | The OPAQUE Asymmetric PAKE Protocol |

### NIST Publications

| Publication | Title |
|-------------|-------|
| FIPS 197 | Advanced Encryption Standard (AES) |
| FIPS 203 | Module-Lattice-Based Key-Encapsulation Mechanism Standard |
| FIPS 204 | Module-Lattice-Based Digital Signature Standard |
| SP 800-38D | Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC |

### Other References

| Reference | Relevance |
|-----------|-----------|
| OWASP Password Storage Cheat Sheet (2024) | Argon2id parameter recommendations |
| Password Hashing Competition (2015) | Selection of Argon2 as recommended KDF |
| Shamir, A. "How to Share a Secret" (1979) | Mathematical foundation for threshold secret sharing |
| OpenTimestamps Protocol Specification | Proof-of-existence via Bitcoin blockchain |

---

## Appendix D: Document History

| Version | Date | Changes |
|---------|------|---------|
| 2.0 | March 2026 | Complete rewrite. Restructured for auditor audience. Removed implementation details and source references. Added supply chain security, algorithm agility, and explicit limitations sections. |
| 1.0 | March 2026 | Initial release. |

---

*This document describes the cryptographic architecture of the StenVault open-source web client as deployed in production. It is a living document and will be updated as the system evolves.*

*For security reports: [security@stenvault.app](mailto:security@stenvault.app)*
*Source code: [github.com/StenVault/stenvault](https://github.com/StenVault/stenvault)*
