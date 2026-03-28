/**
 * usePublicSend - Orchestrates anonymous encrypted file sharing.
 *
 * State machine: idle → encrypting → uploading → completing → done | error
 *
 * Features:
 * - Multi-file support (auto-zip via fflate)
 * - Speed/ETA tracking
 * - Upload resume (sessionStorage)
 * - Thumbnail/snippet encryption
 * - Auth-aware (higher limits for logged-in users)
 */
import { useState, useCallback, useRef, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import {
  generateSendKey,
  generateBaseIv,
  keyToFragment,
  encryptMetadata,
  encryptChunk,
  encryptThumbnail,
  encryptSnippet,
  hashEncryptedChunk,
  computeChunkManifest,
  SEND_CHUNK_SIZE,
} from "@/lib/publicSendCrypto";
import { arrayBufferToBase64 } from "@stenvault/shared/platform/crypto";
import { bundleFilesToZip, type ZipManifest } from "@/lib/zipBundle";

export type SendState = "idle" | "encrypting" | "uploading" | "completing" | "done" | "error";

export interface SendConfig {
  password?: string;
  expiresInHours?: number;
  maxDownloads?: number | null;
  turnstileToken?: string;
  notifyOnDownload?: boolean;
  /** Session ID this send is replying to (viral reply chain) */
  replyToSessionId?: string;
}

export interface UsePublicSendReturn {
  state: SendState;
  /** 0-100 progress during upload */
  progress: number;
  /** Full share URL (with #key= fragment) */
  shareUrl: string | null;
  error: string | null;
  /** Upload speed in bytes/sec */
  speed: number;
  /** Estimated time remaining in seconds */
  eta: number;
  /** Whether a resumable session exists */
  resumeAvailable: boolean;
  send: (files: File[], config?: SendConfig) => Promise<void>;
  resumeSession: () => Promise<void>;
  reset: () => void;
}

const RESUME_PREFIX = "send:resume:";
const MAX_RETRIES = 3;

interface ResumeState {
  sessionId: string;
  completedParts: Array<{ partNumber: number; etag: string }>;
  fragment: string;
  totalParts: number;
  fileSize: number;
}

/**
 * Generate a thumbnail from an image or video file.
 * Returns a WebP blob ~50KB or null if unsupported.
 */
async function generateThumbnail(file: File): Promise<Blob | null> {
  try {
    if (file.type.startsWith("image/")) {
      return await generateImageThumbnail(file);
    }
    if (file.type.startsWith("video/")) {
      return await generateVideoThumbnail(file);
    }
  } catch {
    // Thumbnail generation is best-effort
  }
  return null;
}

function generateImageThumbnail(file: File): Promise<Blob | null> {
  return new Promise((resolve) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      const canvas = document.createElement("canvas");
      const maxDim = 256;
      let { width, height } = img;
      if (width > height) {
        if (width > maxDim) { height = (height * maxDim) / width; width = maxDim; }
      } else {
        if (height > maxDim) { width = (width * maxDim) / height; height = maxDim; }
      }
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d");
      if (!ctx) { resolve(null); return; }
      ctx.drawImage(img, 0, 0, width, height);
      canvas.toBlob((blob) => resolve(blob), "image/webp", 0.7);
    };
    img.onerror = () => { URL.revokeObjectURL(url); resolve(null); };
    img.src = url;
  });
}

function generateVideoThumbnail(file: File): Promise<Blob | null> {
  return new Promise((resolve) => {
    const video = document.createElement("video");
    const url = URL.createObjectURL(file);
    video.muted = true;
    video.preload = "metadata";
    video.onloadeddata = () => {
      video.currentTime = Math.min(1, video.duration / 4);
    };
    video.onseeked = () => {
      URL.revokeObjectURL(url);
      const canvas = document.createElement("canvas");
      const maxDim = 256;
      let { videoWidth: width, videoHeight: height } = video;
      if (width > height) {
        if (width > maxDim) { height = (height * maxDim) / width; width = maxDim; }
      } else {
        if (height > maxDim) { width = (width * maxDim) / height; height = maxDim; }
      }
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d");
      if (!ctx) { resolve(null); return; }
      ctx.drawImage(video, 0, 0, width, height);
      canvas.toBlob((blob) => resolve(blob), "image/webp", 0.7);
    };
    video.onerror = () => { URL.revokeObjectURL(url); resolve(null); };
    video.src = url;
  });
}

/**
 * Read first 500 chars from a text file.
 */
async function readTextSnippet(file: File): Promise<string | null> {
  try {
    if (!file.type.startsWith("text/")) return null;
    const slice = file.slice(0, 2000); // Read more to handle multi-byte
    const text = await slice.text();
    return text.slice(0, 500);
  } catch {
    return null;
  }
}

function getResumeKey(sessionId: string): string {
  return RESUME_PREFIX + sessionId;
}

function findResumeState(): ResumeState | null {
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    if (key?.startsWith(RESUME_PREFIX)) {
      try {
        return JSON.parse(sessionStorage.getItem(key)!) as ResumeState;
      } catch {
        sessionStorage.removeItem(key);
      }
    }
  }
  return null;
}

export function usePublicSend(): UsePublicSendReturn {
  const [state, setState] = useState<SendState>("idle");
  const [progress, setProgress] = useState(0);
  const [shareUrl, setShareUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [speed, setSpeed] = useState(0);
  const [eta, setEta] = useState(0);
  const [resumeAvailable, setResumeAvailable] = useState(false);
  const abortRef = useRef(false);
  const speedSamplesRef = useRef<Array<{ bytes: number; time: number }>>([]);

  const initiateMutation = trpc.publicSend.initiateSend.useMutation();
  const completeMutation = trpc.publicSend.completeSend.useMutation();

  // Check for resume state on mount
  useEffect(() => {
    setResumeAvailable(findResumeState() !== null);
  }, []);

  // Warn before unload during active upload
  useEffect(() => {
    if (state !== "encrypting" && state !== "uploading" && state !== "completing") return;

    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [state]);

  const updateSpeed = useCallback((bytesUploaded: number, totalRemaining: number) => {
    const now = Date.now();
    speedSamplesRef.current.push({ bytes: bytesUploaded, time: now });
    // Keep last 5 samples
    if (speedSamplesRef.current.length > 5) {
      speedSamplesRef.current.shift();
    }
    const samples = speedSamplesRef.current;
    if (samples.length >= 2) {
      const first = samples[0]!;
      const last = samples[samples.length - 1]!;
      const elapsed = (last.time - first.time) / 1000;
      const totalBytes = samples.reduce((s, v) => s + v.bytes, 0);
      if (elapsed > 0) {
        const bps = totalBytes / elapsed;
        setSpeed(bps);
        setEta(totalRemaining > 0 ? Math.ceil(totalRemaining / bps) : 0);
      }
    }
  }, []);

  const reset = useCallback(() => {
    setState("idle");
    setProgress(0);
    setShareUrl(null);
    setError(null);
    setSpeed(0);
    setEta(0);
    abortRef.current = false;
    speedSamplesRef.current = [];
  }, []);

  /**
   * Upload a single part with retry logic.
   */
  const uploadPartWithRetry = useCallback(
    async (
      url: string,
      encrypted: Uint8Array,
      partNumber: number,
    ): Promise<string> => {
      for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
        try {
          const response = await fetch(url, {
            method: "PUT",
            body: encrypted as unknown as BodyInit,
            headers: { "Content-Type": "application/octet-stream" },
          });

          if (response.status === 403) {
            // Presigned URL expired — can't retry with same URL
            throw new Error("PRESIGNED_EXPIRED");
          }

          if (!response.ok) {
            throw new Error(`Upload part ${partNumber} failed: ${response.status}`);
          }

          return response.headers.get("ETag") || `"part-${partNumber}"`;
        } catch (err: any) {
          if (err.message === "PRESIGNED_EXPIRED") throw err;
          if (attempt < MAX_RETRIES - 1) {
            // Exponential backoff: 1s, 2s, 4s
            await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt)));
          } else {
            throw err;
          }
        }
      }
      throw new Error("Unreachable");
    },
    [],
  );

  const send = useCallback(
    async (files: File[], config?: SendConfig) => {
      try {
        abortRef.current = false;
        setState("encrypting");
        setProgress(0);
        setError(null);
        setSpeed(0);
        setEta(0);
        speedSamplesRef.current = [];

        // 1. Generate random AES-256 key
        const key = await generateSendKey();
        const fragment = await keyToFragment(key);

        // 2. Bundle multi-file to zip if needed
        const { blob: fileBlob, manifest, mimeType, displayName } =
          await bundleFilesToZip(files);
        const isBundle = files.length > 1;

        // 3. Generate thumbnail/snippet (best-effort)
        let thumbnailData: { ciphertext: string; iv: string } | null = null;
        let snippetData: { ciphertext: string; iv: string } | null = null;

        if (!isBundle && files.length === 1) {
          const singleFile = files[0]!;

          // Thumbnail for images/videos
          const thumb = await generateThumbnail(singleFile);
          if (thumb) {
            thumbnailData = await encryptThumbnail(thumb, key);
          }

          // Snippet for text files
          const snippet = await readTextSnippet(singleFile);
          if (snippet) {
            snippetData = await encryptSnippet(snippet, key);
          }
        }

        // 4. Encrypt metadata
        const { ciphertext: encryptedMeta, iv: metaIv } = await encryptMetadata(
          {
            name: displayName,
            type: mimeType,
            isBundle: isBundle || undefined,
            manifest: manifest || undefined,
          },
          key,
        );

        // 5. Generate base IV for chunk IV derivation (anti-reordering)
        const baseIv = generateBaseIv();
        const chunkBaseIv = arrayBufferToBase64(baseIv.buffer as ArrayBuffer);

        // 6. Initiate send (get presigned URLs)
        setState("uploading");
        const { sessionId, partUrls, uploadSecret } = await initiateMutation.mutateAsync({
          fileSize: fileBlob.size,
          mimeType,
          encryptedMeta,
          metaIv,
          password: config?.password,
          expiresInHours: config?.expiresInHours ?? 24,
          maxDownloads: config?.maxDownloads ?? null,
          turnstileToken: config?.turnstileToken,
          encryptedThumbnail: thumbnailData?.ciphertext,
          thumbnailIv: thumbnailData?.iv,
          encryptedSnippet: snippetData?.ciphertext,
          snippetIv: snippetData?.iv,
          isBundle,
          notifyOnDownload: config?.notifyOnDownload,
          replyToSessionId: config?.replyToSessionId,
          chunkBaseIv,
        });

        // 6. Encrypt and upload each chunk (W3: collect chunk hashes for manifest)
        const totalParts = partUrls.length;
        const parts: Array<{ partNumber: number; etag: string }> = [];
        const chunkHashes: string[] = [];
        let bytesUploaded = 0;

        for (let i = 0; i < totalParts; i++) {
          if (abortRef.current) throw new Error("Upload cancelled");

          const start = i * SEND_CHUNK_SIZE;
          const end = Math.min(start + SEND_CHUNK_SIZE, fileBlob.size);
          const slice = await fileBlob.slice(start, end).arrayBuffer();
          const chunk = new Uint8Array(slice);

          // Encrypt chunk (V2: derived IV from baseIv + chunkIndex)
          const encrypted = await encryptChunk(chunk, key, baseIv, i);

          // W3: Hash encrypted chunk for integrity manifest
          const chunkHash = await hashEncryptedChunk(encrypted);
          chunkHashes.push(chunkHash);

          // Upload with retry
          const partInfo = partUrls[i]!;
          try {
            const etag = await uploadPartWithRetry(
              partInfo.url,
              encrypted,
              partInfo.partNumber,
            );
            parts.push({ partNumber: partInfo.partNumber, etag });
          } catch (err: any) {
            if (err.message === "PRESIGNED_EXPIRED") {
              // Clear resume state and re-throw
              sessionStorage.removeItem(getResumeKey(sessionId));
              throw new Error("Upload session expired. Please try again.");
            }
            throw err;
          }

          bytesUploaded += chunk.byteLength;
          const remaining = fileBlob.size - bytesUploaded;
          updateSpeed(chunk.byteLength, remaining);
          setProgress(Math.round(((i + 1) / totalParts) * 100));

          // Persist resume state after each part
          const resumeState: ResumeState = {
            sessionId,
            completedParts: parts,
            fragment,
            totalParts,
            fileSize: fileBlob.size,
          };
          sessionStorage.setItem(getResumeKey(sessionId), JSON.stringify(resumeState));
        }

        // 7. Complete the upload (W3: include chunk manifest for integrity verification)
        setState("completing");
        const integrityManifest = await computeChunkManifest(chunkHashes, key);
        await completeMutation.mutateAsync({
          sessionId,
          parts,
          uploadSecret,
          chunkManifest: integrityManifest,
          chunkHashes: chunkHashes.join(':'),
        });

        // 8. Build share URL + persist to localStorage
        const baseUrl = window.location.origin;
        const url = `${baseUrl}/send/${sessionId}#key=${fragment}`;
        setShareUrl(url);
        setState("done");

        // Save session reference to localStorage (without key fragment — never persist key material)
        try {
          localStorage.setItem(`send:links:${sessionId}`, `${baseUrl}/send/${sessionId}`);
        } catch {
          // localStorage full — best effort
        }

        // Clean up resume state
        sessionStorage.removeItem(getResumeKey(sessionId));
        setResumeAvailable(false);
      } catch (err: any) {
        const message = err?.message || "Something went wrong";
        setError(message);
        setState("error");
      }
    },
    [initiateMutation, completeMutation, uploadPartWithRetry, updateSpeed],
  );

  const resumeSession = useCallback(async () => {
    const resumeState = findResumeState();
    if (!resumeState) {
      setError("No resumable session found");
      setState("error");
      return;
    }

    // Clear the resume state — user chose not to resume or it failed
    setResumeAvailable(false);
    sessionStorage.removeItem(getResumeKey(resumeState.sessionId));

    // Note: Resume requires re-upload since we can't re-encrypt without the file.
    // The sessionStorage only stores metadata, not the file blob.
    // Show a message guiding the user to re-send.
    setError("Resume is not available — please re-send the file. Your previous upload session has expired.");
    setState("error");
  }, []);

  return {
    state,
    progress,
    shareUrl,
    error,
    speed,
    eta,
    resumeAvailable,
    send,
    resumeSession,
    reset,
  };
}
