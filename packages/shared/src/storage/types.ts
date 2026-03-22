/**
 * Storage Backend Interface
 *
 * Platform-agnostic abstraction for blob storage operations.
 * Implementations: R2StorageBackend (Cloudflare R2), future backends.
 *
 * Design notes:
 * - generateFileKey() is NOT here — it's business logic, not storage.
 * - withRetry() is internal to each implementation.
 * - All presigned URL methods omit ContentLength for uploads
 *   (client encrypts after URL generation, actual size unknown).
 */

// ── Supporting Types ──────────────────────────────────────────

export interface DownloadUrlOptions {
  /** Expiration in seconds (default: backend-specific) */
  expiresIn?: number;
  /** Use shorter expiration for sensitive content */
  sensitive?: boolean;
  /** Override response Content-Type (e.g., for media streaming) */
  contentType?: string;
  /** Force download with this filename (Content-Disposition: attachment) */
  downloadFilename?: string;
}

export interface UploadUrlOptions {
  /** Content type for the upload */
  contentType: string;
  /** Expiration in seconds (default: 300) */
  expiresIn?: number;
}

export interface MultipartUploadPart {
  partNumber: number;
  etag: string;
}

export interface MultipartUploadInfo {
  key: string;
  uploadId: string;
  initiated: Date;
}

export interface ListObjectsOptions {
  /** Key prefix filter */
  prefix: string;
  /** Maximum keys to return per page */
  maxKeys?: number;
  /** Continuation token for pagination */
  continuationToken?: string;
}

export interface ListObjectsResult {
  objects: Array<{
    key: string;
    size: number;
    lastModified: Date;
  }>;
  /** Token for next page, undefined if no more pages */
  nextContinuationToken?: string;
}

export interface HeadObjectResult {
  contentLength: number;
  contentType?: string;
  lastModified?: Date;
}

export interface StorageBackendConfig {
  /** Multipart upload threshold in bytes */
  multipartThreshold: number;
  /** Default part size for multipart uploads in bytes */
  multipartPartSize: number;
  /** Part size optimized for mobile/P2P transfers in bytes */
  p2pPartSize: number;
}

// ── Main Interface ────────────────────────────────────────────

export interface StorageBackend {
  readonly config: StorageBackendConfig;

  // ── Presigned URLs ──

  getDownloadUrl(key: string, options?: DownloadUrlOptions): Promise<string>;
  getUploadUrl(key: string, options: UploadUrlOptions): Promise<string>;

  // ── Object Operations ──

  deleteObject(key: string): Promise<void>;
  deleteObjects(keys: string[]): Promise<void>;
  copyObject(sourceKey: string, destKey: string): Promise<void>;
  headObject(key: string): Promise<HeadObjectResult>;
  getObjectRange(
    key: string,
    startByte: number,
    endByte: number,
  ): Promise<ReadableStream<Uint8Array>>;
  listObjects(options: ListObjectsOptions): Promise<ListObjectsResult>;

  // ── Multipart Upload ──

  createMultipartUpload(
    key: string,
    contentType: string,
  ): Promise<{ uploadId: string }>;

  getUploadPartUrl(
    key: string,
    uploadId: string,
    partNumber: number,
    contentLength: number,
  ): Promise<string>;

  completeMultipartUpload(
    key: string,
    uploadId: string,
    parts: MultipartUploadPart[],
  ): Promise<{ location: string }>;

  abortMultipartUpload(key: string, uploadId: string): Promise<void>;
  listMultipartUploads(prefix?: string): Promise<MultipartUploadInfo[]>;

  // ── Health ──

  isConfigured(): boolean;
  checkHealth(): Promise<boolean>;
  getStatus(): { configured: boolean; healthy: boolean };
}
