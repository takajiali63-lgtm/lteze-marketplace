import crypto from "node:crypto";
import { DeleteObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

/**
 * Storage providers recorded per image in product_images.storage_provider:
 *  - "external": a URL we do not own (legacy image, Shopify CDN link...) — never deleted by us
 *  - "s3":       S3-compatible object storage (Cloudflare R2, AWS S3, Backblaze B2, DigitalOcean Spaces...)
 *  - "shopify":  reserved for Shopify Files (storage_key = Shopify file GID) — no schema change needed
 *  - "db":       fallback persistent store (media_blobs table) used when no object storage is configured.
 *                Survives redeploys; switch to "s3" by setting STORAGE_DRIVER=s3 + S3_* env vars.
 * product_images only ever stores URL + provider + key.
 */
export type StorageProvider = "external" | "s3" | "shopify" | "db";

export interface StoredObject {
  provider: StorageProvider;
  key: string;
  url: string;
}

export interface StorageDriver {
  readonly provider: StorageProvider;
  put(key: string, body: Buffer, contentType: string): Promise<StoredObject>;
  delete(key: string): Promise<void>;
}

class S3Driver implements StorageDriver {
  readonly provider = "s3" as const;
  private client: S3Client;

  constructor(
    private bucket: string,
    private publicBaseUrl: string,
    opts: { endpoint?: string; region: string; accessKeyId: string; secretAccessKey: string },
  ) {
    this.client = new S3Client({
      region: opts.region,
      endpoint: opts.endpoint,
      forcePathStyle: !!opts.endpoint,
      credentials: { accessKeyId: opts.accessKeyId, secretAccessKey: opts.secretAccessKey },
    });
  }

  async put(key: string, body: Buffer, contentType: string): Promise<StoredObject> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: contentType,
        CacheControl: "public, max-age=31536000, immutable",
      }),
    );
    return { provider: this.provider, key, url: `${this.publicBaseUrl}/${key}` };
  }

  async delete(key: string): Promise<void> {
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
  }
}

let cached: StorageDriver | null | undefined;
let dbFallback: StorageDriver | null = null;

/** Registers the database-backed fallback driver (see stores.ts). */
export function setDbFallback(driver: StorageDriver): void {
  dbFallback = driver;
}

/**
 * Returns the active storage driver:
 *  - S3-compatible object storage when STORAGE_DRIVER=s3 and all S3_* variables are set
 *  - otherwise the persistent database fallback (if registered)
 */
export function getStorage(): StorageDriver | null {
  if (cached) return cached;
  const driver = (process.env.STORAGE_DRIVER ?? "none").toLowerCase();
  if (driver !== "s3") return dbFallback;
  const bucket = process.env.S3_BUCKET;
  const publicBase = process.env.S3_PUBLIC_BASE_URL?.replace(/\/+$/, "");
  const accessKeyId = process.env.S3_ACCESS_KEY_ID;
  const secretAccessKey = process.env.S3_SECRET_ACCESS_KEY;
  if (!bucket || !publicBase || !accessKeyId || !secretAccessKey) {
    if (cached === undefined) {
      console.error("[storage] STORAGE_DRIVER=s3 but S3 settings are incomplete; using database storage instead.");
      cached = null;
    }
    return dbFallback;
  }
  cached = new S3Driver(bucket, publicBase, {
    endpoint: process.env.S3_ENDPOINT || undefined,
    region: process.env.S3_REGION || "auto",
    accessKeyId,
    secretAccessKey,
  });
  return cached;
}

/** Unguessable object key: products/<productId>/<random>.webp */
export function newImageKey(productId: string, ext = "webp"): string {
  return `products/${productId}/${crypto.randomUUID()}.${ext}`;
}

/** Hosts allowed for image URLs added by link (not upload). */
export function allowedImageHosts(): string[] {
  const hosts = (process.env.IMAGE_URL_ALLOWED_HOSTS ?? "cdn.shopify.com")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  const pub = process.env.S3_PUBLIC_BASE_URL;
  if (pub) {
    try {
      hosts.push(new URL(pub).host.toLowerCase());
    } catch {
      /* ignore */
    }
  }
  return hosts;
}

export function isAllowedImageUrl(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== "https:" || u.username || u.password) return false;
  const host = u.host.toLowerCase();
  return allowedImageHosts().some((h) => host === h || (h.startsWith(".") && host.endsWith(h)));
}
