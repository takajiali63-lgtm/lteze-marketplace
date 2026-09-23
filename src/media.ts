import "dotenv/config";
import crypto from "node:crypto";
import express, { NextFunction, Request, Response, RequestHandler } from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import argon2 from "argon2";
import { z, ZodError } from "zod";
import { Pool, PoolClient } from "pg";
import multer from "multer";
import { ARGON2_OPTIONS, bootstrapAdmin, createPool, normalizePhone, runMigrations } from "./migrate";
import {
  ALLOWED_UPLOAD_MIME,
  GalleryError,
  GalleryItem,
  ImageRejected,
  MAX_IMAGES_PER_PRODUCT,
  MAX_UPLOAD_BYTES,
  ProcessedImage,
  appendToGallery,
  normalizeGallery,
  processImage,
  removeFromGallery,
  reorderGallery,
  setPrimaryInGallery,
} from "./images";
import { StorageProvider, getStorage, isAllowedImageUrl, newImageKey } from "./storage";
import {
  JWT_SECRET,
  PORT,
  COOKIE_SECURE,
  COOKIE_DOMAIN,
  ALLOWED_ORIGINS,
  ADMIN_WHATSAPP,
  AUTO_MIGRATE,
  EXPIRY_JOB_INTERVAL_MS,
  SELLER_COOKIE,
  ADMIN_COOKIE,
  SELLER_SESSION_SECONDS,
  ADMIN_SESSION_SECONDS,
  RESET_TOKEN_MINUTES,
  VISIBILITIES,
  Visibility,
  pool,
  setPool,
  DUMMY_HASH,
  setDummyHash,
  HttpError,
  h,
  tx,
  Db,
  waLink,
  sha256,
  publicBaseUrl,
  audit,
  productOut,
  phoneSchema,
  passwordSchema,
  uuidSchema,
  pagingSchema,
  parse,
  compat,
  pageQuery,
  idParam,
  SubjectType,
  createSession,
  clearSessionCookie,
  readSession,
  revokeAllSessions,
  authCtx,
  sellerId,
  adminId,
  authSeller,
  authAdmin,
  hasActiveSubscription,
  effectiveVisibleState,
  hideForSubscription,
  restoreFromSubscription,
  app,
  authLimiter,
} from "./core";

export const imageUrlSchema = z
  .string()
  .trim()
  .url()
  .max(2000)
  .refine((u) => isAllowedImageUrl(u), "رابط الصورة غير مسموح. يجب أن يكون https ومن مصدر معتمد (مثل cdn.shopify.com)");

export const productFields = {
  name: z.string().trim().min(1).max(200),
  description: z.string().trim().max(5000),
  price: z.coerce.number().nonnegative().max(1_000_000_000),
  // Legacy single image (still accepted; maps to the primary gallery image).
  image: imageUrlSchema.nullable(),
  category_id: uuidSchema.nullable(),
};

export const imageLinkSchema = z.object({ url: imageUrlSchema, alt: z.string().trim().max(200).optional() });

export async function assertActiveCategory(db: Db, categoryId: string | null | undefined): Promise<void> {
  if (!categoryId) return;
  const { rowCount } = await db.query("SELECT 1 FROM categories WHERE id = $1 AND active", [categoryId]);
  if (!rowCount) throw new HttpError(400, "invalid_category", "التصنيف غير موجود");
}

export const PRODUCT_COLUMNS = "id, seller_id, name, description, price, image, category_id, visibility, created_at, updated_at";

// ============================================================ images: output

export interface ImageOut {
  id: string;
  url: string;
  position: number;
  is_primary: boolean;
  width: number | null;
  height: number | null;
  alt: string | null;
}

export async function loadImages(db: Db, productIds: string[]): Promise<Map<string, ImageOut[]>> {
  const map = new Map<string, ImageOut[]>();
  if (productIds.length === 0) return map;
  const { rows } = await db.query<ImageOut & { product_id: string }>(
    `SELECT id, product_id, url, position, is_primary, width, height, alt_text AS alt
       FROM product_images WHERE product_id = ANY($1::uuid[])
      ORDER BY product_id, position`,
    [productIds],
  );
  for (const { product_id, ...img } of rows) {
    const list = map.get(product_id) ?? [];
    list.push(img);
    map.set(product_id, list);
  }
  return map;
}

/**
 * Product JSON with:
 *  images:        gallery in display order (position 0..n-1), each with is_primary + width/height
 *  primary_image: the cover image (for cards / thumbnails)
 *  image:         primary URL — kept for old clients that expect a single image
 */
export function withImages(row: Record<string, unknown>, images: ImageOut[]): Record<string, unknown> {
  const primary = images.find((i) => i.is_primary) ?? null;
  return {
    ...productOut(row),
    image: primary?.url ?? (row.image as string | null) ?? null,
    image_url: primary?.url ?? (row.image as string | null) ?? null, // legacy alias
    primary_image: primary,
    images,
  };
}

export async function productsWithImages(db: Db, rows: Record<string, unknown>[]): Promise<Record<string, unknown>[]> {
  const map = await loadImages(db, rows.map((r) => String(r.id)));
  return rows.map((r) => withImages(r, map.get(String(r.id)) ?? []));
}

// ============================================================ images: persistence

export interface NewImageRow {
  id: string;
  url: string;
  provider: StorageProvider;
  key: string | null;
  mime: string | null;
  size: number | null;
  width: number | null;
  height: number | null;
  alt: string | null;
}

/** Locks a non-deleted product. ownerId = seller id (ownership enforced) or null for admin. */
export async function lockProduct(c: PoolClient, productId: string, ownerId: string | null): Promise<{ seller_id: string; name: string }> {
  const { rows } = await c.query<{ seller_id: string; name: string }>(
    `SELECT seller_id, name FROM products
      WHERE id = $1 AND visibility <> 'deleted' AND ($2::uuid IS NULL OR seller_id = $2::uuid)
      FOR UPDATE`,
    [productId, ownerId],
  );
  if (!rows[0]) throw new HttpError(404, "not_found", "المنتج غير موجود");
  return rows[0];
}

export async function readGallery(c: PoolClient, productId: string): Promise<GalleryItem[]> {
  const { rows } = await c.query<GalleryItem>(
    "SELECT id, position, is_primary FROM product_images WHERE product_id = $1 ORDER BY position",
    [productId],
  );
  return rows;
}

export async function insertImages(c: PoolClient, productId: string, imgs: NewImageRow[], startPos: number): Promise<void> {
  let pos = startPos;
  for (const i of imgs) {
    await c.query(
      `INSERT INTO product_images
         (id, product_id, url, storage_provider, storage_key, mime_type, size_bytes, width, height, alt_text, position, is_primary)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, FALSE)`,
      [i.id, productId, i.url, i.provider, i.key, i.mime, i.size, i.width, i.height, i.alt, pos++],
    );
  }
}

/** Persists positions + primary and syncs products.image (legacy field) to the primary URL. */
export async function writeGallery(c: PoolClient, productId: string, items: GalleryItem[]): Promise<void> {
  // Primary: clear first, then set — the one-primary unique index is not deferrable.
  await c.query("UPDATE product_images SET is_primary = FALSE WHERE product_id = $1 AND is_primary", [productId]);
  if (items.length > 0) {
    await c.query(
      `UPDATE product_images i SET position = x.pos, updated_at = now()
         FROM unnest($2::uuid[], $3::int[]) AS x(id, pos)
        WHERE i.id = x.id AND i.product_id = $1 AND i.position <> x.pos`,
      [productId, items.map((i) => i.id), items.map((i) => i.position)],
    );
    const primary = items.find((i) => i.is_primary);
    if (primary) {
      await c.query("UPDATE product_images SET is_primary = TRUE, updated_at = now() WHERE id = $1 AND product_id = $2", [
        primary.id,
        productId,
      ]);
    }
  }
  await c.query(
    `UPDATE products SET image = (SELECT url FROM product_images WHERE product_id = $1 AND is_primary), updated_at = now()
      WHERE id = $1`,
    [productId],
  );
}

// ============================================================ images: uploads

export interface UploadedFile {
  buffer: Buffer;
  originalname: string;
  mimetype: string;
  size: number;
}

export const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES, files: MAX_IMAGES_PER_PRODUCT, fields: 30, parts: 45 },
  fileFilter: (_req, file, cb) => {
    if ((ALLOWED_UPLOAD_MIME as readonly string[]).includes(file.mimetype)) cb(null, true);
    else cb(new ImageRejected("نوع الملف غير مسموح. المسموح: JPG, PNG, WebP"));
  },
});
export const uploadMany = upload.array("files", MAX_IMAGES_PER_PRODUCT);
export const uploadOne = upload.single("file");

export const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "too_many_requests", message: "محاولات رفع كثيرة، حاول لاحقاً" },
});

export function filesOf(req: Request): UploadedFile[] {
  const f = (req as unknown as { files?: unknown }).files;
  return Array.isArray(f) ? (f as UploadedFile[]) : [];
}

export function fileOf(req: Request): UploadedFile | null {
  return ((req as unknown as { file?: UploadedFile }).file ?? null) as UploadedFile | null;
}

/** Multipart bodies arrive as strings: drop empty fields and parse JSON fields. */
export function bodyOf(req: Request): Record<string, unknown> {
  const raw = (req.body ?? {}) as Record<string, unknown>;
  if (!req.is("multipart/form-data")) return raw;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (v === "") continue;
    if ((k === "images" || k === "image_ids") && typeof v === "string") {
      try {
        out[k] = JSON.parse(v);
      } catch {
        throw new HttpError(400, "invalid_json_field", `${k} يجب أن يكون JSON`);
      }
    } else out[k] = v;
  }
  return out;
}

/** Validates + re-encodes files (fails before anything is stored), then uploads them. */
export async function processAndUpload(productId: string, files: UploadedFile[], alt: string): Promise<NewImageRow[]> {
  if (files.length === 0) return [];
  const storage = getStorage();
  if (!storage) {
    throw new HttpError(
      503,
      "storage_not_configured",
      "رفع الصور غير مفعّل على الخادم بعد (لم يتم إعداد التخزين). يمكنك إضافة الصور عبر روابط.",
    );
  }
  const processed: ProcessedImage[] = [];
  for (const f of files) processed.push(await processImage(f.buffer)); // sequential: low memory
  const stored: NewImageRow[] = [];
  try {
    for (const p of processed) {
      const obj = await storage.put(newImageKey(productId), p.buffer, p.mime);
      stored.push({
        id: crypto.randomUUID(),
        url: obj.url,
        provider: obj.provider,
        key: obj.key,
        mime: p.mime,
        size: p.bytes,
        width: p.width,
        height: p.height,
        alt,
      });
    }
  } catch (err) {
    await discardUploaded(stored);
    console.error("[storage] upload failed:", err instanceof Error ? err.message : err);
    throw new HttpError(502, "storage_error", "تعذّر حفظ الصور. حاول مرة أخرى.");
  }
  return stored;
}

/** Removes objects that were uploaded but not committed. Falls back to the cleanup queue. */
export async function discardUploaded(rows: NewImageRow[]): Promise<void> {
  const storage = getStorage();
  for (const r of rows) {
    if (!r.key || r.provider === "external") continue;
    try {
      if (!storage) throw new Error("no storage");
      await storage.delete(r.key);
    } catch {
      await pool
        .query("INSERT INTO storage_orphans (storage_provider, storage_key) VALUES ($1, $2)", [r.provider, r.key])
        .catch(() => undefined);
    }
  }
}

export function linkRows(links: { url: string; alt?: string }[], fallbackAlt: string): NewImageRow[] {
  return links.map((l) => ({
    id: crypto.randomUUID(),
    url: l.url,
    provider: "external" as const,
    key: null,
    mime: null,
    size: null,
    width: null,
    height: null,
    alt: l.alt ?? fallbackAlt,
  }));
}
