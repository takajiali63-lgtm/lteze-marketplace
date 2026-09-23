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
import {
  imageUrlSchema,
  productFields,
  imageLinkSchema,
  assertActiveCategory,
  PRODUCT_COLUMNS,
  ImageOut,
  loadImages,
  withImages,
  productsWithImages,
  NewImageRow,
  lockProduct,
  readGallery,
  insertImages,
  writeGallery,
  UploadedFile,
  upload,
  uploadMany,
  uploadOne,
  uploadLimiter,
  filesOf,
  fileOf,
  bodyOf,
  processAndUpload,
  discardUploaded,
  linkRows,
} from "./media";

import "./auth";
import "./products";
import "./admin";

// ------------------------------------------------------------- errors

app.use((_req: Request, _res: Response, next: NextFunction) => next(new HttpError(404, "not_found", "Route not found")));

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.code, message: err.message });
    return;
  }
  if (err instanceof GalleryError) {
    res.status(err.status).json({ error: err.code, message: err.message });
    return;
  }
  if (err instanceof ImageRejected) {
    res.status(415).json({ error: "image_rejected", message: err.message });
    return;
  }
  if (err instanceof multer.MulterError) {
    const map: Record<string, [number, string]> = {
      LIMIT_FILE_SIZE: [413, `حجم الصورة يتجاوز ${Math.round(MAX_UPLOAD_BYTES / 1024 / 1024)}MB`],
      LIMIT_FILE_COUNT: [409, `الحد الأقصى ${MAX_IMAGES_PER_PRODUCT} صور`],
      LIMIT_UNEXPECTED_FILE: [400, "اسم حقل الملف غير صحيح (files للصور المتعددة، file لاستبدال صورة)"],
    };
    const [status, message] = map[err.code] ?? [400, "خطأ في رفع الملفات"];
    res.status(status).json({ error: "upload_error", code: err.code, message });
    return;
  }
  if (err instanceof ZodError) {
    res.status(400).json({
      error: "validation_error",
      message: err.issues[0]?.message ?? "بيانات غير صالحة",
      issues: err.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
    });
    return;
  }
  const e = err as { type?: string; status?: number };
  if (e?.type === "entity.parse.failed") {
    res.status(400).json({ error: "invalid_json", message: "JSON غير صالح" });
    return;
  }
  if (e?.type === "entity.too.large") {
    res.status(413).json({ error: "payload_too_large", message: "الطلب كبير جداً" });
    return;
  }
  console.error("[error]", err);
  res.status(500).json({ error: "internal_error", message: "حدث خطأ في الخادم" });
});

// ============================================================== expiry job

const EXPIRY_LOCK_ID = 774412;

export async function runExpiryJob(): Promise<number> {
  const client = await pool.connect();
  let expired = 0;
  try {
    const lock = await client.query<{ ok: boolean }>("SELECT pg_try_advisory_lock($1) AS ok", [EXPIRY_LOCK_ID]);
    if (!lock.rows[0]?.ok) return 0;
    try {
      for (;;) {
        await client.query("BEGIN");
        const { rows } = await client.query<{ id: string; seller_id: string }>(
          `SELECT id, seller_id FROM subscriptions
            WHERE status = 'active' AND expires_at <= now()
            ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED`,
        );
        if (rows.length === 0) {
          await client.query("COMMIT");
          break;
        }
        for (const s of rows) {
          await client.query("UPDATE subscriptions SET status = 'expired', updated_at = now() WHERE id = $1", [s.id]);
          const hidden = await hideForSubscription(client, s.seller_id);
          await audit(client, {
            adminId: null,
            action: "subscription_expired",
            sellerId: s.seller_id,
            metadata: { subscription_id: s.id, products_hidden: hidden, by: "system" },
          });
        }
        await client.query("COMMIT");
        expired += rows.length;
      }
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      await client.query("SELECT pg_advisory_unlock($1)", [EXPIRY_LOCK_ID]);
    }
  } finally {
    client.release();
  }
  return expired;
}

// ============================================================== image cleanup jobs

const DELETED_PRODUCT_RETENTION_DAYS = Number(process.env.DELETED_PRODUCT_RETENTION_DAYS ?? 30);

/** Deletes stored files queued by the product_images trigger. External URLs are never touched. */
export async function runStorageCleanup(): Promise<number> {
  const storage = getStorage();
  if (!storage) return 0;
  const { rows } = await pool.query<{ id: string; storage_provider: string; storage_key: string }>(
    `SELECT id, storage_provider, storage_key FROM storage_orphans
      WHERE attempts < 10 ORDER BY created_at LIMIT 100`,
  );
  let done = 0;
  for (const o of rows) {
    if (o.storage_provider !== storage.provider) continue;
    try {
      // Never delete a key that is (again) referenced by a live image.
      const used = await pool.query("SELECT 1 FROM product_images WHERE storage_key = $1", [o.storage_key]);
      if (!used.rowCount) await storage.delete(o.storage_key);
      await pool.query("DELETE FROM storage_orphans WHERE id = $1", [o.id]);
      done++;
    } catch (err) {
      await pool.query("UPDATE storage_orphans SET attempts = attempts + 1, last_error = $2 WHERE id = $1", [
        o.id,
        (err instanceof Error ? err.message : String(err)).slice(0, 500),
      ]);
    }
  }
  return done;
}

/** Permanently removes products soft-deleted long ago. Images cascade; their files get queued for deletion. */
export async function purgeDeletedProducts(): Promise<number> {
  const r = await pool.query(
    `DELETE FROM products WHERE id IN (
       SELECT id FROM products
        WHERE visibility = 'deleted' AND deleted_at < now() - make_interval(days => $1::int)
        LIMIT 200)`,
    [DELETED_PRODUCT_RETENTION_DAYS],
  );
  return r.rowCount ?? 0;
}

// ============================================================== start

async function start(): Promise<void> {
  if (JWT_SECRET.length < 32) {
    console.error("[config] JWT_SECRET is missing or shorter than 32 characters. Refusing to start.");
    process.exit(1);
  }
  try {
    setPool(createPool());
  } catch (err) {
    console.error("[config]", err instanceof Error ? err.message : err);
    process.exit(1);
  }
  pool.on("error", (err) => console.error("[pg] idle client error:", err.message));

  if (AUTO_MIGRATE) {
    await runMigrations(pool);
    console.log("[startup] schema applied");
  }
  const adminState = await bootstrapAdmin(pool);
  console.log(`[startup] bootstrap admin: ${adminState}`);

  setDummyHash(await argon2.hash(crypto.randomBytes(16).toString("hex"), ARGON2_OPTIONS));

  const log = (tag: string) => (err: unknown) => console.error(`[${tag}] failed:`, err instanceof Error ? err.message : err);
  const runJob = async () => {
    await runExpiryJob()
      .then((n) => n && console.log(`[expiry] expired ${n} subscription(s)`))
      .catch(log("expiry"));
    await purgeDeletedProducts()
      .then((n) => n && console.log(`[purge] removed ${n} deleted product(s)`))
      .catch(log("purge"));
    await runStorageCleanup()
      .then((n) => n && console.log(`[storage] cleaned ${n} file(s)`))
      .catch(log("storage"));
  };
  if (!getStorage()) console.log("[startup] image uploads disabled (STORAGE_DRIVER not configured); image links still work");
  void runJob();
  const timer = setInterval(runJob, EXPIRY_JOB_INTERVAL_MS);

  const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`[startup] LTEZE API listening on port ${PORT}`);
  });

  const shutdown = (sig: string) => {
    console.log(`[shutdown] ${sig}`);
    clearInterval(timer);
    server.close(() => {
      pool.end().finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

if (require.main === module) {
  start().catch((err: unknown) => {
    console.error("[startup] failed:", err instanceof Error ? err.message : err);
    process.exit(1);
  });
}

export { app };
