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

// ------------------------------------------------------------- auth: seller

export const registerSchema = z
  .object({
    full_name: z.string().trim().min(2).max(100),
    whatsapp: phoneSchema,
    region: z.string().trim().min(2).max(100),
    birth_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "صيغة التاريخ YYYY-MM-DD"),
    password: passwordSchema,
    password_confirmation: z.string().optional(), // checked when sent (older clients did not send it)
  })
  .refine((d) => d.password_confirmation === undefined || d.password === d.password_confirmation, {
    message: "كلمتا المرور غير متطابقتين",
    path: ["password_confirmation"],
  })
  .refine(
    (d) => {
      const bd = new Date(d.birth_date + "T00:00:00Z");
      if (Number.isNaN(bd.getTime())) return false;
      const now = new Date();
      const age18 = new Date(Date.UTC(bd.getUTCFullYear() + 18, bd.getUTCMonth(), bd.getUTCDate()));
      return age18 <= now && bd.getUTCFullYear() > 1900;
    },
    { message: "يجب أن يكون عمر التاجر 18 سنة على الأقل", path: ["birth_date"] },
  );

app.post(
  "/auth/register",
  authLimiter,
  h(async (req, res) => {
    const d = parse(registerSchema, compat(req.body));
    const hash = await argon2.hash(d.password, ARGON2_OPTIONS);
    try {
      await pool.query(
        `INSERT INTO sellers (full_name, phone_normalized, region, birth_date, password_hash)
         VALUES ($1, $2, $3, $4, $5)`,
        [d.full_name, d.whatsapp, d.region, d.birth_date, hash],
      );
    } catch (err) {
      if ((err as { code?: string }).code === "23505") {
        throw new HttpError(409, "phone_taken", "رقم الواتساب مسجل مسبقاً");
      }
      throw err;
    }
    // Password is NEVER included in this message.
    const message = [
      "🏪 طلب انضمام كتاجر – LTEZE",
      "",
      `الاسم: ${d.full_name}`,
      `رقم WhatsApp: ${d.whatsapp}`,
      `المنطقة: ${d.region}`,
      `تاريخ الميلاد: ${d.birth_date}`,
      "",
      "ملاحظة:",
      "كلمة المرور اختارها التاجر بنفسه ولم يتم إرسالها عبر WhatsApp.",
    ].join("\n");
    res.status(201).json({
      ok: true,
      status: "pending",
      message: "تم استلام طلبك. حسابك قيد المراجعة وسيتم تفعيله بعد موافقة الإدارة.",
      admin_whatsapp_url: waLink(ADMIN_WHATSAPP, message),
    });
  }),
);


export const loginSchema = z.object({ whatsapp: phoneSchema, password: z.string().min(1).max(128) });

app.post(
  "/auth/login",
  authLimiter,
  h(async (req, res) => {
    const d = parse(loginSchema, compat(req.body));
    const { rows } = await pool.query<{ id: string; password_hash: string; account_status: string; full_name: string }>(
      "SELECT id, password_hash, account_status, full_name FROM sellers WHERE phone_normalized = $1",
      [d.whatsapp],
    );
    const seller = rows[0];
    const valid = await argon2.verify(seller?.password_hash ?? DUMMY_HASH, d.password).catch(() => false);
    if (!seller || !valid) throw new HttpError(401, "invalid_credentials", "رقم الواتساب أو كلمة المرور غير صحيحة");
    if (seller.account_status === "pending") {
      throw new HttpError(403, "account_pending", "حسابك قيد المراجعة. لا يمكنك الدخول قبل موافقة الإدارة.");
    }
    if (seller.account_status !== "active") throw new HttpError(403, "account_suspended", "حسابك موقوف. تواصل مع الإدارة.");
    if (argon2.needsRehash(seller.password_hash, ARGON2_OPTIONS)) {
      const newHash = await argon2.hash(d.password, ARGON2_OPTIONS);
      await pool.query("UPDATE sellers SET password_hash = $1, updated_at = now() WHERE id = $2", [newHash, seller.id]);
    }
    await createSession(res, "seller", seller.id);
    res.json({ ok: true, seller: { id: seller.id, full_name: seller.full_name } });
  }),
);

app.post(
  "/auth/logout",
  h(async (req, res) => {
    const s = await readSession(req, "seller");
    if (s) await pool.query("UPDATE sessions SET revoked_at = now() WHERE id = $1", [s.sid]);
    clearSessionCookie(res, "seller");
    res.json({ ok: true });
  }),
);

// Step 1: seller asks for a reset. Generic answer (no account enumeration).
app.post(
  "/auth/password-reset-request",
  authLimiter,
  h(async (req, res) => {
    const d = parse(z.object({ whatsapp: phoneSchema }), compat(req.body));
    const { rows } = await pool.query<{ id: string }>("SELECT id FROM sellers WHERE phone_normalized = $1", [d.whatsapp]);
    if (rows[0]) {
      await pool.query(
        `INSERT INTO password_reset_requests (seller_id)
         SELECT $1 WHERE NOT EXISTS (
           SELECT 1 FROM password_reset_requests
            WHERE seller_id = $1 AND status = 'open' AND created_at > now() - interval '1 hour')`,
        [rows[0].id],
      );
    }
    res.json({
      ok: true,
      message: "إذا كان الرقم مسجلاً، ستتواصل معك الإدارة عبر واتساب برمز إعادة التعيين.",
      admin_whatsapp_url: waLink(ADMIN_WHATSAPP, `🔑 طلب إعادة تعيين كلمة المرور – LTEZE\nرقم WhatsApp: ${d.whatsapp}`),
    });
  }),
);

// Step 2: seller sets a new password with the one-time token issued by admin.
export const resetConfirmSchema = z
  .object({
    whatsapp: phoneSchema,
    token: z.string().min(20).max(200),
    password: passwordSchema,
    password_confirmation: z.string(),
  })
  .refine((d) => d.password === d.password_confirmation, {
    message: "كلمتا المرور غير متطابقتين",
    path: ["password_confirmation"],
  });

app.post(
  "/auth/password-reset-confirm",
  authLimiter,
  h(async (req, res) => {
    const d = parse(resetConfirmSchema, compat(req.body));
    const hash = await argon2.hash(d.password, ARGON2_OPTIONS);
    const ok = await tx(async (c) => {
      const { rows } = await c.query<{ token_id: string; seller_id: string }>(
        `SELECT t.id AS token_id, t.seller_id FROM password_reset_tokens t
           JOIN sellers s ON s.id = t.seller_id
          WHERE t.token_hash = $1 AND s.phone_normalized = $2
            AND t.used_at IS NULL AND t.expires_at > now()
          FOR UPDATE OF t`,
        [sha256(d.token), d.whatsapp],
      );
      if (!rows[0]) return false;
      await c.query("UPDATE password_reset_tokens SET used_at = now() WHERE id = $1", [rows[0].token_id]);
      await c.query("UPDATE sellers SET password_hash = $1, updated_at = now() WHERE id = $2", [hash, rows[0].seller_id]);
      await c.query(
        "UPDATE password_reset_requests SET status = 'done', resolved_at = now() WHERE seller_id = $1 AND status = 'open'",
        [rows[0].seller_id],
      );
      await revokeAllSessions(c, "seller", rows[0].seller_id);
      return true;
    });
    if (!ok) throw new HttpError(400, "invalid_token", "الرمز غير صالح أو منتهي الصلاحية");
    res.json({ ok: true, message: "تم تغيير كلمة المرور. يمكنك تسجيل الدخول الآن." });
  }),
);

// ------------------------------------------------------------- seller API

app.get(
  "/seller/me",
  authSeller,
  h(async (req, res) => {
    const id = sellerId(req);
    const { rows } = await pool.query(
      `SELECT id, full_name, phone_normalized AS whatsapp, region, birth_date, account_status, created_at, approved_at
         FROM sellers WHERE id = $1`,
      [id],
    );
    const sub = await pool.query(
      `SELECT id, status, starts_at, expires_at FROM subscriptions
        WHERE seller_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [id],
    );
    const counts = await pool.query(
      `SELECT visibility, count(*)::int AS n FROM products
        WHERE seller_id = $1 AND visibility <> 'deleted' GROUP BY visibility`,
      [id],
    );
    res.json({ seller: rows[0], subscription: sub.rows[0] ?? null, product_counts: counts.rows });
  }),
);
