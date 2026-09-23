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
import {
  createProductSchema,
  updateProductSchema,
  applyLegacyImage,
  updateSellerProduct,
  Owner,
  AfterChange,
  galleryRoutes,
  sellerGallery,
  VISIBLE_SQL,
  catalogQuerySchema,
  catalogItem,
} from "./products";

// ------------------------------------------------------------- admin auth

export const adminLoginSchema = z
  .object({ phone: phoneSchema.optional(), whatsapp: phoneSchema.optional(), password: z.string().min(1).max(256) })
  .refine((d) => d.phone || d.whatsapp, { message: "رقم الهاتف مطلوب", path: ["phone"] });

app.post(
  "/admin/login",
  authLimiter,
  h(async (req, res) => {
    const d = parse(adminLoginSchema, req.body);
    const phone = (d.phone ?? d.whatsapp) as string;
    const { rows } = await pool.query<{ id: string; password_hash: string; active: boolean }>(
      "SELECT id, password_hash, active FROM admins WHERE phone_normalized = $1",
      [phone],
    );
    const admin = rows[0];
    const valid = await argon2.verify(admin?.password_hash ?? DUMMY_HASH, d.password).catch(() => false);
    if (!admin || !valid || !admin.active) throw new HttpError(401, "invalid_credentials", "بيانات الدخول غير صحيحة");
    await pool.query("UPDATE admins SET last_login_at = now() WHERE id = $1", [admin.id]);
    await createSession(res, "admin", admin.id);
    res.json({ ok: true });
  }),
);

app.post(
  "/admin/logout",
  h(async (req, res) => {
    const s = await readSession(req, "admin");
    if (s) await pool.query("UPDATE sessions SET revoked_at = now() WHERE id = $1", [s.sid]);
    clearSessionCookie(res, "admin");
    res.json({ ok: true });
  }),
);

// Every /admin route below requires an admin session.
export const admin = express.Router();
admin.use(authAdmin);
app.use("/admin", admin);

admin.get(
  "/me",
  h(async (req, res) => {
    const { rows } = await pool.query(
      "SELECT id, full_name, phone_normalized AS phone, last_login_at FROM admins WHERE id = $1",
      [adminId(req)],
    );
    res.json({ admin: rows[0] });
  }),
);

admin.get(
  "/dashboard",
  h(async (_req, res) => {
    const { rows } = await pool.query(`
      SELECT
        (SELECT count(*) FROM sellers)::int AS total_sellers,
        (SELECT count(*) FROM sellers WHERE account_status = 'active')::int AS active_sellers,
        (SELECT count(*) FROM sellers WHERE account_status = 'pending')::int AS pending_sellers,
        (SELECT count(*) FROM sellers WHERE account_status = 'suspended')::int AS suspended_sellers,
        (SELECT count(*) FROM subscriptions
          WHERE status = 'active' AND expires_at BETWEEN now() AND now() + interval '7 days')::int AS expiring_subscriptions,
        (SELECT count(DISTINCT s.seller_id) FROM subscriptions s
          WHERE s.status = 'expired'
            AND NOT EXISTS (SELECT 1 FROM subscriptions a WHERE a.seller_id = s.seller_id AND a.status = 'active'))::int
          AS expired_subscriptions,
        (SELECT count(*) FROM products WHERE visibility <> 'deleted')::int AS total_products,
        (SELECT count(*) FROM products WHERE visibility NOT IN ('published','deleted'))::int AS hidden_products,
        (SELECT count(*) FROM password_reset_requests WHERE status = 'open')::int AS open_password_reset_requests
    `);
    res.json(rows[0]);
  }),
);

export const sellersQuerySchema = pagingSchema.extend({
  status: z.enum(["pending", "active", "suspended"]).optional(),
  q: z.string().trim().max(100).optional(),
});

admin.get(
  "/sellers",
  h(async (req, res) => {
    const d = parse(sellersQuerySchema, pageQuery(req));
    const vals: unknown[] = [];
    const conds: string[] = [];
    if (d.status) {
      vals.push(d.status);
      conds.push(`s.account_status = $${vals.length}`);
    }
    if (d.q) {
      vals.push(`%${d.q.replace(/[%_\\]/g, "\\$&")}%`);
      conds.push(`(s.full_name ILIKE $${vals.length} OR s.phone_normalized ILIKE $${vals.length})`);
    }
    vals.push(d.limit, (d.page - 1) * d.limit);
    const { rows } = await pool.query(
      `SELECT s.id, s.full_name, s.phone_normalized AS whatsapp, s.region, s.birth_date, s.account_status,
              s.created_at, s.approved_at, s.suspended_at, s.suspension_reason,
              sub.status AS subscription_status, sub.expires_at AS subscription_expires_at,
              (SELECT count(*) FROM products p WHERE p.seller_id = s.id AND p.visibility <> 'deleted')::int AS products,
              count(*) OVER()::int AS total
         FROM sellers s
         LEFT JOIN LATERAL (SELECT status, expires_at FROM subscriptions
                             WHERE seller_id = s.id ORDER BY created_at DESC LIMIT 1) sub ON TRUE
        ${conds.length ? "WHERE " + conds.join(" AND ") : ""}
        ORDER BY s.created_at DESC
        LIMIT $${vals.length - 1} OFFSET $${vals.length}`,
      vals,
    );
    res.json({ page: d.page, limit: d.limit, total: rows[0]?.total ?? 0, items: rows.map(({ total: _t, ...r }) => r) });
  }),
);

admin.get(
  "/sellers/:id",
  h(async (req, res) => {
    const id = idParam(req);
    const s = await pool.query(
      `SELECT id, full_name, phone_normalized AS whatsapp, region, birth_date, account_status, created_at,
              approved_at, approved_by, suspended_at, suspension_reason, updated_at
         FROM sellers WHERE id = $1`,
      [id],
    );
    if (!s.rows[0]) throw new HttpError(404, "not_found", "التاجر غير موجود");
    const subs = await pool.query("SELECT * FROM subscriptions WHERE seller_id = $1 ORDER BY created_at DESC", [id]);
    const counts = await pool.query(
      "SELECT visibility, count(*)::int AS n FROM products WHERE seller_id = $1 GROUP BY visibility",
      [id],
    );
    res.json({ seller: s.rows[0], subscriptions: subs.rows, product_counts: counts.rows });
  }),
);

export const reasonSchema = z.object({ reason: z.string().trim().max(500).optional() });

admin.post(
  "/sellers/:id/approve",
  h(async (req, res) => {
    const id = idParam(req);
    const aid = adminId(req);
    const d = parse(reasonSchema, req.body ?? {});
    await tx(async (c) => {
      const r = await c.query(
        `UPDATE sellers SET account_status = 'active', approved_at = now(), approved_by = $2, updated_at = now()
          WHERE id = $1 AND account_status = 'pending'`,
        [id, aid],
      );
      if (!r.rowCount) throw new HttpError(409, "not_pending", "التاجر غير موجود أو ليس قيد المراجعة");
      await restoreFromSubscription(c, id);
      await audit(c, { adminId: aid, action: "seller_approve", sellerId: id, reason: d.reason });
    });
    res.json({ ok: true, status: "active" });
  }),
);

admin.post(
  "/sellers/:id/suspend",
  h(async (req, res) => {
    const id = idParam(req);
    const aid = adminId(req);
    const d = parse(z.object({ reason: z.string().trim().min(2).max(500) }), req.body ?? {});
    const hidden = await tx(async (c) => {
      const r = await c.query(
        `UPDATE sellers SET account_status = 'suspended', suspended_at = now(), suspension_reason = $2, updated_at = now()
          WHERE id = $1 AND account_status <> 'suspended'`,
        [id, d.reason],
      );
      if (!r.rowCount) throw new HttpError(409, "already_suspended", "التاجر غير موجود أو موقوف مسبقاً");
      const p = await c.query(
        `UPDATE products SET prior_visibility = visibility, visibility = 'hidden_suspension', updated_at = now()
          WHERE seller_id = $1 AND visibility = 'published'`,
        [id],
      );
      await revokeAllSessions(c, "seller", id);
      await audit(c, {
        adminId: aid,
        action: "seller_suspend",
        sellerId: id,
        reason: d.reason,
        metadata: { products_hidden: p.rowCount ?? 0 },
      });
      return p.rowCount ?? 0;
    });
    res.json({ ok: true, status: "suspended", products_hidden: hidden });
  }),
);

admin.post(
  "/sellers/:id/reactivate",
  h(async (req, res) => {
    const id = idParam(req);
    const aid = adminId(req);
    const d = parse(reasonSchema, req.body ?? {});
    const result = await tx(async (c) => {
      const r = await c.query(
        `UPDATE sellers SET account_status = 'active', suspended_at = NULL, suspension_reason = NULL,
                approved_at = COALESCE(approved_at, now()), approved_by = COALESCE(approved_by, $2), updated_at = now()
          WHERE id = $1 AND account_status = 'suspended'`,
        [id, aid],
      );
      if (!r.rowCount) throw new HttpError(409, "not_suspended", "التاجر غير موجود أو غير موقوف");
      // Only products hidden BY the suspension come back. Manual hides stay hidden.
      const target: Visibility = (await hasActiveSubscription(c, id)) ? "published" : "hidden_subscription";
      const p = await c.query(
        `UPDATE products SET visibility = $2, prior_visibility = 'hidden_suspension', updated_at = now()
          WHERE seller_id = $1 AND visibility = 'hidden_suspension'`,
        [id, target],
      );
      await audit(c, {
        adminId: aid,
        action: "seller_reactivate",
        sellerId: id,
        reason: d.reason,
        metadata: { products_restored_to: target, count: p.rowCount ?? 0 },
      });
      return { target, count: p.rowCount ?? 0 };
    });
    res.json({ ok: true, status: "active", products: result });
  }),
);

// Admin issues a one-time reset token (shown once) to send to the seller via WhatsApp.
admin.get(
  "/password-reset-requests",
  h(async (_req, res) => {
    const { rows } = await pool.query(
      `SELECT r.id, r.seller_id, s.full_name, s.phone_normalized AS whatsapp, r.status, r.created_at
         FROM password_reset_requests r JOIN sellers s ON s.id = r.seller_id
        WHERE r.status = 'open' ORDER BY r.created_at DESC LIMIT 100`,
    );
    res.json({ items: rows });
  }),
);

admin.post(
  "/sellers/:id/password-reset",
  h(async (req, res) => {
    const id = idParam(req);
    const aid = adminId(req);
    const { rows } = await pool.query<{ phone: string }>("SELECT phone_normalized AS phone FROM sellers WHERE id = $1", [id]);
    if (!rows[0]) throw new HttpError(404, "not_found", "التاجر غير موجود");
    const token = crypto.randomBytes(32).toString("base64url");
    await tx(async (c) => {
      // invalidate older unused tokens
      await c.query("UPDATE password_reset_tokens SET used_at = now() WHERE seller_id = $1 AND used_at IS NULL", [id]);
      await c.query(
        `INSERT INTO password_reset_tokens (seller_id, token_hash, expires_at, created_by)
         VALUES ($1, $2, now() + make_interval(mins => $3::int), $4)`,
        [id, sha256(token), RESET_TOKEN_MINUTES, aid],
      );
      await audit(c, { adminId: aid, action: "seller_password_reset_issued", sellerId: id });
    });
    const text = `🔑 LTEZE\nرمز إعادة تعيين كلمة المرور (صالح ${RESET_TOKEN_MINUTES} دقيقة):\n${token}`;
    res.set("Cache-Control", "no-store");
    res.json({
      ok: true,
      token,
      expires_in_minutes: RESET_TOKEN_MINUTES,
      seller_whatsapp_url: waLink(rows[0].phone, text),
    });
  }),
);

// ------------------------------------------------------------- subscriptions

export const subscriptionSchema = z.object({
  // Older clients sent only { days }: "renew" works whether or not a subscription is active.
  action: z.enum(["activate", "renew", "extend", "cancel"]).default("renew"),
  days: z.coerce.number().int().min(1).max(3650).default(30),
  reason: z.string().trim().max(500).optional(),
});

admin.get(
  "/subscriptions/:sellerId",
  h(async (req, res) => {
    const id = idParam(req, "sellerId");
    const { rows } = await pool.query("SELECT * FROM subscriptions WHERE seller_id = $1 ORDER BY created_at DESC", [id]);
    res.json({ items: rows });
  }),
);

admin.post(
  "/subscriptions/:sellerId",
  h(async (req, res) => {
    const id = idParam(req, "sellerId");
    const aid = adminId(req);
    const d = parse(subscriptionSchema, req.body);

    const result = await tx(async (c) => {
      const seller = await c.query("SELECT 1 FROM sellers WHERE id = $1 FOR UPDATE", [id]);
      if (!seller.rowCount) throw new HttpError(404, "not_found", "التاجر غير موجود");
      const cur = await c.query<{ id: string; expires_at: Date }>(
        "SELECT id, expires_at FROM subscriptions WHERE seller_id = $1 AND status = 'active' FOR UPDATE",
        [id],
      );
      const active = cur.rows[0];
      const interval = `${d.days} days`;
      let sub: Record<string, unknown> | undefined;
      let restored = 0;
      let hidden = 0;

      if (d.action === "activate") {
        if (active) throw new HttpError(409, "already_active", "يوجد اشتراك فعال. استخدم renew أو extend.");
        const r = await c.query(
          `INSERT INTO subscriptions (seller_id, status, starts_at, expires_at, created_by)
           VALUES ($1, 'active', now(), now() + $2::interval, $3) RETURNING *`,
          [id, interval, aid],
        );
        sub = r.rows[0];
        restored = await restoreFromSubscription(c, id);
      } else if (d.action === "renew") {
        const prev = active
          ? active.id
          : (
              await c.query<{ id: string }>(
                "SELECT id FROM subscriptions WHERE seller_id = $1 ORDER BY created_at DESC LIMIT 1",
                [id],
              )
            ).rows[0]?.id ?? null;
        if (active) {
          await c.query("UPDATE subscriptions SET status = 'renewed', updated_at = now() WHERE id = $1", [active.id]);
        }
        // New period stacks on top of remaining time of the current active one.
        const r = await c.query(
          `INSERT INTO subscriptions (seller_id, status, starts_at, expires_at, created_by, renewed_from)
           VALUES ($1, 'active', now(), GREATEST(now(), COALESCE($2::timestamptz, now())) + $3::interval, $4, $5)
           RETURNING *`,
          [id, active?.expires_at ?? null, interval, aid, prev],
        );
        sub = r.rows[0];
        restored = await restoreFromSubscription(c, id);
      } else if (d.action === "extend") {
        if (!active) throw new HttpError(409, "no_active", "لا يوجد اشتراك فعال للتمديد. استخدم activate أو renew.");
        const r = await c.query(
          "UPDATE subscriptions SET expires_at = expires_at + $2::interval, updated_at = now() WHERE id = $1 RETURNING *",
          [active.id, interval],
        );
        sub = r.rows[0];
      } else {
        if (!active) throw new HttpError(409, "no_active", "لا يوجد اشتراك فعال للإلغاء");
        const r = await c.query(
          "UPDATE subscriptions SET status = 'cancelled', cancelled_at = now(), updated_at = now() WHERE id = $1 RETURNING *",
          [active.id],
        );
        sub = r.rows[0];
        hidden = await hideForSubscription(c, id);
      }

      await audit(c, {
        adminId: aid,
        action: `subscription_${d.action}`,
        sellerId: id,
        reason: d.reason,
        metadata: { days: d.action === "cancel" ? null : d.days, subscription_id: sub?.id, restored, hidden },
      });
      return { subscription: sub, products_restored: restored, products_hidden: hidden };
    });
    res.json({ ok: true, ...result });
  }),
);

// ------------------------------------------------------------- admin products

export const adminProductsQuery = pagingSchema.extend({
  seller_id: uuidSchema.optional(),
  visibility: z.enum(VISIBILITIES).optional(),
});

admin.get(
  "/products",
  h(async (req, res) => {
    const d = parse(adminProductsQuery, pageQuery(req));
    const vals: unknown[] = [];
    const conds: string[] = [];
    if (d.seller_id) {
      vals.push(d.seller_id);
      conds.push(`p.seller_id = $${vals.length}`);
    }
    if (d.visibility) {
      vals.push(d.visibility);
      conds.push(`p.visibility = $${vals.length}`);
    }
    vals.push(d.limit, (d.page - 1) * d.limit);
    const { rows } = await pool.query(
      `SELECT p.id, p.seller_id, s.full_name AS seller_name, p.name, p.description, p.price, p.image,
              p.category_id, p.visibility, p.prior_visibility, p.created_at, p.updated_at,
              count(*) OVER()::int AS total
         FROM products p JOIN sellers s ON s.id = p.seller_id
        ${conds.length ? "WHERE " + conds.join(" AND ") : ""}
        ORDER BY p.created_at DESC
        LIMIT $${vals.length - 1} OFFSET $${vals.length}`,
      vals,
    );
    res.json({
      page: d.page,
      limit: d.limit,
      total: rows[0]?.total ?? 0,
      items: await productsWithImages(pool, rows.map(({ total: _t, ...r }) => r)),
    });
  }),
);

export const adminProductUpdate = z
  .object({
    name: productFields.name.optional(),
    description: productFields.description.optional(),
    price: productFields.price.optional(),
    image: productFields.image.optional(),
    category_id: productFields.category_id.optional(),
    action: z.enum(["hide", "unhide"]).optional(),
    reason: z.string().trim().max(500).optional(),
  })
  .strict();

admin.patch(
  "/products/:id",
  h(async (req, res) => {
    const pid = idParam(req);
    const aid = adminId(req);
    const d = parse(adminProductUpdate, req.body);
    await assertActiveCategory(pool, d.category_id);
    const product = await tx(async (c) => {
      const { rows } = await c.query<{ seller_id: string; visibility: Visibility }>(
        "SELECT seller_id, visibility FROM products WHERE id = $1 FOR UPDATE",
        [pid],
      );
      if (!rows[0]) throw new HttpError(404, "not_found", "المنتج غير موجود");
      const { seller_id, visibility: current } = rows[0];
      let next: Visibility = current;
      if (d.action === "hide") next = "hidden_by_admin";
      if (d.action === "unhide") {
        if (current !== "hidden_by_admin") throw new HttpError(409, "not_admin_hidden", "المنتج ليس مخفياً من الإدارة");
        next = await effectiveVisibleState(c, seller_id);
      }
      const sets: string[] = [];
      const vals: unknown[] = [];
      const add = (col: string, v: unknown) => {
        vals.push(v);
        sets.push(`${col} = $${vals.length}`);
      };
      if (d.name !== undefined) add("name", d.name);
      if (d.description !== undefined) add("description", d.description);
      if (d.price !== undefined) add("price", d.price);
      if (d.category_id !== undefined) add("category_id", d.category_id);
      if (next !== current) {
        add("prior_visibility", current);
        add("visibility", next);
      }
      vals.push(pid);
      await c.query(`UPDATE products SET ${[...sets, "updated_at = now()"].join(", ")} WHERE id = $${vals.length}`, vals);
      if (d.image !== undefined) await applyLegacyImage(c, pid, d.image, d.name ?? "");
      const changed = Object.keys(d).filter((k) => k !== "reason" && k !== "action");
      await audit(c, {
        adminId: aid,
        action: d.action ? `product_${d.action}` : "product_update",
        sellerId: seller_id,
        productId: pid,
        reason: d.reason,
        metadata: { changed, from: current, to: next },
      });
      const fresh = await c.query(`SELECT ${PRODUCT_COLUMNS} FROM products WHERE id = $1`, [pid]);
      return (await productsWithImages(c, fresh.rows))[0];
    });
    res.json({ product });
  }),
);

admin.delete(
  "/products/:id",
  h(async (req, res) => {
    const pid = idParam(req);
    const aid = adminId(req);
    const d = parse(reasonSchema, req.body ?? {});
    await tx(async (c) => {
      const r = await c.query<{ seller_id: string }>(
        `UPDATE products SET prior_visibility = visibility, visibility = 'deleted', deleted_at = now(), updated_at = now()
          WHERE id = $1 AND visibility <> 'deleted' RETURNING seller_id`,
        [pid],
      );
      if (!r.rows[0]) throw new HttpError(404, "not_found", "المنتج غير موجود");
      await audit(c, { adminId: aid, action: "product_delete", sellerId: r.rows[0].seller_id, productId: pid, reason: d.reason });
    });
    res.json({ ok: true });
  }),
);

// Admin gallery: any product; every change is audited.
galleryRoutes(admin, "/products", [], () => null, async (c, req, info) => {
  await audit(c, {
    adminId: adminId(req),
    action: info.action,
    sellerId: info.sellerId,
    productId: info.productId,
    metadata: info.meta ?? {},
  });
});

// ------------------------------------------------------------- admin categories

export const slugSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, "slug: أحرف إنجليزية صغيرة وأرقام و - فقط")
  .max(80);

export const categoryCreate = z.object({
  name: z.string().trim().min(1).max(100),
  slug: slugSchema.optional(),
  active: z.boolean().default(true),
  sort_order: z.coerce.number().int().min(-10000).max(10000).default(0),
});

export function autoSlug(name: string): string {
  const base = name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return base || `cat-${crypto.randomBytes(3).toString("hex")}`;
}

admin.get(
  "/categories",
  h(async (_req, res) => {
    const { rows } = await pool.query("SELECT * FROM categories ORDER BY sort_order, name");
    res.json({ items: rows });
  }),
);

admin.post(
  "/categories",
  h(async (req, res) => {
    const aid = adminId(req);
    const d = parse(categoryCreate, req.body);
    const cat = await tx(async (c) => {
      let r;
      try {
        r = await c.query(
          "INSERT INTO categories (name, slug, active, sort_order) VALUES ($1, $2, $3, $4) RETURNING *",
          [d.name, d.slug ?? autoSlug(d.name), d.active, d.sort_order],
        );
      } catch (err) {
        if ((err as { code?: string }).code === "23505") throw new HttpError(409, "slug_taken", "الـ slug مستخدم مسبقاً");
        throw err;
      }
      await audit(c, { adminId: aid, action: "category_create", metadata: { category_id: r.rows[0].id, name: d.name } });
      return r.rows[0];
    });
    res.status(201).json({ category: cat });
  }),
);

admin.patch(
  "/categories/:id",
  h(async (req, res) => {
    const id = idParam(req);
    const aid = adminId(req);
    const d = parse(categoryCreate.partial().strict(), req.body);
    const cat = await tx(async (c) => {
      const sets: string[] = [];
      const vals: unknown[] = [];
      for (const [k, v] of Object.entries(d)) {
        if (v === undefined) continue;
        vals.push(v);
        sets.push(`${k} = $${vals.length}`);
      }
      vals.push(id);
      let r;
      try {
        r = await c.query(
          `UPDATE categories SET ${[...sets, "updated_at = now()"].join(", ")} WHERE id = $${vals.length} RETURNING *`,
          vals,
        );
      } catch (err) {
        if ((err as { code?: string }).code === "23505") throw new HttpError(409, "slug_taken", "الـ slug مستخدم مسبقاً");
        throw err;
      }
      if (!r.rows[0]) throw new HttpError(404, "not_found", "التصنيف غير موجود");
      await audit(c, { adminId: aid, action: "category_update", metadata: { category_id: id, changes: d } });
      return r.rows[0];
    });
    res.json({ category: cat });
  }),
);

admin.delete(
  "/categories/:id",
  h(async (req, res) => {
    const id = idParam(req);
    const aid = adminId(req);
    await tx(async (c) => {
      // Products keep existing; their category_id becomes NULL (FK ON DELETE SET NULL).
      const r = await c.query<{ name: string }>("DELETE FROM categories WHERE id = $1 RETURNING name", [id]);
      if (!r.rows[0]) throw new HttpError(404, "not_found", "التصنيف غير موجود");
      await audit(c, { adminId: aid, action: "category_delete", metadata: { category_id: id, name: r.rows[0].name } });
    });
    res.json({ ok: true });
  }),
);

// ------------------------------------------------------------- audit logs

admin.get(
  "/audit-logs",
  h(async (req, res) => {
    const d = parse(pagingSchema.extend({ action: z.string().max(60).optional(), seller_id: uuidSchema.optional() }), pageQuery(req));
    const vals: unknown[] = [];
    const conds: string[] = [];
    if (d.action) {
      vals.push(d.action);
      conds.push(`action = $${vals.length}`);
    }
    if (d.seller_id) {
      vals.push(d.seller_id);
      conds.push(`seller_id = $${vals.length}`);
    }
    vals.push(d.limit, (d.page - 1) * d.limit);
    const { rows } = await pool.query(
      `SELECT *, count(*) OVER()::int AS total FROM audit_logs
        ${conds.length ? "WHERE " + conds.join(" AND ") : ""}
        ORDER BY created_at DESC LIMIT $${vals.length - 1} OFFSET $${vals.length}`,
      vals,
    );
    res.json({ page: d.page, limit: d.limit, total: rows[0]?.total ?? 0, items: rows.map(({ total: _t, ...r }) => r) });
  }),
);
