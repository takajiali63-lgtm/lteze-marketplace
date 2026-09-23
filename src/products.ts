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

// ============================================================ seller products

app.get(
  "/seller/products",
  authSeller,
  h(async (req, res) => {
    const id = sellerId(req);
    const { page, limit } = parse(pagingSchema, pageQuery(req));
    const { rows } = await pool.query(
      `SELECT ${PRODUCT_COLUMNS}, count(*) OVER()::int AS total FROM products
        WHERE seller_id = $1 AND visibility <> 'deleted'
        ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [id, limit, (page - 1) * limit],
    );
    const total = rows[0]?.total ?? 0;
    const items = await productsWithImages(pool, rows.map(({ total: _t, ...r }) => r));
    res.json({ page, limit, offset: (page - 1) * limit, total, items, products: items });
  }),
);

app.get(
  "/seller/products/:id",
  authSeller,
  h(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT ${PRODUCT_COLUMNS} FROM products WHERE id = $1 AND seller_id = $2 AND visibility <> 'deleted'`,
      [idParam(req), sellerId(req)],
    );
    if (!rows[0]) throw new HttpError(404, "not_found", "المنتج غير موجود");
    res.json({ product: (await productsWithImages(pool, rows))[0] });
  }),
);

export const createProductSchema = z.object({
  name: productFields.name,
  description: productFields.description.default(""),
  price: productFields.price,
  image: productFields.image.optional(), // legacy
  images: z.array(imageLinkSchema).max(MAX_IMAGES_PER_PRODUCT).optional(),
  primary_index: z.coerce.number().int().min(0).max(MAX_IMAGES_PER_PRODUCT - 1).optional(),
  category_id: productFields.category_id.optional().default(null),
  visibility: z.enum(["published", "hidden_by_seller"]).default("published"),
});

/**
 * Create a product. Accepts JSON, or multipart/form-data with up to 10 files in field "files".
 * Gallery order: link images (`images`) first, then uploaded files, in the order sent.
 * `primary_index` selects the cover (default 0).
 */
app.post(
  "/seller/products",
  authSeller,
  uploadLimiter,
  uploadMany,
  h(async (req, res) => {
    const id = sellerId(req);
    const d = parse(createProductSchema, compat(bodyOf(req)));
    const files = filesOf(req);
    const links = d.images ?? (d.image ? [{ url: d.image }] : []);
    const total = links.length + files.length;
    if (total > MAX_IMAGES_PER_PRODUCT) {
      throw new HttpError(409, "too_many_images", `الحد الأقصى ${MAX_IMAGES_PER_PRODUCT} صور للمنتج`);
    }
    if (d.primary_index !== undefined && d.primary_index >= total) {
      throw new HttpError(400, "invalid_primary_index", "primary_index خارج عدد الصور");
    }
    await assertActiveCategory(pool, d.category_id);

    const productId = crypto.randomUUID();
    const uploaded = await processAndUpload(productId, files, d.name);
    const imgs = [...linkRows(links, d.name), ...uploaded];

    let product: Record<string, unknown>;
    try {
      product = await tx(async (c) => {
        const visibility: Visibility =
          d.visibility === "hidden_by_seller" ? "hidden_by_seller" : await effectiveVisibleState(c, id);
        const { rows } = await c.query(
          `INSERT INTO products (id, seller_id, name, description, price, category_id, visibility)
           VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING ${PRODUCT_COLUMNS}`,
          [productId, id, d.name, d.description, d.price, d.category_id, visibility],
        );
        await insertImages(c, productId, imgs, 0);
        let gallery = appendToGallery([], imgs.map((i) => i.id));
        if (d.primary_index !== undefined) gallery = setPrimaryInGallery(gallery, imgs[d.primary_index].id);
        await writeGallery(c, productId, gallery);
        const fresh = await c.query(`SELECT ${PRODUCT_COLUMNS} FROM products WHERE id = $1`, [productId]);
        return (await productsWithImages(c, fresh.rows))[0] ?? rows[0];
      });
    } catch (err) {
      await discardUploaded(uploaded);
      throw err;
    }
    res.status(201).json({ product });
  }),
);

export const updateProductSchema = z
  .object({
    name: productFields.name.optional(),
    description: productFields.description.optional(),
    price: productFields.price.optional(),
    image: productFields.image.optional(), // legacy: replaces the primary image (null removes it)
    category_id: productFields.category_id.optional(),
    visibility: z.enum(["published", "hidden_by_seller"]).optional(),
  })
  .strict();

/** Legacy single-image update: replace primary with a link (or add one), or remove it with null. */
export async function applyLegacyImage(c: PoolClient, productId: string, url: string | null, alt: string): Promise<void> {
  const gallery = await readGallery(c, productId);
  const primary = normalizeGallery(gallery).find((i) => i.is_primary);
  if (url === null) {
    if (!primary) return;
    const next = removeFromGallery(gallery, primary.id);
    await c.query("DELETE FROM product_images WHERE id = $1", [primary.id]);
    await writeGallery(c, productId, next);
    return;
  }
  if (primary) {
    await c.query(
      `UPDATE product_images SET url = $2, storage_provider = 'external', storage_key = NULL, mime_type = NULL,
              size_bytes = NULL, width = NULL, height = NULL, updated_at = now() WHERE id = $1`,
      [primary.id, url],
    );
    await writeGallery(c, productId, normalizeGallery(gallery));
    return;
  }
  const [row] = linkRows([{ url }], alt);
  const next = appendToGallery(gallery, [row.id]);
  await insertImages(c, productId, [row], next.length - 1);
  await writeGallery(c, productId, setPrimaryInGallery(next, row.id));
}

export const updateSellerProduct = h(async (req, res) => {
    const sid = sellerId(req);
    const pid = idParam(req);
    const d = parse(updateProductSchema, compat(req.body));
    await assertActiveCategory(pool, d.category_id);

    const product = await tx(async (c) => {
      // Ownership enforced by the WHERE clause: seller_id must equal the authenticated seller.
      const { rows } = await c.query<{ visibility: Visibility; name: string }>(
        "SELECT visibility, name FROM products WHERE id = $1 AND seller_id = $2 AND visibility <> 'deleted' FOR UPDATE",
        [pid, sid],
      );
      if (!rows[0]) throw new HttpError(404, "not_found", "المنتج غير موجود");
      const current = rows[0].visibility;

      let nextVisibility: Visibility = current;
      if (d.visibility) {
        if (current === "hidden_by_admin" || current === "hidden_suspension") {
          throw new HttpError(403, "locked_by_admin", "لا يمكنك تغيير ظهور هذا المنتج. تواصل مع الإدارة.");
        }
        nextVisibility = d.visibility === "hidden_by_seller" ? "hidden_by_seller" : await effectiveVisibleState(c, sid);
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
      if (nextVisibility !== current) {
        add("prior_visibility", current);
        add("visibility", nextVisibility);
      }
      vals.push(pid, sid);
      await c.query(
        `UPDATE products SET ${[...sets, "updated_at = now()"].join(", ")}
          WHERE id = $${vals.length - 1} AND seller_id = $${vals.length}`,
        vals,
      );
      if (d.image !== undefined) await applyLegacyImage(c, pid, d.image, d.name ?? rows[0].name);
      const fresh = await c.query(`SELECT ${PRODUCT_COLUMNS} FROM products WHERE id = $1`, [pid]);
      return (await productsWithImages(c, fresh.rows))[0];
    });
    res.json({ product });
  });

app.patch("/seller/products/:id", authSeller, updateSellerProduct);
// Legacy route from the earlier API: body { visibility }
app.patch("/seller/products/:id/visibility", authSeller, updateSellerProduct);

/**
 * Soft delete. Images stay (the product is recoverable and audit stays intact) but are never
 * served, because the product leaves the catalog. After DELETED_PRODUCT_RETENTION_DAYS the purge
 * job removes the product; image rows cascade and their stored files are queued for deletion.
 */
app.delete(
  "/seller/products/:id",
  authSeller,
  h(async (req, res) => {
    const sid = sellerId(req);
    const pid = idParam(req);
    const r = await pool.query(
      `UPDATE products SET prior_visibility = visibility, visibility = 'deleted', deleted_at = now(), updated_at = now()
        WHERE id = $1 AND seller_id = $2 AND visibility <> 'deleted'`,
      [pid, sid],
    );
    if (!r.rowCount) throw new HttpError(404, "not_found", "المنتج غير موجود");
    res.json({ ok: true });
  }),
);

// ============================================================ gallery endpoints (seller + admin)

export type Owner = (req: Request) => string | null; // seller id, or null = admin (any product)
export type AfterChange = (c: PoolClient, req: Request, info: { productId: string; sellerId: string; action: string; meta?: Record<string, unknown> }) => Promise<void>;

export function galleryRoutes(
  router: express.Router,
  base: string,
  auth: RequestHandler[],
  owner: Owner,
  afterChange: AfterChange,
): void {
  const reply = async (res: Response, productId: string) => {
    const imgs = await loadImages(pool, [productId]);
    const list = imgs.get(productId) ?? [];
    res.json({ images: list, primary_image: list.find((i) => i.is_primary) ?? null });
  };

  // List
  router.get(
    `${base}/:id/images`,
    ...auth,
    h(async (req, res) => {
      const pid = idParam(req);
      await tx((c) => lockProduct(c, pid, owner(req)));
      await reply(res, pid);
    }),
  );

  // Add: multipart "files" (up to remaining slots) and/or JSON { images: [{url, alt?}] }, optional make_primary
  router.post(
    `${base}/:id/images`,
    ...auth,
    uploadLimiter,
    uploadMany,
    h(async (req, res) => {
      const pid = idParam(req);
      const d = parse(
        z.object({
          images: z.array(imageLinkSchema).max(MAX_IMAGES_PER_PRODUCT).optional(),
          make_primary: z.union([z.boolean(), z.enum(["true", "false"])]).optional(),
        }),
        bodyOf(req),
      );
      const files = filesOf(req);
      const links = d.images ?? [];
      if (files.length + links.length === 0) throw new HttpError(400, "no_images", "لم يتم إرسال أي صورة");

      // Fail fast on the limit before processing/uploading anything.
      const pre = await tx(async (c) => {
        const p = await lockProduct(c, pid, owner(req));
        const count = (await readGallery(c, pid)).length;
        return { ...p, count };
      });
      if (pre.count + files.length + links.length > MAX_IMAGES_PER_PRODUCT) {
        throw new HttpError(
          409,
          "too_many_images",
          `الحد الأقصى ${MAX_IMAGES_PER_PRODUCT} صور للمنتج. المتبقي: ${MAX_IMAGES_PER_PRODUCT - pre.count}`,
        );
      }

      const uploaded = await processAndUpload(pid, files, pre.name);
      const imgs = [...linkRows(links, pre.name), ...uploaded];
      try {
        await tx(async (c) => {
          const p = await lockProduct(c, pid, owner(req));
          const current = await readGallery(c, pid);
          let next = appendToGallery(current, imgs.map((i) => i.id)); // re-checks the limit under lock
          await insertImages(c, pid, imgs, normalizeGallery(current).length);
          const mp = d.make_primary === true || d.make_primary === "true";
          if (mp) next = setPrimaryInGallery(next, imgs[0].id);
          await writeGallery(c, pid, next);
          await afterChange(c, req, { productId: pid, sellerId: p.seller_id, action: "product_images_add", meta: { added: imgs.length } });
        });
      } catch (err) {
        await discardUploaded(uploaded);
        throw err;
      }
      res.status(201);
      await reply(res, pid);
    }),
  );

  // Reorder: { image_ids: [...] } — must contain every image exactly once
  router.put(
    `${base}/:id/images/order`,
    ...auth,
    h(async (req, res) => {
      const pid = idParam(req);
      const d = parse(z.object({ image_ids: z.array(uuidSchema).min(1).max(MAX_IMAGES_PER_PRODUCT) }), bodyOf(req));
      await tx(async (c) => {
        const p = await lockProduct(c, pid, owner(req));
        await writeGallery(c, pid, reorderGallery(await readGallery(c, pid), d.image_ids));
        await afterChange(c, req, { productId: pid, sellerId: p.seller_id, action: "product_images_reorder" });
      });
      await reply(res, pid);
    }),
  );

  // Set primary
  router.post(
    `${base}/:id/images/:imageId/primary`,
    ...auth,
    h(async (req, res) => {
      const pid = idParam(req);
      const imageId = idParam(req, "imageId");
      await tx(async (c) => {
        const p = await lockProduct(c, pid, owner(req));
        await writeGallery(c, pid, setPrimaryInGallery(await readGallery(c, pid), imageId));
        await afterChange(c, req, { productId: pid, sellerId: p.seller_id, action: "product_images_set_primary", meta: { image_id: imageId } });
      });
      await reply(res, pid);
    }),
  );

  // Replace one image in place (keeps its position and primary flag): multipart "file" or JSON { url, alt? }
  router.put(
    `${base}/:id/images/:imageId`,
    ...auth,
    uploadLimiter,
    uploadOne,
    h(async (req, res) => {
      const pid = idParam(req);
      const imageId = idParam(req, "imageId");
      const file = fileOf(req);
      const d = parse(z.object({ url: imageUrlSchema.optional(), alt: z.string().trim().max(200).optional() }), bodyOf(req));
      if (!file && !d.url) throw new HttpError(400, "no_image", "أرسل ملفاً في الحقل file أو رابطاً في url");

      const pre = await tx((c) => lockProduct(c, pid, owner(req)));
      const [replacement] = file ? await processAndUpload(pid, [file], d.alt ?? pre.name) : linkRows([{ url: d.url as string, alt: d.alt }], pre.name);
      try {
        await tx(async (c) => {
          const p = await lockProduct(c, pid, owner(req));
          const r = await c.query(
            `UPDATE product_images SET url = $3, storage_provider = $4, storage_key = $5, mime_type = $6,
                    size_bytes = $7, width = $8, height = $9, alt_text = COALESCE($10, alt_text), updated_at = now()
              WHERE id = $1 AND product_id = $2`,
            [
              imageId, pid, replacement.url, replacement.provider, replacement.key, replacement.mime,
              replacement.size, replacement.width, replacement.height, d.alt ?? null,
            ],
          );
          if (!r.rowCount) throw new HttpError(404, "image_not_found", "الصورة غير موجودة");
          await writeGallery(c, pid, normalizeGallery(await readGallery(c, pid)));
          await afterChange(c, req, { productId: pid, sellerId: p.seller_id, action: "product_images_replace", meta: { image_id: imageId } });
        });
      } catch (err) {
        await discardUploaded([replacement]);
        throw err;
      }
      await reply(res, pid);
    }),
  );

  // Edit alt text
  router.patch(
    `${base}/:id/images/:imageId`,
    ...auth,
    h(async (req, res) => {
      const pid = idParam(req);
      const imageId = idParam(req, "imageId");
      const d = parse(z.object({ alt: z.string().trim().max(200).nullable() }).strict(), req.body);
      await tx(async (c) => {
        await lockProduct(c, pid, owner(req));
        const r = await c.query(
          "UPDATE product_images SET alt_text = $3, updated_at = now() WHERE id = $1 AND product_id = $2",
          [imageId, pid, d.alt],
        );
        if (!r.rowCount) throw new HttpError(404, "image_not_found", "الصورة غير موجودة");
      });
      await reply(res, pid);
    }),
  );

  // Delete one image (stored file is queued for deletion by DB trigger)
  router.delete(
    `${base}/:id/images/:imageId`,
    ...auth,
    h(async (req, res) => {
      const pid = idParam(req);
      const imageId = idParam(req, "imageId");
      await tx(async (c) => {
        const p = await lockProduct(c, pid, owner(req));
        const next = removeFromGallery(await readGallery(c, pid), imageId);
        await c.query("DELETE FROM product_images WHERE id = $1 AND product_id = $2", [imageId, pid]);
        await writeGallery(c, pid, next);
        await afterChange(c, req, { productId: pid, sellerId: p.seller_id, action: "product_images_delete", meta: { image_id: imageId } });
      });
      await reply(res, pid);
    }),
  );
}

// Seller gallery: ownership enforced (seller_id = authenticated seller).
export const sellerGallery = express.Router();
galleryRoutes(sellerGallery, "/seller/products", [authSeller], (req) => sellerId(req), async () => undefined);
app.use(sellerGallery);

// ------------------------------------------------------------- public

app.get(
  "/categories",
  h(async (_req, res) => {
    const { rows } = await pool.query(
      "SELECT id, name, slug, sort_order FROM categories WHERE active ORDER BY sort_order, name",
    );
    res.set("Cache-Control", "public, max-age=60");
    res.json({ items: rows, categories: rows });
  }),
);

export const VISIBLE_SQL = `
  p.visibility = 'published'
  AND s.account_status = 'active'
  AND EXISTS (SELECT 1 FROM subscriptions sub
               WHERE sub.seller_id = s.id AND sub.status = 'active' AND sub.expires_at > now())`;

export const catalogQuerySchema = pagingSchema.extend({
  category: z.string().trim().max(100).optional(),
  q: z.string().trim().max(100).optional(),
});

export function catalogItem(req: Request, row: Record<string, unknown>, images: ImageOut[]): Record<string, unknown> {
  return {
    ...withImages(row, images),
    // Seller phone is never exposed; the backend redirects to WhatsApp.
    order_whatsapp_url: `${publicBaseUrl(req)}/catalog/${String(row.id)}/whatsapp`,
  };
}

app.get(
  "/catalog",
  h(async (req, res) => {
    const d = parse(catalogQuerySchema, pageQuery(req));
    const vals: unknown[] = [];
    let where = VISIBLE_SQL;
    if (d.category) {
      vals.push(d.category);
      where += uuidSchema.safeParse(d.category).success
        ? ` AND p.category_id = $${vals.length}`
        : ` AND c.slug = $${vals.length}`;
    }
    if (d.q) {
      vals.push(`%${d.q.replace(/[%_\\]/g, "\\$&")}%`);
      where += ` AND (p.name ILIKE $${vals.length} OR p.description ILIKE $${vals.length})`;
    }
    vals.push(d.limit, (d.page - 1) * d.limit);
    const { rows } = await pool.query(
      `SELECT p.id, p.name, p.description, p.price, p.image, p.category_id,
              c.name AS category_name, c.slug AS category_slug,
              s.full_name AS seller_name, s.region AS seller_region, p.created_at,
              count(*) OVER()::int AS total
         FROM products p
         JOIN sellers s ON s.id = p.seller_id
         LEFT JOIN categories c ON c.id = p.category_id
        WHERE ${where}
        ORDER BY p.created_at DESC
        LIMIT $${vals.length - 1} OFFSET $${vals.length}`,
      vals,
    );
    const total = rows[0]?.total ?? 0;
    const imgs = await loadImages(pool, rows.map((r) => String(r.id)));
    const items = rows.map(({ total: _t, ...r }) => catalogItem(req, r, imgs.get(String(r.id)) ?? []));
    res.set("Cache-Control", "public, max-age=30");
    res.json({ page: d.page, limit: d.limit, offset: (d.page - 1) * d.limit, total, items, products: items });
  }),
);

app.get(
  "/catalog/:id",
  h(async (req, res) => {
    const pid = idParam(req);
    const { rows } = await pool.query(
      `SELECT p.id, p.name, p.description, p.price, p.image, p.category_id,
              c.name AS category_name, c.slug AS category_slug,
              s.full_name AS seller_name, s.region AS seller_region, p.created_at
         FROM products p JOIN sellers s ON s.id = p.seller_id
         LEFT JOIN categories c ON c.id = p.category_id
        WHERE p.id = $1 AND ${VISIBLE_SQL}`,
      [pid],
    );
    if (!rows[0]) throw new HttpError(404, "not_found", "المنتج غير متاح");
    const imgs = await loadImages(pool, [pid]);
    res.json({ product: catalogItem(req, rows[0], imgs.get(pid) ?? []) });
  }),
);

/** Redirects the buyer to the seller's WhatsApp with a prefilled message. */
app.get(
  "/catalog/:id/whatsapp",
  h(async (req, res) => {
    const pid = idParam(req);
    const { rows } = await pool.query<{ name: string; price: string; phone: string }>(
      `SELECT p.name, p.price, s.phone_normalized AS phone
         FROM products p JOIN sellers s ON s.id = p.seller_id
        WHERE p.id = $1 AND ${VISIBLE_SQL}`,
      [pid],
    );
    if (!rows[0]) throw new HttpError(404, "not_found", "المنتج غير متاح");

    // Only accept product links on our own storefront.
    let link = `${ALLOWED_ORIGINS[0] ?? "https://lteze.com"}`;
    const raw = typeof req.query.url === "string" ? req.query.url : "";
    try {
      const u = new URL(raw);
      if (ALLOWED_ORIGINS.includes(u.origin)) link = u.toString();
    } catch {
      /* ignore invalid url */
    }
    const text = [
      "مرحباً، أريد طلب:",
      "",
      `اسم المنتج: ${rows[0].name}`,
      `السعر: ${Number(rows[0].price)}`,
      `الرابط: ${link}`,
      "",
      "من LTEZE.",
    ].join("\n");
    res.set("Cache-Control", "no-store");
    res.set("X-Robots-Tag", "noindex, nofollow");
    res.redirect(302, waLink(rows[0].phone, text));
  }),
);
