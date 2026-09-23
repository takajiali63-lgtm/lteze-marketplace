import argon2 from "argon2";
import { Request } from "express";
import { z } from "zod";
import { ARGON2_OPTIONS } from "./migrate";
import { StorageDriver, setDbFallback } from "./storage";
import {
  HttpError,
  adminId,
  app,
  audit,
  authSeller,
  h,
  idParam,
  pageQuery,
  pagingSchema,
  parse,
  passwordSchema,
  phoneSchema,
  pool,
  publicBaseUrl,
  sellerId,
  tx,
} from "./core";
import { ImageOut, loadImages, withImages } from "./media";
import { VISIBLE_SQL } from "./products";
import { admin } from "./admin";

// ============================================================ persistent DB image storage
// Used automatically when no S3-compatible storage is configured. Images are already
// validated, re-encoded to WebP and stripped of metadata before they reach this driver.

function mediaBaseUrl(): string {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, "");
  if (process.env.RENDER_EXTERNAL_HOSTNAME) return `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`;
  return "";
}

const dbDriver: StorageDriver = {
  provider: "db",
  async put(key: string, body: Buffer, contentType: string) {
    await pool.query(
      `INSERT INTO media_blobs (key, mime_type, bytes, size_bytes) VALUES ($1, $2, $3, $4)
       ON CONFLICT (key) DO NOTHING`,
      [key, contentType, body, body.length],
    );
    return { provider: "db" as const, key, url: `${mediaBaseUrl()}/media/${key}` };
  },
  async delete(key: string) {
    await pool.query("DELETE FROM media_blobs WHERE key = $1", [key]);
  },
};
setDbFallback(dbDriver);

const MEDIA_KEY = /^products\/[0-9a-f-]{36}\/[0-9a-f-]{36}\.webp$/;

app.get(
  /^\/media\/(.+)$/,
  h(async (req, res) => {
    const key = String((req.params as Record<string, string>)[0] ?? "");
    if (!MEDIA_KEY.test(key)) throw new HttpError(404, "not_found", "Not found");
    const { rows } = await pool.query<{ mime_type: string; bytes: Buffer }>(
      "SELECT mime_type, bytes FROM media_blobs WHERE key = $1",
      [key],
    );
    if (!rows[0]) throw new HttpError(404, "not_found", "Not found");
    res.set("Content-Type", rows[0].mime_type);
    res.set("Cache-Control", "public, max-age=31536000, immutable");
    res.set("Content-Security-Policy", "default-src 'none'");
    res.send(rows[0].bytes);
  }),
);

// ============================================================ seller store profile (private)

const STORE_COLUMNS = "store_name, store_slug, store_bio, region";

app.get(
  "/seller/store",
  authSeller,
  h(async (req, res) => {
    const { rows } = await pool.query(`SELECT ${STORE_COLUMNS} FROM sellers WHERE id = $1`, [sellerId(req)]);
    res.json({ store: { ...rows[0], public_path: `/stores/${rows[0]?.store_slug}` } });
  }),
);

const storeUpdateSchema = z
  .object({
    store_name: z.string().trim().min(2).max(80).optional(),
    store_bio: z.string().trim().max(1000).nullable().optional(),
    region: z.string().trim().min(2).max(100).optional(),
  })
  .strict();

app.patch(
  "/seller/store",
  authSeller,
  h(async (req, res) => {
    const d = parse(storeUpdateSchema, req.body);
    const sets: string[] = [];
    const vals: unknown[] = [];
    for (const [k, v] of Object.entries(d)) {
      if (v === undefined) continue;
      vals.push(v);
      sets.push(`${k} = $${vals.length}`);
    }
    vals.push(sellerId(req));
    const { rows } = await pool.query(
      `UPDATE sellers SET ${[...sets, "updated_at = now()"].join(", ")} WHERE id = $${vals.length} RETURNING ${STORE_COLUMNS}`,
      vals,
    );
    res.json({ store: rows[0] });
  }),
);

// ============================================================ public market API
// Never returns seller phone numbers. Ordering goes through /catalog/:id/whatsapp.

const PUBLIC_PRODUCT_SQL = `
  SELECT p.id, p.name, p.description, p.price, p.image, p.category_id, p.created_at,
         c.name AS category_name, c.slug AS category_slug,
         s.store_name, s.store_slug, s.region AS store_region
    FROM products p
    JOIN sellers s ON s.id = p.seller_id
    LEFT JOIN categories c ON c.id = p.category_id`;

function publicItem(req: Request, row: Record<string, unknown>, images: ImageOut[]): Record<string, unknown> {
  return {
    ...withImages(row, images),
    store: { name: row.store_name, slug: row.store_slug, region: row.store_region },
    order_whatsapp_url: `${publicBaseUrl(req)}/catalog/${String(row.id)}/whatsapp`,
  };
}

const marketQuerySchema = pagingSchema.extend({
  category: z.string().trim().max(100).optional(),
  store: z.string().trim().max(60).optional(),
  q: z.string().trim().max(100).optional(),
});

app.get(
  "/market/products",
  h(async (req, res) => {
    const d = parse(marketQuerySchema, pageQuery(req));
    const vals: unknown[] = [];
    let where = VISIBLE_SQL;
    if (d.category) {
      vals.push(d.category);
      where += z.string().uuid().safeParse(d.category).success
        ? ` AND p.category_id = $${vals.length}`
        : ` AND c.slug = $${vals.length}`;
    }
    if (d.store) {
      vals.push(d.store);
      where += ` AND s.store_slug = $${vals.length}`;
    }
    if (d.q) {
      vals.push(`%${d.q.replace(/[%_\\]/g, "\\$&")}%`);
      where += ` AND (p.name ILIKE $${vals.length} OR p.description ILIKE $${vals.length})`;
    }
    vals.push(d.limit, (d.page - 1) * d.limit);
    const { rows } = await pool.query(
      `${PUBLIC_PRODUCT_SQL} WHERE ${where}
        ORDER BY p.created_at DESC LIMIT $${vals.length - 1} OFFSET $${vals.length}`,
      vals,
    );
    const countRes = await pool.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM products p JOIN sellers s ON s.id = p.seller_id
        LEFT JOIN categories c ON c.id = p.category_id WHERE ${where}`,
      vals.slice(0, -2),
    );
    const imgs = await loadImages(pool, rows.map((r) => String(r.id)));
    const items = rows.map((r) => publicItem(req, r, imgs.get(String(r.id)) ?? []));
    res.set("Cache-Control", "public, max-age=30");
    res.json({ page: d.page, limit: d.limit, total: countRes.rows[0]?.n ?? 0, items });
  }),
);

app.get(
  "/market/products/:id",
  h(async (req, res) => {
    const pid = idParam(req);
    const { rows } = await pool.query(`${PUBLIC_PRODUCT_SQL} WHERE p.id = $1 AND ${VISIBLE_SQL}`, [pid]);
    if (!rows[0]) throw new HttpError(404, "not_found", "المنتج غير متاح");
    const imgs = await loadImages(pool, [pid]);
    res.set("Cache-Control", "public, max-age=30");
    res.json({ product: publicItem(req, rows[0], imgs.get(pid) ?? []) });
  }),
);

/** Public storefront: visible only while the seller account is active. */
app.get(
  "/stores/:slug",
  h(async (req, res) => {
    const slug = z.string().trim().min(2).max(60).regex(/^[a-z0-9-]+$/).safeParse(req.params.slug);
    if (!slug.success) throw new HttpError(404, "not_found", "المتجر غير موجود");
    const { rows } = await pool.query(
      `SELECT s.store_name AS name, s.store_slug AS slug, s.store_bio AS bio, s.region,
              (SELECT count(*) FROM products p WHERE p.seller_id = s.id AND ${VISIBLE_SQL})::int AS product_count
         FROM sellers s WHERE s.store_slug = $1 AND s.account_status = 'active'`,
      [slug.data],
    );
    if (!rows[0]) throw new HttpError(404, "not_found", "المتجر غير موجود");
    res.set("Cache-Control", "public, max-age=60");
    res.json({ store: rows[0] });
  }),
);

// ============================================================ admin: create seller directly

const adminCreateSellerSchema = z.object({
  full_name: z.string().trim().min(2).max(100),
  whatsapp: phoneSchema,
  region: z.string().trim().min(2).max(100),
  birth_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  password: passwordSchema,
  store_name: z.string().trim().min(2).max(80).optional(),
  subscription_days: z.coerce.number().int().min(0).max(3650).default(0),
});

admin.post(
  "/sellers",
  h(async (req, res) => {
    const d = parse(adminCreateSellerSchema, req.body);
    const aid = adminId(req);
    const hash = await argon2.hash(d.password, ARGON2_OPTIONS);
    const seller = await tx(async (c) => {
      let r;
      try {
        r = await c.query<{ id: string; store_slug: string }>(
          `INSERT INTO sellers (full_name, phone_normalized, region, birth_date, password_hash, account_status,
                                approved_at, approved_by, store_name)
           VALUES ($1, $2, $3, $4, $5, 'active', now(), $6, $7) RETURNING id, store_slug`,
          [d.full_name, d.whatsapp, d.region, d.birth_date, hash, aid, d.store_name ?? null],
        );
      } catch (err) {
        if ((err as { code?: string }).code === "23505") throw new HttpError(409, "phone_taken", "رقم الواتساب مسجل مسبقاً");
        throw err;
      }
      const id = r.rows[0].id;
      if (d.subscription_days > 0) {
        await c.query(
          `INSERT INTO subscriptions (seller_id, status, starts_at, expires_at, created_by)
           VALUES ($1, 'active', now(), now() + make_interval(days => $2::int), $3)`,
          [id, d.subscription_days, aid],
        );
      }
      await audit(c, {
        adminId: aid,
        action: "seller_create",
        sellerId: id,
        metadata: { subscription_days: d.subscription_days },
      });
      return r.rows[0];
    });
    res.status(201).json({ ok: true, seller });
  }),
);
