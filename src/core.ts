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

// ============================================================== config

export const JWT_SECRET = process.env.JWT_SECRET ?? "";
export const PORT = Number(process.env.PORT ?? 10000);
export const COOKIE_SECURE = (process.env.COOKIE_SECURE ?? "true") !== "false";
export const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;
export const ALLOWED_ORIGINS = (process.env.FRONTEND_ORIGIN ?? "https://lteze.com")
  .split(",")
  .map((o) => o.trim().replace(/\/+$/, ""))
  .filter(Boolean);
export const ADMIN_WHATSAPP = process.env.ADMIN_WHATSAPP ?? "+96176691688";
export const AUTO_MIGRATE = process.env.AUTO_MIGRATE !== "false";
export const EXPIRY_JOB_INTERVAL_MS = 15 * 60 * 1000;

export const SELLER_COOKIE = "lteze_seller";
export const ADMIN_COOKIE = "lteze_admin";
export const SELLER_SESSION_SECONDS = 7 * 24 * 3600;
export const ADMIN_SESSION_SECONDS = 12 * 3600;
export const RESET_TOKEN_MINUTES = 30;

export const VISIBILITIES = [
  "published",
  "hidden_by_seller",
  "hidden_by_admin",
  "hidden_subscription",
  "hidden_suspension",
  "deleted",
] as const;
export type Visibility = (typeof VISIBILITIES)[number];

export let pool: Pool;
export function setPool(p: Pool): void {
  pool = p;
}

/** Argon2 hash of random data, used to keep login timing constant for unknown users. */
export let DUMMY_HASH = "";
export function setDummyHash(v: string): void {
  DUMMY_HASH = v;
}

// ============================================================== helpers

export class HttpError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

/** Wraps async handlers so errors reach the error middleware. */
export function h(fn: (req: Request, res: Response) => Promise<unknown>): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };
}

export async function tx<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

export type Db = Pool | PoolClient;

export function waLink(phone: string, text: string): string {
  return `https://wa.me/${phone.replace(/\D/g, "")}?text=${encodeURIComponent(text)}`;
}

export function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function publicBaseUrl(req: Request): string {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, "");
  return `${req.protocol}://${req.get("host") ?? "localhost"}`;
}

export async function audit(
  db: Db,
  entry: {
    adminId: string | null;
    action: string;
    sellerId?: string | null;
    productId?: string | null;
    reason?: string | null;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  await db.query(
    `INSERT INTO audit_logs (admin_id, action, seller_id, product_id, reason, metadata)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
    [
      entry.adminId,
      entry.action,
      entry.sellerId ?? null,
      entry.productId ?? null,
      entry.reason ?? null,
      JSON.stringify(entry.metadata ?? {}),
    ],
  );
}

export function productOut(row: Record<string, unknown>): Record<string, unknown> {
  return { ...row, price: row.price === null || row.price === undefined ? null : Number(row.price) };
}

// ------------------------------------------------------ validation

export const phoneSchema = z
  .string()
  .trim()
  .min(6)
  .max(25)
  .transform((v, ctx) => {
    const p = normalizePhone(v);
    if (!p) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "رقم واتساب غير صالح" });
      return z.NEVER;
    }
    return p;
  });

export const passwordSchema = z.string().min(8, "كلمة المرور يجب أن تكون 8 أحرف على الأقل").max(128);
export const uuidSchema = z.string().uuid();
export const pagingSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

export function parse<T extends z.ZodTypeAny>(schema: T, data: unknown): z.infer<T> {
  return schema.parse(data);
}

/**
 * Accepts field names used by the earlier LTEZE API so an existing theme keeps working:
 * phone → whatsapp, image_url → image.
 */
export function compat(body: unknown): Record<string, unknown> {
  const b = { ...((body ?? {}) as Record<string, unknown>) };
  if (b.whatsapp === undefined && b.phone !== undefined) b.whatsapp = b.phone;
  delete b.phone;
  if (b.image === undefined && b.image_url !== undefined) b.image = b.image_url;
  delete b.image_url;
  return b;
}

/** Query with legacy `offset` support (converted to page). */
export function pageQuery(req: Request): Record<string, unknown> {
  const q = { ...(req.query as Record<string, unknown>) };
  if (q.page === undefined && q.offset !== undefined) {
    const limit = Math.min(Math.max(Number(q.limit ?? 20) || 20, 1), 100);
    q.page = Math.floor(Math.max(Number(q.offset) || 0, 0) / limit) + 1;
  }
  delete q.offset;
  return q;
}

export function idParam(req: Request, name = "id"): string {
  const r = uuidSchema.safeParse(req.params[name]);
  if (!r.success) throw new HttpError(404, "not_found", "غير موجود");
  return r.data;
}

// ------------------------------------------------------ sessions

export type SubjectType = "seller" | "admin";

export async function createSession(res: Response, type: SubjectType, subjectId: string): Promise<void> {
  const seconds = type === "seller" ? SELLER_SESSION_SECONDS : ADMIN_SESSION_SECONDS;
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO sessions (subject_type, subject_id, expires_at)
     VALUES ($1, $2, now() + make_interval(secs => $3::int)) RETURNING id`,
    [type, subjectId, seconds],
  );
  const token = jwt.sign({ sid: rows[0].id, typ: type }, JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: seconds,
    subject: subjectId,
  });
  res.cookie(type === "seller" ? SELLER_COOKIE : ADMIN_COOKIE, token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SECURE ? "none" : "lax",
    domain: COOKIE_DOMAIN,
    path: "/",
    maxAge: seconds * 1000,
  });
}

export function clearSessionCookie(res: Response, type: SubjectType): void {
  res.clearCookie(type === "seller" ? SELLER_COOKIE : ADMIN_COOKIE, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SECURE ? "none" : "lax",
    domain: COOKIE_DOMAIN,
    path: "/",
  });
}

/** Returns { sid, subjectId } for a valid, non-revoked session, or null. */
export async function readSession(req: Request, type: SubjectType): Promise<{ sid: string; subjectId: string } | null> {
  const token: unknown = req.cookies?.[type === "seller" ? SELLER_COOKIE : ADMIN_COOKIE];
  if (typeof token !== "string" || !token) return null;
  let payload: unknown;
  try {
    payload = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
  } catch {
    return null;
  }
  if (typeof payload !== "object" || payload === null) return null;
  const p = payload as { sid?: unknown; typ?: unknown; sub?: unknown };
  if (p.typ !== type || typeof p.sid !== "string" || typeof p.sub !== "string") return null;
  const { rowCount } = await pool.query(
    `SELECT 1 FROM sessions
      WHERE id = $1 AND subject_type = $2 AND subject_id = $3
        AND revoked_at IS NULL AND expires_at > now()`,
    [p.sid, type, p.sub],
  );
  if (!rowCount) return null;
  return { sid: p.sid, subjectId: p.sub };
}

export async function revokeAllSessions(db: Db, type: SubjectType, subjectId: string): Promise<void> {
  await db.query(
    "UPDATE sessions SET revoked_at = now() WHERE subject_type = $1 AND subject_id = $2 AND revoked_at IS NULL",
    [type, subjectId],
  );
}

// Per-request auth context
export const authCtx = new WeakMap<Request, { sellerId?: string; adminId?: string; sid: string }>();

export function sellerId(req: Request): string {
  const id = authCtx.get(req)?.sellerId;
  if (!id) throw new HttpError(401, "unauthorized", "يجب تسجيل الدخول");
  return id;
}

export function adminId(req: Request): string {
  const id = authCtx.get(req)?.adminId;
  if (!id) throw new HttpError(401, "unauthorized", "يجب تسجيل دخول الإدارة");
  return id;
}

// Auth middlewares: load session, verify account state, then continue.
export const authSeller: RequestHandler = (req, _res, next) => {
  (async () => {
    const s = await readSession(req, "seller");
    if (!s) throw new HttpError(401, "unauthorized", "يجب تسجيل الدخول");
    const { rows } = await pool.query<{ account_status: string }>(
      "SELECT account_status FROM sellers WHERE id = $1",
      [s.subjectId],
    );
    if (!rows[0]) throw new HttpError(401, "unauthorized", "يجب تسجيل الدخول");
    if (rows[0].account_status === "pending") throw new HttpError(403, "account_pending", "حسابك قيد المراجعة من الإدارة");
    if (rows[0].account_status !== "active") throw new HttpError(403, "account_suspended", "حسابك موقوف");
    authCtx.set(req, { sellerId: s.subjectId, sid: s.sid });
  })().then(() => next(), next);
};

export const authAdmin: RequestHandler = (req, _res, next) => {
  (async () => {
    const s = await readSession(req, "admin");
    if (!s) throw new HttpError(401, "unauthorized", "يجب تسجيل دخول الإدارة");
    const { rows } = await pool.query<{ active: boolean }>("SELECT active FROM admins WHERE id = $1", [s.subjectId]);
    if (!rows[0]?.active) throw new HttpError(403, "forbidden", "غير مسموح");
    authCtx.set(req, { adminId: s.subjectId, sid: s.sid });
  })().then(() => next(), next);
};

// ------------------------------------------------------ visibility logic

export async function hasActiveSubscription(db: Db, sid: string): Promise<boolean> {
  const { rowCount } = await db.query(
    "SELECT 1 FROM subscriptions WHERE seller_id = $1 AND status = 'active' AND expires_at > now()",
    [sid],
  );
  return !!rowCount;
}

/** What a product that "should be visible" becomes, given seller + subscription state. */
export async function effectiveVisibleState(db: Db, sid: string): Promise<Visibility> {
  const { rows } = await db.query<{ account_status: string }>("SELECT account_status FROM sellers WHERE id = $1", [sid]);
  if (rows[0]?.account_status === "suspended") return "hidden_suspension";
  if (!(await hasActiveSubscription(db, sid))) return "hidden_subscription";
  return "published";
}

/** Subscription ended: published -> hidden_subscription. Manual hides untouched. */
export async function hideForSubscription(db: Db, sid: string): Promise<number> {
  const r = await db.query(
    `UPDATE products SET prior_visibility = visibility, visibility = 'hidden_subscription', updated_at = now()
      WHERE seller_id = $1 AND visibility = 'published'`,
    [sid],
  );
  return r.rowCount ?? 0;
}

/** Subscription (re)activated: only products hidden because of the subscription come back. */
export async function restoreFromSubscription(db: Db, sid: string): Promise<number> {
  const r = await db.query(
    `UPDATE products SET visibility = 'published', prior_visibility = NULL, updated_at = now()
      WHERE seller_id = $1 AND visibility = 'hidden_subscription'
        AND EXISTS (SELECT 1 FROM sellers WHERE id = $1 AND account_status = 'active')`,
    [sid],
  );
  return r.rowCount ?? 0;
}

// ============================================================== app

export const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.includes(origin)),
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
    maxAge: 600,
  }),
);
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

// CSRF defence: cookie-authenticated state changes must come from an allowed origin.
app.use((req: Request, _res: Response, next: NextFunction) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const origin = req.get("origin");
  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    return next(new HttpError(403, "bad_origin", "Origin not allowed"));
  }
  next();
});

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 600,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  }),
);
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "too_many_requests", message: "محاولات كثيرة، حاول لاحقاً" },
});

// ------------------------------------------------------------- health

app.get(
  "/health",
  h(async (_req, res) => {
    try {
      await pool.query("SELECT 1");
      res.json({ ok: true, db: "up" });
    } catch {
      res.status(503).json({ ok: false, db: "down" });
    }
  }),
);
