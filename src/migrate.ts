import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { Pool } from "pg";
import argon2 from "argon2";

export const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MiB (OWASP recommendation)
  timeCost: 2,
  parallelism: 1,
};

/** Normalizes a phone number to +<digits>. Local Lebanese numbers get +961. */
export function normalizePhone(input: string): string | null {
  let digits = input.replace(/[^\d+]/g, "");
  if (digits.startsWith("+")) digits = digits.slice(1);
  else if (digits.startsWith("00")) digits = digits.slice(2);
  else if (digits.startsWith("0") && digits.length === 8) digits = "961" + digits.slice(1);
  else if (digits.length === 7 || digits.length === 8) digits = "961" + digits;
  digits = digits.replace(/\D/g, "");
  if (digits.length < 8 || digits.length > 15) return null;
  return "+" + digits;
}

export function createPool(): Pool {
  const url = process.env.DATABASE_URL;
  if (!url) {
    throw new Error("DATABASE_URL is missing. Set it to the Internal Database URL of lteze-marketplace-db.");
  }
  // Render internal URLs (host like dpg-xxxx-a) need no SSL; external URLs (*.render.com) require it.
  const needsSsl = process.env.DATABASE_SSL === "true" || /\.render\.com/i.test(url);
  return new Pool({
    connectionString: url,
    ssl: needsSsl ? { rejectUnauthorized: false } : undefined,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  });
}

const MIGRATION_LOCK_ID = 774411; // arbitrary constant for pg_advisory_lock

export async function runMigrations(pool: Pool): Promise<void> {
  // schema.sql first, then numbered migrations (002_*.sql, 003_*.sql, ...) in order.
  // Every file must be idempotent: the whole set runs on every startup.
  const sqlDir = path.resolve(__dirname, "..", "sql");
  const files = [
    "schema.sql",
    ...fs.readdirSync(sqlDir).filter((f) => /^\d{3}_[\w-]+\.sql$/.test(f)).sort(),
  ];
  const client = await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK_ID]);
    try {
      await client.query("BEGIN");
      for (const f of files) {
        await client.query(fs.readFileSync(path.join(sqlDir, f), "utf8"));
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      await client.query("SELECT pg_advisory_unlock($1)", [MIGRATION_LOCK_ID]);
    }
  } finally {
    client.release();
  }
}

/** Creates the first admin from env vars if it does not exist yet. Never overwrites. */
export async function bootstrapAdmin(pool: Pool): Promise<"created" | "exists" | "skipped"> {
  const rawPhone = process.env.ADMIN_BOOTSTRAP_PHONE;
  const password = process.env.ADMIN_BOOTSTRAP_PASSWORD;
  if (!rawPhone || !password) return "skipped";
  const phone = normalizePhone(rawPhone);
  if (!phone) throw new Error("ADMIN_BOOTSTRAP_PHONE is not a valid phone number.");
  if (password.length < 12) throw new Error("ADMIN_BOOTSTRAP_PASSWORD must be at least 12 characters.");

  const existing = await pool.query("SELECT 1 FROM admins WHERE phone_normalized = $1", [phone]);
  if (existing.rowCount && existing.rowCount > 0) return "exists";

  const hash = await argon2.hash(password, ARGON2_OPTIONS);
  await pool.query(
    "INSERT INTO admins (phone_normalized, password_hash) VALUES ($1, $2) ON CONFLICT (phone_normalized) DO NOTHING",
    [phone, hash],
  );
  return "created";
}

async function main(): Promise<void> {
  const pool = createPool();
  try {
    await runMigrations(pool);
    console.log("[migrate] schema applied");
    const admin = await bootstrapAdmin(pool);
    console.log(`[migrate] bootstrap admin: ${admin}`);
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  main().catch((err: unknown) => {
    console.error("[migrate] failed:", err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
