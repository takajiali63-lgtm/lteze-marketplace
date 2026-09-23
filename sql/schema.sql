-- LTEZE Marketplace schema
-- Idempotent: safe to run many times. Never drops tables or data.

-- gen_random_uuid() is built into PostgreSQL 13+ (no extension needed).

-- ---------------------------------------------------------------- admins
CREATE TABLE IF NOT EXISTS admins (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name        TEXT NOT NULL DEFAULT 'Admin',
  phone_normalized TEXT NOT NULL UNIQUE,
  password_hash    TEXT NOT NULL,
  active           BOOLEAN NOT NULL DEFAULT TRUE,
  last_login_at    TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- --------------------------------------------------------------- sellers
CREATE TABLE IF NOT EXISTS sellers (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name         TEXT NOT NULL,
  phone_normalized  TEXT NOT NULL UNIQUE,
  region            TEXT NOT NULL,
  birth_date        DATE NOT NULL,
  password_hash     TEXT NOT NULL,
  account_status    TEXT NOT NULL DEFAULT 'pending',
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_at       TIMESTAMPTZ,
  approved_by       UUID REFERENCES admins(id) ON DELETE SET NULL,
  suspended_at      TIMESTAMPTZ,
  suspension_reason TEXT,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Upgrade path from the earlier LTEZE schema (safe no-ops on a fresh database)
ALTER TABLE sellers ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
ALTER TABLE sellers ADD COLUMN IF NOT EXISTS approved_by UUID;
ALTER TABLE sellers ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;
ALTER TABLE sellers ADD COLUMN IF NOT EXISTS suspension_reason TEXT;
ALTER TABLE sellers ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

DO $$ BEGIN
  ALTER TABLE sellers ADD CONSTRAINT sellers_account_status_chk
    CHECK (account_status IN ('pending','active','suspended'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS sellers_status_idx ON sellers(account_status);

-- --------------------------------------------------------- subscriptions
CREATE TABLE IF NOT EXISTS subscriptions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seller_id    UUID NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
  status       TEXT NOT NULL DEFAULT 'active',
  starts_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  cancelled_at TIMESTAMPTZ,
  created_by   UUID REFERENCES admins(id) ON DELETE SET NULL,
  renewed_from UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Upgrade path: the earlier schema's status check did not allow 'renewed'.
ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_status_check;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS renewed_from UUID;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
UPDATE subscriptions SET starts_at = created_at WHERE starts_at IS NULL;

DO $$ BEGIN
  ALTER TABLE subscriptions ADD CONSTRAINT subscriptions_status_chk
    CHECK (status IN ('active','expired','cancelled','renewed'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE subscriptions ADD CONSTRAINT subscriptions_dates_chk
    CHECK (expires_at > starts_at);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- at most one active subscription per seller
CREATE UNIQUE INDEX IF NOT EXISTS subscriptions_one_active_idx
  ON subscriptions(seller_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS subscriptions_seller_idx ON subscriptions(seller_id);
CREATE INDEX IF NOT EXISTS subscriptions_active_expiry_idx
  ON subscriptions(expires_at) WHERE status = 'active';

-- ------------------------------------------------------------ categories
CREATE TABLE IF NOT EXISTS categories (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name       TEXT NOT NULL,
  slug       TEXT NOT NULL UNIQUE,
  active     BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE categories ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE categories ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS categories_active_sort_idx ON categories(active, sort_order);

-- -------------------------------------------------------------- products
CREATE TABLE IF NOT EXISTS products (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seller_id        UUID NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  description      TEXT NOT NULL DEFAULT '',
  price            NUMERIC(12,2) NOT NULL,
  image            TEXT,
  category_id      UUID REFERENCES categories(id) ON DELETE SET NULL,
  visibility       TEXT NOT NULL DEFAULT 'published',
  prior_visibility TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Upgrade path: earlier schema used image_url; copy it into image (image_url is left in place).
ALTER TABLE products ADD COLUMN IF NOT EXISTS image TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS prior_visibility TEXT;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = current_schema() AND table_name = 'products' AND column_name = 'image_url') THEN
    EXECUTE 'UPDATE products SET image = image_url WHERE image IS NULL AND image_url IS NOT NULL';
  END IF;
END $$;

DO $$ BEGIN
  ALTER TABLE products ADD CONSTRAINT products_visibility_chk
    CHECK (visibility IN ('published','hidden_by_seller','hidden_by_admin',
                          'hidden_subscription','hidden_suspension','deleted'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE products ADD CONSTRAINT products_price_chk CHECK (price >= 0);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS products_seller_idx ON products(seller_id);
CREATE INDEX IF NOT EXISTS products_category_idx ON products(category_id);
CREATE INDEX IF NOT EXISTS products_visibility_idx ON products(visibility);
CREATE INDEX IF NOT EXISTS products_published_created_idx
  ON products(created_at DESC) WHERE visibility = 'published';

-- ------------------------------------------------------------ audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id         BIGSERIAL PRIMARY KEY,
  admin_id   UUID REFERENCES admins(id) ON DELETE SET NULL,
  action     TEXT NOT NULL,
  seller_id  UUID REFERENCES sellers(id) ON DELETE SET NULL,
  product_id UUID REFERENCES products(id) ON DELETE SET NULL,
  reason     TEXT,
  metadata   JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS product_id UUID;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS reason TEXT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS audit_logs_created_idx ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_seller_idx ON audit_logs(seller_id);
CREATE INDEX IF NOT EXISTS audit_logs_action_idx ON audit_logs(action);

-- -------------------------------------------------------------- sessions
-- Server-side session records so logout / suspension / password reset
-- revoke JWTs immediately.
CREATE TABLE IF NOT EXISTS sessions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_type TEXT NOT NULL,
  subject_id   UUID NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  revoked_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$ BEGIN
  ALTER TABLE sessions ADD CONSTRAINT sessions_subject_type_chk
    CHECK (subject_type IN ('seller','admin'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS sessions_subject_idx ON sessions(subject_type, subject_id);

-- ------------------------------------------------- password_reset_tokens
-- Only a SHA-256 hash of the token is stored.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seller_id  UUID NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at    TIMESTAMPTZ,
  created_by UUID REFERENCES admins(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS prt_seller_idx ON password_reset_tokens(seller_id);

-- ------------------------------------------------ password_reset_requests
-- Seller asks for a reset; admin reviews and issues a one-time token.
CREATE TABLE IF NOT EXISTS password_reset_requests (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seller_id   UUID NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
  status      TEXT NOT NULL DEFAULT 'open',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS prr_status_idx ON password_reset_requests(status, created_at DESC);

-- ======================================================= product images
-- Only URLs / storage references are stored — never image bytes.

ALTER TABLE products ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
-- products.image is kept as a denormalized copy of the primary image URL (backward compatibility).

CREATE TABLE IF NOT EXISTS product_images (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id       UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  url              TEXT NOT NULL,
  storage_provider TEXT NOT NULL DEFAULT 'external',
  storage_key      TEXT,
  mime_type        TEXT,
  size_bytes       INTEGER,
  width            INTEGER,
  height           INTEGER,
  alt_text         TEXT,
  position         SMALLINT NOT NULL,
  is_primary       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$ BEGIN
  ALTER TABLE product_images ADD CONSTRAINT product_images_provider_chk
    CHECK (storage_provider IN ('external','s3','shopify'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE product_images ADD CONSTRAINT product_images_position_chk
    CHECK (position BETWEEN 0 AND 9);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Deferred so a full reorder can swap positions inside one transaction.
DO $$ BEGIN
  ALTER TABLE product_images ADD CONSTRAINT product_images_position_uniq
    UNIQUE (product_id, position) DEFERRABLE INITIALLY DEFERRED;
EXCEPTION WHEN duplicate_object OR duplicate_table THEN NULL; END $$;

CREATE UNIQUE INDEX IF NOT EXISTS product_images_one_primary_idx
  ON product_images(product_id) WHERE is_primary;
CREATE INDEX IF NOT EXISTS product_images_product_pos_idx ON product_images(product_id, position);

-- Objects waiting to be removed from storage (filled automatically by trigger).
CREATE TABLE IF NOT EXISTS storage_orphans (
  id               BIGSERIAL PRIMARY KEY,
  storage_provider TEXT NOT NULL,
  storage_key      TEXT NOT NULL,
  attempts         INTEGER NOT NULL DEFAULT 0,
  last_error       TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION lteze_queue_image_cleanup() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.storage_key IS NOT NULL AND OLD.storage_provider <> 'external' THEN
      INSERT INTO storage_orphans (storage_provider, storage_key) VALUES (OLD.storage_provider, OLD.storage_key);
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.storage_key IS NOT NULL AND OLD.storage_provider <> 'external'
     AND OLD.storage_key IS DISTINCT FROM NEW.storage_key THEN
    INSERT INTO storage_orphans (storage_provider, storage_key) VALUES (OLD.storage_provider, OLD.storage_key);
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE TRIGGER product_images_cleanup_trg
  AFTER DELETE OR UPDATE OF storage_key ON product_images
  FOR EACH ROW EXECUTE FUNCTION lteze_queue_image_cleanup();

-- Backfill: legacy single-image products get one primary gallery image. Runs only once per product.
INSERT INTO product_images (product_id, url, storage_provider, position, is_primary, alt_text)
SELECT p.id, p.image, 'external', 0, TRUE, p.name
  FROM products p
 WHERE p.image IS NOT NULL AND p.image <> ''
   AND NOT EXISTS (SELECT 1 FROM product_images i WHERE i.product_id = p.id);
