CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS sellers (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), full_name text NOT NULL, phone_normalized text UNIQUE NOT NULL,
 region text NOT NULL, birth_date date NOT NULL, password_hash text NOT NULL,
 account_status text NOT NULL DEFAULT 'pending' CHECK(account_status IN ('pending','active','suspended','disabled')),
 created_at timestamptz NOT NULL DEFAULT now(), approved_at timestamptz, approved_by uuid, suspended_at timestamptz, suspension_reason text
);
CREATE TABLE IF NOT EXISTS subscriptions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), seller_id uuid NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','expired','cancelled')),
 starts_at timestamptz, expires_at timestamptz, cancelled_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), created_by uuid, renewed_from uuid
);
CREATE TABLE IF NOT EXISTS categories (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text UNIQUE NOT NULL, slug text UNIQUE NOT NULL, active boolean NOT NULL DEFAULT true, sort_order int NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS products (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), seller_id uuid NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
 name text NOT NULL, description text NOT NULL DEFAULT '', price numeric(12,2) NOT NULL CHECK(price >= 0), image_url text,
 category_id uuid REFERENCES categories(id), visibility text NOT NULL DEFAULT 'published' CHECK(visibility IN ('published','hidden_by_seller','hidden_by_admin','hidden_subscription','hidden_suspension','deleted')),
 prior_visibility text, hidden_reason text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS products_seller_idx ON products(seller_id);
CREATE INDEX IF NOT EXISTS products_category_idx ON products(category_id);
CREATE INDEX IF NOT EXISTS products_visibility_idx ON products(visibility);
CREATE INDEX IF NOT EXISTS subscriptions_expiry_idx ON subscriptions(status,expires_at);
CREATE TABLE IF NOT EXISTS audit_logs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), admin_id uuid, action text NOT NULL, seller_id uuid, product_id uuid, reason text, metadata jsonb, created_at timestamptz NOT NULL DEFAULT now()
);
