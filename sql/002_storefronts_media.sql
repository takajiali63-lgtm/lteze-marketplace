-- 002: seller storefronts + persistent database image storage. Idempotent.

-- ---------------------------------------------------------- seller storefronts
ALTER TABLE sellers ADD COLUMN IF NOT EXISTS store_name TEXT;
ALTER TABLE sellers ADD COLUMN IF NOT EXISTS store_slug TEXT;
ALTER TABLE sellers ADD COLUMN IF NOT EXISTS store_bio  TEXT;

UPDATE sellers SET store_name = full_name WHERE store_name IS NULL OR store_name = '';
UPDATE sellers SET store_slug = 's' || substr(replace(id::text, '-', ''), 1, 10)
 WHERE store_slug IS NULL OR store_slug = '';

CREATE UNIQUE INDEX IF NOT EXISTS sellers_store_slug_idx ON sellers(store_slug);

-- New sellers automatically get a store name and a unique, non-guessable-by-phone slug.
CREATE OR REPLACE FUNCTION lteze_seller_store_defaults() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.store_name IS NULL OR NEW.store_name = '' THEN
    NEW.store_name := NEW.full_name;
  END IF;
  IF NEW.store_slug IS NULL OR NEW.store_slug = '' THEN
    NEW.store_slug := 's' || substr(replace(NEW.id::text, '-', ''), 1, 10);
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE TRIGGER sellers_store_defaults_trg
  BEFORE INSERT ON sellers
  FOR EACH ROW EXECUTE FUNCTION lteze_seller_store_defaults();

-- ---------------------------------------------------------- database image storage
ALTER TABLE product_images DROP CONSTRAINT IF EXISTS product_images_provider_chk;
ALTER TABLE product_images ADD CONSTRAINT product_images_provider_chk
  CHECK (storage_provider IN ('external','s3','shopify','db'));

-- Only re-encoded, metadata-free WebP images (max 2000px) are stored here.
CREATE TABLE IF NOT EXISTS media_blobs (
  key        TEXT PRIMARY KEY,
  mime_type  TEXT NOT NULL,
  bytes      BYTEA NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
