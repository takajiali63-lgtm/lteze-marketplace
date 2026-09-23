# LTEZE Marketplace Backend

Real backend foundation for seller accounts, secure password hashing, seller ownership, subscriptions, server-side expiry, categories, catalog, admin approval/suspension, and audit logs.

## Run
1. Install Node 20+ and PostgreSQL 15+.
2. Create database `lteze`.
3. Run `psql "$DATABASE_URL" -f sql/schema.sql`.
4. Copy `.env.example` to `.env` and set real secrets.
5. `npm install`
6. `npm run dev`

## Theme integration
Set the LTEZE theme setting `api_base` to the deployed backend URL, e.g. `https://api.example.com`.

## Important
- Passwords are Argon2 hashes; plaintext passwords are never stored.
- Seller phone numbers are backend-only and are not returned by the public catalog.
- Public catalog only exposes products belonging to active sellers with an active, non-expired subscription.
- Subscription expiration is enforced server-side every minute and also at public catalog query time.
- Keep the current Shopify MAIN theme untouched until testing is complete.
