DROP INDEX IF EXISTS idx_users_deleted_at;
DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS bid_status;
DROP TYPE IF EXISTS offer_status;
DROP TYPE IF EXISTS payment_status;
DROP TYPE IF EXISTS order_status;
DROP TYPE IF EXISTS listing_status;
DROP TYPE IF EXISTS user_role;
