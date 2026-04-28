-- 127_clean_polluted_user_names.sql
--
-- The custom-login signup flow used to write the full email into users.name
-- (controllers/enduser/enduser_controller.go:1904 pre-fix). The admin UI
-- then split that on whitespace and showed the email as `first_name`.
--
-- This migration replaces any users.name that equals the user's email with
-- the email's local-part. Cosmetic only — does not affect auth or scope
-- resolution. Idempotent: re-running is a no-op once names diverge from
-- the email.

UPDATE users
   SET name = split_part(email, '@', 1)
 WHERE name = email
   AND email IS NOT NULL
   AND email <> '';
