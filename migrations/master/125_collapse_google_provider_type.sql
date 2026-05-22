-- Migration: 125_collapse_google_provider_type.sql
-- Description:
--   Google is a flavor of OIDC, not a distinct identity_providers.provider_type.
--   The provider_name on the underlying oidc_providers row is the discriminator.
--   Collapse the 'google' value into 'oidc' so the code only branches on
--   provider_type ∈ {oidc, saml, ad, entra, scim}.

UPDATE identity_providers SET provider_type = 'oidc' WHERE provider_type = 'google';

ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS identity_providers_type_chk;
ALTER TABLE identity_providers
    ADD CONSTRAINT identity_providers_type_chk
    CHECK (provider_type IN ('oidc', 'saml', 'ad', 'entra', 'scim'));
