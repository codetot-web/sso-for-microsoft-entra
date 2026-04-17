# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.2.0 (2026-04-17)

### Added

- Auto-extract Tenant ID and Client ID from federation metadata URL on import — eliminates manual entry of connection settings when using SAML metadata URL
- Auto-switch authentication protocol to SAML when importing federation metadata
- Rate Limiting settings section in admin — configurable max attempts and window duration from the settings page
- Debug logging for `sso_build_url_failed` error to aid troubleshooting

### Fixed

- Strip UTF-8 BOM from Microsoft federation metadata XML responses that caused XML parsing to fail silently
- Use Application (client) ID as SAML AuthnRequest Issuer instead of home URL — fixes AADSTS700016 "application not found" error
- Accept client_id as valid SAML AudienceRestriction value for Entra compatibility

### Changed

- Rate limiter now reads max attempts and window from database options instead of hardcoded defaults

## 1.1.0 (2026-04-17)

### Security

- **[Critical]** Fix SAML Signature Wrapping (XSW) — bind claims extraction to the verified assertion element instead of searching the entire document (#1)
- **[Critical]** Fix XPath injection in SAML reference lookup — validate ID with strict regex before interpolation (#1)
- **[High]** Remove dual-dispatch — SSO actions now only fire via `/sso/*` rewrite endpoints, old `wp-login.php?action=entra_*` routes disabled (#2)
- **[High]** Fix double rate-limit increment — remove redundant `Rate_Limiter::check()` from `OIDC_Client` that caused lockout after 2 logins (#2)
- **[High]** Add JWKS cache-refresh-on-failure — retry with fresh keys when signature verification fails (#3)
- **[High]** Use HKDF for encryption key derivation with plugin-specific context string (#3)
- **[High]** Route AJAX metadata import through `sanitize_saml_metadata()` callback (#3)
- **[Medium]** Require SAML `AudienceRestriction` — reject assertions that omit it (#4)
- **[Medium]** Read `redirect_to` from `$_GET` only, not `$_REQUEST` (#4)
- **[Medium]** Enforce HTTPS-only on OIDC discovery endpoint URLs (#4)
- **[Medium]** Fix `uninstall.php` meta key prefix from `_microsoft_entra_sso_` to `_messo_` (#4)

### Changed

- SSO callback endpoints moved from `wp-login.php` to custom `/sso/*` rewrite URLs:
  - `/sso/login` — initiate SSO
  - `/sso/callback` — OIDC authorization code callback
  - `/sso/saml-acs` — SAML Assertion Consumer Service
  - `/sso/logout` — single log-out
- **Breaking:** Azure App Registration redirect URI must be updated to `https://yoursite.com/sso/callback`
- **Breaking:** Existing encrypted client secrets must be re-entered (HKDF key derivation change)

## 1.0.0 (2026-03-31)

- Initial release
- OpenID Connect authentication with PKCE
- SAML 2.0 support with federation metadata XML import
- Admin settings page with encrypted secret storage
- User provisioning and role mapping from Entra groups
- Rate limiting on login attempts
- WordPress.org Plugin Check (PCP) compliant
