# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2.5.0 (2026-04-28)

### Breaking

- Removed role mapping and default role selector — all new SSO users are assigned the Subscriber role
- Administrators promote users to other roles manually from the Users screen

### Removed

- `includes/user/class-role-mapper.php`
- `OPTION_ROLE_MAP` and `OPTION_DEFAULT_ROLE` constants
- Role Mapping settings section, `sanitize_role()`, `sanitize_role_map()`
- Role mapping JS (add/remove rows)

## 2.4.0 (2026-04-28)

### Added

- Settings link on the Plugins page next to Deactivate (#15)

## 2.3.0 (2026-04-28)

### Fixed

- Validate `$_SERVER['REQUEST_METHOD']` with `isset()` before accessing (Plugin Check compliance)
- Sanitize `redirect_to` parameter with `sanitize_url()` before passing to `wp_validate_redirect()`
- Prefix template variables (`$valid_styles`, `$style_class`, `$btn_css_class`) with `sfme_` to avoid global namespace collisions
- Suppress expected `slow_db_query` warning on Entra OID user lookup — runs once per login, required for identity resolution
- Reduce readme.txt tags from 6 to 5 (WordPress.org maximum)
- Add `phpcs:ignore` to uninstall.php direct DB queries (expected for cleanup)

## 2.2.0 (2026-04-28)

### Breaking

- **Removed SAML 2.0 support** — plugin now uses OpenID Connect with PKCE exclusively (#12)
- Removed `robrichards/xmlseclibs` and `litesaml/lightsaml` Composer dependencies
- Removed `/sso/saml-acs` endpoint, SAML Metadata Import section, and protocol selector from settings
- Removed `OPTION_AUTH_PROTOCOL` and `OPTION_SAML_METADATA` constants
- PHP 8.1 requirement remains (unchanged from 2.0.0)

### Fixed

- Client secret sanitization no longer trims whitespace before encrypting — preserves secrets that contain leading/trailing spaces
- Removed `load_plugin_textdomain()` call — unnecessary for WordPress.org hosted plugins since WordPress 4.6

### Changed

- External Services section in readme rewritten with detailed data flow description per WordPress.org review feedback
- Plugin description updated to reflect OIDC-only scope
- Admin help tabs updated: removed SAML Setup tab, rewrote Quick Start for OIDC
- Admin JS simplified: removed metadata import and protocol toggle functions

### Removed

- `includes/auth/class-saml-client.php`
- `includes/xml/class-metadata-parser.php`
- `includes/xml/class-xml-security.php`
- `tests/test-metadata-parser.php`
- `includes/xml/` directory

## 2.1.1 (2026-04-25)

### Added

- Admin notice warning when SAML protocol is active, recommending OIDC with PKCE (#10)
- Vietnamese translations for all new security strings
- SAML labeled as "Legacy", OIDC labeled as "Recommended" in protocol selector

### Changed

- Protocol description updated to explain SAML security risks (XSW, replay attacks)
- Updated .pot template and recompiled .mo binary for Vietnamese

## 2.1.0 (2026-04-25)

### Security

- **[Critical]** Fix SAML XML Signature Wrapping (XSW) — require assertion-level signature, reject response-only signatures that allow forged assertions to bypass authentication (#5)
- **[Critical]** Guard against privilege escalation via SSO default role — block `administrator` as default role in settings sanitization (#6)
- **[Medium]** Enforce SAML assertion conditions (NotBefore, NotOnOrAfter, AudienceRestriction) — prevents replay attacks with expired assertions (#7)
- **[Medium]** Add SSRF protection to SAML metadata import — host allowlist (Entra endpoints only) and private IP blocking (#8)

### Changed

- Default role for SSO auto-provisioning now defaults to `subscriber` (was `editor` in some deployments)
- Metadata import restricted to known Microsoft Entra hosts: `login.microsoftonline.com`, `login.windows.net`, `login.microsoftonline.us`, `login.chinacloudapi.cn`

## 2.0.3 (2026-04-17)

### Fixed

- JS lint errors in protocol toggle for CI compliance

## 2.0.2 (2026-04-17)

### Fixed

- Skip Client Secret requirement when SAML protocol is selected — no more false warning
- Hide Client Secret field in settings UI when SAML 2.0 is active
- Fix settings page URL slug and plugin name in admin notices

## 2.0.1 (2026-04-17)

### Fixed

- Update "Tested up to" to WordPress 6.9
- Include composer.json in distribution (required by Plugin Check)
- Full readme.txt rewrite with complete changelog and upgrade notices
- Add README.md for GitHub with badges, features, and issue reporting link

## 2.0.0 (2026-04-17)

### Breaking

- **Renamed plugin** from "Microsoft Entra SSO" to "SSO for Microsoft Entra" for WordPress.org and Microsoft trademark compliance
- **Renamed all internals** — namespace (`SFME`), constants (`SFME_*`), option keys (`sfme_*`), CSS/JS classes (`sfme-*`), AJAX actions, transients
- **Requires PHP 8.1+** (LightSaml dependency)

### Added

- Auto-migration of option keys from old prefix (`microsoft_entra_sso_*`) to new (`sfme_*`) on activation
- WordPress.org plugin assets (icon with shield design, banner)
- Contextual Help tabs on settings page (Quick Start, Azure Setup, SAML Setup, Troubleshooting)

### Fixed

- SAML signature verification rewritten using LightSaml — fixes digest validation failures with Azure responses
- NinjaFirewall compatibility documented (`.htninja` whitelist for SAML ACS endpoint)

### Changed

- GitHub repository: `microsoft-entra-sso` → `sso-for-microsoft-entra`
- SAML response parsing uses LightSaml for reliable binding, signature, and claims extraction

## 1.3.0 (2026-04-17)

### Added

- Contextual Help tabs on settings page — Quick Start, Azure Setup, SAML Setup, and Troubleshooting guides accessible via the Help button

### Fixed

- Replace manual XML signature verification with LightSaml library for reliable SAML response validation
- Load Composer vendor autoloader for third-party dependencies (LightSaml, xmlseclibs)
- NinjaFirewall compatibility: document `.htninja` whitelist requirement for SAML ACS endpoint

### Changed

- Require PHP 8.1+ (LightSaml dependency)
- SAML response parsing now uses LightSaml (same library as other WordPress SAML plugins)

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
