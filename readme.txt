=== SSO for Microsoft Entra ===
Contributors: khoipro, codetot
Tags: sso, microsoft, entra, azure, openid-connect, saml, single-sign-on
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 2.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Single Sign-On authentication for WordPress using Microsoft Entra ID (Azure AD). Supports OpenID Connect with PKCE and SAML 2.0.

== Description ==

**SSO for Microsoft Entra** enables your WordPress site to authenticate users through Microsoft Entra ID (formerly Azure Active Directory). Users can sign in with their existing Microsoft 365 / work accounts — no separate WordPress password required.

**Key features:**

* **SAML 2.0** with one-click federation metadata import — paste the metadata URL and everything auto-configures.
* **OpenID Connect (OIDC)** with PKCE — the most secure OAuth 2.0 flow.
* **Auto-extract Tenant ID and Client ID** from the federation metadata URL — no manual copy-paste.
* Automatic user provisioning — create WordPress accounts on first SSO login.
* Role mapping — assign WordPress roles based on Entra group membership.
* Encrypted client-secret storage using WordPress secret keys.
* Configurable rate limiting on SSO login attempts.
* Optional auto-redirect from the WordPress login page directly to Entra.
* Contextual Help tabs with setup guides built into the settings page.
* Vietnamese translation included. Community translations via translate.wordpress.org.
* No jQuery dependency.

== Installation ==

= Quick Start (SAML — Recommended) =

1. Upload the `sso-for-microsoft-entra` folder to `/wp-content/plugins/` or install via the WordPress plugin installer.
2. Activate the plugin from the **Plugins** screen.
3. In Azure Portal, go to **Enterprise Applications → your app → Single sign-on → SAML**.
4. Set **Reply URL (ACS)** to `https://yoursite.com/sso/saml-acs`.
5. Copy the **App Federation Metadata URL** from the SAML Certificates section.
6. In WordPress, go to **Settings → Entra SSO**, paste the metadata URL, and click **Import Metadata**.
7. Tenant ID, Client ID, and protocol are auto-filled. Click **Save Changes**.
8. Test in an incognito window — click "Sign in with Microsoft" on the login page.

= OIDC Setup =

1. Create an Azure App Registration with redirect URI: `https://yoursite.com/sso/callback`.
2. Enter **Tenant ID**, **Client ID**, and **Client Secret** in **Settings → Entra SSO**.
3. Save and test.

For detailed instructions, click the **Help** button on the settings page, or see the [setup guide on GitHub](https://github.com/codetot-web/sso-for-microsoft-entra).

== External Services ==

This plugin communicates with Microsoft Entra ID endpoints to perform authentication. Data transmitted includes OAuth 2.0 / OIDC tokens and user profile information returned by Microsoft's identity platform.

**Endpoints contacted:**

* Authorization: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`
* Token: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
* SAML SSO: `https://login.microsoftonline.com/{tenant}/saml2`
* Federation metadata: `https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml`
* OIDC discovery: `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration`

All endpoints are owned and operated by Microsoft Corporation.

* [Microsoft Privacy Statement](https://privacy.microsoft.com/en-us/privacystatement)
* [Microsoft Terms of Service](https://www.microsoft.com/en-us/servicesagreement)

No data is sent to third-party services. Authentication tokens are validated locally and never stored beyond the active session.

== Frequently Asked Questions ==

= Does this plugin work with personal Microsoft accounts (outlook.com)? =

No. It is designed for organisational accounts managed through a Microsoft Entra ID tenant.

= Can I map Entra security groups to WordPress roles? =

Yes. Go to **Settings → Entra SSO → Role Mapping** and enter the Object ID of each Entra group with the desired WordPress role. Group membership is evaluated at every login.

= What happens when a user logs in for the first time? =

If **Auto-Create Users** is enabled, the plugin creates a WordPress account using the email and display name from the Entra token, assigned the **Default Role** unless a group mapping matches.

= Is the client secret stored securely? =

Yes. Encrypted using libsodium (XSalsa20-Poly1305) or AES-256-GCM with a key derived from WordPress secret keys. Never written to log files.

= I use NinjaFirewall and SAML login fails =

NinjaFirewall blocks the base64-encoded SAML POST data. Create a `.htninja` file in your document root:

`<?php
if ( strpos( $_SERVER["REQUEST_URI"], "/sso/saml-acs" ) !== false ) {
    return "ALLOW";
}`

== Support ==

* **Bug reports and feature requests:** [GitHub Issues](https://github.com/codetot-web/sso-for-microsoft-entra/issues)
* **Documentation:** Click the Help button on the plugin settings page, or see the [GitHub README](https://github.com/codetot-web/sso-for-microsoft-entra).
* **Security vulnerabilities:** Please report privately via [GitHub Security Advisories](https://github.com/codetot-web/sso-for-microsoft-entra/security/advisories).

== Screenshots ==

1. **Settings page** — Connection, authentication, and user provisioning settings.
2. **SAML metadata import** — One-click import from federation metadata URL.
3. **Role mapping** — Map Entra group Object IDs to WordPress roles.
4. **Login page** — Microsoft sign-in button on the WordPress login form.

== Changelog ==

= 2.0.3 =
* **Fixed:** JS lint errors in protocol toggle (CI green).

= 2.0.2 =
* **Fixed:** Skip Client Secret requirement when SAML protocol is selected.
* **Fixed:** Hide Client Secret field in settings when SAML 2.0 is active.
* **Fixed:** Settings URL slug and plugin name in admin notices.

= 2.0.1 =
* **Fixed:** Update "Tested up to" to WordPress 6.9.
* **Fixed:** Include composer.json in distribution (Plugin Check compliance).
* **Added:** README.md for GitHub with badges, support links.
* **Added:** Support section in readme.txt with GitHub Issues link.

= 2.0.0 =
* **Breaking:** Renamed plugin from "Microsoft Entra SSO" to "SSO for Microsoft Entra" for trademark compliance.
* **Breaking:** All internal names changed — namespace (`SFME`), option keys (`sfme_*`), CSS/JS classes (`sfme-*`). Existing settings auto-migrate on activation.
* **Breaking:** Requires PHP 8.1+ (LightSaml dependency).
* **Added:** Auto-extract Tenant ID and Client ID from federation metadata URL.
* **Added:** Auto-switch to SAML protocol when importing metadata.
* **Added:** Configurable rate limiting settings in admin (Max Attempts, Window).
* **Added:** Contextual Help tabs on settings page (Quick Start, Azure Setup, SAML Setup, Troubleshooting).
* **Added:** WordPress.org plugin assets (icon, banner).
* **Added:** Vietnamese translation.
* **Fixed:** SAML signature verification — replaced manual XML canonicalization with LightSaml library.
* **Fixed:** UTF-8 BOM in Microsoft federation metadata causing XML parse failure.
* **Fixed:** SAML Issuer using home URL instead of client ID (AADSTS700016).
* **Fixed:** Metadata wiped on settings save — now preserves AJAX-imported values.

= 1.2.0 =
* Auto-extract Tenant ID and Client ID from federation metadata URL on import.
* Auto-switch to SAML protocol when importing metadata.
* Rate limiting settings in admin UI.
* Strip UTF-8 BOM from Microsoft metadata XML.
* Use client ID as SAML AuthnRequest Issuer.
* Preserve SAML metadata on settings form save.

= 1.1.0 =
* **Security:** Fix critical SAML Signature Wrapping (XSW) and XPath injection.
* **Security:** Fix double rate-limiting lockout after 2 logins.
* **Security:** Add JWKS cache-refresh-on-failure.
* **Security:** Use HKDF for encryption key derivation.
* **Changed:** SSO endpoints moved from `wp-login.php` to `/sso/*` custom URLs.

= 1.0.0 =
* Initial release.
* OpenID Connect with PKCE, SAML 2.0, user provisioning, role mapping, rate limiting.

== Upgrade Notices ==

= 2.0.2 =
Client Secret field is now hidden for SAML setups and no longer triggers a missing-field warning.

= 2.0.1 =
Fix WordPress 6.9 compatibility header and Plugin Check compliance.

= 2.0.0 =
**Breaking:** Plugin renamed and all internal prefixes changed. Settings auto-migrate on activation — just deactivate and reactivate. Requires PHP 8.1+. If using NinjaFirewall, create a `.htninja` whitelist for `/sso/saml-acs`.

= 1.1.0 =
**Breaking:** Update Azure redirect URI to `https://yoursite.com/sso/callback`. Re-enter client secret (encryption changed). Flush permalinks.

= 1.0.0 =
Initial release.
