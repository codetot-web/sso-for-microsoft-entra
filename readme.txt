=== Microsoft Entra SSO ===
Contributors: khoipro, codetot
Tags: sso, microsoft, entra, azure, openid-connect
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Single Sign-On authentication for WordPress using Microsoft Entra ID (Azure AD). Supports OpenID Connect with PKCE and SAML 2.0.

== Description ==

**Microsoft Entra SSO** enables your WordPress site to authenticate users through Microsoft Entra ID (formerly Azure Active Directory). Users can sign in with their existing Microsoft 365 / work accounts — no separate WordPress password required.

**Key features:**

* OpenID Connect (OIDC) authentication with PKCE — the most secure OAuth 2.0 flow.
* SAML 2.0 support with one-click federation metadata XML import.
* Automatic user provisioning — create WordPress accounts on first SSO login.
* Role mapping — assign WordPress roles based on Entra group membership.
* Encrypted client-secret storage using WordPress secret keys.
* Rate limiting on SSO login attempts to defend against brute-force attacks.
* Optional auto-redirect from the WordPress login page directly to Entra.
* WordPress.org Plugin Check (PCP) compliant.
* No jQuery dependency.

== Installation ==

1. Upload the `microsoft-entra-sso` folder to `/wp-content/plugins/`.
2. Activate the plugin from the **Plugins** screen in WordPress admin.
3. Navigate to **Settings → Microsoft Entra SSO**.
4. Enter your **Tenant ID**, **Client ID**, and **Client Secret** from your Azure App Registration.
5. Choose your authentication protocol (OIDC or SAML).
6. Save changes and test SSO login.

For detailed setup instructions, including how to create the Azure App Registration, see the [documentation on GitHub](https://github.com/codetot-web/microsoft-entra-sso).

== External Services ==

This plugin communicates with Microsoft Entra ID endpoints to perform authentication. Data transmitted includes OAuth 2.0 / OIDC tokens and (optionally) user profile information returned by Microsoft's identity platform.

**Endpoints contacted:**

* Authorization endpoint:
  `https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize`
* Token endpoint:
  `https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token`
* UserInfo endpoint:
  `https://graph.microsoft.com/oidc/userinfo`
* SAML metadata endpoint:
  `https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml`
* OpenID Connect discovery document:
  `https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration`

All endpoints are owned and operated by Microsoft Corporation.

* Microsoft Privacy Statement: https://privacy.microsoft.com/en-us/privacystatement
* Microsoft Terms of Service: https://www.microsoft.com/en-us/servicesagreement

No data is sent to third-party services by this plugin. Authentication tokens are validated locally and never stored beyond the active session.

== Frequently Asked Questions ==

= Does this plugin work with personal Microsoft accounts (outlook.com)? =

No. The plugin is designed for organisational accounts managed through a Microsoft Entra ID tenant. Personal consumer accounts are not supported.

= Can I map Entra security groups to WordPress roles? =

Yes. Navigate to **Settings → Microsoft Entra SSO → Role Mapping** and enter the Object ID of each Entra group alongside the WordPress role you want to assign. Group membership is evaluated at every login so role changes in Entra are reflected immediately.

= What happens when a user logs in for the first time? =

If **User Provisioning** is enabled, the plugin automatically creates a new WordPress user using the email address and display name from the Entra ID token. The user is assigned the **Default Role** unless a group mapping matches first.

= Is the client secret stored securely? =

Yes. The client secret is encrypted using AES-256-CBC with a key derived from your WordPress secret keys before it is saved to the database. It is never written to log files or exposed through the REST API.

== Screenshots ==

1. **Settings overview** — General settings screen showing tenant ID, client ID, and protocol selection.
2. **OIDC configuration** — Detailed OIDC tab with redirect URI and scope selection.
3. **SAML configuration** — SAML tab with federation metadata XML import and certificate management.
4. **Role mapping** — Table mapping Entra group Object IDs to WordPress roles with add/remove controls.

== Changelog ==

= 1.1.0 =
* **Security:** Fix critical SAML Signature Wrapping (XSW) and XPath injection vulnerabilities.
* **Security:** Fix double rate-limiting that locked users out after 2 successful logins.
* **Security:** Add JWKS cache-refresh-on-failure for seamless key rotation handling.
* **Security:** Use HKDF for encryption key derivation with domain separation.
* **Security:** Require SAML AudienceRestriction, enforce HTTPS on discovery endpoints.
* **Changed:** SSO endpoints moved from `wp-login.php` to `/sso/*` custom URLs (login, callback, saml-acs, logout).
* **Fixed:** Uninstall routine now correctly cleans up user meta with `_messo_` prefix.

= 1.0.0 =
* Initial release.
* OpenID Connect authentication with PKCE flow.
* SAML 2.0 support with federation metadata XML import.
* Admin settings page with encrypted client-secret storage.
* Automatic user provisioning on first SSO login.
* Role mapping from Entra security groups to WordPress roles.
* Rate limiting on SSO login attempts.
* WordPress.org Plugin Check (PCP) compliant.

== Upgrade Notices ==

= 1.1.0 =
**Breaking changes:** (1) Update your Azure App Registration redirect URI to `https://yoursite.com/sso/callback`. (2) Re-enter your client secret in Settings → Entra SSO (encryption key derivation changed). (3) Re-activate the plugin or visit Settings → Permalinks to flush rewrite rules.

= 1.0.0 =
Initial release — no upgrade steps required.
