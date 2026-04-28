# Microsoft Entra SSO — Setup Guide

This guide walks through configuring the Microsoft Entra SSO WordPress plugin end-to-end. No developer knowledge is required. Estimated time: 20–30 minutes.

---

## Prerequisites

- A Microsoft Entra ID (Azure AD) account with permission to register applications (Application Administrator role or higher)
- WordPress 6.0+ with the Microsoft Entra SSO plugin installed and activated
- Your site must be accessible over HTTPS in production

---

## Part 1 — Azure Portal Setup

### 1.1 Create a new App Registration

1. Sign in to the [Azure Portal](https://portal.azure.com).
2. Search for **Microsoft Entra ID** in the top search bar and open it.
3. In the left sidebar, click **App registrations**.
4. Click **+ New registration**.
5. Fill in the registration form:
   - **Name**: `WordPress SSO` (or your site name — this is visible to users on the sign-in page)
   - **Supported account types**: Select **"Accounts in this organizational directory only (Single tenant)"**
     - Choose "Multitenant" only if you need to allow logins from multiple Microsoft 365 organizations.
   - **Redirect URI**:
     - Platform: **Web**
     - URI: `https://yoursite.com/sso/callback`
     - Replace `yoursite.com` with your actual WordPress site domain.
6. Click **Register**.

> **Important**: The redirect URI must match exactly what you enter in the plugin settings — including whether it has a trailing slash, uppercase/lowercase letters, and the protocol (https vs http).

### 1.2 Copy your Application IDs

After registration you will land on the app overview page. **Copy and save** the following values — you will need them in the plugin:

| Value | Where to find it |
|---|---|
| **Application (client) ID** | Overview page, under "Essentials" |
| **Directory (tenant) ID** | Overview page, under "Essentials" |

### 1.3 Create a Client Secret

1. In the left sidebar, click **Certificates & secrets**.
2. Click **+ New client secret**.
3. Enter a description (e.g., `WordPress SSO`) and choose an expiry period.
4. Click **Add**.
5. **Immediately copy the "Value" column** — this is shown only once. If you navigate away without copying it, you must create a new secret.

> **Security note**: Store this secret value securely. The plugin encrypts it at rest, but you should treat it like a password.

### 1.4 Add API Permissions

1. In the left sidebar, click **API permissions**.
2. Click **+ Add a permission**.
3. Select **Microsoft Graph**.
4. Select **Delegated permissions**.
5. Search for and check each of the following permissions:
   - `openid`
   - `profile`
   - `email`
6. Click **Add permissions**.
7. If your organization requires admin approval, click **Grant admin consent for [Your Organization]** and confirm.

### 1.5 Add Optional Claims (Recommended)

Adding optional claims ensures the user's name and email are always included in the token.

1. In the left sidebar, click **Token configuration**.
2. Click **+ Add optional claim**.
3. Select **ID token**.
4. Check the following claims:
   - `email`
   - `given_name`
   - `family_name`
5. Click **Add**. If prompted to add Microsoft Graph permissions, accept.

---

## Part 2 — Plugin Configuration

### 2.1 Open Plugin Settings

1. Log in to the WordPress admin (`/wp-admin`).
2. Go to **Settings → Entra SSO**.

### 2.2 Connection Section

Enter the values you copied from the Azure Portal:

| Field | Value |
|---|---|
| **Tenant ID** | Directory (tenant) ID from Step 1.2 |
| **Client ID** | Application (client) ID from Step 1.2 |
| **Client Secret** | Secret value from Step 1.3 |

The **Redirect URI** is displayed below these fields — it is auto-generated and read-only. Confirm this URI matches exactly what you registered in Azure (Step 1.1).

### 2.3 Authentication Section

- **Allow local login**: Keep this checked during initial setup and testing so you can still log in with your WordPress username/password if something goes wrong. You can uncheck it later to force all logins through Microsoft.

### 2.4 User Provisioning

- **Auto-create users**: Enable this to automatically create a WordPress account the first time a user signs in via Microsoft Entra. If disabled, users must already have a WordPress account with a matching email address.
- All new SSO users are assigned the **Subscriber** role. Administrators can promote users to other roles manually from the Users screen.

> New accounts will have the email address and display name from the Microsoft token. Users can change their WordPress display name later in their profile.

### 2.5 Login Button Customization

- **Button text**: Change the label shown on the login page (default: "Sign in with Microsoft").
- **Button style**: Choose between the Microsoft-branded style and a plain WordPress-style button.

### 2.7 Save and Test

1. Click **Save Changes**.
2. Open a new **private / incognito browser window**.
3. Navigate to `https://yoursite.com/wp-login.php`.
4. You should see the Microsoft sign-in button.
5. Click the button and complete the Microsoft login flow.
6. You should be redirected back and logged in to WordPress.

> Always test in an incognito window so your existing WordPress admin session is not affected.

---

## Part 3 — Troubleshooting

### AADSTS50011: Redirect URI mismatch

**Symptom**: Microsoft login redirects back to Azure with this error code.

**Cause**: The redirect URI registered in Azure does not exactly match the URI generated by the plugin.

**Fix**:
1. In WordPress admin, go to **Settings → Entra SSO** and note the **Redirect URI** shown there.
2. In the Azure Portal, go to your app registration → **Authentication**.
3. Under **Web → Redirect URIs**, verify the URI matches exactly — including:
   - Protocol (`https://` not `http://`)
   - Domain spelling and case
   - Presence or absence of a trailing slash
4. Save in Azure.

---

### AADSTS700016: Application not found in directory

**Symptom**: Error on the Microsoft sign-in page.

**Cause**: The Tenant ID or Client ID entered in the plugin is incorrect.

**Fix**: Return to the Azure Portal, open your app registration, and re-copy the **Directory (tenant) ID** and **Application (client) ID** to the plugin settings.

---

### "User not assigned to a role"

**Symptom**: Users can authenticate with Microsoft but receive an authorization error.

**Cause**: The Enterprise Application requires explicit user assignment.

**Fix**:
1. In Azure Portal → **Enterprise applications** → your app.
2. Click **Users and groups** in the sidebar.
3. Click **+ Add user/group** and assign the user (or a group containing the user).

---

### Token validation failed

**Symptom**: An error in `wp-content/debug.log` such as `jwt_signature_invalid` or `jwt_expired`.

**Common causes**:
- **Clock drift**: The WordPress server clock is out of sync. Run `date` on the server to check the current time; use NTP to correct it. The plugin allows 60 seconds of clock skew.
- **Cached JWKS**: Microsoft may have rotated signing keys. Clear the `messo_jwks_*` transients via **WP-Admin → Tools → Delete expired transients** (or with WP-CLI: `wp transient delete --all`).

---

### Login loop (redirects back to login page)

**Symptom**: After Microsoft authentication succeeds, the browser keeps returning to the WordPress login page.

**Fix**:
1. Enable `WP_DEBUG_LOG` in `wp-config.php`:
   ```php
   define( 'WP_DEBUG', true );
   define( 'WP_DEBUG_LOG', true );
   define( 'WP_DEBUG_DISPLAY', false );
   ```
2. Reproduce the issue, then check `wp-content/debug.log` for the specific error.
3. Common sub-causes:
   - Auto-create users is disabled and no matching WordPress account exists → enable auto-create or create the user manually.
   - Session / cookie conflict → clear browser cookies or try a different browser.

---

### Rate limited: "Too many login attempts"

**Symptom**: The plugin blocks login attempts after several failures.

**Cause**: The default rate limit is 5 attempts per 15-minute window per IP address.

**Fix (for admins)**: Clear the rate-limit transients. In WP-CLI:
```bash
wp transient delete --search="messo_rate_"
```
Or wait 15 minutes for the window to expire automatically.

---

### "Encryption unavailable"

**Symptom**: Admin notice warning that the client secret cannot be encrypted.

**Cause**: Neither the `sodium` nor the `openssl` PHP extension is available.

**Fix**: Ask your hosting provider or server administrator to enable `php-sodium` (preferred) or `php-openssl`. Both are standard extensions available in virtually all PHP distributions.

---

## Part 4 — Security Notes

### Encrypted secrets

The client secret is never stored in plain text. The plugin uses libsodium (XSalsa20-Poly1305) when available, falling back to OpenSSL AES-256-GCM. The encryption key is derived from WordPress's built-in authentication salts using SHA-256.

**Important**: If WordPress security salts are regenerated (e.g., after a compromise), the encrypted client secret will become unreadable. You must re-enter the client secret in the plugin settings after any salt rotation.

### PKCE (Proof Key for Code Exchange)

The OIDC flow uses RFC 7636 PKCE with the S256 challenge method. This prevents authorization code interception attacks even if the callback URL is observed by an attacker.

### Rate limiting

The plugin applies IP-based rate limiting to the SSO callback endpoint: 5 attempts per 15-minute window by default. These defaults can be adjusted with WordPress filters:

```php
// In your theme's functions.php or a custom plugin:
add_filter( 'microsoft_entra_sso_rate_limit_attempts', fn() => 10 );
add_filter( 'microsoft_entra_sso_rate_limit_window', fn() => 1800 ); // 30 minutes.
```

### HTTPS requirement

Always use HTTPS in production. The redirect URI registered in Azure must use `https://`. Browsers will not send secure cookies over plain HTTP, which will break the authentication flow.

### Algorithm whitelist

The plugin only accepts RS256 (RSA-SHA256) as a JWT signing algorithm. Tokens signed with `none`, `HS256`, `HS384`, `HS512`, or any other algorithm are rejected to prevent known algorithm-confusion attacks.

## Part 5 — Frequently Asked Questions

**Q: Can users still log in with their WordPress username and password?**

Yes, as long as **"Allow local login"** is checked in the plugin settings. Uncheck it only after confirming that all users can sign in via Microsoft.

**Q: What happens if Microsoft Entra is unavailable?**

If Microsoft's authentication service is unreachable, users relying on SSO will not be able to log in. Keep **"Allow local login"** enabled and ensure at least one administrator account can log in with a local password as a fallback.

**Q: Where is the client secret stored?**

The client secret is encrypted and stored in the `wp_options` database table under the `microsoft_entra_sso_client_secret` key. It is never written to log files.

**Q: How often does the plugin fetch the JWKS signing keys from Microsoft?**

JWKS documents are cached as WordPress transients for 24 hours. Microsoft rotates signing keys infrequently. If you need to force a refresh, delete any transients prefixed with `messo_jwks_`.

**Q: Does the plugin support multi-site WordPress installations?**

The plugin settings are stored per-site. On a WordPress multisite network, each site has its own settings and can be configured with different Entra app registrations.
