# SSO for Microsoft Entra

[![Lint & Test](https://github.com/codetot-web/sso-for-microsoft-entra/actions/workflows/ci.yml/badge.svg)](https://github.com/codetot-web/sso-for-microsoft-entra/actions/workflows/ci.yml)
[![PHP 8.1+](https://img.shields.io/badge/PHP-8.1%2B-blue.svg)](https://www.php.net/)
[![WordPress 6.0+](https://img.shields.io/badge/WordPress-6.0%2B-blue.svg)](https://wordpress.org/)
[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

Single Sign-On authentication for WordPress using Microsoft Entra ID (Azure AD) via OpenID Connect with PKCE.

## Features

- **OpenID Connect (OIDC)** with PKCE — the most secure OAuth 2.0 flow
- **Automatic user provisioning** on first SSO login
- **Encrypted** client-secret storage
- **Configurable rate limiting** on login attempts
- **Contextual Help tabs** built into the settings page
- **Vietnamese translation** included, community translations via [translate.wordpress.org](https://translate.wordpress.org/)

## Quick Start

1. Install and activate the plugin.
2. In Azure Portal: **App registrations** > **+ New registration**.
3. Set **Redirect URI** (Web) to `https://yoursite.com/sso/callback`.
4. Copy the **Application (client) ID** and **Directory (tenant) ID**.
5. Go to **Certificates & secrets** > **+ New client secret** > copy the Value.
6. In WordPress: **Settings** > **Entra SSO** > enter Tenant ID, Client ID, Client Secret > **Save Changes**.
7. Add API permissions: **Microsoft Graph** > Delegated: `openid`, `profile`, `email`.
8. Test in an incognito window.

## Requirements

- PHP 8.1 or higher
- WordPress 6.0 or higher
- A Microsoft Entra ID (Azure AD) tenant

## Installation

### From WordPress Admin

1. Download the latest release zip from [Releases](https://github.com/codetot-web/sso-for-microsoft-entra/releases).
2. Go to **Plugins** > **Add New** > **Upload Plugin**.
3. Upload the zip file and activate.

### Manual

```bash
cd wp-content/plugins/
git clone https://github.com/codetot-web/sso-for-microsoft-entra.git
```

Activate the plugin from the WordPress admin.

## Configuration

Click the **Help** button (top-right) on the settings page for step-by-step guides:

- **Quick Start** — OIDC setup walkthrough
- **Azure Setup** — Full app registration walkthrough
- **Troubleshooting** — Common errors and fixes

## Security

- PKCE (Proof Key for Code Exchange) prevents authorization code interception
- OAuth state parameter prevents CSRF attacks
- ID token nonce prevents token replay
- `administrator` role is blocked as the SSO default role
- Default role for new SSO users is `subscriber`
- Client secret encrypted at rest using libsodium or AES-256-GCM

## Development

```bash
# Install dependencies (including dev)
composer install

# Run linter
vendor/bin/phpcs --standard=phpcs.xml.dist

# Run tests
vendor/bin/phpunit
```

## Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change.

## Support

- **Bug reports:** [GitHub Issues](https://github.com/codetot-web/sso-for-microsoft-entra/issues)
- **Security vulnerabilities:** Please report privately via [GitHub Security Advisories](https://github.com/codetot-web/sso-for-microsoft-entra/security/advisories)

## License

[GPL-2.0-or-later](LICENSE)
