# SSO for Microsoft Entra

[![Lint & Test](https://github.com/codetot-web/sso-for-microsoft-entra/actions/workflows/ci.yml/badge.svg)](https://github.com/codetot-web/sso-for-microsoft-entra/actions/workflows/ci.yml)
[![PHP 8.1+](https://img.shields.io/badge/PHP-8.1%2B-blue.svg)](https://www.php.net/)
[![WordPress 6.0+](https://img.shields.io/badge/WordPress-6.0%2B-blue.svg)](https://wordpress.org/)
[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

Single Sign-On authentication for WordPress using Microsoft Entra ID (Azure AD). Supports SAML 2.0 and OpenID Connect with PKCE.

## Features

- **SAML 2.0** with one-click federation metadata import
- **OpenID Connect (OIDC)** with PKCE
- **Auto-extract** Tenant ID and Client ID from the metadata URL
- **Automatic user provisioning** on first SSO login
- **Role mapping** from Entra security groups to WordPress roles
- **Encrypted** client-secret storage
- **Configurable rate limiting** on login attempts
- **Contextual Help tabs** built into the settings page
- **Vietnamese translation** included, community translations via [translate.wordpress.org](https://translate.wordpress.org/)

## Quick Start (SAML)

1. Install and activate the plugin.
2. In Azure Portal: **Enterprise Applications** > your app > **Single sign-on** > **SAML**.
3. Set **Reply URL (ACS)** to `https://yoursite.com/sso/saml-acs`.
4. Copy the **App Federation Metadata URL**.
5. In WordPress: **Settings** > **Entra SSO** > paste the URL > click **Import Metadata**.
6. Click **Save Changes**. Done.

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
cd sso-for-microsoft-entra
composer install --no-dev
```

Activate the plugin from the WordPress admin.

## Configuration

Click the **Help** button (top-right) on the settings page for step-by-step guides:

- **Quick Start** — 6-step SAML setup
- **Azure Setup** — Full app registration walkthrough
- **SAML Setup** — Entity ID, ACS URL, NinjaFirewall notes
- **Troubleshooting** — Common errors and fixes

## NinjaFirewall Compatibility

If you use NinjaFirewall, create a `.htninja` file in your document root:

```php
<?php
if ( isset( $_SERVER["REQUEST_URI"] ) &&
     strpos( $_SERVER["REQUEST_URI"], "/sso/saml-acs" ) !== false ) {
    return "ALLOW";
}
```

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
