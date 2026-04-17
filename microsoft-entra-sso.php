<?php
/**
 * Plugin Name:       Microsoft Entra SSO
 * Plugin URI:        https://github.com/codetot-web/microsoft-entra-sso
 * Description:       Single Sign-On authentication for WordPress using Microsoft Entra ID (Azure AD). Supports OpenID Connect with PKCE and SAML 2.0.
 * Version:           1.2.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Khoi Pro, CODE TOT
 * Author URI:        https://codetot.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       microsoft-entra-sso
 * Domain Path:       /languages
 *
 * @package MicrosoftEntraSSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Plugin version.
 *
 * @var string
 */
define( 'MESSO_VERSION', '1.2.0' );

/**
 * Absolute path to the main plugin file.
 *
 * @var string
 */
define( 'MESSO_PLUGIN_FILE', __FILE__ );

/**
 * Absolute path to the plugin directory (with trailing slash).
 *
 * @var string
 */
define( 'MESSO_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Public URL to the plugin directory (with trailing slash).
 *
 * @var string
 */
define( 'MESSO_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

/**
 * Verify minimum PHP version requirement.
 *
 * Displays an admin notice and halts plugin loading when the server runs
 * a PHP version older than 7.4.
 */
if ( version_compare( PHP_VERSION, '7.4', '<' ) ) {
	add_action(
		'admin_notices',
		function () {
			printf(
				'<div class="notice notice-error"><p>%s</p></div>',
				esc_html__(
					'Microsoft Entra SSO requires PHP 7.4 or higher. Please upgrade PHP to activate this plugin.',
					'microsoft-entra-sso'
				)
			);
		}
	);
	return;
}

/**
 * Verify minimum WordPress version requirement.
 *
 * Displays an admin notice and halts plugin loading when WordPress is older
 * than version 6.0.
 */
if ( version_compare( get_bloginfo( 'version' ), '6.0', '<' ) ) {
	add_action(
		'admin_notices',
		function () {
			printf(
				'<div class="notice notice-error"><p>%s</p></div>',
				esc_html__(
					'Microsoft Entra SSO requires WordPress 6.0 or higher. Please upgrade WordPress to activate this plugin.',
					'microsoft-entra-sso'
				)
			);
		}
	);
	return;
}

// Load the PSR-4-style autoloader for all plugin classes.
require_once MESSO_PLUGIN_DIR . 'includes/class-autoloader.php';

// Boot the plugin singleton.
\MicrosoftEntraSSO\Plugin::get_instance();

/**
 * Flush rewrite rules on activation so any custom endpoints are registered
 * before WordPress first processes a request.
 */
register_activation_hook(
	__FILE__,
	function () {
		flush_rewrite_rules();
	}
);

/**
 * Flush rewrite rules on deactivation to remove any custom endpoints the
 * plugin may have registered.
 */
register_deactivation_hook(
	__FILE__,
	function () {
		flush_rewrite_rules();
	}
);
