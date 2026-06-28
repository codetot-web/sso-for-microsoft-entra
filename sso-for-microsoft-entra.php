<?php
/**
 * Plugin Name:       SSO for Microsoft Entra
 * Plugin URI:        https://github.com/codetot-web/sso-for-microsoft-entra
 * Description:       Single Sign-On authentication for WordPress using Microsoft Entra ID (Azure AD) via OpenID Connect with PKCE.
 * Version:           2.7.0
 * Requires at least: 6.0
 * Requires PHP:      8.0
 * Author:            Khoi Pro, CODE TOT
 * Author URI:        https://codetot.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       sso-for-microsoft-entra
 * Domain Path:       /languages
 *
 * @package SFME
 */

defined( 'ABSPATH' ) || exit;

/**
 * Plugin version.
 *
 * @var string
 */
define( 'SFME_VERSION', '2.7.0' );

/**
 * Database schema version.
 *
 * Increment when adding a new migration step in SFME\Upgrader so that
 * the upgrade routine runs automatically on the next admin page load.
 *
 * @var int
 */
define( 'SFME_DB_VERSION', 1 );

/**
 * Absolute path to the main plugin file.
 *
 * @var string
 */
define( 'SFME_PLUGIN_FILE', __FILE__ );

/**
 * Absolute path to the plugin directory (with trailing slash).
 *
 * @var string
 */
define( 'SFME_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Public URL to the plugin directory (with trailing slash).
 *
 * @var string
 */
define( 'SFME_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

/**
 * Verify minimum PHP version requirement.
 *
 * Displays an admin notice and halts plugin loading when the server runs
 * a PHP version older than 8.0.
 */
if ( version_compare( PHP_VERSION, '8.0', '<' ) ) {
	add_action(
		'admin_notices',
		function () {
			printf(
				'<div class="notice notice-error"><p>%s</p></div>',
				esc_html__(
					'Microsoft Entra SSO requires PHP 8.0 or higher. Please upgrade PHP to activate this plugin.',
					'sso-for-microsoft-entra'
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
					'sso-for-microsoft-entra'
				)
			);
		}
	);
	return;
}

// Load Composer autoloader for third-party dependencies (xmlseclibs, etc.).
if ( file_exists( SFME_PLUGIN_DIR . 'vendor/autoload.php' ) ) {
	require_once SFME_PLUGIN_DIR . 'vendor/autoload.php';
}

// Load the PSR-4-style autoloader for all plugin classes.
require_once SFME_PLUGIN_DIR . 'includes/class-autoloader.php';

// Boot the plugin singleton.
\SFME\Plugin::get_instance();

/**
 * Flush rewrite rules on activation so any custom endpoints are registered
 * before WordPress first processes a request.
 */
register_activation_hook(
	__FILE__,
	function () {
		// Run any pending database upgrades so a fresh activation always
		// starts with the current schema.
		\SFME\Upgrader::maybe_upgrade();

		// Register the rewrite rule before flushing so it is included in the
		// persisted rules. On normal page loads this is done via the init hook,
		// but during activation init may not have fired yet.
		add_rewrite_rule( '^sso/([a-z-]+)/?$', 'index.php?sfme_action=$matches[1]', 'top' );
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
