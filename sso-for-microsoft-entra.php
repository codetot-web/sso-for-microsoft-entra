<?php
/**
 * Plugin Name:       SSO for Microsoft Entra
 * Plugin URI:        https://github.com/codetot-web/sso-for-microsoft-entra
 * Description:       Single Sign-On authentication for WordPress using Microsoft Entra ID (Azure AD) via OpenID Connect with PKCE.
 * Version:           2.2.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
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
define( 'SFME_VERSION', '2.2.0' );

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
		// Migrate options from old plugin key prefix (microsoft_entra_sso_*) to new (sfme_*).
		$migrate_keys = array(
			'microsoft_entra_sso_tenant_id'         => 'sfme_tenant_id',
			'microsoft_entra_sso_client_id'         => 'sfme_client_id',
			'microsoft_entra_sso_client_secret'     => 'sfme_client_secret',
			'microsoft_entra_sso_auto_redirect'     => 'sfme_auto_redirect',
			'microsoft_entra_sso_role_map'          => 'sfme_role_map',
			'microsoft_entra_sso_default_role'      => 'sfme_default_role',
			'microsoft_entra_sso_user_provisioning' => 'sfme_user_provisioning',
			'microsoft_entra_sso_rate_limit_max'    => 'sfme_rate_limit_max',
			'microsoft_entra_sso_rate_limit_window' => 'sfme_rate_limit_window',
			'microsoft_entra_sso_button_text'       => 'sfme_button_text',
			'microsoft_entra_sso_button_style'      => 'sfme_button_style',
			'microsoft_entra_sso_allow_local_login' => 'sfme_allow_local_login',
		);

		foreach ( $migrate_keys as $old_key => $new_key ) {
			$old_value = get_option( $old_key, null );
			if ( null !== $old_value && false === get_option( $new_key, null ) ) {
				update_option( $new_key, $old_value );
				delete_option( $old_key );
			}
		}

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
