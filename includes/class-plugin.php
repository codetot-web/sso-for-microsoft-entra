<?php
/**
 * Main plugin class — bootstraps all subsystems.
 *
 * @package MicrosoftEntraSSO
 */

namespace MicrosoftEntraSSO;

defined( 'ABSPATH' ) || exit;

/**
 * Class Plugin
 *
 * Central coordinator for the Microsoft Entra SSO plugin. Uses a singleton
 * pattern to guarantee a single instance is booted per request. Lazy-loads
 * admin-only components when inside the WordPress admin context.
 */
class Plugin {

	// -------------------------------------------------------------------------
	// Option key constants
	// -------------------------------------------------------------------------

	/**
	 * Tenant ID (Directory ID) for the Entra application registration.
	 */
	const OPTION_TENANT_ID = 'microsoft_entra_sso_tenant_id';

	/**
	 * Application (client) ID of the Entra app registration.
	 */
	const OPTION_CLIENT_ID = 'microsoft_entra_sso_client_id';

	/**
	 * Encrypted client secret for the Entra application.
	 */
	const OPTION_CLIENT_SECRET = 'microsoft_entra_sso_client_secret';

	/**
	 * Authentication protocol to use: "oidc" or "saml".
	 */
	const OPTION_AUTH_PROTOCOL = 'microsoft_entra_sso_auth_protocol';

	/**
	 * Whether to redirect users directly to Entra login (bypass WP login form).
	 */
	const OPTION_AUTO_REDIRECT = 'microsoft_entra_sso_auto_redirect';

	/**
	 * Role mapping JSON: maps Entra group object IDs to WP role slugs.
	 */
	const OPTION_ROLE_MAP = 'microsoft_entra_sso_role_map';

	/**
	 * Default WordPress role assigned to newly provisioned users.
	 */
	const OPTION_DEFAULT_ROLE = 'microsoft_entra_sso_default_role';

	/**
	 * Whether automatic user provisioning is enabled.
	 */
	const OPTION_USER_PROVISIONING = 'microsoft_entra_sso_user_provisioning';

	/**
	 * Raw SAML federation metadata XML (imported from Entra).
	 */
	const OPTION_SAML_METADATA = 'microsoft_entra_sso_saml_metadata';

	/**
	 * Maximum number of failed SSO login attempts before temporary lockout.
	 */
	const OPTION_RATE_LIMIT_MAX = 'microsoft_entra_sso_rate_limit_max';

	/**
	 * Duration of a rate-limit lockout window in seconds.
	 */
	const OPTION_RATE_LIMIT_WINDOW = 'microsoft_entra_sso_rate_limit_window';

	// -------------------------------------------------------------------------
	// Singleton
	// -------------------------------------------------------------------------

	/**
	 * Shared instance.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Retrieve or create the singleton instance.
	 *
	 * @return Plugin
	 */
	public static function get_instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->init();
		}
		return self::$instance;
	}

	/**
	 * Private constructor — prevents direct instantiation.
	 */
	private function __construct() {}

	/**
	 * Prevent cloning of the singleton.
	 */
	private function __clone() {}

	// -------------------------------------------------------------------------
	// Bootstrapping
	// -------------------------------------------------------------------------

	/**
	 * Register WordPress hooks that drive the plugin lifecycle.
	 *
	 * Called once by get_instance(). Hooks are split by context so
	 * admin-only classes are never loaded on the front end.
	 *
	 * @return void
	 */
	private function init(): void {
		// Load plugin text domain for translations.
		add_action( 'init', array( $this, 'load_textdomain' ) );

		// Front-end + REST API authentication hooks.
		add_action( 'init', array( $this, 'on_init' ) );

		// Login-page hooks (handles OIDC/SAML callbacks and auto-redirect).
		add_action( 'login_init', array( $this, 'on_login_init' ) );

		// Admin-only hooks — lazy-loaded to avoid unnecessary overhead.
		if ( is_admin() ) {
			add_action( 'admin_init', array( $this, 'on_admin_init' ) );
			add_action( 'admin_menu', array( $this, 'on_admin_menu' ) );
			add_action( 'admin_enqueue_scripts', array( 'MicrosoftEntraSSO\Admin\Settings_Page', 'enqueue_assets' ) );
			add_action( 'admin_notices', array( 'MicrosoftEntraSSO\Admin\Admin_Notices', 'render_notices' ) );
			add_action( 'wp_ajax_messo_import_metadata', array( 'MicrosoftEntraSSO\Admin\Settings_Page', 'handle_import_metadata' ) );
			add_action( 'wp_ajax_messo_dismiss_notice', array( 'MicrosoftEntraSSO\Admin\Admin_Notices', 'handle_dismiss' ) );
		}
	}

	// -------------------------------------------------------------------------
	// Hook callbacks (stubs — implemented by later phases)
	// -------------------------------------------------------------------------

	/**
	 * Load the plugin's translated strings.
	 *
	 * @return void
	 */
	public function load_textdomain(): void {
		load_plugin_textdomain(
			'microsoft-entra-sso',
			false,
			dirname( plugin_basename( MESSO_PLUGIN_FILE ) ) . '/languages'
		);
	}

	/**
	 * Early init hook — registers custom rewrite endpoints used by the plugin.
	 *
	 * Full implementation is provided in later phases.
	 *
	 * @return void
	 */
	public function on_init(): void {
		// Placeholder: register rewrite rules, REST routes, etc.
	}

	/**
	 * Login-page init hook — handles SSO callback and optional auto-redirect.
	 *
	 * Initialises Login_Handler (action routing + force-SSO) and Login_Button
	 * (SSO button rendering + inline styles) on the WordPress login page.
	 *
	 * @return void
	 */
	public function on_login_init(): void {
		\MicrosoftEntraSSO\Login\Login_Handler::init();
		\MicrosoftEntraSSO\Login\Login_Button::init();
	}

	/**
	 * Admin init hook — registers settings sections, fields, and sanitizers.
	 *
	 * Delegates to Settings_Page which owns all Settings API registration.
	 *
	 * @return void
	 */
	public function on_admin_init(): void {
		Admin\Settings_Page::register_settings();
	}

	/**
	 * Admin menu hook — registers the settings page under the Settings menu.
	 *
	 * @return void
	 */
	public function on_admin_menu(): void {
		Admin\Settings_Page::add_menu_page();
	}

	// -------------------------------------------------------------------------
	// Settings helpers
	// -------------------------------------------------------------------------

	/**
	 * Retrieve a plugin option with an optional fallback default.
	 *
	 * Wraps get_option() so callers throughout the codebase always use the
	 * correct option name prefix without hard-coding it.
	 *
	 * @param string $key           Option key — one of the OPTION_* class constants.
	 * @param mixed  $default_value Value to return when the option is not set.
	 * @return mixed Stored option value, or $default_value.
	 */
	public function get_option( string $key, $default_value = false ) {
		return get_option( $key, $default_value );
	}
}
