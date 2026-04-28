<?php
/**
 * Main plugin class — bootstraps all subsystems.
 *
 * @package SFME
 */

namespace SFME;

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
	const OPTION_TENANT_ID = 'sfme_tenant_id';

	/**
	 * Application (client) ID of the Entra app registration.
	 */
	const OPTION_CLIENT_ID = 'sfme_client_id';

	/**
	 * Encrypted client secret for the Entra application.
	 */
	const OPTION_CLIENT_SECRET = 'sfme_client_secret';

	/**
	 * Whether to redirect users directly to Entra login (bypass WP login form).
	 */
	const OPTION_AUTO_REDIRECT = 'sfme_auto_redirect';

	/**
	 * Whether automatic user provisioning is enabled.
	 */
	const OPTION_USER_PROVISIONING = 'sfme_user_provisioning';

	/**
	 * Maximum number of failed SSO login attempts before temporary lockout.
	 */
	const OPTION_RATE_LIMIT_MAX = 'sfme_rate_limit_max';

	/**
	 * Duration of a rate-limit lockout window in seconds.
	 */
	const OPTION_RATE_LIMIT_WINDOW = 'sfme_rate_limit_window';

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
		// Front-end + REST API authentication hooks.
		add_action( 'init', array( $this, 'on_init' ) );

		// Login-page hooks — only renders the SSO button on wp-login.php.
		// SSO action dispatch is handled via /sso/* rewrite endpoints (on_init).
		add_action( 'login_init', array( $this, 'on_login_init' ) );

		// Admin-only hooks — lazy-loaded to avoid unnecessary overhead.
		if ( is_admin() ) {
			add_action( 'admin_init', array( $this, 'on_admin_init' ) );
			add_action( 'admin_menu', array( $this, 'on_admin_menu' ) );
			add_action( 'admin_enqueue_scripts', array( 'SFME\Admin\Settings_Page', 'enqueue_assets' ) );
			add_action( 'admin_notices', array( 'SFME\Admin\Admin_Notices', 'render_notices' ) );
			add_action( 'wp_ajax_sfme_dismiss_notice', array( 'SFME\Admin\Admin_Notices', 'handle_dismiss' ) );
			add_filter( 'plugin_action_links_' . plugin_basename( SFME_PLUGIN_FILE ), array( $this, 'add_settings_link' ) );
		}
	}

	// -------------------------------------------------------------------------
	// Hook callbacks (stubs — implemented by later phases)
	// -------------------------------------------------------------------------

	/**
	 * Early init hook — registers custom rewrite endpoints for SSO.
	 *
	 * Registers /sso/{action} rewrite rules so SSO callbacks bypass
	 * wp-login.php and wp-admin/ entirely. These front-end URLs are
	 * not blocked by security plugins that restrict login page access.
	 *
	 * @return void
	 */
	public function on_init(): void {
		// Register /sso/{slug} rewrite rule — matches login, callback, logout.
		add_rewrite_rule( '^sso/([a-z-]+)/?$', 'index.php?sfme_action=$matches[1]', 'top' );
		add_filter( 'query_vars', array( $this, 'register_query_vars' ) );
		add_action( 'template_redirect', array( $this, 'handle_sso_request' ) );
	}

	/**
	 * Register custom query var so WordPress does not strip it.
	 *
	 * @param string[] $vars Existing query vars.
	 * @return string[] Modified query vars.
	 */
	public function register_query_vars( array $vars ): array {
		$vars[] = 'sfme_action';
		return $vars;
	}

	/**
	 * Dispatch SSO requests arriving via the /sso/{slug} rewrite rule.
	 *
	 * Maps URL slugs to internal action names and delegates to
	 * Login_Handler::dispatch() which reads $_GET['action'].
	 *
	 * @return void
	 */
	public function handle_sso_request(): void {
		$action = get_query_var( 'sfme_action', '' );
		if ( '' === $action ) {
			return;
		}

		$action_map = array(
			'login'    => 'entra_login',
			'callback' => 'entra_callback',
			'logout'   => 'entra_logout',
		);

		if ( ! isset( $action_map[ $action ] ) ) {
			return;
		}

		// Set $_GET['action'] so Login_Handler::dispatch() works unchanged.
		$_GET['action'] = $action_map[ $action ];
		\SFME\Login\Login_Handler::dispatch();
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
		// Only render the SSO button on wp-login.php.
		// SSO action dispatch is now handled via /sso/* rewrite endpoints
		// registered in on_init() — do NOT register Login_Handler::init() here
		// to avoid double-dispatch and doubled attack surface (H-1).
		\SFME\Login\Login_Button::init();
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

	/**
	 * Add a "Settings" link to the plugin action links on the Plugins page.
	 *
	 * @param string[] $links Existing action links.
	 * @return string[] Modified action links.
	 */
	public function add_settings_link( array $links ): array {
		$settings_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'options-general.php?page=' . Admin\Settings_Page::PAGE_SLUG ) ),
			esc_html__( 'Settings', 'sso-for-microsoft-entra' )
		);
		array_unshift( $links, $settings_link );
		return $links;
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
