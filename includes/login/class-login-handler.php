<?php
/**
 * Login flow handler — intercepts wp-login.php actions for SSO.
 *
 * Handles all SSO-related actions on the WordPress login page:
 *  - entra_login      : redirect the browser to the IdP authorization endpoint.
 *  - entra_callback   : process the OIDC authorization code response.
 *  - entra_logout     : single log-out redirect.
 *
 * Security notes throughout this file explain every decision that affects the
 * authentication security boundary.
 *
 * @package SFME\Login
 */

namespace SFME\Login;

defined( 'ABSPATH' ) || exit;

use SFME\Plugin;
use SFME\Auth\OIDC_Client;
use SFME\Security\Rate_Limiter;
use SFME\Security\State_Manager;
use SFME\User\User_Handler;
use SFME\User\User_Meta;

/**
 * Class Login_Handler
 *
 * All methods are static so this class acts as a namespace for hooks rather
 * than a stateful object. Hooks are registered via init().
 */
class Login_Handler {

	// -------------------------------------------------------------------------
	// Initialisation
	// -------------------------------------------------------------------------

	/**
	 * Register all login-page hooks.
	 *
	 * Called once from Plugin::on_login_init(). Two separate priorities are
	 * used so maybe_force_sso() runs before the standard form is rendered.
	 *
	 * @return void
	 */
	public static function init(): void {
		// Priority 1 — runs before WordPress outputs any HTML so we can
		// issue a redirect without "headers already sent" errors.
		add_action( 'login_init', array( __CLASS__, 'maybe_force_sso' ), 1 );

		// Default priority — dispatch SSO-specific actions.
		add_action( 'login_init', array( __CLASS__, 'dispatch' ) );
	}

	// -------------------------------------------------------------------------
	// Dispatcher
	// -------------------------------------------------------------------------

	/**
	 * Route the request to the appropriate handler based on the 'action' param.
	 *
	 * WordPress itself uses the 'action' query parameter on wp-login.php to
	 * distinguish login, logout, register, etc. We follow the same convention
	 * with Entra-specific action names to avoid collisions.
	 *
	 * @return void
	 */
	public static function dispatch(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_GET['action'] ) ? sanitize_key( $_GET['action'] ) : '';

		switch ( $action ) {
			case 'entra_login':
				self::handle_login();
				break;

			case 'entra_callback':
				self::handle_callback();
				break;

			case 'entra_logout':
				self::handle_logout();
				break;
		}
	}

	// -------------------------------------------------------------------------
	// Action: entra_login
	// -------------------------------------------------------------------------

	/**
	 * Redirect the user to the IdP authorization endpoint.
	 *
	 * Reads the configured auth protocol and delegates URL construction to
	 * the appropriate client class. Rate-limiting is applied here to prevent
	 * an attacker from hammering the endpoint to exhaust Entra quota.
	 *
	 * @return void
	 */
	public static function handle_login(): void {
		$plugin = Plugin::get_instance();

		// Bail if SSO is not configured.
		if ( ! self::is_sso_configured() ) {
			wp_die(
				esc_html__( 'SSO is not configured. Please contact your administrator.', 'sso-for-microsoft-entra' ),
				esc_html__( 'SSO Not Configured', 'sso-for-microsoft-entra' ),
				array( 'response' => 503 )
			);
		}

		// Security: rate-limit by IP to reduce IdP redirect abuse.
		$ip = self::get_client_ip();
		if ( ! Rate_Limiter::check( $ip ) ) {
			wp_die(
				esc_html__( 'Too many login attempts. Please try again later.', 'sso-for-microsoft-entra' ),
				esc_html__( 'Rate Limited', 'sso-for-microsoft-entra' ),
				array( 'response' => 429 )
			);
		}
		Rate_Limiter::record( $ip );

		$auth_url = OIDC_Client::get_authorization_url();

		if ( is_wp_error( $auth_url ) ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug logging
				error_log( 'SFME build URL error: ' . $auth_url->get_error_code() . ' — ' . $auth_url->get_error_message() );
			}
			self::redirect_with_error( 'sso_build_url_failed' );
			return;
		}

		// Security: wp_redirect() calls wp_sanitize_redirect() internally and
		// wp_safe_redirect() would block the external Entra domain. We use
		// wp_redirect() intentionally here because the destination is an
		// external HTTPS URL constructed entirely by our own code.
		wp_redirect( $auth_url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	// -------------------------------------------------------------------------
	// Action: entra_callback (OIDC)
	// -------------------------------------------------------------------------

	/**
	 * Process the OIDC authorization code callback from Entra.
	 *
	 * Flow:
	 *  1. Verify required parameters are present.
	 *  2. Check for error response from IdP.
	 *  3. Delegate to OIDC_Client::handle_callback() to exchange code for tokens.
	 *  4. Find or create the WordPress user via User_Handler.
	 *  5. Log the user in and redirect.
	 *
	 * @return void
	 */
	public static function handle_callback(): void {
		// Security: verify this is a GET request; OIDC redirects are always GET.
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'GET' !== $_SERVER['REQUEST_METHOD'] ) {
			self::redirect_with_error( 'invalid_request_method' );
			return;
		}

		// Surface IdP errors immediately with a safe error code.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['error'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$idp_error = sanitize_key( $_GET['error'] );
			self::redirect_with_error( 'idp_error_' . $idp_error );
			return;
		}

		// Security: code and state must both be present; absence indicates a
		// tampered or incomplete redirect.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['code'] ) || empty( $_GET['state'] ) ) {
			self::redirect_with_error( 'missing_callback_params' );
			return;
		}

		// Rate-limit by IP to prevent code-hammering.
		// Note: OIDC_Client::handle_callback() also applies its own rate limit
		// internally, but we check here first to fail fast before building params.
		$ip = self::get_client_ip();
		if ( ! Rate_Limiter::check( $ip ) ) {
			self::redirect_with_error( 'rate_limited' );
			return;
		}
		Rate_Limiter::record( $ip );

		// Delegate token exchange and claims extraction to OIDC_Client.
		// Pass the entire $_GET array so it can access code, state, and any
		// additional parameters (e.g. session_state) without coupling.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$claims = OIDC_Client::handle_callback( $_GET );

		if ( is_wp_error( $claims ) ) {
			// Log the internal error without exposing details to the browser.
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug logging when WP_DEBUG is enabled
				error_log( 'SFME OIDC callback error: ' . $claims->get_error_message() );
			}
			self::redirect_with_error( 'oidc_callback_failed' );
			return;
		}

		self::authenticate_user( $claims, 'oidc' );
	}

	// -------------------------------------------------------------------------
	// Action: entra_logout
	// -------------------------------------------------------------------------

	/**
	 * Handle log-out from both WordPress and Entra.
	 *
	 * Signs the user out of WordPress first, then redirects to the Entra
	 * logout endpoint to clear the Entra session. Without this, a user who
	 * clicks "Logout" in WordPress would still have an active Entra session
	 * and could silently re-authenticate.
	 *
	 * @return void
	 */
	public static function handle_logout(): void {
		// Security: require a valid WP nonce to prevent CSRF-triggered logouts
		// from malicious pages embedding a hidden image or iframe.
		$nonce = isset( $_REQUEST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) ) : '';

		if ( ! wp_verify_nonce( $nonce, 'log-out' ) ) {
			// Fall through to standard WordPress logout page.
			return;
		}

		// Sign the user out of WordPress.
		wp_logout();

		$plugin = Plugin::get_instance();
		$tenant = (string) $plugin->get_option( Plugin::OPTION_TENANT_ID, '' );

		// Only redirect to Entra logout when tenant is configured.
		if ( '' !== $tenant ) {
			$logout_url = 'https://login.microsoftonline.com/' . rawurlencode( $tenant ) . '/oauth2/v2.0/logout';

			$post_logout_redirect = add_query_arg(
				'loggedout',
				'true',
				home_url()
			);

			$logout_url = add_query_arg(
				'post_logout_redirect_uri',
				rawurlencode( $post_logout_redirect ),
				$logout_url
			);

			wp_redirect( $logout_url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
			exit;
		}

		// No Entra logout configured — redirect to home page.
		wp_safe_redirect( add_query_arg( 'loggedout', 'true', home_url() ) );
		exit;
	}

	// -------------------------------------------------------------------------
	// Force SSO
	// -------------------------------------------------------------------------

	/**
	 * Automatically redirect unauthenticated visitors to the SSO login flow.
	 *
	 * Runs at priority 1 on login_init so it fires before any HTML output.
	 * The redirect is skipped when:
	 *  - The user is already authenticated.
	 *  - The current action is an SSO callback (would cause an infinite loop).
	 *  - allow_local_login is enabled AND the ?local=1 query parameter is set.
	 *
	 * @return void
	 */
	public static function maybe_force_sso(): void {
		$plugin = Plugin::get_instance();

		// Feature must be explicitly enabled.
		if ( ! (bool) $plugin->get_option( Plugin::OPTION_AUTO_REDIRECT, false ) ) {
			return;
		}

		// Already logged in — nothing to do.
		if ( is_user_logged_in() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_GET['action'] ) ? sanitize_key( $_GET['action'] ) : '';

		// Security: never redirect mid-callback — that would create an infinite
		// loop and discard the authorization code.
		$sso_actions = array( 'entra_login', 'entra_callback', 'entra_logout' );
		if ( in_array( $action, $sso_actions, true ) ) {
			return;
		}

		// Allow a local-login bypass so admins can recover access if SSO breaks.
		// The bypass requires the ?local=1 query parameter.
		$allow_local = (bool) $plugin->get_option( 'sfme_allow_local_login', false );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $allow_local && isset( $_GET['local'] ) && '1' === $_GET['local'] ) {
			return;
		}

		// Build the SSO initiation URL.
		$sso_url = home_url( '/sso/login' );

		wp_redirect( $sso_url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	// -------------------------------------------------------------------------
	// Internal helpers
	// -------------------------------------------------------------------------

	/**
	 * Find or create a WordPress user from IdP claims, then log them in.
	 *
	 * @param array  $claims   Normalised user claims (sub, email, given_name, …).
	 * @param string $protocol Authentication protocol used — stored as user meta.
	 *
	 * @return void
	 */
	private static function authenticate_user( array $claims, string $protocol ): void {
		// Delegate user provisioning / lookup to User_Handler.
		// find_or_create() accepts only the claims array; protocol is stored separately below.
		$user_id = User_Handler::find_or_create( $claims );

		if ( is_wp_error( $user_id ) ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug logging when WP_DEBUG is enabled
				error_log( 'SFME user provisioning error: ' . $user_id->get_error_message() );
			}
			self::redirect_with_error( 'user_provision_failed' );
			return;
		}

		if ( ! $user_id || ! get_userdata( $user_id ) ) {
			self::redirect_with_error( 'user_not_found' );
			return;
		}

		// Security: reset the rate-limit counter on successful authentication
		// so legitimate users are not penalised for previous failed attempts.
		Rate_Limiter::reset( self::get_client_ip() );

		// Record which authentication protocol was used for this login.
		User_Meta::update( $user_id, User_Meta::LOGIN_METHOD, $protocol );

		// Establish the WordPress session.
		wp_set_current_user( $user_id );
		wp_set_auth_cookie( $user_id, false );

		/**
		 * Fires after a user has been authenticated via Entra SSO.
		 *
		 * @param int    $user_id  WordPress user ID.
		 * @param array  $claims   Normalised IdP claims.
		 * @param string $protocol Authentication protocol used ('oidc').
		 */
		do_action( 'sfme_user_authenticated', $user_id, $claims, $protocol );

		// Determine redirect destination.
		$redirect_to = self::get_redirect_url();

		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Redirect to wp-login.php with an 'sso_error' query parameter.
	 *
	 * Passing only an opaque error code (never internal error details) prevents
	 * information leakage that could assist an attacker.
	 *
	 * @param string $code Machine-readable error code (no spaces).
	 *
	 * @return void
	 */
	private static function redirect_with_error( string $code ): void {
		$url = add_query_arg( 'sso_error', rawurlencode( $code ), home_url() );
		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Determine the post-login redirect URL.
	 *
	 * Respects the standard WordPress 'redirect_to' parameter but validates
	 * it to prevent open-redirect attacks. Falls back to the admin dashboard.
	 *
	 * @return string Validated, safe redirect URL.
	 */
	private static function get_redirect_url(): string {
		// Security (M-2): use $_GET only — $_REQUEST merges cookies which could
		// be abused for session fixation in edge cases.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Standard WordPress redirect_to parameter; validated by wp_validate_redirect() below.
		$redirect_to = isset( $_GET['redirect_to'] )
			? sanitize_url( wp_unslash( $_GET['redirect_to'] ) )
			: '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( '' !== $redirect_to ) {
			// Security: wp_validate_redirect() only permits same-host URLs.
			// Pass admin_url() as the fallback so attackers cannot redirect
			// to external domains by manipulating the redirect_to parameter.
			return wp_validate_redirect( $redirect_to, admin_url() );
		}

		return admin_url();
	}

	/**
	 * Obtain the client IP address for rate-limiting purposes.
	 *
	 * Uses REMOTE_ADDR as the authoritative value. Proxy headers (X-Forwarded-For
	 * etc.) are intentionally ignored because they are trivially spoofed and
	 * would let an attacker bypass IP-based rate limits.
	 *
	 * @return string IP address string, or an empty string when unavailable.
	 */
	private static function get_client_ip(): string {
		return isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';
	}

	/**
	 * Check whether the minimum SSO configuration is present.
	 *
	 * OIDC requires a tenant ID. Protocol-specific requirements
	 * (client_id/secret) are validated by OIDC_Client.
	 *
	 * @return bool
	 */
	private static function is_sso_configured(): bool {
		$plugin    = Plugin::get_instance();
		$tenant_id = (string) $plugin->get_option( Plugin::OPTION_TENANT_ID, '' );

		return '' !== $tenant_id;
	}
}
