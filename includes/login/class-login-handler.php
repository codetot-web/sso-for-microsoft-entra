<?php
/**
 * Login flow handler — intercepts wp-login.php actions for SSO.
 *
 * Handles all SSO-related actions on the WordPress login page:
 *  - entra_login      : redirect the browser to the IdP authorization endpoint.
 *  - entra_callback   : process the OIDC authorization code response.
 *  - entra_saml_acs   : process the SAML assertion POSTed by Entra.
 *  - entra_logout     : single log-out (SLO) redirect.
 *
 * Security notes throughout this file explain every decision that affects the
 * authentication security boundary.
 *
 * @package MicrosoftEntraSSO\Login
 */

namespace MicrosoftEntraSSO\Login;

defined( 'ABSPATH' ) || exit;

use MicrosoftEntraSSO\Plugin;
use MicrosoftEntraSSO\Auth\OIDC_Client;
use MicrosoftEntraSSO\Auth\SAML_Client;
use MicrosoftEntraSSO\Security\Rate_Limiter;
use MicrosoftEntraSSO\Security\State_Manager;
use MicrosoftEntraSSO\User\User_Handler;
use MicrosoftEntraSSO\User\User_Meta;

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

			case 'entra_saml_acs':
				self::handle_saml_acs();
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
				esc_html__( 'SSO is not configured. Please contact your administrator.', 'microsoft-entra-sso' ),
				esc_html__( 'SSO Not Configured', 'microsoft-entra-sso' ),
				array( 'response' => 503 )
			);
		}

		// Security: rate-limit by IP to reduce IdP redirect abuse.
		$ip = self::get_client_ip();
		if ( ! Rate_Limiter::check( $ip ) ) {
			wp_die(
				esc_html__( 'Too many login attempts. Please try again later.', 'microsoft-entra-sso' ),
				esc_html__( 'Rate Limited', 'microsoft-entra-sso' ),
				array( 'response' => 429 )
			);
		}
		Rate_Limiter::record( $ip );

		$protocol = (string) $plugin->get_option( Plugin::OPTION_AUTH_PROTOCOL, 'oidc' );

		if ( 'saml' === $protocol ) {
			$auth_url = SAML_Client::get_authorization_url();
		} else {
			$auth_url = OIDC_Client::get_authorization_url();
		}

		if ( is_wp_error( $auth_url ) ) {
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
		if ( 'GET' !== $_SERVER['REQUEST_METHOD'] ) {
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
			error_log( 'MicrosoftEntraSSO OIDC callback error: ' . $claims->get_error_message() );
			self::redirect_with_error( 'oidc_callback_failed' );
			return;
		}

		self::authenticate_user( $claims, 'oidc' );
	}

	// -------------------------------------------------------------------------
	// Action: entra_saml_acs (SAML Assertion Consumer Service)
	// -------------------------------------------------------------------------

	/**
	 * Process the SAML response POSTed by Entra to the ACS endpoint.
	 *
	 * SAML responses arrive via HTTP POST. The SAMLResponse parameter contains
	 * a base64-encoded, optionally deflated XML assertion.
	 *
	 * @return void
	 */
	public static function handle_saml_acs(): void {
		// Security: SAML responses MUST be delivered via POST per the SAML
		// HTTP POST binding spec. Reject any other method.
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
			self::redirect_with_error( 'saml_invalid_method' );
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['SAMLResponse'] ) ) {
			self::redirect_with_error( 'saml_missing_response' );
			return;
		}

		// Security (CSRF): validate the RelayState token that was issued during
		// the outbound SAML request. Without this check an attacker could submit
		// a captured SAMLResponse outside of an active login flow (IdP-initiated
		// replay). The state is consumed on first use — replay is blocked.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$relay_state = isset( $_POST['RelayState'] )
			? sanitize_text_field( wp_unslash( $_POST['RelayState'] ) )
			: '';

		if ( '' === $relay_state || ! State_Manager::validate_state( $relay_state ) ) {
			self::redirect_with_error( 'saml_invalid_relay_state' );
			return;
		}

		// Security (M3): strip all characters that are not valid base64 alphabet.
		// sanitize_text_field() would collapse newlines to spaces and strip angle
		// brackets, which corrupts line-wrapped base64 payloads. A character-class
		// filter is safe because base64_decode() only uses [A-Za-z0-9+/=\r\n].
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$saml_response = preg_replace( '/[^A-Za-z0-9+\/=\r\n]/', '', wp_unslash( $_POST['SAMLResponse'] ) );

		// Rate-limit SAML ACS endpoint the same as OIDC callback.
		$ip = self::get_client_ip();
		if ( ! Rate_Limiter::check( $ip ) ) {
			self::redirect_with_error( 'rate_limited' );
			return;
		}
		Rate_Limiter::record( $ip );

		$claims = SAML_Client::handle_response( $saml_response );

		if ( is_wp_error( $claims ) ) {
			error_log( 'MicrosoftEntraSSO SAML ACS error: ' . $claims->get_error_message() );
			self::redirect_with_error( 'saml_response_failed' );
			return;
		}

		self::authenticate_user( $claims, 'saml' );
	}

	// -------------------------------------------------------------------------
	// Action: entra_logout (SLO)
	// -------------------------------------------------------------------------

	/**
	 * Handle single log-out from both WordPress and Entra.
	 *
	 * If SSO logout is enabled, the user is signed out of WordPress first,
	 * then redirected to the Entra logout endpoint which will clear the Entra
	 * session. Without this, a user who clicks "Logout" in WordPress would
	 * still have an active Entra session and could silently re-authenticate.
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

		$plugin  = Plugin::get_instance();
		$tenant  = (string) $plugin->get_option( Plugin::OPTION_TENANT_ID, '' );

		// Only redirect to Entra logout when tenant is configured.
		if ( '' !== $tenant ) {
			$logout_url = 'https://login.microsoftonline.com/' . rawurlencode( $tenant ) . '/oauth2/v2.0/logout';

			$post_logout_redirect = add_query_arg(
				'loggedout',
				'true',
				wp_login_url()
			);

			$logout_url = add_query_arg(
				'post_logout_redirect_uri',
				rawurlencode( $post_logout_redirect ),
				$logout_url
			);

			wp_redirect( $logout_url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
			exit;
		}

		// No Entra logout configured — redirect to WordPress login page.
		wp_safe_redirect( add_query_arg( 'loggedout', 'true', wp_login_url() ) );
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
		$sso_actions = array( 'entra_login', 'entra_callback', 'entra_saml_acs', 'entra_logout' );
		if ( in_array( $action, $sso_actions, true ) ) {
			return;
		}

		// Allow a local-login bypass so admins can recover access if SSO breaks.
		// The bypass requires the ?local=1 query parameter.
		$allow_local = (bool) $plugin->get_option( 'microsoft_entra_sso_allow_local_login', false );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $allow_local && isset( $_GET['local'] ) && '1' === $_GET['local'] ) {
			return;
		}

		// Build the SSO initiation URL.
		$sso_url = add_query_arg( 'action', 'entra_login', wp_login_url() );

		wp_redirect( $sso_url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	// -------------------------------------------------------------------------
	// Internal helpers
	// -------------------------------------------------------------------------

	/**
	 * Find or create a WordPress user from IdP claims, then log them in.
	 *
	 * This shared path is used by both the OIDC callback and the SAML ACS
	 * handler. Both produce the same normalised claims array so User_Handler
	 * needs no knowledge of the underlying protocol.
	 *
	 * @param array  $claims   Normalised user claims (sub, email, given_name, …).
	 * @param string $protocol 'oidc' or 'saml' — stored as user meta.
	 *
	 * @return void
	 */
	private static function authenticate_user( array $claims, string $protocol ): void {
		// Delegate user provisioning / lookup to User_Handler.
		// find_or_create() accepts only the claims array; protocol is stored separately below.
		$user_id = User_Handler::find_or_create( $claims );

		if ( is_wp_error( $user_id ) ) {
			error_log( 'MicrosoftEntraSSO user provisioning error: ' . $user_id->get_error_message() );
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
		 * @param string $protocol Authentication protocol used ('oidc' or 'saml').
		 */
		do_action( 'microsoft_entra_sso_user_authenticated', $user_id, $claims, $protocol );

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
		$url = add_query_arg( 'sso_error', rawurlencode( $code ), wp_login_url() );
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
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$redirect_to = isset( $_REQUEST['redirect_to'] )
			? wp_unslash( $_REQUEST['redirect_to'] )
			: '';

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
	 * Both OIDC and SAML require a tenant ID. Protocol-specific requirements
	 * (client_id/secret vs. metadata) are validated by the respective client.
	 *
	 * @return bool
	 */
	private static function is_sso_configured(): bool {
		$plugin    = Plugin::get_instance();
		$tenant_id = (string) $plugin->get_option( Plugin::OPTION_TENANT_ID, '' );

		return '' !== $tenant_id;
	}
}
