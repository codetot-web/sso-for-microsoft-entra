<?php
/**
 * Microsoft Entra OIDC client — Authorization Code flow with PKCE.
 *
 * Implements the full Authorization Code + PKCE flow against the Microsoft
 * Entra v2.0 endpoints. Discovery metadata is fetched once and cached for
 * 24 hours. All security tokens (state, nonce, PKCE verifier) are managed
 * via State_Manager as short-lived, single-use WordPress transients.
 *
 * @package SFME\Auth
 */

namespace SFME\Auth;

use SFME\Plugin;
use SFME\Security\Encryption;
use SFME\Security\Rate_Limiter;
use SFME\Security\State_Manager;

defined( 'ABSPATH' ) || exit;

/**
 * OIDC client for the Authorization Code + PKCE flow.
 *
 * All public methods are static so callers never need to manage an object
 * lifecycle. Network I/O uses WordPress HTTP API exclusively (wp_remote_get /
 * wp_remote_post) to respect proxy settings and reuse WordPress's TLS
 * handling.
 */
class OIDC_Client {

	// -------------------------------------------------------------------------
	// Authorization URL
	// -------------------------------------------------------------------------

	/**
	 * Build and return the Microsoft Entra authorisation endpoint URL.
	 *
	 * Creates a fresh state token, nonce, and PKCE verifier for this login
	 * attempt, stores them as transients via State_Manager, then constructs
	 * the full authorization URL that the browser should be redirected to.
	 *
	 * @return string|\WP_Error Fully-qualified authorization URL, or WP_Error
	 *                          when the discovery document cannot be fetched.
	 */
	public static function get_authorization_url() {
		// ------------------------------------------------------------------
		// Step 1: Fetch discovery config to get the authorization_endpoint.
		// ------------------------------------------------------------------
		$discovery = self::get_discovery_config();

		if ( is_wp_error( $discovery ) ) {
			return $discovery;
		}

		// ------------------------------------------------------------------
		// Step 2: Generate one-time-use security tokens.
		//
		// Security: state prevents CSRF; nonce prevents token replay;
		// PKCE prevents code interception. All three must be used together.
		// ------------------------------------------------------------------
		$state          = State_Manager::create_state();
		$nonce          = State_Manager::create_nonce();
		$pkce_verifier  = PKCE::generate_verifier();
		$pkce_challenge = PKCE::generate_challenge( $pkce_verifier );

		// ------------------------------------------------------------------
		// Step 3: Persist the PKCE verifier keyed by the state token so it
		// can be retrieved during the callback.
		// ------------------------------------------------------------------
		State_Manager::store_pkce_verifier( $state, $pkce_verifier );

		// ------------------------------------------------------------------
		// Step 4: Assemble the authorization URL.
		// ------------------------------------------------------------------
		$plugin    = Plugin::get_instance();
		$client_id = (string) $plugin->get_option( Plugin::OPTION_CLIENT_ID, '' );

		/**
		 * Filters the OIDC scopes requested during authorization.
		 *
		 * The minimum required scopes are 'openid', 'profile', and 'email'.
		 * Additional scopes (e.g. 'offline_access', 'User.Read') may be added
		 * by site administrators via this filter.
		 *
		 * @param string[] $scopes Array of scope strings.
		 */
		$scopes = apply_filters(
			'sfme_oidc_scopes',
			array( 'openid', 'profile', 'email' )
		);

		$params = array(
			'response_type'         => 'code',
			'client_id'             => $client_id,
			'redirect_uri'          => self::get_redirect_uri(),
			'scope'                 => implode( ' ', $scopes ),
			'state'                 => $state,
			'nonce'                 => $nonce,
			'code_challenge'        => $pkce_challenge,
			'code_challenge_method' => 'S256',
		);

		return $discovery['authorization_endpoint'] . '?' . http_build_query( $params, '', '&', PHP_QUERY_RFC3986 );
	}

	// -------------------------------------------------------------------------
	// Callback handling
	// -------------------------------------------------------------------------

	/**
	 * Process the OIDC authorization callback and return user identity claims.
	 *
	 * Validates the state to prevent CSRF, exchanges the authorization code for
	 * tokens, verifies the ID token signature and claims, and validates the
	 * nonce to prevent token replay. On success returns the identity claims.
	 * On any failure records the attempt against the rate limiter.
	 *
	 * @param array $params Associative array of query parameters from the
	 *                      callback request (typically $_GET).
	 *
	 * @return array|\WP_Error User identity claims on success, WP_Error on failure.
	 */
	public static function handle_callback( array $params ) {
		// Note: rate-limit check is handled by Login_Handler before calling
		// this method. Applying check() again here would double-count attempts
		// (H-6), locking users out after only 2 successful logins. We still
		// record() individual failures below for accurate per-error tracking.
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		// ------------------------------------------------------------------
		// Step 2: Validate the OAuth state parameter.
		//
		// Security: validating state here (before touching the code) is the
		// CSRF check. The transient is consumed on first use so replay is
		// impossible even if the attacker obtains a valid state value.
		// ------------------------------------------------------------------
		$state = isset( $params['state'] ) ? sanitize_text_field( $params['state'] ) : '';

		if ( '' === $state || ! State_Manager::validate_state( $state ) ) {
			Rate_Limiter::record( $ip );

			return new \WP_Error(
				'state_invalid',
				esc_html__( 'The OAuth state parameter is invalid or has expired. Please try signing in again.', 'sso-for-microsoft-entra' )
			);
		}

		// ------------------------------------------------------------------
		// Step 3: Retrieve (and consume) the PKCE verifier for this state.
		// ------------------------------------------------------------------
		$code_verifier = State_Manager::get_pkce_verifier( $state );

		if ( false === $code_verifier ) {
			Rate_Limiter::record( $ip );

			return new \WP_Error(
				'pkce_verifier_missing',
				esc_html__( 'The PKCE verifier could not be found. Please try signing in again.', 'sso-for-microsoft-entra' )
			);
		}

		// ------------------------------------------------------------------
		// Step 4: Exchange the authorization code for tokens.
		// ------------------------------------------------------------------
		$code = isset( $params['code'] ) ? sanitize_text_field( $params['code'] ) : '';

		if ( '' === $code ) {
			Rate_Limiter::record( $ip );

			// Surface any error the IdP sent back to the callback.
			$error             = isset( $params['error'] ) ? sanitize_key( $params['error'] ) : 'callback_error';
			$error_description = isset( $params['error_description'] )
				? sanitize_text_field( $params['error_description'] )
				: esc_html__( 'No authorization code was returned.', 'sso-for-microsoft-entra' );

			return new \WP_Error( $error, esc_html( $error_description ) );
		}

		$tokens = self::exchange_code( $code, $code_verifier );

		if ( is_wp_error( $tokens ) ) {
			Rate_Limiter::record( $ip );
			return $tokens;
		}

		// ------------------------------------------------------------------
		// Step 5: Validate the ID token.
		// ------------------------------------------------------------------
		if ( empty( $tokens['id_token'] ) ) {
			Rate_Limiter::record( $ip );

			return new \WP_Error(
				'id_token_missing',
				esc_html__( 'No ID token was returned by the token endpoint.', 'sso-for-microsoft-entra' )
			);
		}

		$discovery = self::get_discovery_config();

		if ( is_wp_error( $discovery ) ) {
			Rate_Limiter::record( $ip );
			return $discovery;
		}

		$plugin    = Plugin::get_instance();
		$client_id = (string) $plugin->get_option( Plugin::OPTION_CLIENT_ID, '' );
		$tenant_id = (string) $plugin->get_option( Plugin::OPTION_TENANT_ID, '' );

		// The nonce is embedded in the ID token but we need to retrieve it
		// from the token itself for validation — we validate it in step 6
		// by comparing it against the stored transient.
		$decoded = Token_Validator::decode_jwt( $tokens['id_token'] );

		$nonce_from_token = isset( $decoded['payload']['nonce'] )
			? $decoded['payload']['nonce']
			: '';

		// Validate the nonce transient before passing it as "expected" so
		// that the Token_Validator also checks consistency.
		// Security: validate_nonce() consumes the transient (one-time use).
		if ( '' === $nonce_from_token || ! State_Manager::validate_nonce( $nonce_from_token ) ) {
			Rate_Limiter::record( $ip );

			return new \WP_Error(
				'nonce_invalid',
				esc_html__( 'The ID token nonce is invalid or has already been used.', 'sso-for-microsoft-entra' )
			);
		}

		// Per-app signing keys: Entra apps configured with optional claims
		// or a custom token signing policy sign id_tokens with a key that
		// only appears in the JWKS document when the appid query parameter
		// is appended. Without it, the standard /discovery/v2.0/keys
		// response omits that key and signature validation fails with
		// jwt_signature_invalid even though the token is genuine.
		// See https://learn.microsoft.com/azure/active-directory/develop/access-tokens#validating-tokens.
		$jwks_uri_with_appid = $discovery['jwks_uri'];
		if ( '' !== $client_id ) {
			$jwks_uri_with_appid = add_query_arg( 'appid', $client_id, $jwks_uri_with_appid );
		}

		$expected = array(
			'client_id' => $client_id,
			'issuer'    => $discovery['issuer'],
			'jwks_uri'  => $jwks_uri_with_appid,
			'nonce'     => $nonce_from_token,
		);

		$claims = Token_Validator::validate_id_token( $tokens['id_token'], $expected );

		if ( is_wp_error( $claims ) ) {
			Rate_Limiter::record( $ip );
			return $claims;
		}

		// ------------------------------------------------------------------
		// Step 7: Authentication succeeded — reset rate limiter for this IP.
		// ------------------------------------------------------------------
		Rate_Limiter::reset( $ip );

		return $claims;
	}

	// -------------------------------------------------------------------------
	// Token endpoint
	// -------------------------------------------------------------------------

	/**
	 * Exchange an authorization code for tokens at the token endpoint.
	 *
	 * Sends the code along with the PKCE verifier (code_verifier) and the
	 * encrypted client secret to the token endpoint. The client secret is
	 * decrypted in-memory and never logged or persisted in plaintext.
	 *
	 * @param string $code          Authorization code received in the callback.
	 * @param string $code_verifier PKCE verifier generated before the redirect.
	 *
	 * @return array|\WP_Error Decoded token response on success, WP_Error on failure.
	 */
	public static function exchange_code( string $code, string $code_verifier ) {
		$discovery = self::get_discovery_config();

		if ( is_wp_error( $discovery ) ) {
			return $discovery;
		}

		$plugin = Plugin::get_instance();

		$client_id        = (string) $plugin->get_option( Plugin::OPTION_CLIENT_ID, '' );
		$encrypted_secret = (string) $plugin->get_option( Plugin::OPTION_CLIENT_SECRET, '' );

		// Security: decrypt the client secret immediately before use and do
		// not retain it in any variable that survives beyond this scope.
		$client_secret = Encryption::decrypt( $encrypted_secret );

		if ( '' === $client_id || '' === $client_secret ) {
			return new \WP_Error(
				'credentials_missing',
				esc_html__( 'The plugin client credentials are not configured.', 'sso-for-microsoft-entra' )
			);
		}

		$body = array(
			'grant_type'    => 'authorization_code',
			'code'          => $code,
			'redirect_uri'  => self::get_redirect_uri(),
			'client_id'     => $client_id,
			'client_secret' => $client_secret,
			'code_verifier' => $code_verifier,
		);

		$response = wp_remote_post(
			$discovery['token_endpoint'],
			array(
				'timeout'    => 15,
				'user-agent' => 'Microsoft-Entra-SSO-Plugin/' . SFME_VERSION,
				'headers'    => array(
					'Content-Type' => 'application/x-www-form-urlencoded',
					'Accept'       => 'application/json',
				),
				'body'       => $body,
			)
		);

		// Immediately overwrite the client_secret variable.
		// PHP does not guarantee memory wiping but this reduces the window.
		$client_secret = '';

		if ( is_wp_error( $response ) ) {
			return new \WP_Error(
				'token_request_failed',
				esc_html__( 'The token request to Microsoft Entra failed.', 'sso-for-microsoft-entra' )
			);
		}

		$code_http = wp_remote_retrieve_response_code( $response );

		if ( 200 !== (int) $code_http ) {
			// Parse the error from the token endpoint response body for logging,
			// but do not surface the raw message to the end user.
			$error_body = json_decode( wp_remote_retrieve_body( $response ), true );
			$error_code = isset( $error_body['error'] ) ? sanitize_key( $error_body['error'] ) : 'token_error';

			return new \WP_Error(
				$error_code,
				esc_html__( 'Microsoft Entra returned an error during token exchange.', 'sso-for-microsoft-entra' )
			);
		}

		$tokens = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $tokens ) ) {
			return new \WP_Error(
				'token_parse_failed',
				esc_html__( 'The token endpoint response could not be parsed.', 'sso-for-microsoft-entra' )
			);
		}

		return $tokens;
	}

	// -------------------------------------------------------------------------
	// Discovery
	// -------------------------------------------------------------------------

	/**
	 * Fetch and cache the OpenID Connect discovery document.
	 *
	 * Retrieves the well-known configuration from Microsoft Entra using the
	 * configured tenant ID. The response is cached as a transient for 24 hours.
	 *
	 * The transient key is derived from an MD5 hash of the tenant ID so that
	 * multi-tenant deployments with different tenant IDs each get an
	 * independent cache entry.
	 *
	 * Extracted fields:
	 *   - authorization_endpoint
	 *   - token_endpoint
	 *   - jwks_uri
	 *   - issuer
	 *
	 * @return array|\WP_Error Extracted discovery fields on success, WP_Error on failure.
	 */
	public static function get_discovery_config() {
		$plugin    = Plugin::get_instance();
		$tenant_id = (string) $plugin->get_option( Plugin::OPTION_TENANT_ID, '' );

		if ( '' === $tenant_id ) {
			return new \WP_Error(
				'tenant_id_missing',
				esc_html__( 'The Microsoft Entra tenant ID is not configured.', 'sso-for-microsoft-entra' )
			);
		}

		$transient_key = 'sfme_discovery_' . md5( $tenant_id );

		$cached = get_transient( $transient_key );

		if ( false !== $cached && is_array( $cached ) ) {
			return $cached;
		}

		$discovery_url = self::get_base_url() . '/.well-known/openid-configuration';

		$response = wp_remote_get(
			$discovery_url,
			array(
				'timeout'    => 10,
				'user-agent' => 'Microsoft-Entra-SSO-Plugin/' . SFME_VERSION,
			)
		);

		if ( is_wp_error( $response ) ) {
			return new \WP_Error(
				'discovery_fetch_failed',
				esc_html__( 'Failed to fetch the OpenID Connect discovery document.', 'sso-for-microsoft-entra' )
			);
		}

		$code = wp_remote_retrieve_response_code( $response );

		if ( 200 !== (int) $code ) {
			return new \WP_Error(
				'discovery_fetch_failed',
				esc_html__( 'The discovery endpoint returned an unexpected HTTP response.', 'sso-for-microsoft-entra' )
			);
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) ) {
			return new \WP_Error(
				'discovery_parse_failed',
				esc_html__( 'The discovery document could not be parsed.', 'sso-for-microsoft-entra' )
			);
		}

		// Validate that all required fields are present.
		$required = array( 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'issuer' );

		foreach ( $required as $field ) {
			if ( empty( $body[ $field ] ) ) {
				return new \WP_Error(
					'discovery_incomplete',
					sprintf(
						/* translators: %s: missing field name */
						esc_html__( 'The discovery document is missing the required field: %s.', 'sso-for-microsoft-entra' ),
						esc_html( $field )
					)
				);
			}
		}

		// Extract only the fields we need to limit cached surface area.
		// Security (M-6): enforce HTTPS-only to prevent MitM via cache poisoning.
		$https_only = array( 'https' );
		$config     = array(
			'authorization_endpoint' => esc_url_raw( $body['authorization_endpoint'], $https_only ),
			'token_endpoint'         => esc_url_raw( $body['token_endpoint'], $https_only ),
			'jwks_uri'               => esc_url_raw( $body['jwks_uri'], $https_only ),
			'issuer'                 => sanitize_text_field( $body['issuer'] ),
		);

		set_transient( $transient_key, $config, DAY_IN_SECONDS );

		return $config;
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Build the Microsoft Entra v2.0 base URL for the configured tenant.
	 *
	 * @return string Base URL, e.g. https://login.microsoftonline.com/{tenant_id}/v2.0
	 */
	private static function get_base_url(): string {
		$plugin    = Plugin::get_instance();
		$tenant_id = (string) $plugin->get_option( Plugin::OPTION_TENANT_ID, '' );

		return 'https://login.microsoftonline.com/' . rawurlencode( $tenant_id ) . '/v2.0';
	}

	/**
	 * Return the OIDC redirect URI (callback URL).
	 *
	 * Uses a custom /sso/callback front-end endpoint instead of wp-login.php
	 * so the callback works even when wp-login.php is blocked by security rules.
	 * This URI must be registered in the Entra application's Redirect URIs list.
	 *
	 * @return string Fully-qualified callback URL.
	 */
	public static function get_redirect_uri(): string {
		return home_url( '/sso/callback' );
	}
}
