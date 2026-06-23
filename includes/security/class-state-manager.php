<?php
/**
 * OAuth 2.0 / OIDC state, nonce, and PKCE verifier management.
 *
 * All tokens are stored as short-lived WordPress transients with a 10-minute
 * TTL. Every token is single-use: validation deletes the transient so that
 * replay attacks and state-fixation attacks cannot succeed.
 *
 * @package SFME\Security
 */

namespace SFME\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Manages OAuth state tokens, OIDC nonces, and PKCE verifiers.
 *
 * Transient key prefixes:
 *   sfme_state_{state}        – OAuth state token
 *   sfme_nonce_{nonce}        – OIDC nonce
 *   sfme_pkce_{sha256(state)} – PKCE code verifier keyed by state hash
 */
class State_Manager {

	/**
	 * Transient prefix for OAuth state tokens.
	 *
	 * @var string
	 */
	const PREFIX_STATE = 'sfme_state_';

	/**
	 * Transient prefix for OIDC nonces.
	 *
	 * @var string
	 */
	const PREFIX_NONCE = 'sfme_nonce_';

	/**
	 * Transient prefix for PKCE code verifiers.
	 *
	 * @var string
	 */
	const PREFIX_PKCE = 'sfme_pkce_';

	/**
	 * Token time-to-live in seconds (10 minutes).
	 *
	 * @var int
	 */
	const TTL = 600;

	/**
	 * Cookie name used to bind the OAuth state to the initiating browser.
	 *
	 * @var string
	 */
	const SESSION_COOKIE = 'sfme_oauth_session';

	// -------------------------------------------------------------------------
	// State
	// -------------------------------------------------------------------------

	/**
	 * Generate a cryptographically random OAuth state token and store it.
	 *
	 * The generated value is stored as a transient so that `validate_state()`
	 * can verify it later. The hex encoding ensures the value is safe to
	 * include in query strings without additional encoding.
	 *
	 * Security (L2): random_bytes() is a CSPRNG on all supported platforms.
	 * wp_generate_password() uses str_shuffle() / mt_rand() on PHP < 8.0,
	 * which is not cryptographically secure and would make state tokens
	 * predictable, undermining CSRF protection.
	 *
	 * Security (L3): the state transient is bound to a short-lived browser
	 * cookie. A state value received in the callback is only accepted when
	 * it was issued to the same browser session, mitigating cross-site
	 * login attacks where an attacker forwards a valid state parameter.
	 *
	 * @return string A 32-character lowercase hex state token (128 bits of entropy).
	 */
	public static function create_state(): string {
		$state = bin2hex( random_bytes( 16 ) );

		$session_token = self::get_or_create_session_token();
		set_transient( self::PREFIX_STATE . $state, hash( 'sha256', $session_token ), self::TTL );

		return $state;
	}

	/**
	 * Validate and consume a state token.
	 *
	 * The transient is deleted immediately upon the first successful check
	 * (one-time use). Subsequent calls with the same value will return false,
	 * preventing replay attacks.
	 *
	 * @param string $state The state value received in the OAuth callback.
	 *
	 * @return bool True when the state is valid and has not been used before.
	 */
	public static function validate_state( string $state ): bool {
		if ( '' === $state ) {
			return false;
		}

		$session_token = self::get_session_token();
		if ( '' === $session_token ) {
			return false;
		}

		$key           = self::PREFIX_STATE . $state;
		$expected_hash = get_transient( $key );

		if ( false === $expected_hash || ! hash_equals( $expected_hash, hash( 'sha256', $session_token ) ) ) {
			// State not found, expired, already used, or bound to another session.
			return false;
		}

		// Consume the token immediately to prevent replay.
		delete_transient( $key );

		return true;
	}

	/**
	 * Return the session token from the browser cookie, or an empty string.
	 *
	 * @return string
	 */
	private static function get_session_token(): string {
		if ( isset( $_COOKIE[ self::SESSION_COOKIE ] ) && is_string( $_COOKIE[ self::SESSION_COOKIE ] ) ) {
			return sanitize_text_field( wp_unslash( $_COOKIE[ self::SESSION_COOKIE ] ) );
		}

		return '';
	}

	/**
	 * Get the existing session token from the browser cookie, or generate and
	 * set a new one.
	 *
	 * @return string Session token.
	 */
	private static function get_or_create_session_token(): string {
		$token = self::get_session_token();
		if ( '' !== $token ) {
			return $token;
		}

		$token = bin2hex( random_bytes( 16 ) );

		/**
		 * Filters the cookie parameters used for the OAuth session cookie.
		 *
		 * @param array $params Cookie parameters for setcookie().
		 */
		$params = apply_filters(
			'sfme_oauth_session_cookie_params',
			array(
				'expires'  => time() + self::TTL,
				'path'     => COOKIEPATH,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);

		setcookie(
			self::SESSION_COOKIE,
			$token,
			$params
		);

		// Make the cookie available immediately for the current request.
		$_COOKIE[ self::SESSION_COOKIE ] = $token;

		return $token;
	}

	// -------------------------------------------------------------------------
	// Nonce
	// -------------------------------------------------------------------------

	/**
	 * Generate a cryptographically random OIDC nonce and store it.
	 *
	 * Security (L2): same rationale as create_state() — random_bytes() is a
	 * CSPRNG; wp_generate_password() is not on PHP 7.4.
	 *
	 * @return string A 32-character lowercase hex nonce (128 bits of entropy).
	 */
	public static function create_nonce(): string {
		$nonce = bin2hex( random_bytes( 16 ) );

		set_transient( self::PREFIX_NONCE . $nonce, '1', self::TTL );

		return $nonce;
	}

	/**
	 * Validate and consume an OIDC nonce.
	 *
	 * One-time use: the transient is deleted on first successful validation.
	 *
	 * @param string $nonce The nonce value received in the OIDC ID token.
	 *
	 * @return bool True when the nonce is valid and has not been used before.
	 */
	public static function validate_nonce( string $nonce ): bool {
		if ( '' === $nonce ) {
			return false;
		}

		$key   = self::PREFIX_NONCE . $nonce;
		$value = get_transient( $key );

		if ( false === $value ) {
			return false;
		}

		// Consume the nonce to prevent reuse in token replay attacks.
		delete_transient( $key );

		return true;
	}

	// -------------------------------------------------------------------------
	// PKCE
	// -------------------------------------------------------------------------

	/**
	 * Store a PKCE code verifier associated with a given state token.
	 *
	 * The verifier is keyed by a SHA-256 hash of the state value so that the
	 * raw state is not stored as a transient key. The transient shares the
	 * same TTL as the state token so they expire together.
	 *
	 * @param string $state    The OAuth state token generated by `create_state()`.
	 * @param string $verifier The PKCE code verifier (43–128 characters per RFC 7636).
	 *
	 * @return void
	 */
	public static function store_pkce_verifier( string $state, string $verifier ): void {
		$key = self::pkce_key( $state );

		set_transient( $key, $verifier, self::TTL );
	}

	/**
	 * Retrieve and delete the PKCE code verifier for a given state token.
	 *
	 * One-time use: the transient is deleted on retrieval to prevent reuse.
	 *
	 * @param string $state The OAuth state token whose verifier is needed.
	 *
	 * @return string|false The code verifier string, or false if not found or
	 *                      already consumed.
	 */
	public static function get_pkce_verifier( string $state ) {
		if ( '' === $state ) {
			return false;
		}

		$key      = self::pkce_key( $state );
		$verifier = get_transient( $key );

		if ( false === $verifier ) {
			return false;
		}

		// Consume immediately – the verifier must only be used once.
		delete_transient( $key );

		return $verifier;
	}

	// -------------------------------------------------------------------------
	// Internal helpers
	// -------------------------------------------------------------------------

	/**
	 * Build the transient key for a PKCE verifier from a state value.
	 *
	 * Hashing avoids exposing the raw state value in the options table while
	 * still producing a deterministic, collision-resistant key.
	 *
	 * @param string $state The OAuth state token.
	 *
	 * @return string Transient key of the form `sfme_pkce_{hex_hash}`.
	 */
	private static function pkce_key( string $state ): string {
		return self::PREFIX_PKCE . hash( 'sha256', $state );
	}
}
