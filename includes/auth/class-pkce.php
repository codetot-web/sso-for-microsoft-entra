<?php
/**
 * PKCE (Proof Key for Code Exchange) helper per RFC 7636.
 *
 * Generates the code_verifier / code_challenge pair required for the
 * Authorization Code flow with PKCE. Using PKCE prevents authorization code
 * interception attacks because an attacker who steals the authorization code
 * cannot exchange it without also possessing the verifier.
 *
 * @package MicrosoftEntraSSO\Auth
 */

namespace MicrosoftEntraSSO\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Generates RFC 7636-compliant PKCE verifier / challenge pairs.
 */
class PKCE {

	/**
	 * Generate a cryptographically random PKCE code verifier.
	 *
	 * RFC 7636 §4.1 requires the verifier to be 43–128 characters drawn from
	 * the unreserved character set [A-Z a-z 0-9 - . _ ~]. Using random_bytes
	 * encoded as lowercase hex satisfies this constraint: hex output contains
	 * only [0-9 a-f], all of which are unreserved characters.
	 *
	 * 64 random bytes → 128 hex characters (exactly the RFC 7636 maximum,
	 * maximising entropy while remaining within the allowed length).
	 *
	 * @return string 128-character hex-encoded code verifier.
	 */
	public static function generate_verifier(): string {
		// Security: random_bytes() uses a CSPRNG; never substitute with rand()
		// or mt_rand() here — the verifier must be unpredictable.
		return bin2hex( random_bytes( 64 ) );
	}

	/**
	 * Derive the PKCE code challenge from a verifier.
	 *
	 * Implements the S256 method mandated by RFC 7636 §4.2:
	 *   code_challenge = BASE64URL( SHA-256( ASCII( code_verifier ) ) )
	 *
	 * BASE64URL encoding differs from standard base64 in three ways:
	 *   1. '+' is replaced with '-'
	 *   2. '/' is replaced with '_'
	 *   3. Padding '=' characters are removed
	 *
	 * This produces a URL-safe string that can be included in the
	 * authorization request query string without percent-encoding.
	 *
	 * @param string $verifier The code verifier returned by generate_verifier().
	 *
	 * @return string BASE64URL-encoded SHA-256 hash of the verifier.
	 */
	public static function generate_challenge( string $verifier ): string {
		// Raw binary digest of the verifier string.
		$digest = hash( 'sha256', $verifier, true );

		// BASE64URL encoding: swap +/ → -_ and strip trailing padding.
		return rtrim( strtr( base64_encode( $digest ), '+/', '-_' ), '=' );
	}
}
