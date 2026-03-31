<?php
/**
 * JWT / ID-token validation for Microsoft Entra OIDC tokens.
 *
 * Provides RS256 signature verification against Microsoft's published JWKS
 * endpoint and validates all required OIDC claims. The implementation
 * intentionally rejects any algorithm other than RS256 to prevent the
 * "algorithm confusion" class of JWT attacks (e.g. alg=none, alg=HS256).
 *
 * @package MicrosoftEntraSSO\Auth
 */

namespace MicrosoftEntraSSO\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Validates Microsoft Entra OIDC ID tokens.
 *
 * Algorithm whitelist: RS256 only.
 * Clock skew tolerance: 60 seconds for exp / nbf checks.
 *
 * @package MicrosoftEntraSSO\Auth
 */
class Token_Validator {

	/**
	 * Allowed JWT algorithm.
	 *
	 * Only RS256 is accepted. Rejecting 'none', 'HS256', 'HS384', 'HS512'
	 * prevents known algorithm-confusion and algorithm-substitution attacks.
	 *
	 * @var string
	 */
	const ALLOWED_ALG = 'RS256';

	/**
	 * Permitted clock skew in seconds when evaluating exp / nbf claims.
	 *
	 * A 60-second tolerance accounts for minor clock drift between the
	 * issuer and the relying party without meaningfully extending token
	 * validity.
	 *
	 * @var int
	 */
	const CLOCK_SKEW = 60;

	/**
	 * Validate a signed OIDC ID token JWT and return its payload claims.
	 *
	 * Validation steps (following OpenID Connect Core §3.1.3.7):
	 *  1. Decode the JWT structure (header + payload + signature).
	 *  2. Enforce the RS256 algorithm whitelist.
	 *  3. Fetch the issuer's JWKS and verify the RSA signature.
	 *  4. Validate required claims: iss, aud, exp, nbf, iat, nonce.
	 *  5. Return the payload claims array on success.
	 *
	 * @param string $jwt      Compact serialised JWT (header.payload.sig).
	 * @param array  $expected {
	 *     @type string $client_id Application (client) ID used as audience.
	 *     @type string $issuer    Expected issuer (iss) value.
	 *     @type string $jwks_uri  URI of the issuer's JWKS document.
	 *     @type string $nonce     Nonce value that was sent in the auth request.
	 * }
	 *
	 * @return array|\WP_Error Payload claims on success, WP_Error on failure.
	 */
	public static function validate_id_token( string $jwt, array $expected ) {
		// ------------------------------------------------------------------
		// Step 1: Decode JWT structure.
		// ------------------------------------------------------------------
		$parts = self::decode_jwt( $jwt );

		if ( empty( $parts['header'] ) || empty( $parts['payload'] ) ) {
			return new \WP_Error(
				'jwt_malformed',
				esc_html__( 'The ID token is malformed and could not be decoded.', 'microsoft-entra-sso' )
			);
		}

		$header  = $parts['header'];
		$payload = $parts['payload'];

		// ------------------------------------------------------------------
		// Step 2: Algorithm whitelist — only RS256 is accepted.
		//
		// Security: accepting 'none' allows unsigned tokens; accepting HS256
		// may allow an attacker to forge tokens using the public key as the
		// HMAC secret. We reject everything that is not RS256.
		// ------------------------------------------------------------------
		if ( ! isset( $header['alg'] ) || self::ALLOWED_ALG !== $header['alg'] ) {
			return new \WP_Error(
				'jwt_algorithm_rejected',
				esc_html__( 'The ID token uses a disallowed signing algorithm. Only RS256 is accepted.', 'microsoft-entra-sso' )
			);
		}

		// ------------------------------------------------------------------
		// Step 3: Fetch JWKS and verify the RSA signature.
		// ------------------------------------------------------------------
		if ( empty( $expected['jwks_uri'] ) ) {
			return new \WP_Error(
				'jwks_uri_missing',
				esc_html__( 'The JWKS URI is required for signature verification.', 'microsoft-entra-sso' )
			);
		}

		$jwks = self::get_jwks( $expected['jwks_uri'] );

		if ( is_wp_error( $jwks ) ) {
			return $jwks;
		}

		// Security: signature verification must succeed before trusting any
		// payload claim. Do not read claims before this check passes.
		$sig_valid = self::verify_signature( $jwt, $jwks );

		if ( ! $sig_valid ) {
			return new \WP_Error(
				'jwt_signature_invalid',
				esc_html__( 'The ID token signature could not be verified.', 'microsoft-entra-sso' )
			);
		}

		// ------------------------------------------------------------------
		// Step 4: Validate required claims.
		// ------------------------------------------------------------------
		$now = time();

		// 4a. Issuer (iss) check.
		if ( empty( $expected['issuer'] ) || ! isset( $payload['iss'] ) || $payload['iss'] !== $expected['issuer'] ) {
			return new \WP_Error(
				'jwt_issuer_mismatch',
				esc_html__( 'The ID token issuer does not match the expected value.', 'microsoft-entra-sso' )
			);
		}

		// 4b. Audience (aud) check — must include our client_id.
		if ( empty( $expected['client_id'] ) || ! isset( $payload['aud'] ) ) {
			return new \WP_Error(
				'jwt_audience_missing',
				esc_html__( 'The ID token audience claim is missing.', 'microsoft-entra-sso' )
			);
		}

		$aud = is_array( $payload['aud'] ) ? $payload['aud'] : array( $payload['aud'] );

		if ( ! in_array( $expected['client_id'], $aud, true ) ) {
			return new \WP_Error(
				'jwt_audience_mismatch',
				esc_html__( 'The ID token audience does not include the expected client ID.', 'microsoft-entra-sso' )
			);
		}

		// 4c. Expiry (exp) with clock skew.
		// Security: a missing or expired exp claim means the token must be
		// rejected — using an expired token could enable session hijacking
		// if a token was previously stolen.
		if ( ! isset( $payload['exp'] ) || ( $now - self::CLOCK_SKEW ) > (int) $payload['exp'] ) {
			return new \WP_Error(
				'jwt_expired',
				esc_html__( 'The ID token has expired.', 'microsoft-entra-sso' )
			);
		}

		// 4d. Not-before (nbf) with clock skew — optional claim.
		if ( isset( $payload['nbf'] ) && $now < ( (int) $payload['nbf'] - self::CLOCK_SKEW ) ) {
			return new \WP_Error(
				'jwt_not_yet_valid',
				esc_html__( 'The ID token is not yet valid.', 'microsoft-entra-sso' )
			);
		}

		// 4e. Issued-at (iat) must be present.
		if ( ! isset( $payload['iat'] ) ) {
			return new \WP_Error(
				'jwt_iat_missing',
				esc_html__( 'The ID token is missing the issued-at (iat) claim.', 'microsoft-entra-sso' )
			);
		}

		// 4f. Nonce — must match the value stored before the auth redirect.
		// Security: nonce binding prevents token replay and mix-up attacks.
		if ( ! isset( $payload['nonce'] ) || $payload['nonce'] !== $expected['nonce'] ) {
			return new \WP_Error(
				'jwt_nonce_mismatch',
				esc_html__( 'The ID token nonce does not match the expected value.', 'microsoft-entra-sso' )
			);
		}

		/**
		 * Filters the validated ID token claims before they are returned to
		 * the caller.
		 *
		 * Use this hook to add custom claim checks or to normalise claim values
		 * for downstream consumers.
		 *
		 * @param array $payload Validated JWT payload claims.
		 */
		return apply_filters( 'microsoft_entra_sso_token_claims', $payload );
	}

	/**
	 * Decode the three components of a compact JWT serialisation.
	 *
	 * Splits on '.' and base64url-decodes the header and payload segments.
	 * The signature is returned as a raw (non-decoded) string for use with
	 * openssl_verify().
	 *
	 * @param string $jwt Compact serialised JWT.
	 *
	 * @return array {
	 *     @type array  $header    Decoded JWT JOSE header.
	 *     @type array  $payload   Decoded JWT claims set.
	 *     @type string $signature Raw signature bytes.
	 * }
	 */
	public static function decode_jwt( string $jwt ): array {
		$segments = explode( '.', $jwt );

		if ( 3 !== count( $segments ) ) {
			return array(
				'header'    => array(),
				'payload'   => array(),
				'signature' => '',
			);
		}

		list( $header_b64, $payload_b64, $sig_b64 ) = $segments;

		$header  = json_decode( self::base64url_decode( $header_b64 ), true );
		$payload = json_decode( self::base64url_decode( $payload_b64 ), true );

		return array(
			'header'    => is_array( $header ) ? $header : array(),
			'payload'   => is_array( $payload ) ? $payload : array(),
			'signature' => $sig_b64,
		);
	}

	/**
	 * Verify the RSA-SHA256 signature of a JWT against a JWKS document.
	 *
	 * Locates the signing key by matching the 'kid' (key ID) in the JWT
	 * header against the keys in the JWKS, converts the matching JWK to a
	 * PEM-encoded public key, and verifies the signature with OpenSSL.
	 *
	 * The signing input is the ASCII octets of:
	 *   BASE64URL(header) || '.' || BASE64URL(payload)
	 *
	 * as specified by RFC 7515 §7.2.
	 *
	 * @param string $jwt  Compact serialised JWT.
	 * @param array  $jwks Decoded JWKS document (associative array with 'keys').
	 *
	 * @return bool True when the signature is valid.
	 */
	public static function verify_signature( string $jwt, array $jwks ): bool {
		$segments = explode( '.', $jwt );

		if ( 3 !== count( $segments ) ) {
			return false;
		}

		list( $header_b64, $payload_b64, $sig_b64 ) = $segments;

		// The signed data is the first two dot-separated segments as-is.
		$signing_input = $header_b64 . '.' . $payload_b64;

		// Decode the signature from base64url to raw binary.
		$signature = self::base64url_decode( $sig_b64 );

		// Extract the kid from the JWT header to select the matching JWK.
		$header = json_decode( self::base64url_decode( $header_b64 ), true );
		$kid    = isset( $header['kid'] ) ? $header['kid'] : '';

		if ( ! isset( $jwks['keys'] ) || ! is_array( $jwks['keys'] ) ) {
			return false;
		}

		foreach ( $jwks['keys'] as $jwk ) {
			// Skip keys with non-matching kid when a kid is present in the header.
			if ( '' !== $kid && isset( $jwk['kid'] ) && $jwk['kid'] !== $kid ) {
				continue;
			}

			// Only RSA keys are usable with RS256.
			if ( ! isset( $jwk['kty'] ) || 'RSA' !== $jwk['kty'] ) {
				continue;
			}

			// Skip keys explicitly designated for encryption rather than signing.
			if ( isset( $jwk['use'] ) && 'sig' !== $jwk['use'] ) {
				continue;
			}

			$pem = self::jwk_to_pem( $jwk );

			if ( '' === $pem ) {
				continue;
			}

			$public_key = openssl_pkey_get_public( $pem );

			if ( false === $public_key ) {
				continue;
			}

			// openssl_verify() returns 1 (valid), 0 (invalid), or -1 (error).
			$result = openssl_verify( $signing_input, $signature, $public_key, OPENSSL_ALGO_SHA256 );

			// Free the key resource explicitly (pre-PHP 8.0 compatibility).
			if ( is_resource( $public_key ) ) {
				openssl_free_key( $public_key );
			}

			if ( 1 === $result ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Fetch and cache the JWKS document from the given URI.
	 *
	 * The JWKS document is cached as a WordPress transient for 24 hours to
	 * avoid repeated network requests on every authentication attempt. The
	 * transient key is derived from an MD5 hash of the URI so that multiple
	 * configured tenants each get their own cache entry.
	 *
	 * @param string $jwks_uri HTTPS URI of the JWKS document.
	 *
	 * @return array|\WP_Error Decoded JWKS document on success, WP_Error on failure.
	 */
	public static function get_jwks( string $jwks_uri ) {
		$transient_key = 'messo_jwks_' . md5( $jwks_uri );

		$cached = get_transient( $transient_key );

		if ( false !== $cached && is_array( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get(
			$jwks_uri,
			array(
				'timeout'    => 10,
				'user-agent' => 'Microsoft-Entra-SSO-Plugin/' . MESSO_VERSION,
			)
		);

		if ( is_wp_error( $response ) ) {
			return new \WP_Error(
				'jwks_fetch_failed',
				esc_html__( 'Failed to fetch the JWKS document from the issuer.', 'microsoft-entra-sso' )
			);
		}

		$code = wp_remote_retrieve_response_code( $response );

		if ( 200 !== (int) $code ) {
			return new \WP_Error(
				'jwks_fetch_failed',
				esc_html__( 'The JWKS endpoint returned an unexpected HTTP response.', 'microsoft-entra-sso' )
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$jwks = json_decode( $body, true );

		if ( ! is_array( $jwks ) || empty( $jwks['keys'] ) ) {
			return new \WP_Error(
				'jwks_invalid',
				esc_html__( 'The JWKS document is invalid or contains no keys.', 'microsoft-entra-sso' )
			);
		}

		// Cache for 24 hours. Microsoft rotates keys infrequently; if a new
		// key is needed before the TTL expires the cache can be cleared by
		// deleting the transient via WP-CLI or the admin.
		set_transient( $transient_key, $jwks, DAY_IN_SECONDS );

		return $jwks;
	}

	/**
	 * Convert an RSA JSON Web Key to a PEM-encoded public key.
	 *
	 * Builds the DER-encoded SubjectPublicKeyInfo (SPKI) structure as defined
	 * in RFC 3279 §2.3.1 and RFC 4055 §3.1 from the raw RSA key parameters:
	 *
	 *   SubjectPublicKeyInfo ::= SEQUENCE {
	 *     algorithm AlgorithmIdentifier,      -- OID 1.2.840.113549.1.1.1 + NULL
	 *     subjectPublicKey BIT STRING {
	 *       RSAPublicKey ::= SEQUENCE {
	 *         modulus           INTEGER,       -- n
	 *         publicExponent    INTEGER        -- e
	 *       }
	 *     }
	 *   }
	 *
	 * All ASN.1 elements are encoded using DER (Distinguished Encoding Rules).
	 *
	 * @param array $jwk RSA JWK with at least 'n' (modulus) and 'e' (exponent).
	 *
	 * @return string PEM-encoded public key, or empty string on failure.
	 */
	private static function jwk_to_pem( array $jwk ): string {
		if ( empty( $jwk['n'] ) || empty( $jwk['e'] ) ) {
			return '';
		}

		// Decode modulus (n) and exponent (e) from base64url to raw binary.
		$modulus  = self::base64url_decode( $jwk['n'] );
		$exponent = self::base64url_decode( $jwk['e'] );

		if ( '' === $modulus || '' === $exponent ) {
			return '';
		}

		// ------------------------------------------------------------------
		// Step 1: Encode modulus and exponent as ASN.1 DER INTEGERs.
		//
		// ASN.1 INTEGER: tag 0x02, length, value.
		// If the high bit of the first byte is set a 0x00 pad byte must be
		// prepended to signal that the integer is positive (DER requirement).
		// ------------------------------------------------------------------
		$modulus_der  = self::der_integer( $modulus );
		$exponent_der = self::der_integer( $exponent );

		// ------------------------------------------------------------------
		// Step 2: Wrap modulus + exponent in a SEQUENCE to form RSAPublicKey.
		// ------------------------------------------------------------------
		$rsa_public_key = self::der_sequence( $modulus_der . $exponent_der );

		// ------------------------------------------------------------------
		// Step 3: Encode as BIT STRING.
		//
		// BIT STRING: tag 0x03, length, 0x00 (unused bits count), DER data.
		// The leading 0x00 byte indicates zero unused bits in the last byte.
		// ------------------------------------------------------------------
		$bit_string_content = "\x00" . $rsa_public_key;
		$bit_string         = "\x03" . self::der_length( strlen( $bit_string_content ) ) . $bit_string_content;

		// ------------------------------------------------------------------
		// Step 4: Build the AlgorithmIdentifier SEQUENCE.
		//
		// AlgorithmIdentifier ::= SEQUENCE {
		//   algorithm  OBJECT IDENTIFIER,   -- 1.2.840.113549.1.1.1 (rsaEncryption)
		//   parameters ANY OPTIONAL         -- NULL for RSA
		// }
		//
		// OID 1.2.840.113549.1.1.1 in DER: 2a 86 48 86 f7 0d 01 01 01
		// ------------------------------------------------------------------
		$oid_der       = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"; // OID tag+len+value
		$null_der      = "\x05\x00";                                        // NULL
		$algorithm_id  = self::der_sequence( $oid_der . $null_der );

		// ------------------------------------------------------------------
		// Step 5: Wrap AlgorithmIdentifier + BIT STRING in SubjectPublicKeyInfo SEQUENCE.
		// ------------------------------------------------------------------
		$spki = self::der_sequence( $algorithm_id . $bit_string );

		// ------------------------------------------------------------------
		// Step 6: Base64-encode and wrap in PEM headers.
		// ------------------------------------------------------------------
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		$b64  = chunk_split( base64_encode( $spki ), 64, "\n" );

		return "-----BEGIN PUBLIC KEY-----\n" . $b64 . "-----END PUBLIC KEY-----\n";
	}

	/**
	 * Encode an arbitrary binary integer as an ASN.1 DER INTEGER.
	 *
	 * Prepends a 0x00 pad byte when the most-significant bit of the value is
	 * set (i.e., the first byte is >= 0x80) to ensure DER sign interpretation
	 * treats the value as positive.
	 *
	 * @param string $value Raw binary integer value (big-endian).
	 *
	 * @return string DER-encoded INTEGER TLV.
	 */
	private static function der_integer( string $value ): string {
		// Pad with 0x00 to prevent the integer being interpreted as negative.
		if ( ord( $value[0] ) >= 0x80 ) {
			$value = "\x00" . $value;
		}

		return "\x02" . self::der_length( strlen( $value ) ) . $value;
	}

	/**
	 * Wrap DER-encoded content in an ASN.1 SEQUENCE TLV envelope.
	 *
	 * @param string $content DER-encoded inner content.
	 *
	 * @return string DER-encoded SEQUENCE TLV.
	 */
	private static function der_sequence( string $content ): string {
		return "\x30" . self::der_length( strlen( $content ) ) . $content;
	}

	/**
	 * Encode a length value in DER definite-length form.
	 *
	 * Short form (0–127): single byte equal to the length.
	 * Long form (128+):   0x80 | (number of length bytes), then length bytes
	 *                     in big-endian order.
	 *
	 * @param int $length Non-negative length value.
	 *
	 * @return string Binary DER length encoding.
	 */
	private static function der_length( int $length ): string {
		if ( $length < 0x80 ) {
			// Short form.
			return chr( $length );
		}

		// Long form: determine how many bytes are needed to hold the length.
		$hex_length = dechex( $length );

		// Pad to even number of hex characters.
		if ( strlen( $hex_length ) % 2 !== 0 ) {
			$hex_length = '0' . $hex_length;
		}

		$bytes     = hex2bin( $hex_length );
		$num_bytes = strlen( $bytes );

		// 0x80 | num_bytes, followed by the length bytes.
		return chr( 0x80 | $num_bytes ) . $bytes;
	}

	/**
	 * Decode a base64url-encoded string to raw binary.
	 *
	 * base64url differs from standard base64 in two character substitutions:
	 *   '-' → '+'  and  '_' → '/'
	 * and the omission of '=' padding. We restore standard base64 format
	 * before decoding with the built-in base64_decode().
	 *
	 * @param string $data base64url-encoded input.
	 *
	 * @return string Decoded binary string (may be empty on failure).
	 */
	private static function base64url_decode( string $data ): string {
		// Translate base64url alphabet back to standard base64.
		$base64 = strtr( $data, '-_', '+/' );

		// Add padding if necessary so base64_decode() doesn't fail.
		$pad    = strlen( $base64 ) % 4;
		if ( $pad > 0 ) {
			$base64 .= str_repeat( '=', 4 - $pad );
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$decoded = base64_decode( $base64, true );

		return ( false === $decoded ) ? '' : $decoded;
	}
}
