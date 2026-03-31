<?php
/**
 * Unit tests for MicrosoftEntraSSO\Auth\PKCE.
 *
 * @package MicrosoftEntraSSO\Tests
 */

use MicrosoftEntraSSO\Auth\PKCE;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the PKCE class (RFC 7636).
 */
class Test_PKCE extends TestCase {

	// -------------------------------------------------------------------------
	// Code verifier
	// -------------------------------------------------------------------------

	/**
	 * The generated verifier must be exactly 128 characters long.
	 *
	 * RFC 7636 §4.1 allows 43–128 characters; this implementation always
	 * produces the maximum (64 random bytes → 128 hex chars).
	 */
	public function test_verifier_length_is_128(): void {
		$verifier = PKCE::generate_verifier();

		$this->assertSame( 128, strlen( $verifier ), 'Verifier must be exactly 128 characters.' );
	}

	/**
	 * The verifier must contain only characters from the hex alphabet [0-9a-f].
	 *
	 * These are all "unreserved" characters per RFC 7636 §4.1, so no
	 * percent-encoding is needed when including the verifier in a query string.
	 */
	public function test_verifier_contains_only_hex_characters(): void {
		$verifier = PKCE::generate_verifier();

		$this->assertMatchesRegularExpression(
			'/^[0-9a-f]+$/',
			$verifier,
			'Verifier must contain only lowercase hex characters (RFC 7636 unreserved set).'
		);
	}

	/**
	 * Two successive calls must produce different verifiers.
	 */
	public function test_verifier_is_random(): void {
		$v1 = PKCE::generate_verifier();
		$v2 = PKCE::generate_verifier();

		$this->assertNotSame( $v1, $v2, 'Each verifier must be unique (CSPRNG-based).' );
	}

	// -------------------------------------------------------------------------
	// Code challenge
	// -------------------------------------------------------------------------

	/**
	 * The generated challenge must be a valid base64url string:
	 * characters [A-Za-z0-9\-_] only, no padding '=' characters.
	 */
	public function test_challenge_is_valid_base64url(): void {
		$verifier  = PKCE::generate_verifier();
		$challenge = PKCE::generate_challenge( $verifier );

		$this->assertMatchesRegularExpression(
			'/^[A-Za-z0-9\-_]+$/',
			$challenge,
			'Challenge must use base64url alphabet (no +, /, or = characters).'
		);
	}

	/**
	 * The challenge must NOT contain standard base64 padding characters.
	 */
	public function test_challenge_has_no_padding(): void {
		$verifier  = PKCE::generate_verifier();
		$challenge = PKCE::generate_challenge( $verifier );

		$this->assertStringNotContainsString( '=', $challenge, 'Challenge must not contain base64 padding.' );
		$this->assertStringNotContainsString( '+', $challenge, 'Challenge must not contain "+" (use "-" instead).' );
		$this->assertStringNotContainsString( '/', $challenge, 'Challenge must not contain "/" (use "_" instead).' );
	}

	/**
	 * Test challenge derivation against a known test vector.
	 *
	 * Known vector from RFC 7636 Appendix B:
	 *   verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	 *   challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	 *
	 * This verifies the S256 algorithm is implemented correctly.
	 */
	public function test_challenge_matches_rfc7636_test_vector(): void {
		// RFC 7636 Appendix B test vector.
		$verifier          = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
		$expected_challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

		$actual_challenge = PKCE::generate_challenge( $verifier );

		$this->assertSame(
			$expected_challenge,
			$actual_challenge,
			'Challenge must match RFC 7636 Appendix B test vector.'
		);
	}

	/**
	 * A different verifier must produce a different challenge.
	 */
	public function test_different_verifiers_produce_different_challenges(): void {
		$challenge_1 = PKCE::generate_challenge( PKCE::generate_verifier() );
		$challenge_2 = PKCE::generate_challenge( PKCE::generate_verifier() );

		$this->assertNotSame( $challenge_1, $challenge_2, 'Different verifiers must yield different challenges.' );
	}

	/**
	 * The challenge length for a SHA-256 hash must be 43 characters
	 * (32 bytes → 44 base64 chars − 1 padding char = 43).
	 */
	public function test_challenge_length_is_43(): void {
		$verifier  = PKCE::generate_verifier();
		$challenge = PKCE::generate_challenge( $verifier );

		$this->assertSame( 43, strlen( $challenge ), 'S256 challenge must be 43 characters (base64url of 32-byte SHA-256 digest).' );
	}
}
