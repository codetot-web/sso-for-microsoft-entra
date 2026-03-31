<?php
/**
 * Unit tests for MicrosoftEntraSSO\Security\Encryption.
 *
 * @package MicrosoftEntraSSO\Tests
 */

use MicrosoftEntraSSO\Security\Encryption;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the Encryption class.
 */
class Test_Encryption extends TestCase {

	// -------------------------------------------------------------------------
	// Encrypt / decrypt round-trip
	// -------------------------------------------------------------------------

	/**
	 * Encrypt then decrypt should return the original plaintext.
	 */
	public function test_encrypt_decrypt_roundtrip(): void {
		$plaintext = 'super-secret-client-secret-value';

		$encrypted = Encryption::encrypt( $plaintext );

		$this->assertNotEmpty( $encrypted, 'encrypt() must return a non-empty string.' );
		$this->assertNotSame( $plaintext, $encrypted, 'encrypt() output must not equal plaintext.' );

		$decrypted = Encryption::decrypt( $encrypted );

		$this->assertSame( $plaintext, $decrypted, 'decrypt( encrypt( $x ) ) must equal $x.' );
	}

	/**
	 * Roundtrip should work for an empty string without erroring.
	 */
	public function test_empty_string_roundtrip(): void {
		$encrypted = Encryption::encrypt( '' );
		$this->assertSame( '', $encrypted, 'encrypt() of empty string must return empty string.' );

		$decrypted = Encryption::decrypt( '' );
		$this->assertSame( '', $decrypted, 'decrypt() of empty string must return empty string.' );
	}

	/**
	 * Roundtrip should preserve multi-byte UTF-8 strings.
	 */
	public function test_encrypt_decrypt_utf8_string(): void {
		$plaintext = 'Ünïcödé sëcrét vàlüé — 日本語テスト';

		$decrypted = Encryption::decrypt( Encryption::encrypt( $plaintext ) );

		$this->assertSame( $plaintext, $decrypted, 'Multi-byte strings must survive a round-trip.' );
	}

	// -------------------------------------------------------------------------
	// Corrupted / tampered ciphertext
	// -------------------------------------------------------------------------

	/**
	 * Decrypting a corrupted blob must return an empty string (not throw).
	 */
	public function test_decrypt_corrupted_blob_returns_empty(): void {
		$corrupted = base64_encode( 'this-is-not-valid-ciphertext' );

		$result = Encryption::decrypt( $corrupted );

		$this->assertSame( '', $result, 'decrypt() of corrupted data must return empty string.' );
	}

	/**
	 * Flipping a byte in the ciphertext must cause authentication to fail.
	 */
	public function test_decrypt_tampered_ciphertext_returns_empty(): void {
		$encrypted = Encryption::encrypt( 'important-value' );

		// Decode, flip a byte in the middle of the blob, re-encode.
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$raw     = base64_decode( $encrypted, true );
		$mid     = (int) ( strlen( $raw ) / 2 );
		$raw[ $mid ] = chr( ord( $raw[ $mid ] ) ^ 0xFF );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		$tampered = base64_encode( $raw );

		$result = Encryption::decrypt( $tampered );

		$this->assertSame( '', $result, 'Tampered ciphertext must not decrypt successfully.' );
	}

	/**
	 * Decrypting a short (malformed) blob must return empty string.
	 */
	public function test_decrypt_too_short_blob_returns_empty(): void {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		$too_short = base64_encode( 'X' ); // Only 1 byte — version byte only, no payload.

		$result = Encryption::decrypt( $too_short );

		$this->assertSame( '', $result, 'Blobs with no payload must return empty string.' );
	}

	/**
	 * A blob with an unknown version byte must return empty string.
	 */
	public function test_decrypt_unknown_version_byte_returns_empty(): void {
		// Version byte 0x99 is not defined.
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		$unknown_version = base64_encode( "\x99" . str_repeat( 'A', 40 ) );

		$result = Encryption::decrypt( $unknown_version );

		$this->assertSame( '', $result, 'Unknown version byte must return empty string.' );
	}

	// -------------------------------------------------------------------------
	// Randomness — different ciphertext for same plaintext
	// -------------------------------------------------------------------------

	/**
	 * Two calls to encrypt() with the same input must produce different blobs
	 * (because each call uses a freshly generated nonce/IV).
	 */
	public function test_encrypt_produces_different_output_each_time(): void {
		$plaintext = 'same-input-value';

		$encrypted_1 = Encryption::encrypt( $plaintext );
		$encrypted_2 = Encryption::encrypt( $plaintext );

		$this->assertNotSame(
			$encrypted_1,
			$encrypted_2,
			'Each encrypt() call must produce a unique ciphertext (random nonce).'
		);
	}

	/**
	 * Even though ciphertexts differ, both must decrypt to the same plaintext.
	 */
	public function test_both_random_encryptions_decrypt_correctly(): void {
		$plaintext = 'same-input-value';

		$enc_1 = Encryption::encrypt( $plaintext );
		$enc_2 = Encryption::encrypt( $plaintext );

		$this->assertSame( $plaintext, Encryption::decrypt( $enc_1 ) );
		$this->assertSame( $plaintext, Encryption::decrypt( $enc_2 ) );
	}
}
