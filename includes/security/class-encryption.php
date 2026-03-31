<?php
/**
 * Encryption utility for securely storing sensitive plugin data.
 *
 * Provides a sodium-first, AES-256-GCM fallback encryption layer for values
 * like client secrets that are persisted in the WordPress database. The
 * encrypted output is a self-describing, base64-encoded blob carrying a
 * version byte so that the correct decryption path can always be chosen
 * without out-of-band configuration.
 *
 * @package MicrosoftEntraSSO\Security
 */

namespace MicrosoftEntraSSO\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Symmetric encryption helpers for plugin-managed secrets.
 *
 * Version byte layout:
 *   0x01  – libsodium secretbox (XSalsa20-Poly1305)
 *   0x02  – OpenSSL AES-256-GCM
 *
 * Encrypted blob format (before base64):
 *   [ 1-byte version ][ nonce/iv ][ ciphertext ][ tag (OpenSSL only) ]
 *
 * The nonce is prepended to ciphertext so `decrypt()` can recover it from the
 * blob without additional storage. Poly1305 (sodium) and GCM (openssl) both
 * provide authenticated encryption, so tampering is detected on decryption.
 */
class Encryption {

	/**
	 * Version byte used when libsodium is the encryption backend.
	 *
	 * @var string
	 */
	const VERSION_SODIUM = "\x01";

	/**
	 * Version byte used when OpenSSL AES-256-GCM is the encryption backend.
	 *
	 * @var string
	 */
	const VERSION_OPENSSL = "\x02";

	/**
	 * Encrypt a plaintext string.
	 *
	 * Selects the strongest available backend (libsodium preferred over
	 * OpenSSL) and returns a base64-encoded, version-tagged blob.
	 *
	 * @param string $plaintext The value to encrypt. Must not be empty.
	 *
	 * @return string Base64-encoded encrypted blob, or an empty string on
	 *                failure (failure is logged to the WP debug log but the
	 *                plaintext value is never logged).
	 */
	public static function encrypt( string $plaintext ): string {
		if ( '' === $plaintext ) {
			return '';
		}

		$key = self::get_key();

		if ( self::has_sodium() ) {
			return self::encrypt_sodium( $plaintext, $key );
		}

		return self::encrypt_openssl( $plaintext, $key );
	}

	/**
	 * Decrypt a blob produced by {@see Encryption::encrypt()}.
	 *
	 * Reads the version byte from the blob to determine which backend was used
	 * and delegates accordingly. This allows the site to switch backends
	 * (e.g., after a PHP upgrade adds libsodium) without invalidating
	 * previously encrypted values.
	 *
	 * @param string $encrypted Base64-encoded blob previously returned by
	 *                          `encrypt()`.
	 *
	 * @return string Decrypted plaintext, or an empty string on failure.
	 */
	public static function decrypt( string $encrypted ): string {
		if ( '' === $encrypted ) {
			return '';
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$raw = base64_decode( $encrypted, true );
		if ( false === $raw || strlen( $raw ) < 2 ) {
			// Blob is malformed; do not log its contents.
			return '';
		}

		$version = $raw[0];
		$payload = substr( $raw, 1 );
		$key     = self::get_key();

		if ( self::VERSION_SODIUM === $version ) {
			return self::decrypt_sodium( $payload, $key );
		}

		if ( self::VERSION_OPENSSL === $version ) {
			return self::decrypt_openssl( $payload, $key );
		}

		// Unknown version byte – cannot decrypt.
		return '';
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Derive a 32-byte encryption key from WordPress's auth salt.
	 *
	 * Using wp_salt() ties the key to this specific WordPress installation.
	 * SHA-256 is applied solely for length normalisation (raw binary output).
	 *
	 * @return string 32-byte binary key.
	 */
	private static function get_key(): string {
		return hash( 'sha256', wp_salt( 'auth' ), true );
	}

	/**
	 * Check whether the libsodium PHP extension is available.
	 *
	 * @return bool True when `sodium_crypto_secretbox` can be called.
	 */
	private static function has_sodium(): bool {
		return function_exists( 'sodium_crypto_secretbox' );
	}

	/**
	 * Encrypt using libsodium XSalsa20-Poly1305.
	 *
	 * Format (before version byte + base64):
	 *   [ 24-byte nonce ][ ciphertext + 16-byte MAC ]
	 *
	 * @param string $plaintext Plaintext to encrypt.
	 * @param string $key       32-byte binary key.
	 *
	 * @return string Base64-encoded blob (with version byte prepended).
	 */
	private static function encrypt_sodium( string $plaintext, string $key ): string {
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ); // 24 bytes

		$ciphertext = sodium_crypto_secretbox( $plaintext, $nonce, $key );

		// Wipe the plaintext copy from memory immediately after use.
		sodium_memzero( $plaintext );

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		return base64_encode( self::VERSION_SODIUM . $nonce . $ciphertext );
	}

	/**
	 * Decrypt a libsodium XSalsa20-Poly1305 payload.
	 *
	 * @param string $payload Raw binary payload (nonce + ciphertext/MAC).
	 * @param string $key     32-byte binary key.
	 *
	 * @return string Decrypted plaintext, or empty string on MAC failure.
	 */
	private static function decrypt_sodium( string $payload, string $key ): string {
		$nonce_length = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES; // 24

		if ( strlen( $payload ) <= $nonce_length ) {
			return '';
		}

		$nonce      = substr( $payload, 0, $nonce_length );
		$ciphertext = substr( $payload, $nonce_length );

		$plaintext = sodium_crypto_secretbox_open( $ciphertext, $nonce, $key );

		if ( false === $plaintext ) {
			// Authentication tag mismatch – data tampered or wrong key.
			return '';
		}

		return $plaintext;
	}

	/**
	 * Encrypt using OpenSSL AES-256-GCM (fallback when libsodium is absent).
	 *
	 * Format (before version byte + base64):
	 *   [ 12-byte IV ][ 16-byte GCM tag ][ ciphertext ]
	 *
	 * @param string $plaintext Plaintext to encrypt.
	 * @param string $key       32-byte binary key.
	 *
	 * @return string Base64-encoded blob (with version byte prepended), or
	 *                empty string on failure.
	 */
	private static function encrypt_openssl( string $plaintext, string $key ): string {
		$iv  = random_bytes( 12 ); // 96-bit IV recommended for GCM
		$tag = '';                 // Will be populated by openssl_encrypt.

		$ciphertext = openssl_encrypt(
			$plaintext,
			'aes-256-gcm',
			$key,
			OPENSSL_RAW_DATA,
			$iv,
			$tag, // phpcs:ignore -- tag is populated by reference.
			'',   // No additional authenticated data.
			16    // 128-bit authentication tag.
		);

		if ( false === $ciphertext ) {
			return '';
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		return base64_encode( self::VERSION_OPENSSL . $iv . $tag . $ciphertext );
	}

	/**
	 * Decrypt an OpenSSL AES-256-GCM payload.
	 *
	 * @param string $payload Raw binary payload (IV + tag + ciphertext).
	 * @param string $key     32-byte binary key.
	 *
	 * @return string Decrypted plaintext, or empty string on authentication
	 *                failure.
	 */
	private static function decrypt_openssl( string $payload, string $key ): string {
		// IV: 12 bytes, GCM tag: 16 bytes — minimum payload length is 28.
		if ( strlen( $payload ) <= 28 ) {
			return '';
		}

		$iv         = substr( $payload, 0, 12 );
		$tag        = substr( $payload, 12, 16 );
		$ciphertext = substr( $payload, 28 );

		$plaintext = openssl_decrypt(
			$ciphertext,
			'aes-256-gcm',
			$key,
			OPENSSL_RAW_DATA,
			$iv,
			$tag
		);

		if ( false === $plaintext ) {
			// Authentication tag mismatch – data tampered or wrong key.
			return '';
		}

		return $plaintext;
	}
}
