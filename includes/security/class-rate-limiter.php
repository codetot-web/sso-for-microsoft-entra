<?php
/**
 * IP-based rate limiter for login-related endpoints.
 *
 * Prevents brute-force and denial-of-service attempts by tracking the number
 * of authentication attempts per IP address within a sliding window. Counters
 * are persisted as WordPress transients so no additional storage is required.
 *
 * @package MicrosoftEntraSSO\Security
 */

namespace MicrosoftEntraSSO\Security;

defined( 'ABSPATH' ) || exit;

/**
 * IP-based sliding-window rate limiter.
 *
 * Default policy (filterable):
 *   - 5 attempts per 15-minute window
 *
 * Transient key format:
 *   messo_rate_{md5(identifier)}
 *
 * Stored value (serialised array):
 *   [ 'count' => int, 'first_attempt' => int (Unix timestamp) ]
 */
class Rate_Limiter {

	/**
	 * Transient key prefix for rate-limit counters.
	 *
	 * @var string
	 */
	const PREFIX = 'messo_rate_';

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Check whether the given identifier is within the allowed request budget.
	 *
	 * Returns true (allow) when:
	 *   - No previous attempts are on record, OR
	 *   - The current window has already expired (counter resets implicitly), OR
	 *   - The attempt count is below the configured maximum.
	 *
	 * @param string $identifier Typically the client IP address.
	 *
	 * @return bool True if the request is allowed, false if the limit is exceeded.
	 */
	public static function check( string $identifier ): bool {
		$data = self::get_data( $identifier );

		// No data stored yet – first attempt, always allow.
		if ( null === $data ) {
			return true;
		}

		$max_attempts = self::get_max_attempts();
		$window       = self::get_window();

		// If the window has expired the counter is stale; treat as allowed.
		if ( ( time() - $data['first_attempt'] ) >= $window ) {
			return true;
		}

		return $data['count'] < $max_attempts;
	}

	/**
	 * Record an authentication attempt for the given identifier.
	 *
	 * Increments the attempt counter within the current window. When no
	 * prior record exists, a new window is started anchored to the current
	 * timestamp. The transient TTL is set to the remaining window duration
	 * so WordPress automatically cleans up expired records.
	 *
	 * @param string $identifier Typically the client IP address.
	 *
	 * @return void
	 */
	public static function record( string $identifier ): void {
		$data   = self::get_data( $identifier );
		$window = self::get_window();
		$now    = time();

		if ( null === $data || ( $now - $data['first_attempt'] ) >= $window ) {
			// Start a fresh window.
			$data = [
				'count'         => 1,
				'first_attempt' => $now,
			];
			$ttl = $window;
		} else {
			// Increment within the existing window.
			$data['count']++;
			// Remaining TTL = window end minus now.
			$ttl = max( 1, (int) ( $data['first_attempt'] + $window - $now ) );
		}

		set_transient( self::key( $identifier ), $data, $ttl );
	}

	/**
	 * Reset the rate-limit counter for the given identifier.
	 *
	 * Should be called immediately after a successful authentication so that
	 * legitimate users do not experience unnecessary lock-outs.
	 *
	 * @param string $identifier Typically the client IP address.
	 *
	 * @return void
	 */
	public static function reset( string $identifier ): void {
		delete_transient( self::key( $identifier ) );
	}

	/**
	 * Return the number of seconds remaining until the current lock-out window
	 * expires.
	 *
	 * Returns 0 when the identifier is not rate-limited or the window has
	 * already expired.
	 *
	 * @param string $identifier Typically the client IP address.
	 *
	 * @return int Seconds until the window expires, or 0 if not locked out.
	 */
	public static function get_remaining_lockout( string $identifier ): int {
		$data = self::get_data( $identifier );

		if ( null === $data ) {
			return 0;
		}

		$window       = self::get_window();
		$max_attempts = self::get_max_attempts();
		$elapsed      = time() - $data['first_attempt'];

		// Window has already expired or limit not yet reached.
		if ( $elapsed >= $window || $data['count'] < $max_attempts ) {
			return 0;
		}

		return max( 0, (int) ( $window - $elapsed ) );
	}

	// -------------------------------------------------------------------------
	// Internal helpers
	// -------------------------------------------------------------------------

	/**
	 * Retrieve stored rate-limit data for an identifier.
	 *
	 * @param string $identifier Client identifier.
	 *
	 * @return array|null Associative array with 'count' and 'first_attempt',
	 *                    or null if no record exists.
	 */
	private static function get_data( string $identifier ): ?array {
		$data = get_transient( self::key( $identifier ) );

		if ( false === $data || ! is_array( $data ) ) {
			return null;
		}

		// Ensure required keys are present and correctly typed.
		if ( ! isset( $data['count'], $data['first_attempt'] ) ) {
			return null;
		}

		return $data;
	}

	/**
	 * Build the transient key for an identifier.
	 *
	 * MD5 is used only to produce a short, safe key string – it is not used
	 * for any security-sensitive purpose here.
	 *
	 * @param string $identifier Client identifier (e.g. IP address).
	 *
	 * @return string Transient key of the form `messo_rate_{md5hash}`.
	 */
	private static function key( string $identifier ): string {
		return self::PREFIX . md5( $identifier );
	}

	/**
	 * Return the configured maximum number of attempts per window.
	 *
	 * Filterable via `microsoft_entra_sso_rate_limit_attempts`.
	 *
	 * @return int Maximum attempts (minimum 1).
	 */
	private static function get_max_attempts(): int {
		/**
		 * Filters the maximum number of authentication attempts allowed within
		 * a single rate-limit window.
		 *
		 * @param int $attempts Default: 5.
		 */
		$attempts = (int) apply_filters( 'microsoft_entra_sso_rate_limit_attempts', 5 );

		return max( 1, $attempts );
	}

	/**
	 * Return the configured sliding-window duration in seconds.
	 *
	 * Filterable via `microsoft_entra_sso_rate_limit_window`.
	 *
	 * @return int Window duration in seconds (minimum 60).
	 */
	private static function get_window(): int {
		/**
		 * Filters the duration of the rate-limit window in seconds.
		 *
		 * @param int $window Default: 900 (15 minutes).
		 */
		$window = (int) apply_filters( 'microsoft_entra_sso_rate_limit_window', 900 );

		return max( 60, $window );
	}
}
