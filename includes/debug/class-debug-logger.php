<?php
/**
 * Debug logger for authentication events.
 *
 * Captures the last 100 SSO authentication sessions when debug logging is
 * explicitly enabled. Defaults to off to avoid unnecessary writes.
 *
 * @package SFME\Debug
 */

namespace SFME\Debug;

use SFME\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Class Debug_Logger
 *
 * All methods are static. Each log entry records:
 *  - timestamp (Unix)
 *  - event    ('login_success', 'login_failure', 'callback_error', etc.)
 *  - email    (user email or empty)
 *  - ip       (client IP)
 *  - error    (machine-readable error code, empty on success)
 *  - user_agent (HTTP User-Agent string, truncated)
 */
class Debug_Logger {

	/**
	 * Max log entries kept.
	 *
	 * @var int
	 */
	const MAX_ENTRIES = 100;

	/**
	 * Log an authentication event.
	 *
	 * @param string $event  Event type (e.g. 'login_success', 'login_failure').
	 * @param string $status 'success' or 'failure'.
	 * @param string $email  User email (or '' if unknown).
	 * @param string $error  Machine-readable error code (or '' on success).
	 *
	 * @return void
	 */
	public static function log( string $event, string $status, string $email = '', string $error = '' ): void {
		if ( ! self::is_enabled() ) {
			return;
		}

		$logs  = self::get_logs();
		$entry = array(
			'timestamp'  => time(),
			'event'      => $event,
			'status'     => 'success' === $status ? 'success' : 'failure',
			'email'      => $email,
			'ip'         => self::get_client_ip(),
			'error'      => $error,
			'user_agent' => self::get_user_agent(),
		);

		// Prepend newest entry.
		array_unshift( $logs, $entry );

		// Trim to MAX_ENTRIES.
		if ( count( $logs ) > self::MAX_ENTRIES ) {
			$logs = array_slice( $logs, 0, self::MAX_ENTRIES );
		}

		update_option( Plugin::OPTION_AUTH_LOGS, wp_json_encode( $logs ), false );
	}

	/**
	 * Retrieve stored log entries.
	 *
	 * @return array[] Array of log entry arrays.
	 */
	public static function get_logs(): array {
		$raw  = get_option( Plugin::OPTION_AUTH_LOGS, '[]' );
		$data = json_decode( $raw, true );

		return is_array( $data ) ? $data : array();
	}

	/**
	 * Delete all log entries.
	 *
	 * @return void
	 */
	public static function clear_logs(): void {
		delete_option( Plugin::OPTION_AUTH_LOGS );
	}

	/**
	 * Check whether debug logging is enabled.
	 *
	 * Reads the option directly to avoid bootstrapping the full plugin singleton.
	 *
	 * @return bool
	 */
	public static function is_enabled(): bool {
		return (bool) get_option( Plugin::OPTION_DEBUG_LOG_ENABLED, false );
	}

	/**
	 * Obtain the client IP address.
	 *
	 * @return string
	 */
	private static function get_client_ip(): string {
		if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		return '';
	}

	/**
	 * Obtain the User-Agent string (truncated to 255 chars).
	 *
	 * @return string
	 */
	private static function get_user_agent(): string {
		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
			return substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 );
		}

		return '';
	}
}
