<?php
/**
 * Tests for the Debug_Logger class.
 *
 * @package SFME\Tests
 */

use PHPUnit\Framework\TestCase;
use SFME\Debug\Debug_Logger;
use SFME\Plugin;

/**
 * Class DebugLoggerTest
 *
 * @coversDefaultClass \SFME\Debug\Debug_Logger
 */
class DebugLoggerTest extends TestCase {

	/**
	 * Clean up after each test.
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		delete_option( Plugin::OPTION_AUTH_LOGS );
		delete_option( Plugin::OPTION_DEBUG_LOG_ENABLED );
		parent::tearDown();
	}

	/**
	 * Test that log() does not write when debug logging is disabled.
	 *
	 * @covers ::log
	 * @covers ::is_enabled
	 * @covers ::get_logs
	 * @return void
	 */
	public function test_log_does_not_write_when_disabled(): void {
		// Ensure logging is OFF (default).
		update_option( Plugin::OPTION_DEBUG_LOG_ENABLED, 0 );

		Debug_Logger::log( 'login_success', 'success', 'test@example.com' );

		$this->assertEmpty( Debug_Logger::get_logs(), 'Logs should be empty when debug is disabled.' );
	}

	/**
	 * Test that log() writes entries when debugging is enabled.
	 *
	 * @covers ::log
	 * @covers ::get_logs
	 * @return void
	 */
	public function test_log_writes_entry_when_enabled(): void {
		update_option( Plugin::OPTION_DEBUG_LOG_ENABLED, 1 );

		Debug_Logger::log( 'login_success', 'success', 'test@example.com' );

		$logs = Debug_Logger::get_logs();
		$this->assertCount( 1, $logs );

		$entry = $logs[0];
		$this->assertSame( 'login_success', $entry['event'], 'Event type should match.' );
		$this->assertSame( 'success', $entry['status'], 'Status should be success.' );
		$this->assertSame( 'test@example.com', $entry['email'], 'Email should match.' );
		$this->assertStringContainsString( 'error' === $entry['status'] ? '' : '', $entry['error'] ?? '' );
		$this->assertArrayHasKey( 'timestamp', $entry, 'Entry should have a timestamp.' );
		$this->assertArrayHasKey( 'ip', $entry, 'Entry should have an IP.' );
	}

	/**
	 * Test that get_logs() returns newest entry first.
	 *
	 * @covers ::log
	 * @covers ::get_logs
	 * @return void
	 */
	public function test_logs_ordered_newest_first(): void {
		update_option( Plugin::OPTION_DEBUG_LOG_ENABLED, 1 );

		Debug_Logger::log( 'login_success', 'success', 'first@example.com' );
		sleep( 1 );
		Debug_Logger::log( 'login_success', 'success', 'second@example.com' );

		$logs = Debug_Logger::get_logs();
		$this->assertCount( 2, $logs );
		$this->assertSame( 'second@example.com', $logs[0]['email'], 'Newest entry should be first.' );
	}

	/**
	 * Test that logs are limited to MAX_ENTRIES (oldest evicted).
	 *
	 * @covers ::log
	 * @covers ::get_logs
	 * @return void
	 */
	public function test_logs_capped_at_max_entries(): void {
		update_option( Plugin::OPTION_DEBUG_LOG_ENABLED, 1 );
		$max = Debug_Logger::MAX_ENTRIES;

		// Insert MAX_ENTRIES + 10 entries.
		for ( $i = 0; $i < $max + 10; $i++ ) {
			Debug_Logger::log( 'login_attempt', 'success', "user{$i}@example.com" );
		}

		$logs = Debug_Logger::get_logs();
		$this->assertCount( $max, $logs, 'Logs should be capped at MAX_ENTRIES.' );

		// The oldest 10 entries should be gone.
		$emails = array_column( $logs, 'email' );
		$this->assertContains( "user{$max}@example.com", $emails, 'Latest entries should be present.' );
	}

	/**
	 * Test clear_logs() empties the log store.
	 *
	 * @covers ::clear_logs
	 * @covers ::get_logs
	 * @return void
	 */
	public function test_clear_logs_empties_store(): void {
		update_option( Plugin::OPTION_DEBUG_LOG_ENABLED, 1 );

		Debug_Logger::log( 'login_success', 'success', 'test@example.com' );
		$this->assertNotEmpty( Debug_Logger::get_logs() );

		Debug_Logger::clear_logs();
		$this->assertEmpty( Debug_Logger::get_logs(), 'Logs should be empty after clear.' );
	}

	/**
	 * Test is_enabled() reflects the option value.
	 *
	 * @covers ::is_enabled
	 * @return void
	 */
	public function test_is_enabled_reflects_option(): void {
		update_option( Plugin::OPTION_DEBUG_LOG_ENABLED, 0 );
		$this->assertFalse( Debug_Logger::is_enabled(), 'is_enabled should be false when option is 0.' );

		update_option( Plugin::OPTION_DEBUG_LOG_ENABLED, 1 );
		$this->assertTrue( Debug_Logger::is_enabled(), 'is_enabled should be true when option is 1.' );

		delete_option( Plugin::OPTION_DEBUG_LOG_ENABLED );
		$this->assertFalse( Debug_Logger::is_enabled(), 'is_enabled should be false when option is not set.' );
	}

	/**
	 * Test log() records failure status correctly.
	 *
	 * @covers ::log
	 * @covers ::get_logs
	 * @return void
	 */
	public function test_log_records_failure(): void {
		update_option( Plugin::OPTION_DEBUG_LOG_ENABLED, 1 );

		Debug_Logger::log( 'callback_error', 'failure', '', 'oidc_callback_failed' );

		$logs = Debug_Logger::get_logs();
		$this->assertCount( 1, $logs );
		$this->assertSame( 'failure', $logs[0]['status'], 'Status should be failure.' );
		$this->assertSame( 'oidc_callback_failed', $logs[0]['error'], 'Error code should match.' );
	}
}
