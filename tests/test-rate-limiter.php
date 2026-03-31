<?php
/**
 * Unit tests for MicrosoftEntraSSO\Security\Rate_Limiter.
 *
 * @package MicrosoftEntraSSO\Tests
 */

use MicrosoftEntraSSO\Security\Rate_Limiter;
use PHPUnit\Framework\TestCase;

/**
 * Tests for Rate_Limiter.
 *
 * Each test uses a unique identifier to avoid state bleeding between tests.
 */
class Test_Rate_Limiter extends TestCase {

	/**
	 * Counter used to build unique identifiers per test.
	 *
	 * @var int
	 */
	private static $counter = 0;

	/**
	 * Reset the in-memory transient store before each test.
	 */
	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['_messo_transients'] = array();
	}

	/**
	 * Return a unique test identifier to prevent cross-test state pollution.
	 *
	 * @return string
	 */
	private function unique_id(): string {
		return '192.168.1.' . ( ++self::$counter );
	}

	// -------------------------------------------------------------------------
	// check() — allow path
	// -------------------------------------------------------------------------

	/**
	 * check() must return true for an identifier with no recorded attempts.
	 */
	public function test_check_returns_true_when_no_attempts_recorded(): void {
		$id = $this->unique_id();

		$this->assertTrue( Rate_Limiter::check( $id ), 'First-time identifier must be allowed.' );
	}

	/**
	 * check() must return true when attempts are below the configured maximum.
	 */
	public function test_check_returns_true_below_max_attempts(): void {
		$id = $this->unique_id();

		// Record 4 attempts (default max is 5).
		for ( $i = 0; $i < 4; $i++ ) {
			Rate_Limiter::record( $id );
		}

		$this->assertTrue( Rate_Limiter::check( $id ), 'Identifier below max attempts must be allowed.' );
	}

	/**
	 * check() must return true when exactly one attempt below the maximum.
	 */
	public function test_check_returns_true_one_below_max(): void {
		$id = $this->unique_id();

		// Default max = 5; record 4 so the 5th would be allowed.
		for ( $i = 0; $i < 4; $i++ ) {
			Rate_Limiter::record( $id );
		}

		$this->assertTrue( Rate_Limiter::check( $id ) );
	}

	// -------------------------------------------------------------------------
	// check() — block path
	// -------------------------------------------------------------------------

	/**
	 * check() must return false after the maximum number of attempts.
	 */
	public function test_check_returns_false_after_max_attempts(): void {
		$id = $this->unique_id();

		// Default max attempts = 5. Record 5 attempts.
		for ( $i = 0; $i < 5; $i++ ) {
			Rate_Limiter::record( $id );
		}

		$this->assertFalse( Rate_Limiter::check( $id ), 'Identifier at max attempts must be blocked.' );
	}

	/**
	 * check() must still return false for attempts well beyond the maximum.
	 */
	public function test_check_returns_false_far_above_max(): void {
		$id = $this->unique_id();

		for ( $i = 0; $i < 20; $i++ ) {
			Rate_Limiter::record( $id );
		}

		$this->assertFalse( Rate_Limiter::check( $id ) );
	}

	// -------------------------------------------------------------------------
	// reset()
	// -------------------------------------------------------------------------

	/**
	 * reset() must allow subsequent requests after clearing the counter.
	 */
	public function test_reset_clears_counter(): void {
		$id = $this->unique_id();

		// Block the identifier.
		for ( $i = 0; $i < 5; $i++ ) {
			Rate_Limiter::record( $id );
		}

		$this->assertFalse( Rate_Limiter::check( $id ), 'Pre-condition: should be blocked.' );

		Rate_Limiter::reset( $id );

		$this->assertTrue( Rate_Limiter::check( $id ), 'After reset, identifier must be allowed again.' );
	}

	/**
	 * reset() on an identifier with no recorded attempts should not error.
	 */
	public function test_reset_on_unknown_identifier_is_noop(): void {
		$id = $this->unique_id();

		// Should not throw or return false.
		Rate_Limiter::reset( $id );

		$this->assertTrue( Rate_Limiter::check( $id ) );
	}

	// -------------------------------------------------------------------------
	// get_remaining_lockout()
	// -------------------------------------------------------------------------

	/**
	 * get_remaining_lockout() must return 0 for an identifier with no attempts.
	 */
	public function test_get_remaining_lockout_zero_when_no_attempts(): void {
		$id = $this->unique_id();

		$this->assertSame( 0, Rate_Limiter::get_remaining_lockout( $id ) );
	}

	/**
	 * get_remaining_lockout() must return 0 when under the attempt limit.
	 */
	public function test_get_remaining_lockout_zero_when_under_limit(): void {
		$id = $this->unique_id();

		for ( $i = 0; $i < 3; $i++ ) {
			Rate_Limiter::record( $id );
		}

		$this->assertSame( 0, Rate_Limiter::get_remaining_lockout( $id ) );
	}

	/**
	 * get_remaining_lockout() must return a positive value when the identifier
	 * is rate-limited.
	 */
	public function test_get_remaining_lockout_positive_when_locked_out(): void {
		$id = $this->unique_id();

		// Hit the default limit of 5.
		for ( $i = 0; $i < 5; $i++ ) {
			Rate_Limiter::record( $id );
		}

		$remaining = Rate_Limiter::get_remaining_lockout( $id );

		$this->assertGreaterThan( 0, $remaining, 'Locked-out identifier must have positive remaining lockout.' );
	}

	/**
	 * get_remaining_lockout() must return 0 after reset().
	 */
	public function test_get_remaining_lockout_zero_after_reset(): void {
		$id = $this->unique_id();

		for ( $i = 0; $i < 5; $i++ ) {
			Rate_Limiter::record( $id );
		}

		Rate_Limiter::reset( $id );

		$this->assertSame( 0, Rate_Limiter::get_remaining_lockout( $id ) );
	}

	/**
	 * get_remaining_lockout() must return a value no greater than the window
	 * duration (default 900 seconds).
	 */
	public function test_get_remaining_lockout_does_not_exceed_window(): void {
		$id = $this->unique_id();

		for ( $i = 0; $i < 5; $i++ ) {
			Rate_Limiter::record( $id );
		}

		$remaining = Rate_Limiter::get_remaining_lockout( $id );
		$max_window = 900; // Default window in seconds.

		$this->assertLessThanOrEqual( $max_window, $remaining );
	}

	// -------------------------------------------------------------------------
	// record() edge cases
	// -------------------------------------------------------------------------

	/**
	 * Each call to record() must increment the counter.
	 */
	public function test_record_increments_counter(): void {
		$id = $this->unique_id();

		// At 4 attempts check() should be true; at 5 it becomes false.
		for ( $i = 0; $i < 4; $i++ ) {
			Rate_Limiter::record( $id );
		}

		$this->assertTrue( Rate_Limiter::check( $id ), '4 attempts: should still be allowed.' );

		Rate_Limiter::record( $id ); // 5th attempt.

		$this->assertFalse( Rate_Limiter::check( $id ), '5 attempts: should now be blocked.' );
	}
}
