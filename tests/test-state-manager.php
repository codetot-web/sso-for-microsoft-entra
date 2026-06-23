<?php
/**
 * Tests for the OAuth state / nonce / PKCE manager.
 *
 * @package SFME\Tests
 */

use PHPUnit\Framework\TestCase;
use SFME\Security\State_Manager;

/**
 * State_Manager unit tests.
 */
class Test_State_Manager extends TestCase {

	/**
	 * Reset global state before each test.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();

		$GLOBALS['_sfme_transients'] = array();
		$GLOBALS['_sfme_cookies']    = array();

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Test fixture.
		$_COOKIE = array();
	}

	/**
	 * A generated state validates when the same session cookie is present.
	 *
	 * @return void
	 */
	public function test_state_validates_with_matching_session_cookie(): void {
		$session_token = 'known-test-session-token';
		$_COOKIE[ State_Manager::SESSION_COOKIE ] = $session_token;

		$state = State_Manager::create_state();

		$this->assertNotEmpty( $state );
		$this->assertSame(
			hash( 'sha256', $session_token ),
			get_transient( State_Manager::PREFIX_STATE . $state )
		);
		$this->assertTrue( State_Manager::validate_state( $state ) );
		$this->assertFalse( get_transient( State_Manager::PREFIX_STATE . $state ) );
	}

	/**
	 * State validation fails when the session cookie is missing.
	 *
	 * @return void
	 */
	public function test_state_fails_without_session_cookie(): void {
		$state = State_Manager::create_state();

		// Clear the cookie that create_state set.
		$_COOKIE = array();

		$this->assertFalse( State_Manager::validate_state( $state ) );
	}

	/**
	 * State validation fails when the session cookie does not match.
	 *
	 * @return void
	 */
	public function test_state_fails_with_wrong_session_cookie(): void {
		$_COOKIE[ State_Manager::SESSION_COOKIE ] = 'correct-token';
		$state = State_Manager::create_state();

		$_COOKIE[ State_Manager::SESSION_COOKIE ] = 'wrong-token';

		$this->assertFalse( State_Manager::validate_state( $state ) );
	}

	/**
	 * create_state issues a new session cookie when none exists.
	 *
	 * @return void
	 */
	public function test_create_state_issues_cookie_when_missing(): void {
		$state = State_Manager::create_state();

		$this->assertArrayHasKey(
			State_Manager::SESSION_COOKIE,
			$GLOBALS['_sfme_cookies']
		);
		$this->assertArrayHasKey(
			State_Manager::SESSION_COOKIE,
			$_COOKIE
		);
		$this->assertSame(
			$_COOKIE[ State_Manager::SESSION_COOKIE ],
			$GLOBALS['_sfme_cookies'][ State_Manager::SESSION_COOKIE ]['value']
		);
	}

	/**
	 * State validation fails for an unknown / never-issued state.
	 *
	 * @return void
	 */
	public function test_state_fails_for_unknown_state(): void {
		$_COOKIE[ State_Manager::SESSION_COOKIE ] = 'some-token';

		$this->assertFalse( State_Manager::validate_state( 'nonexistent-state' ) );
	}

	/**
	 * State validation fails for an empty state string.
	 *
	 * @return void
	 */
	public function test_state_fails_for_empty_state(): void {
		$_COOKIE[ State_Manager::SESSION_COOKIE ] = 'some-token';

		$this->assertFalse( State_Manager::validate_state( '' ) );
	}
}
