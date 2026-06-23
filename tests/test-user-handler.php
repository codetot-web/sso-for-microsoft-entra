<?php
/**
 * Tests for user resolution and account linking.
 *
 * @package SFME\Tests
 */

use PHPUnit\Framework\TestCase;
use SFME\User\User_Handler;

/**
 * User_Handler unit tests.
 */
class Test_User_Handler extends TestCase {

	/**
	 * Reset global state before each test.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();

		$GLOBALS['_sfme_actions'] = array();
		add_filter(
			'sfme_allow_email_linking',
			function () {
				return true;
			}
		);
	}

	/**
	 * Clean up filters after each test.
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		remove_all_filters( 'sfme_allow_email_linking' );
		parent::tearDown();
	}

	/**
	 * Email linking is allowed by default when email_verified is absent.
	 *
	 * @return void
	 */
	public function test_email_linking_allowed_by_default(): void {
		$allowed = $this->call_is_email_linking_allowed( array( 'email' => 'test@example.com' ) );

		$this->assertTrue( $allowed );
	}

	/**
	 * Email linking is skipped when the filter returns false.
	 *
	 * @return void
	 */
	public function test_email_linking_disabled_by_filter(): void {
		add_filter(
			'sfme_allow_email_linking',
			function () {
				return false;
			}
		);

		$allowed = $this->call_is_email_linking_allowed( array( 'email' => 'test@example.com' ) );

		$this->assertFalse( $allowed );
	}

	/**
	 * Email linking is skipped when email_verified is false.
	 *
	 * @return void
	 */
	public function test_email_linking_skipped_when_unverified(): void {
		$allowed = $this->call_is_email_linking_allowed(
			array(
				'email'          => 'test@example.com',
				'email_verified' => false,
			)
		);

		$this->assertFalse( $allowed );
	}

	/**
	 * Email linking is allowed when email_verified is true.
	 *
	 * @return void
	 */
	public function test_email_linking_allowed_when_verified(): void {
		$allowed = $this->call_is_email_linking_allowed(
			array(
				'email'          => 'test@example.com',
				'email_verified' => true,
			)
		);

		$this->assertTrue( $allowed );
	}

	/**
	 * Call the private is_email_linking_allowed() helper via reflection.
	 *
	 * @param array $claims Decoded identity claims.
	 * @return bool
	 */
	private function call_is_email_linking_allowed( array $claims ): bool {
		$method = new \ReflectionMethod( User_Handler::class, 'is_email_linking_allowed' );
		$method->setAccessible( true );
		return $method->invoke( null, $claims );
	}
}
