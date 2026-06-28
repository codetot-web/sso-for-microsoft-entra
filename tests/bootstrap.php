<?php
/**
 * PHPUnit bootstrap for the Microsoft Entra SSO plugin unit test suite.
 *
 * Sets up a minimal WordPress-like environment so that plugin classes can be
 * loaded and exercised without a full WordPress installation. Only the WP
 * functions actually called by the tested classes are stubbed here.
 *
 * @package SFME\Tests
 */

// ---------------------------------------------------------------------------
// 1. WordPress environment constants
// ---------------------------------------------------------------------------

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'SFME_VERSION' ) ) {
	define( 'SFME_VERSION', '1.0.0' );
}

if ( ! defined( 'SFME_PLUGIN_DIR' ) ) {
	define( 'SFME_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'SFME_PLUGIN_FILE' ) ) {
	define( 'SFME_PLUGIN_FILE', dirname( __DIR__ ) . '/sso-for-microsoft-entra.php' );
}

if ( ! defined( 'DAY_IN_SECONDS' ) ) {
	define( 'DAY_IN_SECONDS', 86400 );
}

if ( ! defined( 'COOKIEPATH' ) ) {
	define( 'COOKIEPATH', '/' );
}

if ( ! defined( 'COOKIE_DOMAIN' ) ) {
	define( 'COOKIE_DOMAIN', '' );
}

if ( ! defined( 'SODIUM_CRYPTO_SECRETBOX_NONCEBYTES' ) ) {
	// Only define the fallback when the sodium extension is unavailable.
	if ( ! function_exists( 'sodium_crypto_secretbox' ) ) {
		define( 'SODIUM_CRYPTO_SECRETBOX_NONCEBYTES', 24 );
	}
}

// ---------------------------------------------------------------------------
// 2. WordPress function stubs
// ---------------------------------------------------------------------------

if ( ! function_exists( 'wp_salt' ) ) {
	/**
	 * Stub for wp_salt(). Returns a deterministic value for tests.
	 *
	 * @param string $scheme Ignored in test context.
	 * @return string
	 */
	function wp_salt( string $scheme = 'auth' ): string {
		return 'test-salt-for-unit-tests-' . $scheme . '-deterministic-value-abc123';
	}
}

if ( ! function_exists( 'wp_generate_password' ) ) {
	/**
	 * Stub for wp_generate_password().
	 *
	 * @param int  $length             Password length.
	 * @param bool $special_chars      Whether to include special characters.
	 * @param bool $extra_special_chars Whether to include extra special characters.
	 * @return string
	 */
	function wp_generate_password( int $length = 12, bool $special_chars = true, bool $extra_special_chars = false ): string {
		$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		if ( $special_chars ) {
			$chars .= '!@#$%^&*()';
		}
		$password = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$password .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
		}
		return $password;
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	/**
	 * Stub for esc_html__(). Returns the input string unchanged.
	 *
	 * @param string $text   Text to translate.
	 * @param string $domain Text domain (ignored).
	 * @return string
	 */
	function esc_html__( string $text, string $domain = 'default' ): string {
		return $text;
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	/**
	 * Stub for sanitize_text_field().
	 *
	 * @param string $str String to sanitize.
	 * @return string
	 */
	function sanitize_text_field( string $str ): string {
		return $str;
	}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	/**
	 * Stub for wp_unslash().
	 *
	 * @param string $value Value to unslash.
	 * @return string
	 */
	function wp_unslash( string $value ): string {
		return stripslashes( $value );
	}
}

if ( ! function_exists( 'is_ssl' ) ) {
	/**
	 * Stub for is_ssl().
	 *
	 * @return bool
	 */
	function is_ssl(): bool {
		return false;
	}
}

$GLOBALS['_sfme_cookies'] = array();

if ( ! function_exists( 'esc_html' ) ) {
	/**
	 * Stub for esc_html(). Returns the input string unchanged.
	 *
	 * @param string $text Text to escape.
	 * @return string
	 */
	function esc_html( string $text ): string {
		return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	/**
	 * Stub for add_filter(). Stores callbacks for apply_filters().
	 *
	 * @param string   $hook_name     Filter hook name.
	 * @param callable $callback      Callback function.
	 * @param int      $priority      Priority (ignored).
	 * @param int      $accepted_args Number of accepted args (ignored).
	 * @return true
	 */
	function add_filter( string $hook_name, callable $callback, int $priority = 10, int $accepted_args = 1 ): bool {
		$GLOBALS['_sfme_filters'][ $hook_name ][] = $callback;
		return true;
	}
}

if ( ! function_exists( 'remove_all_filters' ) ) {
	/**
	 * Stub for remove_all_filters(). Clears stored callbacks.
	 *
	 * @param string $hook_name Filter hook name.
	 * @return true
	 */
	function remove_all_filters( string $hook_name ): bool {
		$GLOBALS['_sfme_filters'][ $hook_name ] = array();
		return true;
	}
}

$GLOBALS['_sfme_filters'] = array();

if ( ! function_exists( 'apply_filters' ) ) {
	/**
	 * Stub for apply_filters(). Runs registered callbacks in order.
	 *
	 * @param string $hook_name Filter hook name.
	 * @param mixed  $value     Value to filter.
	 * @param mixed  ...$args   Additional arguments.
	 * @return mixed
	 */
	function apply_filters( string $hook_name, $value, ...$args ) {
		$filters = $GLOBALS['_sfme_filters'][ $hook_name ] ?? array();
		foreach ( $filters as $callback ) {
			$value = call_user_func( $callback, $value, ...$args );
		}
		return $value;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	/**
	 * Stub for do_action(). Records fired actions for inspection.
	 *
	 * @param string $hook_name Action hook name.
	 * @param mixed  ...$args   Arguments passed to the action.
	 * @return void
	 */
	function do_action( string $hook_name, ...$args ): void {
		$GLOBALS['_sfme_actions'][] = array(
			'hook' => $hook_name,
			'args' => $args,
		);
	}
}

$GLOBALS['_sfme_actions'] = array();

if ( ! function_exists( 'get_user_by' ) ) {
	/**
	 * Stub for get_user_by(). Looks up users in a global test store.
	 *
	 * @param string $field Field to search by.
	 * @param string $value Value to search for.
	 * @return WP_User|false
	 */
	function get_user_by( string $field, string $value ) {
		if ( 'email' !== $field ) {
			return false;
		}

		$users = $GLOBALS['_sfme_users'] ?? array();
		foreach ( $users as $user ) {
			if ( isset( $user->user_email ) && $user->user_email === $value ) {
				return $user;
			}
		}

		return false;
	}
}

if ( ! class_exists( 'WP_User' ) ) {
	/**
	 * Minimal WP_User stub for unit tests.
	 */
	class WP_User {
		/** @var int */
		public $ID;

		/** @var string */
		public $user_email;

		/**
		 * @param int    $id    User ID.
		 * @param string $email User email.
		 */
		public function __construct( int $id, string $email ) {
			$this->ID         = $id;
			$this->user_email = $email;
		}
	}
}

$GLOBALS['_sfme_users'] = array();

if ( ! function_exists( 'is_wp_error' ) ) {
	/**
	 * Stub for is_wp_error().
	 *
	 * @param mixed $thing Value to test.
	 * @return bool
	 */
	function is_wp_error( $thing ): bool {
		return ( $thing instanceof WP_Error );
	}
}

// ---------------------------------------------------------------------------
// 3. WordPress transient stubs (backed by a simple in-memory store)
// ---------------------------------------------------------------------------

/** @var array<string,array{value:mixed,expiry:int}> In-memory transient store. */
$GLOBALS['_sfme_transients'] = array();

if ( ! function_exists( 'set_transient' ) ) {
	/**
	 * Stub for set_transient(). Stores value in a global array.
	 *
	 * @param string $transient  Transient name.
	 * @param mixed  $value      Value to store.
	 * @param int    $expiration Expiration in seconds (0 = no expiry).
	 * @return bool
	 */
	function set_transient( string $transient, $value, int $expiration = 0 ): bool {
		$GLOBALS['_sfme_transients'][ $transient ] = array(
			'value'  => $value,
			'expiry' => $expiration > 0 ? time() + $expiration : 0,
		);
		return true;
	}
}

if ( ! function_exists( 'get_transient' ) ) {
	/**
	 * Stub for get_transient(). Reads from the in-memory store.
	 *
	 * @param string $transient Transient name.
	 * @return mixed Value or false when not found / expired.
	 */
	function get_transient( string $transient ) {
		if ( ! isset( $GLOBALS['_sfme_transients'][ $transient ] ) ) {
			return false;
		}

		$entry = $GLOBALS['_sfme_transients'][ $transient ];

		if ( $entry['expiry'] > 0 && time() > $entry['expiry'] ) {
			unset( $GLOBALS['_sfme_transients'][ $transient ] );
			return false;
		}

		return $entry['value'];
	}
}

if ( ! function_exists( 'delete_transient' ) ) {
	/**
	 * Stub for delete_transient().
	 *
	 * @param string $transient Transient name.
	 * @return bool
	 */
	function delete_transient( string $transient ): bool {
		unset( $GLOBALS['_sfme_transients'][ $transient ] );
		return true;
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	/**
	 * Stub for wp_json_encode().
	 *
	 * @param mixed $data Data to encode.
	 * @return string
	 */
	function wp_json_encode( $data ): string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
		return json_encode( $data );
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	/**
	 * Stub for delete_option().
	 *
	 * @param string $option Option name.
	 * @return bool
	 */
	function delete_option( string $option ): bool {
		unset( $GLOBALS['_sfme_options'][ $option ] );
		return true;
	}
}

if ( ! function_exists( 'get_option' ) ) {
	/**
	 * Stub for get_option(). Always returns the default.
	 *
	 * @param string $option  Option name.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	function get_option( string $option, $default = false ) {
		return $GLOBALS['_sfme_options'][ $option ] ?? $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	/**
	 * Stub for update_option().
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Option value.
	 * @return bool
	 */
	function update_option( string $option, $value ): bool {
		$GLOBALS['_sfme_options'][ $option ] = $value;
		return true;
	}
}

$GLOBALS['_sfme_options'] = array();

// ---------------------------------------------------------------------------
// 5. WP_Error class stub
// ---------------------------------------------------------------------------

if ( ! class_exists( 'WP_Error' ) ) {
	/**
	 * Minimal WP_Error stub for unit tests.
	 */
	class WP_Error {
		/** @var string */
		private $code;

		/** @var string */
		private $message;

		/** @var mixed */
		private $data;

		/**
		 * @param string $code    Error code.
		 * @param string $message Human-readable message.
		 * @param mixed  $data    Additional error data.
		 */
		public function __construct( string $code = '', string $message = '', $data = '' ) {
			$this->code    = $code;
			$this->message = $message;
			$this->data    = $data;
		}

		/**
		 * @return string
		 */
		public function get_error_code(): string {
			return $this->code;
		}

		/**
		 * @return string
		 */
		public function get_error_message(): string {
			return $this->message;
		}

		/**
		 * @return mixed
		 */
		public function get_error_data() {
			return $this->data;
		}
	}
}

// ---------------------------------------------------------------------------
// 5. Load namespaced function stubs
// ---------------------------------------------------------------------------

require_once __DIR__ . '/stubs/security-functions.php';

// ---------------------------------------------------------------------------
// 6. Load the plugin autoloader
// ---------------------------------------------------------------------------

require_once dirname( __DIR__ ) . '/includes/class-autoloader.php';
