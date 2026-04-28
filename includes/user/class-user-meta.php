<?php
/**
 * User meta key constants and helpers for Entra SSO user data.
 *
 * Centralises all user meta interactions so keys are never scattered
 * across the codebase as magic strings.
 *
 * @package SFME\User
 */

namespace SFME\User;

defined( 'ABSPATH' ) || exit;

/**
 * Class User_Meta
 *
 * Thin wrapper around WP user meta with typed constants for every meta key
 * managed by this plugin.
 */
class User_Meta {

	// -------------------------------------------------------------------------
	// Meta key constants
	// -------------------------------------------------------------------------

	/**
	 * Entra Object ID (OID) — unique and immutable per Azure AD user.
	 *
	 * @var string
	 */
	const ENTRA_OID = '_sfme_entra_oid';

	/**
	 * Unix timestamp of the user's most recent SSO login.
	 *
	 * @var string
	 */
	const LAST_LOGIN = '_sfme_last_login';

	/**
	 * JSON-encoded array of Entra group Object IDs the user belongs to.
	 *
	 * @var string
	 */
	const ENTRA_GROUPS = '_sfme_entra_groups';

	/**
	 * Authentication method used during login: "oidc".
	 *
	 * @var string
	 */
	const LOGIN_METHOD = '_sfme_login_method';

	// -------------------------------------------------------------------------
	// CRUD helpers
	// -------------------------------------------------------------------------

	/**
	 * Retrieve a meta value for the given user.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $key     One of the class constants.
	 * @return mixed Meta value, or false when the key does not exist.
	 */
	public static function get( int $user_id, string $key ) {
		return get_user_meta( $user_id, $key, true );
	}

	/**
	 * Create or update a meta value for the given user.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $key     One of the class constants.
	 * @param mixed  $value   Value to store.
	 * @return void
	 */
	public static function update( int $user_id, string $key, $value ): void {
		update_user_meta( $user_id, $key, $value );
	}

	/**
	 * Delete a meta entry for the given user.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $key     One of the class constants.
	 * @return void
	 */
	public static function delete( int $user_id, string $key ): void {
		delete_user_meta( $user_id, $key );
	}

	/**
	 * Find a WordPress user by their Entra Object ID.
	 *
	 * @param string $oid Entra Object ID (GUID string).
	 * @return int|false WordPress user ID, or false when not found.
	 */
	public static function find_by_oid( string $oid ) {
		if ( '' === $oid ) {
			return false;
		}

		$query = new \WP_User_Query(
			array(
				'meta_key'   => self::ENTRA_OID,
				'meta_value' => $oid,
				'number'     => 1,
				'fields'     => 'ID',
			)
		);

		$results = $query->get_results();

		if ( empty( $results ) ) {
			return false;
		}

		return (int) $results[0];
	}
}
