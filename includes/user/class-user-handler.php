<?php
/**
 * Handles user lookup, creation, and synchronisation from Entra claims.
 *
 * Bridges the gap between a successful SSO authentication (OIDC)
 * and a WordPress user session. The class follows this resolution order:
 *  1. Find an existing user by their Entra Object ID (OID).
 *  2. Fallback to email-based lookup (handles pre-existing WP accounts).
 *  3. Create a new WP user when auto-provisioning is enabled.
 *  4. Return a WP_Error when no user can be resolved and creation is off.
 *
 * @package SFME\User
 */

namespace SFME\User;

defined( 'ABSPATH' ) || exit;

/**
 * Class User_Handler
 *
 * All public methods are static; no instance is needed.
 */
class User_Handler {

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Resolve or create the WordPress user that corresponds to the given Entra
	 * identity claims.
	 *
	 * @param array $claims Decoded identity claims (oid, email, given_name …).
	 * @return int|\WP_Error WordPress user ID on success, WP_Error on failure.
	 */
	public static function find_or_create( array $claims ) {
		// 1. Primary lookup — Entra OID stored in user meta.
		$oid     = isset( $claims['oid'] ) ? (string) $claims['oid'] : '';
		$user_id = $oid ? User_Meta::find_by_oid( $oid ) : false;

		// 2. Fallback — lookup by email address.
		if ( ! $user_id ) {
			$email = self::extract_email( $claims );

			if ( $email ) {
				$user = get_user_by( 'email', $email );
				if ( $user instanceof \WP_User ) {
					$user_id = $user->ID;
				}
			}
		}

		// 3. Create when auto-provisioning is on.
		if ( ! $user_id ) {
			$auto_create = \SFME\Plugin::get_instance()->get_option(
				\SFME\Plugin::OPTION_USER_PROVISIONING,
				false
			);

			if ( $auto_create ) {
				$result = self::create_user( $claims );
				if ( is_wp_error( $result ) ) {
					return $result;
				}
				$user_id = $result;
			} else {
				// 4. Auto-create disabled — cannot log this user in.
				return new \WP_Error(
					'sfme_user_not_found',
					esc_html__(
						'No WordPress account was found for your Microsoft identity and automatic user creation is disabled. Please contact your site administrator.',
						'sso-for-microsoft-entra'
					)
				);
			}
		}

		// 5. Sync meta with the latest claims (updates even existing users).
		self::update_user_meta( $user_id, $claims );

		return $user_id;
	}

	/**
	 * Create a new WordPress user from Entra identity claims.
	 *
	 * @param array $claims Decoded identity claims.
	 * @return int|\WP_Error New user ID on success, WP_Error on failure.
	 */
	public static function create_user( array $claims ) {
		$email = self::extract_email( $claims );

		if ( ! $email ) {
			return new \WP_Error(
				'sfme_no_email',
				esc_html__(
					'The Microsoft identity does not include a valid email address. Cannot create a WordPress account.',
					'sso-for-microsoft-entra'
				)
			);
		}

		// Username derived from preferred_username or the local part of the email.
		$username = self::extract_username( $claims, $email );

		// Ensure the username is unique by appending a counter if needed.
		$base    = $username;
		$counter = 1;
		while ( username_exists( $username ) ) {
			$username = $base . $counter;
			++$counter;
		}

		$display_name = self::build_display_name( $claims );

		$user_id = wp_insert_user(
			array(
				'user_login'   => $username,
				'user_email'   => $email,
				'user_pass'    => wp_generate_password( 24, true, true ),
				'display_name' => $display_name,
				'first_name'   => isset( $claims['given_name'] ) ? (string) $claims['given_name'] : '',
				'last_name'    => isset( $claims['family_name'] ) ? (string) $claims['family_name'] : '',
				'role'         => 'subscriber',
			)
		);

		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		// Persist the OID immediately so subsequent logins use the fast path.
		if ( isset( $claims['oid'] ) && '' !== $claims['oid'] ) {
			User_Meta::update( $user_id, User_Meta::ENTRA_OID, (string) $claims['oid'] );
		}

		User_Meta::update( $user_id, User_Meta::LAST_LOGIN, time() );

		if ( ! empty( $claims['groups'] ) && is_array( $claims['groups'] ) ) {
			User_Meta::update( $user_id, User_Meta::ENTRA_GROUPS, $claims['groups'] );
		}

		return $user_id;
	}

	/**
	 * Refresh WordPress user meta from the latest identity claims.
	 *
	 * Called after every successful SSO login — even for returning users —
	 * so that display name, group membership, and login timestamp stay current.
	 *
	 * @param int   $user_id WordPress user ID.
	 * @param array $claims  Decoded identity claims.
	 * @return void
	 */
	public static function update_user_meta( int $user_id, array $claims ): void {
		// Sync display name / first + last name from claims if present.
		$updates = array();

		if ( isset( $claims['given_name'] ) ) {
			$updates['first_name'] = (string) $claims['given_name'];
		}

		if ( isset( $claims['family_name'] ) ) {
			$updates['last_name'] = (string) $claims['family_name'];
		}

		$display = self::build_display_name( $claims );
		if ( $display ) {
			$updates['display_name'] = $display;
		}

		if ( ! empty( $updates ) ) {
			$updates['ID'] = $user_id;
			wp_update_user( $updates );
		}

		// Always refresh last-login timestamp.
		User_Meta::update( $user_id, User_Meta::LAST_LOGIN, time() );

		// Sync Entra OID in case this user was found via email fallback.
		if ( isset( $claims['oid'] ) && '' !== $claims['oid'] ) {
			User_Meta::update( $user_id, User_Meta::ENTRA_OID, (string) $claims['oid'] );
		}

		// Update group membership when the groups claim is present.
		if ( isset( $claims['groups'] ) && is_array( $claims['groups'] ) ) {
			User_Meta::update( $user_id, User_Meta::ENTRA_GROUPS, $claims['groups'] );
		}
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Extract a canonical email address from claims.
	 *
	 * Prefers the "email" claim; falls back to "preferred_username" when it
	 * contains an "@" character (common for UPN-style identifiers in Entra).
	 *
	 * @param array $claims Decoded claims.
	 * @return string Valid email, or empty string when none is found.
	 */
	private static function extract_email( array $claims ): string {
		if ( ! empty( $claims['email'] ) && is_email( $claims['email'] ) ) {
			return sanitize_email( $claims['email'] );
		}

		if ( ! empty( $claims['preferred_username'] )
			&& false !== strpos( (string) $claims['preferred_username'], '@' )
			&& is_email( $claims['preferred_username'] )
		) {
			return sanitize_email( $claims['preferred_username'] );
		}

		return '';
	}

	/**
	 * Derive a WordPress username from claims.
	 *
	 * @param array  $claims Decoded claims.
	 * @param string $email  Already-extracted email (used as fallback).
	 * @return string Sanitized username candidate.
	 */
	private static function extract_username( array $claims, string $email ): string {
		if ( ! empty( $claims['preferred_username'] ) ) {
			// Strip the domain part if the preferred_username is a UPN.
			$candidate = (string) $claims['preferred_username'];
			$at_pos    = strpos( $candidate, '@' );
			if ( false !== $at_pos ) {
				$candidate = substr( $candidate, 0, $at_pos );
			}
			$candidate = sanitize_user( $candidate, true );
			if ( $candidate ) {
				return $candidate;
			}
		}

		// Fallback: local part of the email address.
		$at_pos = strpos( $email, '@' );
		if ( false !== $at_pos ) {
			return sanitize_user( substr( $email, 0, $at_pos ), true );
		}

		return sanitize_user( $email, true );
	}

	/**
	 * Build a display name from given_name + family_name claims.
	 *
	 * @param array $claims Decoded claims.
	 * @return string Display name, or empty string when claims are absent.
	 */
	private static function build_display_name( array $claims ): string {
		$parts = array();

		if ( ! empty( $claims['given_name'] ) ) {
			$parts[] = (string) $claims['given_name'];
		}

		if ( ! empty( $claims['family_name'] ) ) {
			$parts[] = (string) $claims['family_name'];
		}

		return implode( ' ', $parts );
	}
}
