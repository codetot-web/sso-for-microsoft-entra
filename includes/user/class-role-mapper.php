<?php
/**
 * Maps Entra group memberships to WordPress roles.
 *
 * Reads the plugin's role_mapping setting (an associative array of
 * Entra group Object IDs => WP role slugs) and returns the first
 * matching WP role for the authenticated user's group list.
 *
 * @package MicrosoftEntraSSO\User
 */

namespace MicrosoftEntraSSO\User;

defined( 'ABSPATH' ) || exit;

/**
 * Class Role_Mapper
 *
 * Stateless utility; every public method is static.
 */
class Role_Mapper {

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Determine the WordPress role that should be assigned to a user based on
	 * their Entra group membership.
	 *
	 * Resolution order:
	 *  1. Compare the user's group Object IDs against the admin-configured
	 *     role mapping table (first match wins).
	 *  2. Fall back to the plugin's default_role setting.
	 *  3. Fall back to "subscriber" if no default is configured.
	 *
	 * @param array $claims Decoded token/assertion claims for the user.
	 * @return string WordPress role slug.
	 */
	public static function map_role( array $claims ): string {
		$role_map = \MicrosoftEntraSSO\Plugin::get_instance()->get_option(
			\MicrosoftEntraSSO\Plugin::OPTION_ROLE_MAP,
			array()
		);

		if ( ! empty( $role_map ) && is_array( $role_map ) ) {
			$user_groups = self::get_user_groups( $claims );

			foreach ( $role_map as $group_id => $wp_role ) {
				if ( in_array( (string) $group_id, $user_groups, true ) ) {
					return (string) $wp_role;
				}
			}
		}

		$default_role = \MicrosoftEntraSSO\Plugin::get_instance()->get_option(
			\MicrosoftEntraSSO\Plugin::OPTION_DEFAULT_ROLE,
			'subscriber'
		);

		return $default_role ? (string) $default_role : 'subscriber';
	}

	/**
	 * Extract the user's Entra group Object IDs from their claims.
	 *
	 * The "groups" claim is an array of strings when the Entra application
	 * is configured to emit group membership claims.
	 *
	 * @param array $claims Decoded token/assertion claims.
	 * @return array String array of group Object IDs (may be empty).
	 */
	public static function get_user_groups( array $claims ): array {
		if ( empty( $claims['groups'] ) || ! is_array( $claims['groups'] ) ) {
			return array();
		}

		return array_map( 'strval', $claims['groups'] );
	}
}
