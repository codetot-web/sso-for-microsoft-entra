<?php
/**
 * Centralised field definitions and sanitization helpers for the settings page.
 *
 * All option keys are derived from Plugin::OPTION_* constants. Validation
 * and sanitization logic lives here so class-settings-page.php stays lean.
 *
 * @package SFME\Admin
 */

namespace SFME\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Class Settings_Fields
 *
 * Provides:
 *  - Static field-definition arrays consumed by Settings_Page.
 *  - Individual sanitization/validation callbacks.
 */
class Settings_Fields {

	// -------------------------------------------------------------------------
	// Field definitions
	// -------------------------------------------------------------------------

	/**
	 * Return field definitions for the "Connection" section.
	 *
	 * Each entry:
	 *  'id'          => option key (Plugin::OPTION_* value)
	 *  'label'       => translatable field label
	 *  'type'        => 'text' | 'password' | 'readonly'
	 *  'description' => translatable helper text
	 *
	 * @return array[]
	 */
	public static function connection_fields(): array {
		return array(
			array(
				'id'          => \SFME\Plugin::OPTION_TENANT_ID,
				'label'       => __( 'Tenant ID', 'sso-for-microsoft-entra' ),
				'type'        => 'text',
				'description' => __( 'The Directory (tenant) ID from your Azure app registration. Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', 'sso-for-microsoft-entra' ),
			),
			array(
				'id'          => \SFME\Plugin::OPTION_CLIENT_ID,
				'label'       => __( 'Client ID', 'sso-for-microsoft-entra' ),
				'type'        => 'text',
				'description' => __( 'The Application (client) ID from your Azure app registration.', 'sso-for-microsoft-entra' ),
			),
			array(
				'id'          => \SFME\Plugin::OPTION_CLIENT_SECRET,
				'label'       => __( 'Client Secret', 'sso-for-microsoft-entra' ),
				'type'        => 'password',
				'description' => __( 'The client secret value. Stored encrypted in the database. Leave blank to keep the existing secret.', 'sso-for-microsoft-entra' ),
			),
			array(
				'id'          => 'sfme_redirect_uri',
				'label'       => __( 'Redirect URI', 'sso-for-microsoft-entra' ),
				'type'        => 'readonly',
				'description' => __( 'Add this URL to the "Redirect URIs" list in your Azure app registration.', 'sso-for-microsoft-entra' ),
			),
		);
	}

	/**
	 * Return field definitions for the "Authentication" section.
	 *
	 * @return array[]
	 */
	public static function authentication_fields(): array {
		return array(
			array(
				'id'          => \SFME\Plugin::OPTION_AUTH_PROTOCOL,
				'label'       => __( 'Authentication Protocol', 'sso-for-microsoft-entra' ),
				'type'        => 'radio',
				'options'     => array(
					'oidc' => __( 'OpenID Connect (OIDC)', 'sso-for-microsoft-entra' ),
					'saml' => __( 'SAML 2.0', 'sso-for-microsoft-entra' ),
				),
				'default'     => 'oidc',
				'description' => __( 'OIDC is recommended for most setups. SAML requires federation metadata.', 'sso-for-microsoft-entra' ),
			),
			array(
				'id'          => \SFME\Plugin::OPTION_AUTO_REDIRECT,
				'label'       => __( 'Force SSO', 'sso-for-microsoft-entra' ),
				'type'        => 'checkbox',
				'description' => __( 'Redirect all login attempts directly to Microsoft. Disables the standard WordPress login form.', 'sso-for-microsoft-entra' ),
			),
			array(
				'id'          => 'sfme_allow_local_login',
				'label'       => __( 'Allow Local Login', 'sso-for-microsoft-entra' ),
				'type'        => 'checkbox',
				'description' => __( 'When Force SSO is enabled, still allow users with the administrator role to log in locally via wp-login.php.', 'sso-for-microsoft-entra' ),
			),
		);
	}

	/**
	 * Return field definitions for the "User Provisioning" section.
	 *
	 * @return array[]
	 */
	public static function provisioning_fields(): array {
		return array(
			array(
				'id'          => \SFME\Plugin::OPTION_USER_PROVISIONING,
				'label'       => __( 'Auto-Create Users', 'sso-for-microsoft-entra' ),
				'type'        => 'checkbox',
				'description' => __( 'Automatically create a WordPress account for users who authenticate successfully but do not yet have an account.', 'sso-for-microsoft-entra' ),
			),
			array(
				'id'          => \SFME\Plugin::OPTION_DEFAULT_ROLE,
				'label'       => __( 'Default Role', 'sso-for-microsoft-entra' ),
				'type'        => 'select_roles',
				'description' => __( 'Role assigned to newly created users when no role mapping matches.', 'sso-for-microsoft-entra' ),
			),
			array(
				'id'          => \SFME\Plugin::OPTION_ROLE_MAP,
				'label'       => __( 'Role Mapping', 'sso-for-microsoft-entra' ),
				'type'        => 'role_mapping',
				'description' => __( 'Map Entra group Object IDs to WordPress roles. First matching group wins.', 'sso-for-microsoft-entra' ),
			),
		);
	}

	/**
	 * Return field definitions for the "Login Customization" section.
	 *
	 * @return array[]
	 */
	public static function customization_fields(): array {
		return array(
			array(
				'id'          => 'sfme_button_text',
				'label'       => __( 'Button Text', 'sso-for-microsoft-entra' ),
				'type'        => 'text',
				'default'     => __( 'Sign in with Microsoft', 'sso-for-microsoft-entra' ),
				'description' => __( 'Label displayed on the SSO login button on the WordPress login page.', 'sso-for-microsoft-entra' ),
			),
			array(
				'id'          => 'sfme_button_style',
				'label'       => __( 'Button Style', 'sso-for-microsoft-entra' ),
				'type'        => 'select',
				'options'     => array(
					'default' => __( 'Default (blue)', 'sso-for-microsoft-entra' ),
					'dark'    => __( 'Dark', 'sso-for-microsoft-entra' ),
					'light'   => __( 'Light', 'sso-for-microsoft-entra' ),
				),
				'default'     => 'default',
				'description' => __( 'Visual style of the Microsoft sign-in button.', 'sso-for-microsoft-entra' ),
			),
		);
	}

	/**
	 * Return field definitions for the "Rate Limiting" section.
	 *
	 * @return array[]
	 */
	public static function rate_limiting_fields(): array {
		return array(
			array(
				'id'          => \SFME\Plugin::OPTION_RATE_LIMIT_MAX,
				'label'       => __( 'Max Attempts', 'sso-for-microsoft-entra' ),
				'type'        => 'number',
				'min'         => '1',
				'default'     => 5,
				'description' => __( 'Maximum login attempts per IP before lockout. Default: 5.', 'sso-for-microsoft-entra' ),
			),
			array(
				'id'          => \SFME\Plugin::OPTION_RATE_LIMIT_WINDOW,
				'label'       => __( 'Window (seconds)', 'sso-for-microsoft-entra' ),
				'type'        => 'number',
				'min'         => '60',
				'default'     => 900,
				'description' => __( 'Time window in seconds. Default: 900 (15 minutes).', 'sso-for-microsoft-entra' ),
			),
		);
	}

	// -------------------------------------------------------------------------
	// Sanitization helpers
	// -------------------------------------------------------------------------

	/**
	 * Sanitize a Tenant ID (must be a GUID).
	 *
	 * @param mixed $value Raw user input.
	 * @return string Sanitized GUID, or empty string on invalid format.
	 */
	public static function sanitize_tenant_id( $value ): string {
		$value = sanitize_text_field( (string) $value );
		return self::is_guid( $value ) ? $value : '';
	}

	/**
	 * Sanitize a Client ID (must be a GUID).
	 *
	 * @param mixed $value Raw user input.
	 * @return string Sanitized GUID, or empty string on invalid format.
	 */
	public static function sanitize_client_id( $value ): string {
		$value = sanitize_text_field( (string) $value );
		return self::is_guid( $value ) ? $value : '';
	}

	/**
	 * Sanitize the authentication protocol value.
	 *
	 * @param mixed $value Raw input.
	 * @return string 'oidc' or 'saml' — defaults to 'oidc'.
	 */
	public static function sanitize_protocol( $value ): string {
		$value = sanitize_text_field( (string) $value );
		return in_array( $value, array( 'oidc', 'saml' ), true ) ? $value : 'oidc';
	}

	/**
	 * Sanitize a WordPress role slug for SSO default role.
	 *
	 * Security: blocks 'administrator' to prevent privilege escalation
	 * through SSO auto-provisioning misconfiguration.
	 *
	 * @param mixed $value Raw input.
	 * @return string Role slug if valid and not administrator, otherwise 'subscriber'.
	 */
	public static function sanitize_role( $value ): string {
		$value = sanitize_text_field( (string) $value );
		$roles = wp_roles()->get_names();

		// Security: never allow administrator as the SSO default role.
		if ( 'administrator' === $value ) {
			add_settings_error(
				\SFME\Plugin::OPTION_DEFAULT_ROLE,
				'sfme_role_too_high',
				__( 'Administrator cannot be set as the SSO default role. Reset to Subscriber.', 'sso-for-microsoft-entra' ),
				'error'
			);
			return 'subscriber';
		}

		return isset( $roles[ $value ] ) ? $value : 'subscriber';
	}

	/**
	 * Sanitize the role-mapping array.
	 *
	 * The form submits the repeatable rows under a 'rows' key:
	 *   option_key[rows][][group_id]
	 *   option_key[rows][][role]
	 *
	 * Returns an associative array of group_id => wp_role suitable for
	 * storage and use by Role_Mapper.
	 *
	 * @param mixed $value Raw posted value (expects array with 'rows' key).
	 * @return array Sanitized associative array of group_id => wp_role.
	 */
	public static function sanitize_role_map( $value ): array {
		if ( ! is_array( $value ) ) {
			return array();
		}

		// Handle the 'rows' wrapper added by the form field naming convention.
		$rows = isset( $value['rows'] ) && is_array( $value['rows'] )
			? $value['rows']
			: $value;

		$clean = array();
		$roles = wp_roles()->get_names();

		foreach ( $rows as $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}

			$group_id = sanitize_text_field( (string) ( $entry['group_id'] ?? '' ) );
			$role     = sanitize_text_field( (string) ( $entry['role'] ?? '' ) );

			if ( '' === $group_id || ! isset( $roles[ $role ] ) ) {
				continue;
			}

			$clean[ $group_id ] = $role;
		}

		return $clean;
	}

	/**
	 * Sanitize a value as a positive integer (minimum 1).
	 *
	 * @param mixed $value Raw input.
	 * @return int Positive integer, minimum 1.
	 */
	public static function sanitize_positive_int( $value ): int {
		return max( 1, absint( $value ) );
	}

	// -------------------------------------------------------------------------
	// Validation helpers
	// -------------------------------------------------------------------------

	/**
	 * Validate that a string matches the GUID / UUID format.
	 *
	 * @param string $value Value to test.
	 * @return bool True when the string is a valid GUID.
	 */
	public static function is_guid( string $value ): bool {
		return (bool) preg_match(
			'/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
			$value
		);
	}
}
