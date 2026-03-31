<?php
/**
 * Centralised field definitions and sanitization helpers for the settings page.
 *
 * All option keys are derived from Plugin::OPTION_* constants. Validation
 * and sanitization logic lives here so class-settings-page.php stays lean.
 *
 * @package MicrosoftEntraSSO\Admin
 */

namespace MicrosoftEntraSSO\Admin;

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
				'id'          => \MicrosoftEntraSSO\Plugin::OPTION_TENANT_ID,
				'label'       => __( 'Tenant ID', 'microsoft-entra-sso' ),
				'type'        => 'text',
				'description' => __( 'The Directory (tenant) ID from your Azure app registration. Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', 'microsoft-entra-sso' ),
			),
			array(
				'id'          => \MicrosoftEntraSSO\Plugin::OPTION_CLIENT_ID,
				'label'       => __( 'Client ID', 'microsoft-entra-sso' ),
				'type'        => 'text',
				'description' => __( 'The Application (client) ID from your Azure app registration.', 'microsoft-entra-sso' ),
			),
			array(
				'id'          => \MicrosoftEntraSSO\Plugin::OPTION_CLIENT_SECRET,
				'label'       => __( 'Client Secret', 'microsoft-entra-sso' ),
				'type'        => 'password',
				'description' => __( 'The client secret value. Stored encrypted in the database. Leave blank to keep the existing secret.', 'microsoft-entra-sso' ),
			),
			array(
				'id'          => 'microsoft_entra_sso_redirect_uri',
				'label'       => __( 'Redirect URI', 'microsoft-entra-sso' ),
				'type'        => 'readonly',
				'description' => __( 'Add this URL to the "Redirect URIs" list in your Azure app registration.', 'microsoft-entra-sso' ),
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
				'id'          => \MicrosoftEntraSSO\Plugin::OPTION_AUTH_PROTOCOL,
				'label'       => __( 'Authentication Protocol', 'microsoft-entra-sso' ),
				'type'        => 'radio',
				'options'     => array(
					'oidc' => __( 'OpenID Connect (OIDC)', 'microsoft-entra-sso' ),
					'saml' => __( 'SAML 2.0', 'microsoft-entra-sso' ),
				),
				'default'     => 'oidc',
				'description' => __( 'OIDC is recommended for most setups. SAML requires federation metadata.', 'microsoft-entra-sso' ),
			),
			array(
				'id'          => \MicrosoftEntraSSO\Plugin::OPTION_AUTO_REDIRECT,
				'label'       => __( 'Force SSO', 'microsoft-entra-sso' ),
				'type'        => 'checkbox',
				'description' => __( 'Redirect all login attempts directly to Microsoft. Disables the standard WordPress login form.', 'microsoft-entra-sso' ),
			),
			array(
				'id'          => 'microsoft_entra_sso_allow_local_login',
				'label'       => __( 'Allow Local Login', 'microsoft-entra-sso' ),
				'type'        => 'checkbox',
				'description' => __( 'When Force SSO is enabled, still allow users with the administrator role to log in locally via wp-login.php.', 'microsoft-entra-sso' ),
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
				'id'          => \MicrosoftEntraSSO\Plugin::OPTION_USER_PROVISIONING,
				'label'       => __( 'Auto-Create Users', 'microsoft-entra-sso' ),
				'type'        => 'checkbox',
				'description' => __( 'Automatically create a WordPress account for users who authenticate successfully but do not yet have an account.', 'microsoft-entra-sso' ),
			),
			array(
				'id'          => \MicrosoftEntraSSO\Plugin::OPTION_DEFAULT_ROLE,
				'label'       => __( 'Default Role', 'microsoft-entra-sso' ),
				'type'        => 'select_roles',
				'description' => __( 'Role assigned to newly created users when no role mapping matches.', 'microsoft-entra-sso' ),
			),
			array(
				'id'          => \MicrosoftEntraSSO\Plugin::OPTION_ROLE_MAP,
				'label'       => __( 'Role Mapping', 'microsoft-entra-sso' ),
				'type'        => 'role_mapping',
				'description' => __( 'Map Entra group Object IDs to WordPress roles. First matching group wins.', 'microsoft-entra-sso' ),
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
				'id'          => 'microsoft_entra_sso_button_text',
				'label'       => __( 'Button Text', 'microsoft-entra-sso' ),
				'type'        => 'text',
				'default'     => __( 'Sign in with Microsoft', 'microsoft-entra-sso' ),
				'description' => __( 'Label displayed on the SSO login button on the WordPress login page.', 'microsoft-entra-sso' ),
			),
			array(
				'id'          => 'microsoft_entra_sso_button_style',
				'label'       => __( 'Button Style', 'microsoft-entra-sso' ),
				'type'        => 'select',
				'options'     => array(
					'default' => __( 'Default (blue)', 'microsoft-entra-sso' ),
					'dark'    => __( 'Dark', 'microsoft-entra-sso' ),
					'light'   => __( 'Light', 'microsoft-entra-sso' ),
				),
				'default'     => 'default',
				'description' => __( 'Visual style of the Microsoft sign-in button.', 'microsoft-entra-sso' ),
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
	 * Sanitize a WordPress role slug.
	 *
	 * @param mixed $value Raw input.
	 * @return string Role slug if it exists, otherwise 'subscriber'.
	 */
	public static function sanitize_role( $value ): string {
		$value = sanitize_text_field( (string) $value );
		$roles = wp_roles()->get_names();
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
