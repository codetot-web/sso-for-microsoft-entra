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
				'description' => __( 'Automatically create a WordPress account for users who authenticate successfully but do not yet have an account. New users are assigned the Subscriber role. Administrators can promote users to other roles manually.', 'sso-for-microsoft-entra' ),
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
