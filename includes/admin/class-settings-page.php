<?php
/**
 * Registers and renders the plugin's admin settings page.
 *
 * Uses the WordPress Settings API to handle option persistence so that
 * data goes through the standard sanitize → save cycle with nonce
 * verification provided by settings_fields().
 *
 * @package SFME\Admin
 */

namespace SFME\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Class Settings_Page
 *
 * Manages the Settings > Entra SSO admin page, its five sections, all
 * field registrations, and the AJAX handler for metadata import.
 */
class Settings_Page {

	/**
	 * WordPress Settings API option group name.
	 *
	 * @var string
	 */
	const OPTION_GROUP = 'sfme_settings';

	/**
	 * Menu slug for the settings page.
	 *
	 * @var string
	 */
	const PAGE_SLUG = 'sso-for-microsoft-entra';

	// -------------------------------------------------------------------------
	// Bootstrap
	// -------------------------------------------------------------------------

	/**
	 * Register all admin hooks needed by this class.
	 *
	 * @return void
	 */
	public static function register(): void {
		add_action( 'admin_menu', array( self::class, 'add_menu_page' ) );
		add_action( 'admin_init', array( self::class, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( self::class, 'enqueue_assets' ) );
		// L3: wp_ajax_sfme_import_metadata is already registered by Plugin::init().
		// Do not add it here to avoid a duplicate hook that fires the handler twice.

		Admin_Notices::register();
	}

	// -------------------------------------------------------------------------
	// Menu
	// -------------------------------------------------------------------------

	/**
	 * Register the settings page under the Settings menu.
	 *
	 * @return void
	 */
	public static function add_menu_page(): void {
		$hook = add_options_page(
			__( 'Microsoft Entra SSO', 'sso-for-microsoft-entra' ),
			__( 'Entra SSO', 'sso-for-microsoft-entra' ),
			'manage_options',
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);

		// Add contextual help tabs to the settings page.
		if ( $hook ) {
			add_action( 'load-' . $hook, array( self::class, 'add_help_tabs' ) );
		}
	}

	/**
	 * Register contextual help tabs on the settings page.
	 *
	 * @return void
	 */
	public static function add_help_tabs(): void {
		$screen = get_current_screen();
		if ( ! $screen ) {
			return;
		}

		$screen->add_help_tab(
			array(
				'id'      => 'sfme_help_quick_start',
				'title'   => __( 'Quick Start', 'sso-for-microsoft-entra' ),
				'content' => self::get_help_quick_start(),
			)
		);

		$screen->add_help_tab(
			array(
				'id'      => 'sfme_help_azure_setup',
				'title'   => __( 'Azure Setup', 'sso-for-microsoft-entra' ),
				'content' => self::get_help_azure_setup(),
			)
		);

		$screen->add_help_tab(
			array(
				'id'      => 'sfme_help_saml',
				'title'   => __( 'SAML Setup', 'sso-for-microsoft-entra' ),
				'content' => self::get_help_saml_setup(),
			)
		);

		$screen->add_help_tab(
			array(
				'id'      => 'sfme_help_troubleshooting',
				'title'   => __( 'Troubleshooting', 'sso-for-microsoft-entra' ),
				'content' => self::get_help_troubleshooting(),
			)
		);

		$screen->set_help_sidebar(
			'<p><strong>' . esc_html__( 'Resources', 'sso-for-microsoft-entra' ) . '</strong></p>'
			. '<p><a href="https://portal.azure.com" target="_blank">' . esc_html__( 'Azure Portal', 'sso-for-microsoft-entra' ) . '</a></p>'
			. '<p><a href="https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso" target="_blank">' . esc_html__( 'Microsoft Docs', 'sso-for-microsoft-entra' ) . '</a></p>'
		);
	}

	/**
	 * Quick Start help tab content.
	 *
	 * @return string
	 */
	private static function get_help_quick_start(): string {
		return '<h3>' . esc_html__( 'Quick Start (SAML — Recommended)', 'sso-for-microsoft-entra' ) . '</h3>'
			. '<ol>'
			. '<li>' . esc_html__( 'In Azure Portal, go to Enterprise Applications → your app → Single sign-on → SAML.', 'sso-for-microsoft-entra' ) . '</li>'
			. '<li>' . esc_html__( 'Set Reply URL (ACS) to:', 'sso-for-microsoft-entra' ) . ' <code>' . esc_url( home_url( '/sso/saml-acs' ) ) . '</code></li>'
			. '<li>' . esc_html__( 'Copy the App Federation Metadata URL from the SAML Certificates section.', 'sso-for-microsoft-entra' ) . '</li>'
			. '<li>' . esc_html__( 'Paste it into the Metadata URL field below and click Import Metadata.', 'sso-for-microsoft-entra' ) . '</li>'
			. '<li>' . esc_html__( 'Tenant ID, Client ID, and protocol are auto-filled. Click Save Changes.', 'sso-for-microsoft-entra' ) . '</li>'
			. '<li>' . esc_html__( 'Test in an incognito window — click "Sign in with Microsoft" on the login page.', 'sso-for-microsoft-entra' ) . '</li>'
			. '</ol>';
	}

	/**
	 * Azure Setup help tab content.
	 *
	 * @return string
	 */
	private static function get_help_azure_setup(): string {
		return '<h3>' . esc_html__( 'Azure App Registration', 'sso-for-microsoft-entra' ) . '</h3>'
			. '<ol>'
			. '<li>' . esc_html__( 'Sign in to the Azure Portal → Microsoft Entra ID → App registrations → + New registration.', 'sso-for-microsoft-entra' ) . '</li>'
			. '<li>' . esc_html__( 'Name: "WordPress SSO", Account type: Single tenant, Redirect URI: Web →', 'sso-for-microsoft-entra' ) . ' <code>' . esc_url( home_url( '/sso/callback' ) ) . '</code></li>'
			. '<li>' . esc_html__( 'Copy the Application (client) ID and Directory (tenant) ID from the overview page.', 'sso-for-microsoft-entra' ) . '</li>'
			. '<li>' . esc_html__( 'Go to Certificates & secrets → + New client secret → copy the Value immediately.', 'sso-for-microsoft-entra' ) . '</li>'
			. '<li>' . esc_html__( 'Go to API permissions → + Add permission → Microsoft Graph → Delegated: openid, profile, email.', 'sso-for-microsoft-entra' ) . '</li>'
			. '</ol>'
			. '<p><strong>' . esc_html__( 'For OIDC:', 'sso-for-microsoft-entra' ) . '</strong> '
			. esc_html__( 'Enter Tenant ID, Client ID, and Client Secret in the Connection section below.', 'sso-for-microsoft-entra' ) . '</p>'
			. '<p><strong>' . esc_html__( 'For SAML:', 'sso-for-microsoft-entra' ) . '</strong> '
			. esc_html__( 'Use the Quick Start tab instead — just paste the metadata URL.', 'sso-for-microsoft-entra' ) . '</p>';
	}

	/**
	 * SAML Setup help tab content.
	 *
	 * @return string
	 */
	private static function get_help_saml_setup(): string {
		return '<h3>' . esc_html__( 'SAML 2.0 Configuration', 'sso-for-microsoft-entra' ) . '</h3>'
			. '<ol>'
			. '<li>' . esc_html__( 'In Azure Portal → Enterprise applications → your app → Single sign-on → SAML.', 'sso-for-microsoft-entra' ) . '</li>'
			. '<li>' . esc_html__( 'Set Basic SAML Configuration:', 'sso-for-microsoft-entra' ) . '<br>'
			. '&nbsp;&nbsp;' . esc_html__( 'Identifier (Entity ID):', 'sso-for-microsoft-entra' ) . ' <code>' . esc_html( \SFME\Plugin::get_instance()->get_option( \SFME\Plugin::OPTION_CLIENT_ID, 'your-client-id' ) ) . '</code><br>'
			. '&nbsp;&nbsp;' . esc_html__( 'Reply URL (ACS):', 'sso-for-microsoft-entra' ) . ' <code>' . esc_url( home_url( '/sso/saml-acs' ) ) . '</code></li>'
			. '<li>' . esc_html__( 'Under SAML Certificates, copy the App Federation Metadata URL.', 'sso-for-microsoft-entra' ) . '</li>'
			. '<li>' . esc_html__( 'Paste it in the Metadata URL field below and click Import Metadata.', 'sso-for-microsoft-entra' ) . '</li>'
			. '</ol>'
			. '<p><strong>' . esc_html__( 'NinjaFirewall users:', 'sso-for-microsoft-entra' ) . '</strong> '
			. esc_html__( 'Create a .htninja file in your document root to whitelist /sso/saml-acs — otherwise the firewall blocks the SAML POST data.', 'sso-for-microsoft-entra' ) . '</p>';
	}

	/**
	 * Troubleshooting help tab content.
	 *
	 * @return string
	 */
	private static function get_help_troubleshooting(): string {
		return '<h3>' . esc_html__( 'Common Issues', 'sso-for-microsoft-entra' ) . '</h3>'
			. '<dl>'
			. '<dt><strong>AADSTS50011</strong> — ' . esc_html__( 'Redirect URI mismatch', 'sso-for-microsoft-entra' ) . '</dt>'
			. '<dd>' . esc_html__( 'The redirect URI in Azure must exactly match the Redirect URI shown in Connection settings (including protocol and trailing slash).', 'sso-for-microsoft-entra' ) . '</dd>'
			. '<dt><strong>AADSTS700016</strong> �� ' . esc_html__( 'Application not found', 'sso-for-microsoft-entra' ) . '</dt>'
			. '<dd>' . esc_html__( 'The Tenant ID or Client ID is incorrect. Re-copy from Azure Portal → App registrations → Overview.', 'sso-for-microsoft-entra' ) . '</dd>'
			. '<dt><strong>' . esc_html__( 'Rate limited', 'sso-for-microsoft-entra' ) . '</strong></dt>'
			. '<dd>' . esc_html__( 'Wait for the rate limit window to expire, or adjust Max Attempts / Window in the Rate Limiting section below.', 'sso-for-microsoft-entra' ) . '</dd>'
			. '<dt><strong>' . esc_html__( 'NinjaFirewall blocks SAML callback', 'sso-for-microsoft-entra' ) . '</strong></dt>'
			. '<dd>' . esc_html__( 'Create .htninja in document root with a rule to return "ALLOW" for /sso/saml-acs requests.', 'sso-for-microsoft-entra' ) . '</dd>'
			. '</dl>'
			. '<p>' . esc_html__( 'Enable WP_DEBUG_LOG in wp-config.php and check wp-content/debug.log for detailed error messages.', 'sso-for-microsoft-entra' ) . '</p>';
	}

	// -------------------------------------------------------------------------
	// Asset enqueueing
	// -------------------------------------------------------------------------

	/**
	 * Enqueue admin JS and CSS only on the plugin's own settings page.
	 *
	 * @param string $hook_suffix Current admin page hook suffix.
	 * @return void
	 */
	public static function enqueue_assets( string $hook_suffix ): void {
		// add_options_page() generates 'settings_page_{slug}'.
		if ( 'settings_page_' . self::PAGE_SLUG !== $hook_suffix ) {
			return;
		}

		$plugin_url = SFME_PLUGIN_URL;
		$version    = SFME_VERSION;

		wp_enqueue_style(
			'sfme-admin',
			$plugin_url . 'assets/admin.css',
			array(),
			$version
		);

		wp_enqueue_script(
			'sfme-admin',
			$plugin_url . 'assets/admin.js',
			array(),
			$version,
			true
		);

		wp_localize_script(
			'sfme-admin',
			'sfme_admin',
			array(
				'ajax_url'      => admin_url( 'admin-ajax.php' ),
				'nonce'         => wp_create_nonce( 'sfme_admin_nonce' ),
				'dismiss_nonce' => wp_create_nonce( 'sfme_dismiss_notice' ),
				'strings'       => array(
					'importing'    => __( 'Importing…', 'sso-for-microsoft-entra' ),
					'import_done'  => __( 'Metadata imported successfully.', 'sso-for-microsoft-entra' ),
					'import_error' => __( 'Import failed. Please check the URL and try again.', 'sso-for-microsoft-entra' ),
					'add_row'      => __( 'Add Mapping', 'sso-for-microsoft-entra' ),
					'remove_row'   => __( 'Remove', 'sso-for-microsoft-entra' ),
					'show_secret'  => __( 'Show', 'sso-for-microsoft-entra' ),
					'hide_secret'  => __( 'Hide', 'sso-for-microsoft-entra' ),
				),
			)
		);
	}

	// -------------------------------------------------------------------------
	// Settings registration
	// -------------------------------------------------------------------------

	/**
	 * Register all settings, sections, and fields via the Settings API.
	 *
	 * @return void
	 */
	public static function register_settings(): void {
		// --- Section: Connection ---
		add_settings_section(
			'sfme_section_connection',
			__( 'Connection', 'sso-for-microsoft-entra' ),
			array( self::class, 'render_section_connection' ),
			self::PAGE_SLUG
		);

		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_TENANT_ID,
			array(
				'sanitize_callback' => array( Settings_Fields::class, 'sanitize_tenant_id' ),
				'default'           => '',
			)
		);
		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_CLIENT_ID,
			array(
				'sanitize_callback' => array( Settings_Fields::class, 'sanitize_client_id' ),
				'default'           => '',
			)
		);
		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_CLIENT_SECRET,
			array(
				'sanitize_callback' => array( self::class, 'sanitize_client_secret' ),
				'default'           => '',
			)
		);

		foreach ( Settings_Fields::connection_fields() as $field ) {
			add_settings_field(
				$field['id'],
				esc_html( $field['label'] ),
				array( self::class, 'render_field' ),
				self::PAGE_SLUG,
				'sfme_section_connection',
				$field
			);
		}

		// --- Section: Authentication ---
		add_settings_section(
			'sfme_section_authentication',
			__( 'Authentication', 'sso-for-microsoft-entra' ),
			array( self::class, 'render_section_authentication' ),
			self::PAGE_SLUG
		);

		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_AUTH_PROTOCOL,
			array(
				'sanitize_callback' => array( Settings_Fields::class, 'sanitize_protocol' ),
				'default'           => 'oidc',
			)
		);
		// M1: boolean checkbox options must use absint() so only 0 or 1 is stored.
		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_AUTO_REDIRECT,
			array( 'sanitize_callback' => 'absint' )
		);
		register_setting(
			self::OPTION_GROUP,
			'sfme_allow_local_login',
			array( 'sanitize_callback' => 'absint' )
		);

		foreach ( Settings_Fields::authentication_fields() as $field ) {
			add_settings_field(
				$field['id'],
				esc_html( $field['label'] ),
				array( self::class, 'render_field' ),
				self::PAGE_SLUG,
				'sfme_section_authentication',
				$field
			);
		}

		// --- Section: User Provisioning ---
		add_settings_section(
			'sfme_section_provisioning',
			__( 'User Provisioning', 'sso-for-microsoft-entra' ),
			array( self::class, 'render_section_provisioning' ),
			self::PAGE_SLUG
		);

		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_USER_PROVISIONING,
			array( 'sanitize_callback' => 'absint' )
		);
		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_DEFAULT_ROLE,
			array(
				'sanitize_callback' => array( Settings_Fields::class, 'sanitize_role' ),
				'default'           => 'subscriber',
			)
		);
		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_ROLE_MAP,
			array(
				'sanitize_callback' => array( Settings_Fields::class, 'sanitize_role_map' ),
				'default'           => array(),
			)
		);

		foreach ( Settings_Fields::provisioning_fields() as $field ) {
			add_settings_field(
				$field['id'],
				esc_html( $field['label'] ),
				array( self::class, 'render_field' ),
				self::PAGE_SLUG,
				'sfme_section_provisioning',
				$field
			);
		}

		// --- Section: Login Customization ---
		add_settings_section(
			'sfme_section_customization',
			__( 'Login Customization', 'sso-for-microsoft-entra' ),
			array( self::class, 'render_section_customization' ),
			self::PAGE_SLUG
		);

		register_setting(
			self::OPTION_GROUP,
			'sfme_button_text',
			array(
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => __( 'Sign in with Microsoft', 'sso-for-microsoft-entra' ),
			)
		);
		register_setting(
			self::OPTION_GROUP,
			'sfme_button_style',
			array(
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => 'default',
			)
		);

		foreach ( Settings_Fields::customization_fields() as $field ) {
			add_settings_field(
				$field['id'],
				esc_html( $field['label'] ),
				array( self::class, 'render_field' ),
				self::PAGE_SLUG,
				'sfme_section_customization',
				$field
			);
		}

		// --- Section: Rate Limiting ---
		add_settings_section(
			'sfme_section_rate_limiting',
			__( 'Rate Limiting', 'sso-for-microsoft-entra' ),
			array( self::class, 'render_section_rate_limiting' ),
			self::PAGE_SLUG
		);

		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_RATE_LIMIT_MAX,
			array(
				'sanitize_callback' => array( Settings_Fields::class, 'sanitize_positive_int' ),
				'default'           => 5,
			)
		);
		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_RATE_LIMIT_WINDOW,
			array(
				'sanitize_callback' => array( Settings_Fields::class, 'sanitize_positive_int' ),
				'default'           => 900,
			)
		);

		foreach ( Settings_Fields::rate_limiting_fields() as $field ) {
			add_settings_field(
				$field['id'],
				esc_html( $field['label'] ),
				array( self::class, 'render_field' ),
				self::PAGE_SLUG,
				'sfme_section_rate_limiting',
				$field
			);
		}

		// --- Section: Metadata Import ---
		add_settings_section(
			'sfme_section_metadata',
			__( 'SAML Metadata Import', 'sso-for-microsoft-entra' ),
			array( self::class, 'render_section_metadata' ),
			self::PAGE_SLUG
		);

		register_setting(
			self::OPTION_GROUP,
			\SFME\Plugin::OPTION_SAML_METADATA,
			array(
				// Security (H2): sanitize_textarea_field() destroys XML by stripping tags
				// and encoding entities. Use a callback that validates the XML is parseable
				// via XML_Security::safe_load_xml() and re-serialises from the DOM so only
				// structurally valid XML is ever stored. Invalid input keeps the old value.
				'sanitize_callback' => array( self::class, 'sanitize_saml_metadata' ),
				'default'           => '',
			)
		);

		add_settings_field(
			'sfme_metadata_url',
			esc_html__( 'Metadata URL', 'sso-for-microsoft-entra' ),
			array( self::class, 'render_metadata_import_field' ),
			self::PAGE_SLUG,
			'sfme_section_metadata'
		);
	}

	// -------------------------------------------------------------------------
	// Sanitization
	// -------------------------------------------------------------------------

	/**
	 * Sanitize and encrypt the client secret before it is stored.
	 *
	 * An empty submission means "keep existing value".
	 *
	 * @param mixed $value Raw posted value.
	 * @return string Encrypted secret, or the previously stored encrypted value.
	 */
	public static function sanitize_client_secret( $value ): string {
		$value = trim( (string) $value );

		// Empty means the user left the field blank — preserve the existing value.
		if ( '' === $value ) {
			return (string) get_option( \SFME\Plugin::OPTION_CLIENT_SECRET, '' );
		}

		return \SFME\Security\Encryption::encrypt( $value );
	}

	/**
	 * Validate and sanitize SAML federation metadata XML before storage.
	 *
	 * Attempts to parse the submitted value through XML_Security::safe_load_xml()
	 * (which applies XXE hardening). If parsing succeeds the value is
	 * re-serialised via DOMDocument::saveXML() to normalise whitespace and
	 * remove any injected markup. If parsing fails the previously stored value
	 * is returned unchanged so the option is never set to invalid XML.
	 *
	 * Using sanitize_textarea_field() here would mangle '<', '>', and '&'
	 * characters that are structural parts of XML, breaking the SAML library.
	 *
	 * @param mixed $value Raw posted value.
	 * @return string Valid XML string, or the previously stored value on failure.
	 */
	public static function sanitize_saml_metadata( $value ): string {
		$value = (string) $value;

		if ( '' === trim( $value ) ) {
			// Empty submission — preserve the existing value (may have been
			// imported via AJAX). The metadata field is not part of the main
			// form, so it arrives empty on every normal settings save.
			return (string) get_option( \SFME\Plugin::OPTION_SAML_METADATA, '' );
		}

		$dom = \SFME\XML\XML_Security::safe_load_xml( $value );

		if ( is_wp_error( $dom ) ) {
			// Invalid XML — keep the previously stored value to avoid data loss.
			add_settings_error(
				\SFME\Plugin::OPTION_SAML_METADATA,
				'saml_metadata_invalid',
				__( 'SAML metadata XML is invalid and was not saved.', 'sso-for-microsoft-entra' ),
				'error'
			);
			return (string) get_option( \SFME\Plugin::OPTION_SAML_METADATA, '' );
		}

		return $dom->saveXML();
	}

	// -------------------------------------------------------------------------
	// Section render callbacks
	// -------------------------------------------------------------------------

	/**
	 * Render intro text for the Connection section.
	 *
	 * @return void
	 */
	public static function render_section_connection(): void {
		echo '<p>' . esc_html__( 'Enter the Azure app registration credentials. All values are required for SSO to function.', 'sso-for-microsoft-entra' ) . '</p>';
	}

	/**
	 * Render intro text for the Authentication section.
	 *
	 * @return void
	 */
	public static function render_section_authentication(): void {
		echo '<p>' . esc_html__( 'Choose how users authenticate against Microsoft Entra ID.', 'sso-for-microsoft-entra' ) . '</p>';
	}

	/**
	 * Render intro text for the User Provisioning section.
	 *
	 * @return void
	 */
	public static function render_section_provisioning(): void {
		echo '<p>' . esc_html__( 'Control how WordPress accounts are created and maintained for Entra users.', 'sso-for-microsoft-entra' ) . '</p>';
	}

	/**
	 * Render intro text for the Login Customization section.
	 *
	 * @return void
	 */
	public static function render_section_customization(): void {
		echo '<p>' . esc_html__( 'Customise the appearance of the Microsoft sign-in button on the login page.', 'sso-for-microsoft-entra' ) . '</p>';
	}

	/**
	 * Render intro text for the Rate Limiting section.
	 *
	 * @return void
	 */
	public static function render_section_rate_limiting(): void {
		echo '<p>' . esc_html__( 'Control how many SSO login attempts are allowed per IP address within a time window.', 'sso-for-microsoft-entra' ) . '</p>';
	}

	/**
	 * Render intro text for the Metadata Import section.
	 *
	 * @return void
	 */
	public static function render_section_metadata(): void {
		echo '<p>' . esc_html__( 'Import SAML federation metadata from your Entra app federation metadata URL. Only required when using the SAML 2.0 protocol.', 'sso-for-microsoft-entra' ) . '</p>';
	}

	// -------------------------------------------------------------------------
	// Field render callbacks
	// -------------------------------------------------------------------------

	/**
	 * Generic field render dispatcher — delegates based on field type.
	 *
	 * @param array $field Field definition from Settings_Fields.
	 * @return void
	 */
	public static function render_field( array $field ): void {
		$type  = $field['type'] ?? 'text';
		$id    = $field['id'] ?? '';
		$value = get_option( $id, $field['default'] ?? '' );
		$desc  = $field['description'] ?? '';

		switch ( $type ) {
			case 'text':
				printf(
					'<input type="text" id="%1$s" name="%1$s" value="%2$s" class="regular-text" />',
					esc_attr( $id ),
					esc_attr( (string) $value )
				);
				break;

			case 'number':
				printf(
					'<input type="number" id="%1$s" name="%1$s" value="%2$s" class="small-text" min="%3$s" />',
					esc_attr( $id ),
					esc_attr( (string) $value ),
					esc_attr( (string) ( $field['min'] ?? '1' ) )
				);
				break;

			case 'password':
				// Never output the encrypted blob into the field; show a placeholder.
				$has_value = '' !== (string) $value;
				printf(
					'<div class="sfme-secret-field">'
					. '<input type="password" id="%1$s" name="%1$s" value="" class="regular-text" autocomplete="new-password" placeholder="%2$s" />'
					. '<button type="button" class="button sfme-toggle-secret" data-target="%1$s">%3$s</button>'
					. '</div>',
					esc_attr( $id ),
					$has_value
						? esc_attr__( '(saved — enter new value to replace)', 'sso-for-microsoft-entra' )
						: esc_attr__( 'Enter client secret', 'sso-for-microsoft-entra' ),
					esc_html__( 'Show', 'sso-for-microsoft-entra' )
				);
				break;

			case 'readonly':
				// Uses /sso/callback front-end endpoint instead of wp-login.php.
				$redirect_uri = home_url( '/sso/callback' );
				printf(
					'<input type="text" id="%1$s" name="%1$s" value="%2$s" class="regular-text" readonly />',
					esc_attr( $id ),
					esc_attr( $redirect_uri )
				);
				break;

			case 'checkbox':
				printf(
					'<label><input type="checkbox" id="%1$s" name="%1$s" value="1" %2$s /> %3$s</label>',
					esc_attr( $id ),
					checked( '1', (string) $value, false ),
					esc_html( $desc )
				);
				$desc = ''; // already rendered inline.
				break;

			case 'radio':
				$options = $field['options'] ?? array();
				$output  = '';
				foreach ( $options as $option_value => $option_label ) {
					$output .= sprintf(
						'<label style="display:block;margin-bottom:4px"><input type="radio" name="%1$s" value="%2$s" %3$s /> %4$s</label>',
						esc_attr( $id ),
						esc_attr( $option_value ),
						checked( $option_value, (string) $value, false ),
						esc_html( $option_label )
					);
				}
				echo $output; // phpcs:ignore WordPress.Security.EscapeOutput -- already escaped above.
				break;

			case 'select':
				$options = $field['options'] ?? array();
				printf( '<select id="%1$s" name="%1$s">', esc_attr( $id ) );
				foreach ( $options as $option_value => $option_label ) {
					printf(
						'<option value="%1$s" %2$s>%3$s</option>',
						esc_attr( $option_value ),
						selected( $option_value, (string) $value, false ),
						esc_html( $option_label )
					);
				}
				echo '</select>';
				break;

			case 'select_roles':
				$roles = wp_roles()->get_names();
				printf( '<select id="%1$s" name="%1$s">', esc_attr( $id ) );
				foreach ( $roles as $role_slug => $role_name ) {
					printf(
						'<option value="%1$s" %2$s>%3$s</option>',
						esc_attr( $role_slug ),
						selected( $role_slug, (string) $value, false ),
						esc_html( translate_user_role( $role_name ) )
					);
				}
				echo '</select>';
				break;

			case 'role_mapping':
				self::render_role_mapping_field( $id, $value );
				$desc = ''; // rendered inside the field.
				break;
		}

		if ( $desc ) {
			printf( '<p class="description">%s</p>', esc_html( $desc ) );
		}
	}

	/**
	 * Render the metadata import field (URL input + import button).
	 *
	 * @return void
	 */
	public static function render_metadata_import_field(): void {
		?>
		<div class="sfme-metadata-import">
			<input
				type="url"
				id="sfme_metadata_url"
				name="sfme_metadata_url"
				value=""
				class="regular-text"
				placeholder="<?php esc_attr_e( 'https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml', 'sso-for-microsoft-entra' ); ?>"
			/>
			<button type="button" id="sfme-import-metadata" class="button button-secondary">
				<?php esc_html_e( 'Import Metadata', 'sso-for-microsoft-entra' ); ?>
			</button>
			<span id="sfme-import-status" class="sfme-import-status" aria-live="polite"></span>
		</div>
		<p class="description">
			<?php esc_html_e( 'Paste the App Federation Metadata URL from your Entra Enterprise Application and click Import to populate SAML settings automatically.', 'sso-for-microsoft-entra' ); ?>
		</p>
		<?php
	}

	/**
	 * Render the role-mapping repeatable rows.
	 *
	 * @param string $option_id   Option key.
	 * @param mixed  $saved_value Currently saved mapping array.
	 * @return void
	 */
	private static function render_role_mapping_field( string $option_id, $saved_value ): void {
		$mapping = is_array( $saved_value ) ? $saved_value : array();
		$roles   = wp_roles()->get_names();

		echo '<div id="sfme-role-mapping" class="sfme-role-mapping">';
		echo '<table class="sfme-role-mapping-table widefat striped">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Entra Group Object ID', 'sso-for-microsoft-entra' ) . '</th>';
		echo '<th>' . esc_html__( 'WordPress Role', 'sso-for-microsoft-entra' ) . '</th>';
		echo '<th></th>';
		echo '</tr></thead>';
		echo '<tbody id="sfme-role-mapping-rows">';

		if ( ! empty( $mapping ) ) {
			foreach ( $mapping as $group_id => $role ) {
				self::render_role_mapping_row( $option_id, (string) $group_id, (string) $role, $roles );
			}
		}

		echo '</tbody>';
		echo '</table>';

		printf(
			'<button type="button" id="sfme-add-role-mapping" class="button button-secondary" style="margin-top:8px">%s</button>',
			esc_html__( 'Add Mapping', 'sso-for-microsoft-entra' )
		);

		// Hidden template row cloned by JS.
		echo '<template id="sfme-role-row-template">';
		self::render_role_mapping_row( $option_id, '', '', $roles );
		echo '</template>';

		echo '</div>';
	}

	/**
	 * Render a single role-mapping table row.
	 *
	 * @param string $option_id Option key (used in input names).
	 * @param string $group_id  Entra group Object ID value.
	 * @param string $role      WordPress role slug value.
	 * @param array  $roles     All available WP roles.
	 * @return void
	 */
	private static function render_role_mapping_row( string $option_id, string $group_id, string $role, array $roles ): void {
		echo '<tr class="sfme-role-mapping-row">';

		printf(
			'<td><input type="text" name="%s[rows][][group_id]" value="%s" class="regular-text" placeholder="%s" /></td>',
			esc_attr( $option_id ),
			esc_attr( $group_id ),
			esc_attr__( 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', 'sso-for-microsoft-entra' )
		);

		printf( '<td><select name="%s[rows][][role]">', esc_attr( $option_id ) );
		foreach ( $roles as $role_slug => $role_name ) {
			printf(
				'<option value="%s" %s>%s</option>',
				esc_attr( $role_slug ),
				selected( $role_slug, $role, false ),
				esc_html( translate_user_role( $role_name ) )
			);
		}
		echo '</select></td>';

		printf(
			'<td><button type="button" class="button button-link-delete sfme-remove-row">%s</button></td>',
			esc_html__( 'Remove', 'sso-for-microsoft-entra' )
		);

		echo '</tr>';
	}

	// -------------------------------------------------------------------------
	// Page render
	// -------------------------------------------------------------------------

	/**
	 * Output the settings page HTML.
	 *
	 * @return void
	 */
	public static function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'sso-for-microsoft-entra' ) );
		}

		$template = SFME_PLUGIN_DIR . 'templates/admin-settings.php';

		if ( file_exists( $template ) ) {
			include $template;
		}
	}

	// -------------------------------------------------------------------------
	// URL parsing helpers
	// -------------------------------------------------------------------------

	/**
	 * Extract tenant ID and client ID from a federation metadata URL.
	 *
	 * Parses URLs in the format:
	 * https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid={client_id}
	 *
	 * @param string $url Federation metadata URL.
	 * @return array{tenant_id: string, client_id: string} Extracted IDs (empty strings if not found).
	 */
	private static function extract_ids_from_metadata_url( string $url ): array {
		$result = array(
			'tenant_id' => '',
			'client_id' => '',
		);

		$parsed = wp_parse_url( $url );
		if ( ! $parsed ) {
			return $result;
		}

		// Extract tenant ID from path: /tenant-guid/federationmetadata/etc.
		if ( ! empty( $parsed['path'] ) ) {
			if ( preg_match( '#/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/#i', $parsed['path'], $matches ) ) {
				$result['tenant_id'] = strtolower( $matches[1] );
			}
		}

		// Extract client ID from query string appid parameter.
		if ( ! empty( $parsed['query'] ) ) {
			parse_str( $parsed['query'], $query_params );
			if ( ! empty( $query_params['appid'] ) && Settings_Fields::is_guid( $query_params['appid'] ) ) {
				$result['client_id'] = strtolower( $query_params['appid'] );
			}
		}

		return $result;
	}

	// -------------------------------------------------------------------------
	// AJAX: Metadata import
	// -------------------------------------------------------------------------

	/**
	 * Handle AJAX request to import SAML federation metadata from a URL.
	 *
	 * @return void
	 */
	public static function handle_import_metadata(): void {
		check_ajax_referer( 'sfme_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array( 'message' => esc_html__( 'Insufficient permissions.', 'sso-for-microsoft-entra' ) ),
				403
			);
		}

		$url = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';

		if ( ! $url ) {
			wp_send_json_error(
				array( 'message' => esc_html__( 'No URL provided.', 'sso-for-microsoft-entra' ) )
			);
		}

		// Extract tenant ID and client ID from the metadata URL before fetching.
		$extracted = self::extract_ids_from_metadata_url( $url );

		$dom = \SFME\XML\XML_Security::safe_load_xml_from_url( $url );

		if ( is_wp_error( $dom ) ) {
			wp_send_json_error(
				array( 'message' => $dom->get_error_message() )
			);
		}

		// Security (H-2): pass through sanitize_saml_metadata() so the AJAX path
		// uses the same validation as the Settings API form submission.
		update_option(
			\SFME\Plugin::OPTION_SAML_METADATA,
			self::sanitize_saml_metadata( $dom->saveXML() )
		);

		// Auto-populate tenant ID and client ID extracted from the URL.
		if ( ! empty( $extracted['tenant_id'] ) ) {
			update_option( \SFME\Plugin::OPTION_TENANT_ID, $extracted['tenant_id'] );
		}
		if ( ! empty( $extracted['client_id'] ) ) {
			update_option( \SFME\Plugin::OPTION_CLIENT_ID, $extracted['client_id'] );
		}

		// Auto-switch to SAML protocol since federation metadata is SAML-specific.
		update_option( \SFME\Plugin::OPTION_AUTH_PROTOCOL, 'saml' );

		// Build a descriptive success message.
		$auto_filled = array();
		if ( ! empty( $extracted['tenant_id'] ) ) {
			$auto_filled[] = 'Tenant ID';
		}
		if ( ! empty( $extracted['client_id'] ) ) {
			$auto_filled[] = 'Client ID';
		}
		$auto_filled[] = 'Protocol → SAML';

		$message = __( 'Metadata imported successfully.', 'sso-for-microsoft-entra' );
		if ( $auto_filled ) {
			/* translators: %s: comma-separated list of auto-filled field names */
			$message .= ' ' . sprintf( __( 'Auto-filled: %s.', 'sso-for-microsoft-entra' ), implode( ', ', $auto_filled ) );
		}

		wp_send_json_success(
			array(
				'message'   => $message,
				'tenant_id' => $extracted['tenant_id'],
				'client_id' => $extracted['client_id'],
			)
		);
	}
}
