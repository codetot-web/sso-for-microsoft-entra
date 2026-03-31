<?php
/**
 * Admin notices for the Microsoft Entra SSO plugin.
 *
 * Checks configuration completeness and encryption availability, then
 * surfaces dismissible admin notices to help administrators resolve issues
 * before the SSO integration is used in production.
 *
 * @package MicrosoftEntraSSO\Admin
 */

namespace MicrosoftEntraSSO\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Class Admin_Notices
 *
 * Each notice has a unique ID that maps to a user meta key used for
 * per-user dismissal tracking.
 */
class Admin_Notices {

	/**
	 * User meta key prefix for dismissed notices.
	 *
	 * @var string
	 */
	const DISMISSED_META_PREFIX = 'messo_notice_dismissed_';

	// -------------------------------------------------------------------------
	// Bootstrap
	// -------------------------------------------------------------------------

	/**
	 * Register the admin_notices hook.
	 *
	 * @return void
	 */
	public static function register(): void {
		add_action( 'admin_notices', array( self::class, 'render_notices' ) );
		// L3: wp_ajax_messo_dismiss_notice is already registered by Plugin::init().
		// Do not add it here to avoid a duplicate hook that fires the handler twice.
	}

	// -------------------------------------------------------------------------
	// Hooks
	// -------------------------------------------------------------------------

	/**
	 * Evaluate and output applicable admin notices.
	 *
	 * @return void
	 */
	public static function render_notices(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$plugin = \MicrosoftEntraSSO\Plugin::get_instance();

		// Notice: encryption unavailable.
		$no_sodium  = ! function_exists( 'sodium_crypto_secretbox' );
		$no_openssl = ! extension_loaded( 'openssl' );

		if ( $no_sodium && $no_openssl ) {
			self::render_notice(
				'encryption_unavailable',
				'error',
				__( '<strong>Microsoft Entra SSO:</strong> Neither the <code>sodium</code> nor the <code>openssl</code> PHP extension is available. The client secret cannot be encrypted. Please enable at least one extension.', 'microsoft-entra-sso' ),
				false // not dismissible — must be fixed.
			);
		}

		// Notice: missing required fields.
		$missing = array();

		if ( ! $plugin->get_option( \MicrosoftEntraSSO\Plugin::OPTION_TENANT_ID ) ) {
			$missing[] = __( 'Tenant ID', 'microsoft-entra-sso' );
		}

		if ( ! $plugin->get_option( \MicrosoftEntraSSO\Plugin::OPTION_CLIENT_ID ) ) {
			$missing[] = __( 'Client ID', 'microsoft-entra-sso' );
		}

		if ( ! $plugin->get_option( \MicrosoftEntraSSO\Plugin::OPTION_CLIENT_SECRET ) ) {
			$missing[] = __( 'Client Secret', 'microsoft-entra-sso' );
		}

		if ( ! empty( $missing ) ) {
			$notice_id = 'missing_required_fields';

			if ( ! self::is_dismissed( $notice_id ) ) {
				$settings_url = admin_url( 'options-general.php?page=microsoft-entra-sso' );
				$field_list   = implode( ', ', array_map( 'esc_html', $missing ) );

				self::render_notice(
					$notice_id,
					'warning',
					sprintf(
						/* translators: 1: comma-separated field names, 2: settings page URL */
						__( '<strong>Microsoft Entra SSO:</strong> The following required fields are not configured: %1$s. <a href="%2$s">Configure settings &rarr;</a>', 'microsoft-entra-sso' ),
						$field_list,
						esc_url( $settings_url )
					),
					true
				);
			}
		}
	}

	/**
	 * Handle AJAX request to dismiss a notice.
	 *
	 * @return void
	 */
	public static function handle_dismiss(): void {
		check_ajax_referer( 'messo_dismiss_notice', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '', '', array( 'response' => 403 ) );
		}

		$notice_id = isset( $_POST['notice_id'] ) ? sanitize_key( $_POST['notice_id'] ) : '';

		if ( ! $notice_id ) {
			wp_send_json_error( array( 'message' => 'Invalid notice ID.' ) );
		}

		update_user_meta(
			get_current_user_id(),
			self::DISMISSED_META_PREFIX . $notice_id,
			'1'
		);

		wp_send_json_success();
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Check whether the current user has dismissed a specific notice.
	 *
	 * @param string $notice_id Unique notice identifier.
	 * @return bool True when dismissed.
	 */
	private static function is_dismissed( string $notice_id ): bool {
		return (bool) get_user_meta(
			get_current_user_id(),
			self::DISMISSED_META_PREFIX . $notice_id,
			true
		);
	}

	/**
	 * Output a single admin notice.
	 *
	 * @param string $notice_id   Unique notice identifier (used for dismissal).
	 * @param string $type        Notice type: 'error', 'warning', 'success', 'info'.
	 * @param string $message     Already-escaped HTML message.
	 * @param bool   $dismissible Whether the notice can be dismissed by the user.
	 * @return void
	 */
	private static function render_notice( string $notice_id, string $type, string $message, bool $dismissible ): void {
		$class = 'notice notice-' . esc_attr( $type );
		if ( $dismissible ) {
			$class .= ' is-dismissible messo-dismissible';
		}

		printf(
			'<div class="%s" data-notice-id="%s" data-nonce="%s"><p>%s</p></div>',
			esc_attr( $class ),
			esc_attr( $notice_id ),
			esc_attr( wp_create_nonce( 'messo_dismiss_notice' ) ),
			wp_kses(
				$message,
				array(
					'strong' => array(),
					'a'      => array( 'href' => array() ),
					'code'   => array(),
				)
			)
		);
	}
}
