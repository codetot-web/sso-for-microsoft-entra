<?php
/**
 * Database upgrade routines for the Microsoft Entra SSO plugin.
 *
 * Uses a versioned option (sfme_db_version) to track which upgrades have
 * been applied. On every admin page load the upgrader compares the stored
 * version against the plugin's current DB version constant and runs any
 * pending migrations.
 *
 * @package SFME
 */

namespace SFME;

defined( 'ABSPATH' ) || exit;

/**
 * Class Upgrader
 */
class Upgrader {

	/**
	 * Current database version.
	 *
	 * Increment this constant when adding a new migration step so that
	 * the upgrader runs the new step on the next admin page load.
	 *
	 * @var int
	 */
	const DB_VERSION = 1;

	/**
	 * Option name that stores the current database version.
	 *
	 * @var string
	 */
	const DB_VERSION_OPTION = 'sfme_db_version';

	/**
	 * Register the upgrade check on admin_init.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'admin_init', array( __CLASS__, 'maybe_upgrade' ) );
	}

	/**
	 * Run pending database upgrades if the stored version is out of date.
	 *
	 * Compares the option value against DB_VERSION and sequentially runs
	 * every migration step that has not yet been applied.
	 *
	 * @return void
	 */
	public static function maybe_upgrade(): void {
		$stored_version = (int) get_option( self::DB_VERSION_OPTION, 0 );

		if ( $stored_version >= self::DB_VERSION ) {
			return;
		}

		self::do_upgrade( $stored_version );

		update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Execute all pending upgrade steps.
	 *
	 * @param int $from_version The version currently stored in the database.
	 * @return void
	 */
	private static function do_upgrade( int $from_version ): void {
		$upgrades = array(
			1 => array( __CLASS__, 'upgrade_v1' ),
		);

		foreach ( $upgrades as $version => $callback ) {
			if ( $version > $from_version ) {
				call_user_func( $callback );
			}
		}
	}

	/**
	 * Upgrade step 1 — Migrate legacy option keys to the current sfme_ prefix.
	 *
	 * Earlier versions of the plugin stored options under the
	 * "microsoft_entra_sso_" prefix. This step migrates any remaining
	 * legacy options to the "sfme_" prefix and removes the old keys.
	 *
	 * @return void
	 */
	private static function upgrade_v1(): void {
		$migrate_keys = array(
			'microsoft_entra_sso_tenant_id'         => 'sfme_tenant_id',
			'microsoft_entra_sso_client_id'         => 'sfme_client_id',
			'microsoft_entra_sso_client_secret'     => 'sfme_client_secret',
			'microsoft_entra_sso_auto_redirect'     => 'sfme_auto_redirect',
			'microsoft_entra_sso_user_provisioning' => 'sfme_user_provisioning',
			'microsoft_entra_sso_rate_limit_max'    => 'sfme_rate_limit_max',
			'microsoft_entra_sso_rate_limit_window' => 'sfme_rate_limit_window',
			'microsoft_entra_sso_button_text'       => 'sfme_button_text',
			'microsoft_entra_sso_button_style'      => 'sfme_button_style',
			'microsoft_entra_sso_allow_local_login' => 'sfme_allow_local_login',
		);

		foreach ( $migrate_keys as $old_key => $new_key ) {
			$old_value = get_option( $old_key, null );
			if ( null !== $old_value && false === get_option( $new_key, null ) ) {
				update_option( $new_key, $old_value );
				delete_option( $old_key );
			}
		}
	}
}
