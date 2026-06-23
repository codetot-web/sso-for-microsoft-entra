<?php
/**
 * Uninstall routine for Microsoft Entra SSO.
 *
 * Executed automatically by WordPress when the user deletes the plugin from
 * the Plugins screen. Cleans up all persistent data the plugin stored so that
 * no orphaned rows remain in the database.
 *
 * @package SFME
 */

// Guard: abort unless WordPress triggered this file during a real uninstall.
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

// -------------------------------------------------------------------------
// 1. Delete all plugin options
// Strikes both the current "sfme_" namespace and the legacy
// "microsoft_entra_sso_" prefix from earlier versions.
// -------------------------------------------------------------------------
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup requires direct queries; no caching needed for DELETE.
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE 'sfme\_%'
	    OR option_name LIKE 'microsoft\_entra\_sso\_%'"
);

// -------------------------------------------------------------------------
// 2. Delete all user meta stored by this plugin
// Covers the current "_sfme_" keys, the legacy "_messo_" keys, and the
// admin-notice dismissal keys.
// -------------------------------------------------------------------------
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	"DELETE FROM {$wpdb->usermeta}
	 WHERE meta_key LIKE '\_sfme\_%'
	    OR meta_key LIKE '\_messo\_%'
	    OR meta_key LIKE 'sfme\_notice\_dismissed\_%'"
);

// -------------------------------------------------------------------------
// 3. Delete all transients used by this plugin
// Transients are stored as options with the "_transient_" prefix; the
// plugin namespaces its own transients under "_transient_sfme_".
// Also cleans up the legacy "_transient_messo_" namespace.
// -------------------------------------------------------------------------
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '\_transient\_sfme\_%'
	    OR option_name LIKE '\_transient\_timeout\_sfme\_%'
	    OR option_name LIKE '\_transient\_messo\_%'
	    OR option_name LIKE '\_transient\_timeout\_messo\_%'"
);
