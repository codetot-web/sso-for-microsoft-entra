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
// Matches any option whose name starts with "sfme_".
// -------------------------------------------------------------------------
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup requires direct queries; no caching needed for DELETE.
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE 'microsoft\_entra\_sso\_%'"
);

// -------------------------------------------------------------------------
// 2. Delete all user meta stored by this plugin
// User_Meta keys are prefixed with "_sfme_".
// -------------------------------------------------------------------------
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	"DELETE FROM {$wpdb->usermeta}
	 WHERE meta_key LIKE '\_messo\_%'"
);

// -------------------------------------------------------------------------
// 3. Delete all transients used by this plugin
// Transients are stored as options with the "_transient_" prefix; the
// plugin namespaces its own transients under "_transient_sfme_".
// -------------------------------------------------------------------------
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '\_transient\_messo\_%'
	    OR option_name LIKE '\_transient\_timeout\_messo\_%'"
);
