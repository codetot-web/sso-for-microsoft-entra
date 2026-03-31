<?php
/**
 * Uninstall routine for Microsoft Entra SSO.
 *
 * Executed automatically by WordPress when the user deletes the plugin from
 * the Plugins screen. Cleans up all persistent data the plugin stored so that
 * no orphaned rows remain in the database.
 *
 * @package MicrosoftEntraSSO
 */

// Guard: abort unless WordPress triggered this file during a real uninstall.
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

// -------------------------------------------------------------------------
// 1. Delete all plugin options
//    Matches any option whose name starts with "microsoft_entra_sso_".
// -------------------------------------------------------------------------
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE 'microsoft\_entra\_sso\_%'"
);

// -------------------------------------------------------------------------
// 2. Delete all user meta stored by this plugin
//    All meta keys are prefixed with "_microsoft_entra_sso_".
// -------------------------------------------------------------------------
$wpdb->query(
	"DELETE FROM {$wpdb->usermeta}
	 WHERE meta_key LIKE '\_microsoft\_entra\_sso\_%'"
);

// -------------------------------------------------------------------------
// 3. Delete all transients used by this plugin
//    Transients are stored as options with the "_transient_" prefix; the
//    plugin namespaces its own transients under "_transient_messo_".
// -------------------------------------------------------------------------
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '\_transient\_messo\_%'
	    OR option_name LIKE '\_transient\_timeout\_messo\_%'"
);
