/**
 * Microsoft Entra SSO — Admin JavaScript (vanilla JS, no jQuery).
 *
 * Handles:
 *  1. Client secret visibility toggle.
 *  2. Dismissible admin notices.
 *
 * @package SFME
 */

( function () {
	'use strict';

	/* -----------------------------------------------------------------------
		Guard: sfme_admin must be localised before this script runs.
		----------------------------------------------------------------------- */
	if ( typeof sfme_admin === 'undefined' ) {
		return;
	}

	var ajaxUrl = sfme_admin.ajax_url;
	var nonce   = sfme_admin.nonce;
	var strings = sfme_admin.strings;

	/* -----------------------------------------------------------------------
		1. Client secret visibility toggle
		----------------------------------------------------------------------- */
	function initSecretToggle() {
		document.addEventListener(
			'click',
			function ( event ) {
				var btn = event.target;
				if ( ! btn || ! btn.classList.contains( 'sfme-toggle-secret' ) ) {
					return;
				}

				var targetId = btn.getAttribute( 'data-target' );
				if ( ! targetId ) {
					return;
				}

				var input = document.getElementById( targetId );
				if ( ! input ) {
					return;
				}

				if ( 'password' === input.type ) {
					input.type      = 'text';
					btn.textContent = strings.hide_secret;
				} else {
					input.type      = 'password';
					btn.textContent = strings.show_secret;
				}
			}
		);
	}

	/* -----------------------------------------------------------------------
		2. Dismissible admin notices
		----------------------------------------------------------------------- */
	function initDismissibleNotices() {
		document.addEventListener(
			'click',
			function ( event ) {
				// WP adds a .notice-dismiss button inside .is-dismissible notices.
				var btn = event.target;
				if ( ! btn || ! btn.classList.contains( 'notice-dismiss' ) ) {
					return;
				}

				var notice = btn.closest( '.sfme-dismissible' );
				if ( ! notice ) {
					return;
				}

				var noticeId     = notice.getAttribute( 'data-notice-id' );
				var dismissNonce = notice.getAttribute( 'data-nonce' );

				if ( ! noticeId || ! dismissNonce ) {
					return;
				}

				var body = new URLSearchParams();
				body.append( 'action',    'sfme_dismiss_notice' );
				body.append( 'nonce',     dismissNonce );
				body.append( 'notice_id', noticeId );

				fetch(
					ajaxUrl,
					{
						method:  'POST',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body:    body.toString(),
					}
				);
				// Fire-and-forget — the notice is already hidden by WP's core JS.
			}
		);
	}

	/* -----------------------------------------------------------------------
		Boot
		----------------------------------------------------------------------- */
	document.addEventListener(
		'DOMContentLoaded',
		function () {
			initSecretToggle();
			initDismissibleNotices();
		}
	);

}() );
