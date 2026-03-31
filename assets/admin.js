/**
 * Microsoft Entra SSO — Admin JavaScript (vanilla JS, no jQuery).
 *
 * Handles:
 *  1. Metadata import via AJAX.
 *  2. Role-mapping row add / remove.
 *  3. Client secret visibility toggle.
 *  4. Dismissible admin notices.
 */

( function () {
	'use strict';

	/* -----------------------------------------------------------------------
	   Guard: messo_admin must be localised before this script runs.
	   ----------------------------------------------------------------------- */
	if ( typeof messo_admin === 'undefined' ) {
		return;
	}

	var ajaxUrl  = messo_admin.ajax_url;
	var nonce    = messo_admin.nonce;
	var strings  = messo_admin.strings;

	/* -----------------------------------------------------------------------
	   1. Metadata import
	   ----------------------------------------------------------------------- */
	function initMetadataImport() {
		var btn    = document.getElementById( 'messo-import-metadata' );
		var urlIn  = document.getElementById( 'messo_metadata_url' );
		var status = document.getElementById( 'messo-import-status' );

		if ( ! btn || ! urlIn || ! status ) {
			return;
		}

		btn.addEventListener( 'click', function () {
			var url = urlIn.value.trim();
			if ( ! url ) {
				setStatus( status, strings.import_error, true );
				return;
			}

			btn.disabled = true;
			setStatus( status, strings.importing, false );

			var body = new URLSearchParams();
			body.append( 'action', 'messo_import_metadata' );
			body.append( 'nonce',  nonce );
			body.append( 'url',    url );

			fetch( ajaxUrl, {
				method:  'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body:    body.toString(),
			} )
				.then( function ( response ) {
					return response.json();
				} )
				.then( function ( data ) {
					btn.disabled = false;
					if ( data.success ) {
						setStatus( status, data.data && data.data.message ? data.data.message : strings.import_done, false );
					} else {
						var msg = data.data && data.data.message ? data.data.message : strings.import_error;
						setStatus( status, msg, true );
					}
				} )
				.catch( function () {
					btn.disabled = false;
					setStatus( status, strings.import_error, true );
				} );
		} );
	}

	/**
	 * Update the status indicator element.
	 *
	 * @param {HTMLElement} el      Status element.
	 * @param {string}      message Text to display.
	 * @param {boolean}     isError Whether to apply error styling.
	 */
	function setStatus( el, message, isError ) {
		el.textContent = message;
		if ( isError ) {
			el.classList.add( 'is-error' );
		} else {
			el.classList.remove( 'is-error' );
		}
	}

	/* -----------------------------------------------------------------------
	   2. Role-mapping rows — add / remove
	   ----------------------------------------------------------------------- */
	function initRoleMapping() {
		var container = document.getElementById( 'messo-role-mapping' );
		var addBtn    = document.getElementById( 'messo-add-role-mapping' );
		var tbody     = document.getElementById( 'messo-role-mapping-rows' );
		var template  = document.getElementById( 'messo-role-row-template' );

		if ( ! container || ! addBtn || ! tbody || ! template ) {
			return;
		}

		// Delegate remove-row clicks to the tbody.
		tbody.addEventListener( 'click', function ( event ) {
			var target = event.target;
			if ( target && target.classList.contains( 'messo-remove-row' ) ) {
				var row = target.closest( '.messo-role-mapping-row' );
				if ( row ) {
					row.parentNode.removeChild( row );
				}
			}
		} );

		addBtn.addEventListener( 'click', function () {
			var clone = document.importNode( template.content, true );
			tbody.appendChild( clone );
		} );
	}

	/* -----------------------------------------------------------------------
	   3. Client secret visibility toggle
	   ----------------------------------------------------------------------- */
	function initSecretToggle() {
		document.addEventListener( 'click', function ( event ) {
			var btn = event.target;
			if ( ! btn || ! btn.classList.contains( 'messo-toggle-secret' ) ) {
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
				input.type  = 'text';
				btn.textContent = strings.hide_secret;
			} else {
				input.type  = 'password';
				btn.textContent = strings.show_secret;
			}
		} );
	}

	/* -----------------------------------------------------------------------
	   4. Dismissible admin notices
	   ----------------------------------------------------------------------- */
	function initDismissibleNotices() {
		document.addEventListener( 'click', function ( event ) {
			// WP adds a .notice-dismiss button inside .is-dismissible notices.
			var btn = event.target;
			if ( ! btn || ! btn.classList.contains( 'notice-dismiss' ) ) {
				return;
			}

			var notice = btn.closest( '.messo-dismissible' );
			if ( ! notice ) {
				return;
			}

			var noticeId     = notice.getAttribute( 'data-notice-id' );
			var dismissNonce = notice.getAttribute( 'data-nonce' );

			if ( ! noticeId || ! dismissNonce ) {
				return;
			}

			var body = new URLSearchParams();
			body.append( 'action',    'messo_dismiss_notice' );
			body.append( 'nonce',     dismissNonce );
			body.append( 'notice_id', noticeId );

			fetch( ajaxUrl, {
				method:  'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body:    body.toString(),
			} );
			// Fire-and-forget — the notice is already hidden by WP's core JS.
		} );
	}

	/* -----------------------------------------------------------------------
	   Boot
	   ----------------------------------------------------------------------- */
	document.addEventListener( 'DOMContentLoaded', function () {
		initMetadataImport();
		initRoleMapping();
		initSecretToggle();
		initDismissibleNotices();
	} );

}() );
