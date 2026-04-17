/**
 * Microsoft Entra SSO — Admin JavaScript (vanilla JS, no jQuery).
 *
 * Handles:
 *  1. Metadata import via AJAX.
 *  2. Role-mapping row add / remove.
 *  3. Client secret visibility toggle.
 *  4. Dismissible admin notices.
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
		1. Metadata import
		----------------------------------------------------------------------- */
	function initMetadataImport() {
		var btn    = document.getElementById( 'sfme-import-metadata' );
		var urlIn  = document.getElementById( 'sfme_metadata_url' );
		var status = document.getElementById( 'sfme-import-status' );

		if ( ! btn || ! urlIn || ! status ) {
			return;
		}

		btn.addEventListener(
			'click',
			function () {
				var url = urlIn.value.trim();
				if ( ! url ) {
					setStatus( status, strings.import_error, true );
					return;
				}

				btn.disabled = true;
				setStatus( status, strings.importing, false );

				var body = new URLSearchParams();
				body.append( 'action', 'sfme_import_metadata' );
				body.append( 'nonce',  nonce );
				body.append( 'url',    url );

				fetch(
					ajaxUrl,
					{
						method:  'POST',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body:    body.toString(),
					}
				)
				.then(
					function ( response ) {
						return response.json();
					}
				)
				.then(
					function ( data ) {
						btn.disabled = false;
						if ( data.success ) {
								setStatus( status, data.data && data.data.message ? data.data.message : strings.import_done, false );
								// Auto-populate connection fields extracted from the metadata URL.
							if ( data.data ) {
								fillFieldIfEmpty( 'sfme_tenant_id', data.data.tenant_id );
								fillFieldIfEmpty( 'sfme_client_id', data.data.client_id );
								// Switch protocol radio to SAML since metadata was imported.
								selectRadio( 'sfme_auth_protocol', 'saml' );
							}
						} else {
							var msg = data.data && data.data.message ? data.data.message : strings.import_error;
							setStatus( status, msg, true );
						}
					}
				)
				.catch(
					function () {
						btn.disabled = false;
						setStatus( status, strings.import_error, true );
					}
				);
			}
		);
	}

	/**
	 * Set an input field's value if currently empty, and briefly highlight it.
	 *
	 * @param {string} fieldId Input element ID.
	 * @param {string} value   Value to set.
	 */
	function fillFieldIfEmpty( fieldId, value ) {
		if ( ! value ) {
			return;
		}
		var input = document.getElementById( fieldId );
		if ( ! input ) {
			return;
		}
		input.value = value;
		// Brief highlight to draw attention to the auto-filled field.
		input.style.transition      = 'background-color 0.3s';
		input.style.backgroundColor = '#e7f5e9';
		setTimeout(
			function () {
				input.style.backgroundColor = '';
			},
			2000
		);
	}

	/**
	 * Select a radio button by name and value.
	 *
	 * @param {string} name  Radio input name attribute.
	 * @param {string} value Value to select.
	 */
	function selectRadio( name, value ) {
		var radio = document.querySelector( 'input[name="' + name + '"][value="' + value + '"]' );
		if ( radio ) {
			radio.checked = true;
		}
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
		var container = document.getElementById( 'sfme-role-mapping' );
		var addBtn    = document.getElementById( 'sfme-add-role-mapping' );
		var tbody     = document.getElementById( 'sfme-role-mapping-rows' );
		var template  = document.getElementById( 'sfme-role-row-template' );

		if ( ! container || ! addBtn || ! tbody || ! template ) {
			return;
		}

		// Delegate remove-row clicks to the tbody.
		tbody.addEventListener(
			'click',
			function ( event ) {
				var target = event.target;
				if ( target && target.classList.contains( 'sfme-remove-row' ) ) {
					var row = target.closest( '.sfme-role-mapping-row' );
					if ( row ) {
						row.parentNode.removeChild( row );
					}
				}
			}
		);

		addBtn.addEventListener(
			'click',
			function () {
				var clone = document.importNode( template.content, true );
				tbody.appendChild( clone );
			}
		);
	}

	/* -----------------------------------------------------------------------
		3. Client secret visibility toggle
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
		4. Dismissible admin notices
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
		5. Protocol-dependent field visibility
		----------------------------------------------------------------------- */
	function initProtocolToggle() {
		var radios = document.querySelectorAll( 'input[name="sfme_auth_protocol"]' );
		if ( ! radios.length ) {
			return;
		}

		var secretRow = document.getElementById( 'sfme_client_secret' );
		if ( secretRow ) {
			secretRow = secretRow.closest( 'tr' );
		}

		function toggle() {
			var selected = document.querySelector( 'input[name="sfme_auth_protocol"]:checked' );
			if ( ! selected || ! secretRow ) {
				return;
			}
			if ( 'saml' === selected.value ) {
				secretRow.style.display = 'none';
			} else {
				secretRow.style.display = '';
			}
		}

		for ( var i = 0; i < radios.length; i++ ) {
			radios[ i ].addEventListener( 'change', toggle );
		}

		// Run on load.
		toggle();
	}

	/* -----------------------------------------------------------------------
		Boot
		----------------------------------------------------------------------- */
	document.addEventListener(
		'DOMContentLoaded',
		function () {
			initMetadataImport();
			initRoleMapping();
			initSecretToggle();
			initDismissibleNotices();
			initProtocolToggle();
		}
	);

}() );
