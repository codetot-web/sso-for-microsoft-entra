<?php
/**
 * Federation metadata XML parser for SAML 2.0.
 *
 * Extracts IdP configuration (SSO URL, SLO URL, signing certificates, entity ID,
 * and NameID format) from a SAML 2.0 federation metadata document. This is the
 * XML document typically downloaded from the Entra admin portal under
 * "Enterprise applications → SAML setup → Federation Metadata XML".
 *
 * @package MicrosoftEntraSSO\XML
 */

namespace MicrosoftEntraSSO\XML;

defined( 'ABSPATH' ) || exit;

/**
 * Class Metadata_Parser
 *
 * Stateless; all methods are static.
 */
class Metadata_Parser {

	/**
	 * Metadata interoperability namespace URI.
	 *
	 * @var string
	 */
	const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';

	/**
	 * XML Digital Signature namespace URI.
	 *
	 * @var string
	 */
	const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';

	/**
	 * SAML 2.0 HTTP Redirect binding URI.
	 *
	 * @var string
	 */
	const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

	/**
	 * SAML 2.0 HTTP POST binding URI.
	 *
	 * @var string
	 */
	const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Parse an already-loaded federation metadata DOMDocument.
	 *
	 * Extracts the following fields:
	 *  - entity_id    : The IdP's EntityDescriptor/@entityID attribute.
	 *  - sso_url      : The HTTP-Redirect SingleSignOnService Location.
	 *  - slo_url      : The SingleLogoutService Location (if present).
	 *  - certificates : Array of X.509 certificate strings (base64, no headers).
	 *  - name_id_format: The preferred NameIDFormat string (if present).
	 *
	 * Multiple signing certificates are returned to support key rotation — callers
	 * should try each certificate until one validates successfully.
	 *
	 * @param \DOMDocument $doc Parsed federation metadata document.
	 *
	 * @return array|\WP_Error Associative config array on success, WP_Error on failure.
	 */
	public static function parse( \DOMDocument $doc ) {
		$xpath = new \DOMXPath( $doc );
		$xpath->registerNamespace( 'md', self::NS_MD );
		$xpath->registerNamespace( 'ds', self::NS_DSIG );

		// ── Entity ID ─────────────────────────────────────────────────────── //
		$entity_id = self::extract_entity_id( $xpath );

		if ( '' === $entity_id ) {
			return new \WP_Error(
				'metadata_missing_entity_id',
				esc_html__( 'Federation metadata does not contain an EntityDescriptor @entityID.', 'microsoft-entra-sso' )
			);
		}

		// ── SSO URL (required) ────────────────────────────────────────────── //
		$sso_url = self::extract_sso_url( $xpath );

		if ( '' === $sso_url ) {
			return new \WP_Error(
				'metadata_missing_sso_url',
				esc_html__( 'Federation metadata does not contain a SingleSignOnService with HTTP-Redirect binding.', 'microsoft-entra-sso' )
			);
		}

		// ── SLO URL (optional) ────────────────────────────────────────────── //
		$slo_url = self::extract_slo_url( $xpath );

		// ── Signing certificates (required) ───────────────────────────────── //
		$certificates = self::extract_certificates( $xpath );

		if ( empty( $certificates ) ) {
			return new \WP_Error(
				'metadata_missing_certificate',
				esc_html__( 'Federation metadata does not contain any signing certificates.', 'microsoft-entra-sso' )
			);
		}

		// ── NameID format (optional) ──────────────────────────────────────── //
		$name_id_format = self::extract_name_id_format( $xpath );

		$result = array(
			'entity_id'      => $entity_id,
			'sso_url'        => $sso_url,
			'slo_url'        => $slo_url,
			'certificates'   => $certificates,
			'name_id_format' => $name_id_format,
		);

		return $result;
	}

	/**
	 * Fetch and parse a federation metadata document from a remote HTTPS URL.
	 *
	 * Delegates fetching to XML_Security::safe_load_xml_from_url() so all
	 * XXE protections are applied to remotely fetched documents.
	 *
	 * @param string $url Absolute HTTPS URL to the federation metadata XML.
	 *
	 * @return array|\WP_Error Config array on success, WP_Error on failure.
	 */
	public static function parse_from_url( string $url ) {
		$doc = XML_Security::safe_load_xml_from_url( $url );

		if ( is_wp_error( $doc ) ) {
			return $doc;
		}

		return self::parse( $doc );
	}

	// -------------------------------------------------------------------------
	// Private extraction helpers
	// -------------------------------------------------------------------------

	/**
	 * Extract the IdP entity ID from the EntityDescriptor element.
	 *
	 * @param \DOMXPath $xpath XPath with 'md' namespace prefix registered.
	 *
	 * @return string Entity ID, or empty string when not found.
	 */
	private static function extract_entity_id( \DOMXPath $xpath ): string {
		// EntityDescriptor may be the root element or nested within an EntitiesDescriptor.
		$nodes = $xpath->query( '//md:EntityDescriptor[@entityID]' );

		if ( ! $nodes || 0 === $nodes->length ) {
			// Some implementations omit the namespace on the root element.
			$nodes = $xpath->query( '//*[@entityID]' );
		}

		if ( ! $nodes || 0 === $nodes->length ) {
			return '';
		}

		return trim( $nodes->item( 0 )->getAttribute( 'entityID' ) );
	}

	/**
	 * Extract the HTTP-Redirect SSO URL from the IDPSSODescriptor.
	 *
	 * Prefers the HTTP-Redirect binding per the SAML redirect binding spec.
	 * Falls back to the HTTP-POST binding when redirect is not available.
	 *
	 * @param \DOMXPath $xpath XPath with 'md' namespace prefix registered.
	 *
	 * @return string SSO URL, or empty string when not found.
	 */
	private static function extract_sso_url( \DOMXPath $xpath ): string {
		// Prefer the redirect binding (required for AuthnRequest).
		$redirect_nodes = $xpath->query(
			'//md:IDPSSODescriptor/md:SingleSignOnService[@Binding="' . self::BINDING_REDIRECT . '"]/@Location'
		);

		if ( $redirect_nodes && $redirect_nodes->length > 0 ) {
			return trim( $redirect_nodes->item( 0 )->nodeValue );
		}

		// Fall back to POST binding.
		$post_nodes = $xpath->query(
			'//md:IDPSSODescriptor/md:SingleSignOnService[@Binding="' . self::BINDING_POST . '"]/@Location'
		);

		if ( $post_nodes && $post_nodes->length > 0 ) {
			return trim( $post_nodes->item( 0 )->nodeValue );
		}

		return '';
	}

	/**
	 * Extract the Single Logout Service URL (optional).
	 *
	 * @param \DOMXPath $xpath XPath with 'md' namespace prefix registered.
	 *
	 * @return string SLO URL, or empty string when not present.
	 */
	private static function extract_slo_url( \DOMXPath $xpath ): string {
		$redirect_nodes = $xpath->query(
			'//md:IDPSSODescriptor/md:SingleLogoutService[@Binding="' . self::BINDING_REDIRECT . '"]/@Location'
		);

		if ( $redirect_nodes && $redirect_nodes->length > 0 ) {
			return trim( $redirect_nodes->item( 0 )->nodeValue );
		}

		// Accept any SLO service regardless of binding.
		$any_nodes = $xpath->query( '//md:IDPSSODescriptor/md:SingleLogoutService/@Location' );

		if ( $any_nodes && $any_nodes->length > 0 ) {
			return trim( $any_nodes->item( 0 )->nodeValue );
		}

		return '';
	}

	/**
	 * Extract all signing certificates from the IDPSSODescriptor.
	 *
	 * Multiple certificates may be present during a key rotation period.
	 * All are returned so the caller can try each during signature verification.
	 * Only KeyDescriptor elements with use="signing" (or no use attribute) are
	 * included — encryption certificates are excluded.
	 *
	 * The returned strings are base64-encoded DER with whitespace removed
	 * (i.e. without PEM headers). SAML_Client::verify_xml_signature() adds
	 * PEM headers when constructing the public key.
	 *
	 * @param \DOMXPath $xpath XPath with 'md' and 'ds' namespace prefixes registered.
	 *
	 * @return array Array of base64-encoded certificate strings (may be empty).
	 */
	private static function extract_certificates( \DOMXPath $xpath ): array {
		// Signing certificates are in KeyDescriptor[@use="signing"] elements.
		// Some IdPs omit the use attribute meaning the key is dual-use.
		$nodes = $xpath->query(
			'//md:IDPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'
		);

		if ( ! $nodes || 0 === $nodes->length ) {
			return array();
		}

		$certificates = array();

		foreach ( $nodes as $node ) {
			// Strip all whitespace from the base64 string to normalise it.
			$cert = preg_replace( '/\s+/', '', $node->textContent );

			if ( '' !== $cert ) {
				$certificates[] = $cert;
			}
		}

		return array_unique( $certificates );
	}

	/**
	 * Extract the preferred NameID format from the IDPSSODescriptor.
	 *
	 * @param \DOMXPath $xpath XPath with 'md' namespace prefix registered.
	 *
	 * @return string NameID format URI, or empty string when not specified.
	 */
	private static function extract_name_id_format( \DOMXPath $xpath ): string {
		$nodes = $xpath->query( '//md:IDPSSODescriptor/md:NameIDFormat' );

		if ( ! $nodes || 0 === $nodes->length ) {
			return '';
		}

		return trim( $nodes->item( 0 )->textContent );
	}
}
