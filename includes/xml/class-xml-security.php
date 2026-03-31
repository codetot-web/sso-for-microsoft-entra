<?php
/**
 * Hardened XML parsing helpers for federation metadata and SAML documents.
 *
 * XML External Entity (XXE) injection is a critical vulnerability class when
 * parsing attacker-controlled XML. This class wraps DOMDocument loading with
 * a defence-in-depth approach: entity loading is disabled at the libxml level,
 * network access is prevented via LIBXML_NONET, and oversized payloads are
 * rejected before parsing begins.
 *
 * @package MicrosoftEntraSSO\XML
 */

namespace MicrosoftEntraSSO\XML;

defined( 'ABSPATH' ) || exit;

/**
 * Secure XML loading utilities.
 *
 * XXE prevention strategy:
 *   1. On PHP < 8.0: call libxml_disable_entity_loader(true) to block all
 *      external entity resolution at the libxml level.
 *   2. Pass LIBXML_NONET to DOMDocument::loadXML() so that even if an entity
 *      reference reaches the parser, network fetches are blocked.
 *   3. Do NOT pass LIBXML_NOENT, which would cause libxml to substitute
 *      entities (the attack vector).
 *   4. Reject payloads that exceed 1 MB to guard against billion-laughs and
 *      other entity-expansion attacks.
 *
 * Note: libxml_disable_entity_loader() was deprecated in PHP 8.0 because
 * libxml2 >= 2.9.0 disabled external entity loading by default. The @ operator
 * is intentionally used to suppress the deprecation notice on PHP 8+.
 */
class XML_Security {

	/**
	 * Maximum accepted XML payload size in bytes (1 MB).
	 *
	 * @var int
	 */
	const MAX_SIZE = 1048576;

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Parse an XML string into a DOMDocument using hardened settings.
	 *
	 * @param string $xml_string Raw XML content to parse.
	 *
	 * @return \DOMDocument|\WP_Error A populated DOMDocument on success, or a
	 *                                WP_Error describing the failure.
	 */
	public static function safe_load_xml( string $xml_string ) {
		// ----- Size gate ---------------------------------------------------- //
		if ( strlen( $xml_string ) > self::MAX_SIZE ) {
			return new \WP_Error(
				'xml_too_large',
				esc_html__( 'XML payload exceeds the 1 MB size limit.', 'microsoft-entra-sso' )
			);
		}

		// ----- Disable external entity loading (PHP < 8.0) ------------------ //
		// On PHP 8.0+ libxml2 >= 2.9.0 already blocks this; the function is
		// deprecated and emits a notice, so the @ suppressor is appropriate.
		if ( PHP_VERSION_ID < 80000 ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, Generic.PHP.DeprecatedFunctions.Deprecated -- Required for PHP < 8.0 XXE prevention
			@libxml_disable_entity_loader( true );
		}

		// ----- Parse -------------------------------------------------------- //
		$dom = new \DOMDocument();

		// Suppress libxml warnings so we can capture them via libxml_get_errors().
		$previous_use_errors = libxml_use_internal_errors( true );

		// LIBXML_NONET: block all network requests during parsing.
		// Intentionally omitting LIBXML_NOENT to avoid entity substitution.
		$loaded = $dom->loadXML( $xml_string, LIBXML_NONET );

		$errors = libxml_get_errors();
		libxml_clear_errors();
		libxml_use_internal_errors( $previous_use_errors );

		if ( ! $loaded ) {
			$error_message = ! empty( $errors )
				? $errors[0]->message
				: esc_html__( 'Unknown XML parse error.', 'microsoft-entra-sso' );

			return new \WP_Error(
				'xml_parse_error',
				esc_html(
					sprintf(
						/* translators: %s: libxml error message */
						__( 'XML parsing failed: %s', 'microsoft-entra-sso' ),
						trim( $error_message )
					)
				)
			);
		}

		return $dom;
	}

	/**
	 * Fetch an XML document from a remote HTTPS URL and parse it securely.
	 *
	 * Only HTTPS URLs are accepted to ensure transport-layer integrity. The
	 * fetched body is passed through {@see XML_Security::safe_load_xml()} so
	 * all XXE protections apply regardless of the retrieval path.
	 *
	 * @param string $url Absolute HTTPS URL pointing to an XML resource.
	 *
	 * @return \DOMDocument|\WP_Error A populated DOMDocument on success, or a
	 *                                WP_Error describing the failure.
	 */
	public static function safe_load_xml_from_url( string $url ) {
		// ----- URL validation ----------------------------------------------- //
		$parsed = wp_parse_url( $url );

		if ( ! $parsed || empty( $parsed['scheme'] ) || empty( $parsed['host'] ) ) {
			return new \WP_Error(
				'xml_invalid_url',
				esc_html__( 'The provided URL is not valid.', 'microsoft-entra-sso' )
			);
		}

		// Enforce HTTPS to prevent man-in-the-middle substitution.
		if ( 'https' !== strtolower( $parsed['scheme'] ) ) {
			return new \WP_Error(
				'xml_url_not_https',
				esc_html__( 'Only HTTPS URLs are accepted for XML retrieval.', 'microsoft-entra-sso' )
			);
		}

		// ----- Remote fetch ------------------------------------------------- //
		$response = wp_remote_get(
			$url,
			array(
				'timeout'    => 10,
				'user-agent' => 'MicrosoftEntraSSO/' . MESSO_VERSION . '; WordPress/' . get_bloginfo( 'version' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return new \WP_Error(
				'xml_fetch_failed',
				sprintf(
					/* translators: %s: underlying error message */
					esc_html__( 'Failed to fetch XML from remote URL: %s', 'microsoft-entra-sso' ),
					esc_html( $response->get_error_message() )
				)
			);
		}

		// ----- Response validation ------------------------------------------ //
		$status_code = (int) wp_remote_retrieve_response_code( $response );

		if ( 200 !== $status_code ) {
			return new \WP_Error(
				'xml_fetch_bad_status',
				sprintf(
					/* translators: %d: HTTP status code */
					esc_html__( 'Remote server returned HTTP %d instead of 200.', 'microsoft-entra-sso' ),
					$status_code
				)
			);
		}

		$content_type = wp_remote_retrieve_header( $response, 'content-type' );

		// Accept any content-type that includes 'xml' (e.g. application/xml,
		// application/samlmetadata+xml, text/xml).
		if ( false === stripos( $content_type, 'xml' ) ) {
			return new \WP_Error(
				'xml_wrong_content_type',
				sprintf(
					/* translators: %s: received Content-Type header value */
					esc_html__( 'Expected an XML Content-Type but received: %s', 'microsoft-entra-sso' ),
					esc_html( $content_type )
				)
			);
		}

		$body = wp_remote_retrieve_body( $response );

		if ( '' === $body ) {
			return new \WP_Error(
				'xml_empty_response',
				esc_html__( 'Remote server returned an empty response body.', 'microsoft-entra-sso' )
			);
		}

		// Delegate to the hardened string parser (size check + XXE prevention
		// are both applied inside safe_load_xml()).
		return self::safe_load_xml( $body );
	}
}
