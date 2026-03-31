<?php
/**
 * SAML 2.0 client — builds AuthnRequests and validates Assertions from Entra.
 *
 * This class implements the SAML 2.0 HTTP Redirect binding for the
 * authentication request and the HTTP POST binding for the response, which
 * are the two bindings mandated by the Microsoft Entra / Azure AD SAML
 * implementation.
 *
 * Security design:
 *  - All XML is parsed through XML_Security::safe_load_xml() (XXE prevention).
 *  - Signature verification uses openssl_verify() with the certificate stored
 *    in the plugin settings — we never trust the certificate embedded in the
 *    response itself (that would be trivially forged).
 *  - Conditions (NotBefore, NotOnOrAfter, AudienceRestriction) are strictly
 *    validated with a configurable clock-skew allowance of 120 seconds.
 *  - Claims are normalised to match OIDC claim names so User_Handler works
 *    identically regardless of the authentication protocol.
 *
 * @package MicrosoftEntraSSO\Auth
 */

namespace MicrosoftEntraSSO\Auth;

defined( 'ABSPATH' ) || exit;

use MicrosoftEntraSSO\Plugin;
use MicrosoftEntraSSO\Security\State_Manager;
use MicrosoftEntraSSO\XML\XML_Security;
use MicrosoftEntraSSO\XML\Metadata_Parser;

/**
 * Class SAML_Client
 */
class SAML_Client {

	/**
	 * Clock-skew allowance in seconds for NotBefore / NotOnOrAfter validation.
	 *
	 * 120 seconds is a generous allowance that accommodates most NTP drift
	 * without opening an unacceptably wide replay window.
	 *
	 * @var int
	 */
	const CLOCK_SKEW = 120;

	/**
	 * SAML 2.0 assertion namespace URI.
	 *
	 * @var string
	 */
	const NS_SAML_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

	/**
	 * SAML 2.0 protocol namespace URI.
	 *
	 * @var string
	 */
	const NS_SAML_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

	/**
	 * XML Digital Signature namespace URI.
	 *
	 * @var string
	 */
	const NS_XML_DSIG = 'http://www.w3.org/2000/09/xmldsig#';

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Build the IdP redirect URL for a new SAML authentication request.
	 *
	 * Implements the SAML 2.0 HTTP Redirect binding:
	 *  1. Build the AuthnRequest XML.
	 *  2. Deflate (without the zlib header) and base64url-encode the request.
	 *  3. Generate a relay state token via State_Manager for CSRF protection.
	 *  4. Assemble the final redirect URL.
	 *
	 * @return string|\WP_Error Absolute IdP SSO URL on success, WP_Error on failure.
	 */
	public static function get_authorization_url() {
		$config = self::get_saml_config();

		if ( is_wp_error( $config ) ) {
			return $config;
		}

		$authn_request = self::build_authn_request( $config );

		// Security: deflate without zlib header per the SAML redirect binding
		// spec (section 3.4.4). Using gzdeflate (raw deflate) rather than
		// gzencode (which prepends a gzip header the IdP would not understand).
		$deflated = gzdeflate( $authn_request );

		if ( false === $deflated ) {
			return new \WP_Error(
				'saml_deflate_failed',
				esc_html__( 'Failed to deflate SAML AuthnRequest.', 'microsoft-entra-sso' )
			);
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Required for SAML protocol
		$encoded = base64_encode( $deflated );

		// Create a state token to validate the relay state in the response.
		$relay_state = State_Manager::create_state();

		$sso_url = add_query_arg(
			array(
				'SAMLRequest' => rawurlencode( $encoded ),
				'RelayState'  => rawurlencode( $relay_state ),
			),
			$config['sso_url']
		);

		return $sso_url;
	}

	/**
	 * Validate and decode a SAML Response from the IdP.
	 *
	 * Implements strict validation per the SAML 2.0 core specification:
	 *  1. Base64-decode the raw response string.
	 *  2. Parse XML safely (XXE-hardened).
	 *  3. Verify the XML digital signature.
	 *  4. Validate assertion conditions (time window, audience).
	 *  5. Extract and normalise claims.
	 *
	 * @param string $saml_response Base64-encoded SAML Response from POST body.
	 *
	 * @return array|\WP_Error Normalised claims array on success, WP_Error on failure.
	 */
	public static function handle_response( string $saml_response ) {
		if ( '' === $saml_response ) {
			return new \WP_Error(
				'saml_empty_response',
				esc_html__( 'SAML response is empty.', 'microsoft-entra-sso' )
			);
		}

		// Step 1: base64-decode.
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Required for SAML protocol
		$xml_string = base64_decode( $saml_response, true );

		if ( false === $xml_string || '' === $xml_string ) {
			return new \WP_Error(
				'saml_base64_decode_failed',
				esc_html__( 'Failed to base64-decode SAML response.', 'microsoft-entra-sso' )
			);
		}

		// Step 2: parse XML (XXE-hardened).
		$doc = XML_Security::safe_load_xml( $xml_string );

		if ( is_wp_error( $doc ) ) {
			return $doc;
		}

		// Step 3: verify XML digital signature.
		$config = self::get_saml_config();

		if ( is_wp_error( $config ) ) {
			return $config;
		}

		// Use the first certificate for primary verification.
		// Multiple certificates support key rotation — try each in order.
		$certificates = $config['certificates'];

		if ( empty( $certificates ) ) {
			return new \WP_Error(
				'saml_no_certificate',
				esc_html__( 'No signing certificate is configured for SAML verification.', 'microsoft-entra-sso' )
			);
		}

		$signature_valid = false;

		foreach ( $certificates as $cert ) {
			if ( self::verify_xml_signature( $doc, $cert ) ) {
				$signature_valid = true;
				break;
			}
		}

		if ( ! $signature_valid ) {
			// Security: reject responses with invalid or missing signatures to
			// prevent a forged assertion from creating fraudulent user sessions.
			return new \WP_Error(
				'saml_invalid_signature',
				esc_html__( 'SAML response signature verification failed.', 'microsoft-entra-sso' )
			);
		}

		// Step 4: validate assertion conditions.
		$conditions_result = self::validate_conditions( $doc, $config['entity_id'] );

		if ( is_wp_error( $conditions_result ) ) {
			return $conditions_result;
		}

		// Step 5: extract and normalise claims.
		return self::extract_claims( $doc );
	}

	// -------------------------------------------------------------------------
	// Internal: AuthnRequest builder
	// -------------------------------------------------------------------------

	/**
	 * Build a SAML 2.0 AuthnRequest XML document.
	 *
	 * @param array $config SAML configuration array from get_saml_config().
	 *
	 * @return string Serialised AuthnRequest XML.
	 */
	private static function build_authn_request( array $config ): string {
		$id            = '_' . bin2hex( random_bytes( 16 ) );
		$issue_instant = gmdate( 'Y-m-d\TH:i:s\Z' );
		$acs_url       = esc_url( add_query_arg( 'action', 'entra_saml_acs', wp_login_url() ) );
		$issuer        = esc_url( home_url() );

		// Minimal AuthnRequest per SAML 2.0 core spec §3.4.
		return '<?xml version="1.0" encoding="UTF-8"?>'
			. '<samlp:AuthnRequest'
			. ' xmlns:samlp="' . self::NS_SAML_PROTOCOL . '"'
			. ' xmlns:saml="' . self::NS_SAML_ASSERTION . '"'
			. ' ID="' . esc_attr( $id ) . '"'
			. ' Version="2.0"'
			. ' IssueInstant="' . esc_attr( $issue_instant ) . '"'
			. ' Destination="' . esc_attr( $config['sso_url'] ) . '"'
			. ' AssertionConsumerServiceURL="' . esc_attr( $acs_url ) . '"'
			. ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
			. '>'
			. '<saml:Issuer>' . esc_html( $issuer ) . '</saml:Issuer>'
			. '<samlp:NameIDPolicy'
			. ' Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"'
			. ' AllowCreate="true"'
			. '/>'
			. '</samlp:AuthnRequest>';
	}

	// -------------------------------------------------------------------------
	// Internal: signature verification
	// -------------------------------------------------------------------------

	/**
	 * Verify the XML digital signature on a SAML document.
	 *
	 * Verification steps per the XML-DSig specification:
	 *  1. Locate the ds:Signature element.
	 *  2. Determine the referenced element (the element whose digest was signed).
	 *  3. Canonicalise the referenced element using Exclusive C14N.
	 *  4. Compute SHA-256 digest and compare to the stored DigestValue.
	 *  5. Canonicalise the ds:SignedInfo element.
	 *  6. Verify the SignatureValue against the canonicalised SignedInfo
	 *     using the trusted certificate stored in plugin settings.
	 *
	 * Security: we verify against our stored certificate ONLY. We do NOT
	 * extract or trust any certificate included in the KeyInfo element of the
	 * response — that would allow an attacker who forges the KeyInfo to sign
	 * with their own certificate and bypass verification entirely.
	 *
	 * @param \DOMDocument $doc         Parsed SAML response document.
	 * @param string       $certificate PEM-formatted X.509 certificate (without headers).
	 *
	 * @return bool True when the signature is valid.
	 */
	private static function verify_xml_signature( \DOMDocument $doc, string $certificate ): bool {
		$xpath = new \DOMXPath( $doc );
		$xpath->registerNamespace( 'ds', self::NS_XML_DSIG );

		// Locate the Signature element; absent signature is treated as invalid.
		$sig_nodes = $xpath->query( '//ds:Signature' );

		if ( ! $sig_nodes || 0 === $sig_nodes->length ) {
			return false;
		}

		// @var \DOMElement $signature -- phpcs:ignore Squiz.PHP.CommentedOutCode.Found
		$signature = $sig_nodes->item( 0 );

		// ── Step 1: extract SignatureValue ────────────────────────────────── //
		$sig_value_nodes = $xpath->query( 'ds:SignatureValue', $signature );

		if ( ! $sig_value_nodes || 0 === $sig_value_nodes->length ) {
			return false;
		}

		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHP DOM API property
		$sig_value_b64 = trim( $sig_value_nodes->item( 0 )->textContent );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Required for SAML protocol
		$sig_value = base64_decode( str_replace( array( "\n", "\r", ' ' ), '', $sig_value_b64 ), true );

		if ( false === $sig_value ) {
			return false;
		}

		// ── Step 2: canonicalise ds:SignedInfo ────────────────────────────── //
		$signed_info_nodes = $xpath->query( 'ds:SignedInfo', $signature );

		if ( ! $signed_info_nodes || 0 === $signed_info_nodes->length ) {
			return false;
		}

		// @var \DOMElement $signed_info -- phpcs:ignore Squiz.PHP.CommentedOutCode.Found
		$signed_info = $signed_info_nodes->item( 0 );

		// Security: use Exclusive C14N (#exc-c14n) per XML-DSig best practices.
		// Exclusive C14N prevents namespace injection attacks that can occur
		// with inclusive canonicalisation.
		$signed_info_c14n = $signed_info->C14N( true );

		if ( false === $signed_info_c14n || '' === $signed_info_c14n ) {
			return false;
		}

		// ── Step 3: build PEM-formatted public key ────────────────────────── //
		// Strip any whitespace / header lines if already PEM-wrapped.
		$cert_clean = str_replace( array( '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r", ' ' ), '', $certificate );
		$pem        = "-----BEGIN CERTIFICATE-----\n"
			. chunk_split( $cert_clean, 64, "\n" )
			. "-----END CERTIFICATE-----\n";

		$public_key = openssl_pkey_get_public( $pem );

		if ( false === $public_key ) {
			return false;
		}

		// ── Step 4: determine digest algorithm from SignatureMethod ────────── //
		// Default to SHA-256; we also accept SHA-1 for compatibility with older
		// Entra configurations (though SHA-256 is strongly preferred).
		$sig_method_nodes = $xpath->query( 'ds:SignedInfo/ds:SignatureMethod', $signature );
		$sig_algo         = OPENSSL_ALGO_SHA256;

		if ( $sig_method_nodes && $sig_method_nodes->length > 0 ) {
			$algorithm = $sig_method_nodes->item( 0 )->getAttribute( 'Algorithm' );

			if ( false !== strpos( $algorithm, 'rsa-sha1' ) ) {
				$sig_algo = OPENSSL_ALGO_SHA1;
			} elseif ( false !== strpos( $algorithm, 'rsa-sha384' ) ) {
				$sig_algo = OPENSSL_ALGO_SHA384;
			} elseif ( false !== strpos( $algorithm, 'rsa-sha512' ) ) {
				$sig_algo = OPENSSL_ALGO_SHA512;
			}
		}

		// ── Step 5: verify the signature ─────────────────────────────────── //
		// openssl_verify() returns 1 on success, 0 on failure, -1 on error.
		$verify_result = openssl_verify( $signed_info_c14n, $sig_value, $public_key, $sig_algo );

		// Free the key resource (PHP 8+ handles this automatically via objects,
		// but explicit free is required for PHP 7.4 compatibility).
		if ( PHP_VERSION_ID < 80000 && is_resource( $public_key ) ) {
			// phpcs:ignore Generic.PHP.DeprecatedFunctions.Deprecated -- Required for PHP 7.4 compatibility; deprecated in PHP 8.0
			openssl_free_key( $public_key );
		}

		if ( 1 !== $verify_result ) {
			return false;
		}

		// ── Step 6: verify the Reference digest ───────────────────────────── //
		return self::verify_reference_digest( $doc, $xpath, $signature );
	}

	/**
	 * Verify the digest of the element referenced inside ds:SignedInfo.
	 *
	 * Without digest verification an attacker could substitute the Assertion
	 * body while keeping the signature valid (signature wrapping attack).
	 *
	 * @param \DOMDocument $doc       Full SAML document.
	 * @param \DOMXPath    $xpath     XPath instance with namespace prefixes registered.
	 * @param \DOMElement  $signature The ds:Signature element.
	 *
	 * @return bool True when all referenced digests match.
	 */
	private static function verify_reference_digest(
		\DOMDocument $doc,
		\DOMXPath $xpath,
		\DOMElement $signature
	): bool {
		$ref_nodes = $xpath->query( 'ds:SignedInfo/ds:Reference', $signature );

		if ( ! $ref_nodes || 0 === $ref_nodes->length ) {
			return false;
		}

		foreach ( $ref_nodes as $ref_node ) {
			// @var \DOMElement $ref_node -- phpcs:ignore Squiz.PHP.CommentedOutCode.Found
			$uri = $ref_node->getAttribute( 'URI' );

			// URI can be empty (reference to whole document) or '#ID'.
			if ( '' === $uri ) {
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHP DOM API property
				$referenced_element = $doc->documentElement;
			} elseif ( '#' === substr( $uri, 0, 1 ) ) {
				$id                 = substr( $uri, 1 );
				$referenced_element = $doc->getElementById( $id );

				// Fallback: XPath search by common ID attributes.
				if ( null === $referenced_element ) {
					$search = $xpath->query( '//*[@ID="' . esc_attr( $id ) . '" or @Id="' . esc_attr( $id ) . '"]' );

					if ( $search && $search->length > 0 ) {
						$referenced_element = $search->item( 0 );
					}
				}
			} else {
				// External references are not supported (security boundary).
				return false;
			}

			if ( null === $referenced_element ) {
				return false;
			}

			// Canonicalise the referenced element with exclusive C14N.
			$c14n = $referenced_element->C14N( true );

			if ( false === $c14n ) {
				return false;
			}

			// Determine digest algorithm.
			$digest_method_nodes = $xpath->query( 'ds:DigestMethod', $ref_node );
			$digest_algo         = 'sha256';

			if ( $digest_method_nodes && $digest_method_nodes->length > 0 ) {
				$algorithm = $digest_method_nodes->item( 0 )->getAttribute( 'Algorithm' );

				if ( false !== strpos( $algorithm, 'sha1' ) ) {
					$digest_algo = 'sha1';
				} elseif ( false !== strpos( $algorithm, 'sha384' ) ) {
					$digest_algo = 'sha384';
				} elseif ( false !== strpos( $algorithm, 'sha512' ) ) {
					$digest_algo = 'sha512';
				}
			}

			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Required for SAML protocol
			$computed_digest = base64_encode( hash( $digest_algo, $c14n, true ) );

			$digest_value_nodes = $xpath->query( 'ds:DigestValue', $ref_node );

			if ( ! $digest_value_nodes || 0 === $digest_value_nodes->length ) {
				return false;
			}

			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHP DOM API property
			$stored_digest = trim( $digest_value_nodes->item( 0 )->textContent );

			// Security: use hash_equals() for constant-time comparison to
			// prevent timing attacks that could leak digest value information.
			if ( ! hash_equals( $stored_digest, $computed_digest ) ) {
				return false;
			}
		}

		return true;
	}

	// -------------------------------------------------------------------------
	// Internal: condition validation
	// -------------------------------------------------------------------------

	/**
	 * Validate the saml:Conditions element of the assertion.
	 *
	 * Checks:
	 *  - NotBefore: assertion must not be used before this time.
	 *  - NotOnOrAfter: assertion must not be used at or after this time.
	 *  - AudienceRestriction: our entity ID must be listed.
	 *
	 * @param \DOMDocument $doc       Parsed SAML document.
	 * @param string       $entity_id Our SP entity ID (home_url()).
	 *
	 * @return true|\WP_Error True when conditions are satisfied, WP_Error otherwise.
	 */
	private static function validate_conditions( \DOMDocument $doc, string $entity_id ) {
		$xpath = new \DOMXPath( $doc );
		$xpath->registerNamespace( 'saml', self::NS_SAML_ASSERTION );

		$conditions_nodes = $xpath->query( '//saml:Conditions' );

		if ( ! $conditions_nodes || 0 === $conditions_nodes->length ) {
			// A missing Conditions element is treated as valid per spec, but
			// we require it for security.
			return new \WP_Error(
				'saml_missing_conditions',
				esc_html__( 'SAML assertion is missing a Conditions element.', 'microsoft-entra-sso' )
			);
		}

		// @var \DOMElement $conditions -- phpcs:ignore Squiz.PHP.CommentedOutCode.Found
		$conditions = $conditions_nodes->item( 0 );
		$now        = time();

		// ── NotBefore ─────────────────────────────────────────────────────── //
		$not_before_str = $conditions->getAttribute( 'NotBefore' );

		if ( '' !== $not_before_str ) {
			$not_before = strtotime( $not_before_str );

			if ( false !== $not_before && $now < ( $not_before - self::CLOCK_SKEW ) ) {
				return new \WP_Error(
					'saml_assertion_not_yet_valid',
					esc_html__( 'SAML assertion is not yet valid (NotBefore).', 'microsoft-entra-sso' )
				);
			}
		}

		// ── NotOnOrAfter ──────────────────────────────────────────────────── //
		$not_on_or_after_str = $conditions->getAttribute( 'NotOnOrAfter' );

		if ( '' !== $not_on_or_after_str ) {
			$not_on_or_after = strtotime( $not_on_or_after_str );

			if ( false !== $not_on_or_after && $now >= ( $not_on_or_after + self::CLOCK_SKEW ) ) {
				// Security: expired assertions must be rejected to prevent
				// replay attacks using captured SAML responses.
				return new \WP_Error(
					'saml_assertion_expired',
					esc_html__( 'SAML assertion has expired (NotOnOrAfter).', 'microsoft-entra-sso' )
				);
			}
		}

		// ── AudienceRestriction ───────────────────────────────────────────── //
		$audience_nodes = $xpath->query( 'saml:AudienceRestriction/saml:Audience', $conditions );

		if ( $audience_nodes && $audience_nodes->length > 0 ) {
			$audience_match = false;

			foreach ( $audience_nodes as $audience_node ) {
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHP DOM API property
				$audience = trim( $audience_node->textContent );

				// Security: verify our entity ID is listed in the audience to
				// prevent an assertion issued for another SP from being accepted.
				if ( $entity_id === $audience || home_url() === $audience ) {
					$audience_match = true;
					break;
				}
			}

			if ( ! $audience_match ) {
				return new \WP_Error(
					'saml_audience_mismatch',
					esc_html__( 'SAML assertion audience does not match this service provider.', 'microsoft-entra-sso' )
				);
			}
		}

		return true;
	}

	// -------------------------------------------------------------------------
	// Internal: claims extraction
	// -------------------------------------------------------------------------

	/**
	 * Extract user identity claims from the SAML Assertion.
	 *
	 * Maps SAML attribute names to the OIDC claim names used by User_Handler
	 * so that user provisioning works identically for both protocols.
	 *
	 * SAML → OIDC claim mapping:
	 *  NameID                                                     → sub
	 *  .../claims/emailaddress                                    → email
	 *  .../claims/givenname                                       → given_name
	 *  .../claims/surname                                         → family_name
	 *  .../claims/name                                            → preferred_username
	 *  http://schemas.microsoft.com/ws/2008/06/identity/claims/groups → groups
	 *
	 * @param \DOMDocument $doc Parsed and signature-verified SAML document.
	 *
	 * @return array|\WP_Error Normalised claims array or WP_Error.
	 */
	private static function extract_claims( \DOMDocument $doc ) {
		$xpath = new \DOMXPath( $doc );
		$xpath->registerNamespace( 'saml', self::NS_SAML_ASSERTION );

		$claims = array();

		// ── Subject / NameID → sub ────────────────────────────────────────── //
		$name_id_nodes = $xpath->query( '//saml:Assertion/saml:Subject/saml:NameID' );

		if ( ! $name_id_nodes || 0 === $name_id_nodes->length ) {
			return new \WP_Error(
				'saml_missing_name_id',
				esc_html__( 'SAML assertion does not contain a NameID.', 'microsoft-entra-sso' )
			);
		}

		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHP DOM API property
		$claims['sub'] = trim( $name_id_nodes->item( 0 )->textContent );

		// ── Attribute statements ──────────────────────────────────────────── //
		$attribute_map = array(
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress' => 'email',
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'    => 'given_name',
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'      => 'family_name',
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'         => 'preferred_username',
		);

		// Groups are collected as a multi-value array.
		$groups_attribute = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups';

		$attr_nodes = $xpath->query( '//saml:Assertion/saml:AttributeStatement/saml:Attribute' );

		if ( $attr_nodes ) {
			foreach ( $attr_nodes as $attr_node ) {
				// @var \DOMElement $attr_node -- phpcs:ignore Squiz.PHP.CommentedOutCode.Found
				$attr_name = $attr_node->getAttribute( 'Name' );

				// Map known scalar attributes.
				if ( isset( $attribute_map[ $attr_name ] ) ) {
					$value_nodes = $xpath->query( 'saml:AttributeValue', $attr_node );

					if ( $value_nodes && $value_nodes->length > 0 ) {
						// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHP DOM API property
						$claims[ $attribute_map[ $attr_name ] ] = trim( $value_nodes->item( 0 )->textContent );
					}
					continue;
				}

				// Collect all group memberships into an array.
				if ( $groups_attribute === $attr_name ) {
					$value_nodes = $xpath->query( 'saml:AttributeValue', $attr_node );

					if ( $value_nodes ) {
						$groups = array();

						foreach ( $value_nodes as $value_node ) {
							// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHP DOM API property
							$groups[] = trim( $value_node->textContent );
						}

						if ( ! empty( $groups ) ) {
							$claims['groups'] = $groups;
						}
					}
				}
			}
		}

		// Ensure sub is present and non-empty.
		if ( empty( $claims['sub'] ) ) {
			return new \WP_Error(
				'saml_empty_name_id',
				esc_html__( 'SAML NameID is empty.', 'microsoft-entra-sso' )
			);
		}

		return $claims;
	}

	// -------------------------------------------------------------------------
	// Internal: configuration loader
	// -------------------------------------------------------------------------

	/**
	 * Load and validate the SAML configuration from plugin settings.
	 *
	 * Parses the stored federation metadata XML if present, supplementing or
	 * overriding individual option values.
	 *
	 * @return array|\WP_Error Config array with keys: entity_id, sso_url, certificates.
	 */
	private static function get_saml_config() {
		$plugin = Plugin::get_instance();

		$metadata_xml = (string) $plugin->get_option( Plugin::OPTION_SAML_METADATA, '' );

		if ( '' !== $metadata_xml ) {
			$meta_doc = XML_Security::safe_load_xml( $metadata_xml );

			if ( is_wp_error( $meta_doc ) ) {
				return $meta_doc;
			}

			$parsed = Metadata_Parser::parse( $meta_doc );

			if ( is_wp_error( $parsed ) ) {
				return $parsed;
			}

			// entity_id for AudienceRestriction validation defaults to home URL.
			$parsed['entity_id'] = ! empty( $parsed['entity_id'] ) ? $parsed['entity_id'] : home_url();

			return $parsed;
		}

		// Fall back to individual option values when no metadata XML is stored.
		$sso_url = (string) $plugin->get_option( 'microsoft_entra_sso_saml_sso_url', '' );

		if ( '' === $sso_url ) {
			return new \WP_Error(
				'saml_no_sso_url',
				esc_html__( 'SAML SSO URL is not configured.', 'microsoft-entra-sso' )
			);
		}

		$certificate = (string) $plugin->get_option( 'microsoft_entra_sso_saml_certificate', '' );

		if ( '' === $certificate ) {
			return new \WP_Error(
				'saml_no_certificate',
				esc_html__( 'SAML signing certificate is not configured.', 'microsoft-entra-sso' )
			);
		}

		return array(
			'entity_id'    => home_url(),
			'sso_url'      => $sso_url,
			'certificates' => array( $certificate ),
		);
	}
}
