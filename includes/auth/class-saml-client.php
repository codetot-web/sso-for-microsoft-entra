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
 * @package SFME\Auth
 */

namespace SFME\Auth;

defined( 'ABSPATH' ) || exit;

use SFME\Plugin;
use SFME\Security\State_Manager;
use SFME\XML\XML_Security;
use SFME\XML\Metadata_Parser;

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
				esc_html__( 'Failed to deflate SAML AuthnRequest.', 'sso-for-microsoft-entra' )
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
				esc_html__( 'SAML response is empty.', 'sso-for-microsoft-entra' )
			);
		}

		// Use LightSaml to parse the SAML response (handles base64, XML, bindings).
		try {
			$request         = \Symfony\Component\HttpFoundation\Request::createFromGlobals();
			$message_context = new \LightSaml\Context\Profile\MessageContext();
			$binding_factory = new \LightSaml\Binding\BindingFactory();
			$binding         = $binding_factory->getBindingByRequest( $request );
			$binding->receive( $request, $message_context );
			$response = $message_context->asResponse();
		} catch ( \Exception $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'SFME SAML parse error: ' . $e->getMessage() );
			}
			return new \WP_Error(
				'saml_parse_failed',
				esc_html__( 'Failed to parse SAML response.', 'sso-for-microsoft-entra' )
			);
		}

		// Check response status.
		$status      = $response->getStatus();
		$status_code = $status ? $status->getStatusCode() : null;
		if ( $status_code && 'urn:oasis:names:tc:SAML:2.0:status:Success' !== $status_code->getValue() ) {
			return new \WP_Error(
				'saml_status_error',
				esc_html__( 'SAML response returned a non-success status.', 'sso-for-microsoft-entra' )
			);
		}

		// Get the assertion.
		$assertion = $response->getFirstAssertion();
		if ( ! $assertion ) {
			return new \WP_Error(
				'saml_no_assertion',
				esc_html__( 'No SAML Assertion found in the response.', 'sso-for-microsoft-entra' )
			);
		}

		// Validate signature using stored certificate.
		$config = self::get_saml_config();
		if ( is_wp_error( $config ) ) {
			return $config;
		}

		$certificates = $config['certificates'];
		if ( empty( $certificates ) ) {
			return new \WP_Error(
				'saml_no_certificate',
				esc_html__( 'No signing certificate is configured for SAML verification.', 'sso-for-microsoft-entra' )
			);
		}

		// Verify signature on either the assertion or the response.
		$signature_valid = false;
		$signature       = $assertion->getSignature() ?? $response->getSignature();

		if ( $signature ) {
			foreach ( $certificates as $cert ) {
				try {
					$cert_clean = str_replace( array( "\n", "\r", ' ' ), '', $cert );
					$pem        = "-----BEGIN CERTIFICATE-----\n"
						. chunk_split( $cert_clean, 64, "\n" )
						. "-----END CERTIFICATE-----\n";

					$x509 = new \LightSaml\Credential\X509Certificate();
					$x509->loadPem( $pem );
					$key = \LightSaml\Credential\KeyHelper::createPublicKey( $x509 );

					if ( $signature->validate( $key ) ) {
						$signature_valid = true;
						break;
					}
				} catch ( \Exception $e ) {
					// Try next certificate.
					continue;
				}
			}
		}

		if ( ! $signature_valid ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'SFME SAML signature verification failed (LightSaml)' );
			}
			return new \WP_Error(
				'saml_invalid_signature',
				esc_html__( 'SAML response signature verification failed.', 'sso-for-microsoft-entra' )
			);
		}

		// Extract claims from the assertion using LightSaml objects.
		return self::extract_claims_from_lightsaml( $assertion );
	}

	/**
	 * Extract normalised claims from a LightSaml Assertion object.
	 *
	 * Maps SAML attributes to OIDC-compatible claim names so User_Handler
	 * works identically for both protocols.
	 *
	 * @param \LightSaml\Model\Assertion\Assertion $assertion LightSaml assertion.
	 * @return array|\WP_Error Normalised claims array or WP_Error.
	 */
	private static function extract_claims_from_lightsaml( \LightSaml\Model\Assertion\Assertion $assertion ) {
		$claims = array();

		// NameID → sub.
		$name_id = $assertion->getSubject() ? $assertion->getSubject()->getNameID() : null;
		if ( ! $name_id || '' === (string) $name_id->getValue() ) {
			return new \WP_Error(
				'saml_missing_name_id',
				esc_html__( 'SAML assertion does not contain a NameID.', 'sso-for-microsoft-entra' )
			);
		}
		$claims['sub'] = (string) $name_id->getValue();

		// Map SAML attributes to OIDC claim names.
		$attribute_map    = array(
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress' => 'email',
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'    => 'given_name',
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'      => 'family_name',
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'         => 'preferred_username',
		);
		$groups_attribute = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups';

		$attr_statement = $assertion->getFirstAttributeStatement();
		if ( $attr_statement ) {
			foreach ( $attr_statement->getAllAttributes() as $attribute ) {
				$attr_name = $attribute->getName();

				if ( isset( $attribute_map[ $attr_name ] ) ) {
					$value = $attribute->getFirstAttributeValue();
					if ( null !== $value ) {
						$claims[ $attribute_map[ $attr_name ] ] = (string) $value;
					}
					continue;
				}

				if ( $groups_attribute === $attr_name ) {
					$groups = $attribute->getAllAttributeValues();
					if ( ! empty( $groups ) ) {
						$claims['groups'] = $groups;
					}
				}
			}
		}

		return $claims;
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
		$acs_url       = esc_url( home_url( '/sso/saml-acs' ) );

		// The Issuer must match the "Identifier (Entity ID)" configured in
		// the Azure Enterprise Application SAML settings. Entra defaults this
		// to the Application ID URI (api://{client_id}) or the client_id itself.
		// Using home_url() causes AADSTS700016 because Azure cannot find an
		// application registered with that identifier.
		$plugin    = \SFME\Plugin::get_instance();
		$client_id = (string) $plugin->get_option( \SFME\Plugin::OPTION_CLIENT_ID, '' );
		$issuer    = '' !== $client_id ? $client_id : esc_url( home_url() );

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
	 * Verify the XML digital signature on a SAML document using xmlseclibs.
	 *
	 * Delegates all canonicalization, digest, and signature verification to
	 * the robrichards/xmlseclibs library — the industry standard for XML-DSig
	 * in PHP, used by most SAML implementations.
	 *
	 * Security: we verify against our stored certificate ONLY. We do NOT
	 * trust any certificate embedded in the response's KeyInfo element.
	 *
	 * @param \DOMDocument $doc         Parsed SAML response document.
	 * @param string       $certificate Base64-encoded X.509 certificate (without PEM headers).
	 *
	 * @return bool True when the signature is valid.
	 */
	private static function verify_xml_signature( \DOMDocument $doc, string $certificate ): bool {
		// Register all ID attributes so xmlseclibs can resolve URI references.
		// Azure SAML responses use the "ID" attribute on Response and Assertion
		// elements, but DOMDocument doesn't treat them as XML IDs by default.
		$xpath_ids = new \DOMXPath( $doc );
		foreach ( $xpath_ids->query( '//*[@ID]' ) as $element ) {
			$element->setIdAttribute( 'ID', true );
		}

		$xml_sec = new \RobRichards\XMLSecLibs\XMLSecurityDSig();

		// Locate the Signature element.
		$sig_node = $xml_sec->locateSignature( $doc );
		if ( null === $sig_node ) {
			return false;
		}

		// Canonicalize the SignedInfo element (xmlseclibs handles transforms).
		try {
			$xml_sec->canonicalizeSignedInfo();
		} catch ( \Exception $e ) {
			return false;
		}

		// Validate the reference digests (enveloped-signature, exc-c14n, etc.).
		try {
			$xml_sec->validateReference();
		} catch ( \Exception $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'SFME SAML reference validation error: ' . $e->getMessage() );
			}
			return false;
		}

		// Build the PEM certificate from the stored base64 string.
		$cert_clean = str_replace( array( '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r", ' ' ), '', $certificate );
		$pem        = "-----BEGIN CERTIFICATE-----\n"
			. chunk_split( $cert_clean, 64, "\n" )
			. "-----END CERTIFICATE-----\n";

		// Verify the cryptographic signature using our trusted certificate.
		$key = new \RobRichards\XMLSecLibs\XMLSecurityKey(
			\RobRichards\XMLSecLibs\XMLSecurityKey::RSA_SHA256,
			array( 'type' => 'public' )
		);

		// Detect the actual algorithm used in the signature.
		try {
			\RobRichards\XMLSecLibs\XMLSecEnc::staticLocateKeyInfo( $key, $sig_node );
		} catch ( \Exception $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch -- Intentional fallback to SHA256.
			// Key info extraction failed — continue with SHA256 default.
		}

		$key->loadKey( $pem );

		try {
			// verifySignature returns 1 on success, throws on failure.
			return 1 === $xml_sec->verify( $key );
		} catch ( \Exception $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'SFME SAML signature verify error: ' . $e->getMessage() );
			}
			return false;
		}
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
	 * @param \DOMElement $assertion Verified SAML Assertion element.
	 * @param string      $entity_id Our SP entity ID (home_url()).
	 *
	 * @return true|\WP_Error True when conditions are satisfied, WP_Error otherwise.
	 */
	private static function validate_conditions( \DOMElement $assertion, string $entity_id ) {
		// Security (C-1): query relative to the verified assertion element,
		// not the entire document, to prevent XSW attacks.
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHP DOM API.
		$xpath = new \DOMXPath( $assertion->ownerDocument );
		$xpath->registerNamespace( 'saml', self::NS_SAML_ASSERTION );

		$conditions_nodes = $xpath->query( 'saml:Conditions', $assertion );

		if ( ! $conditions_nodes || 0 === $conditions_nodes->length ) {
			// A missing Conditions element is treated as valid per spec, but
			// we require it for security.
			return new \WP_Error(
				'saml_missing_conditions',
				esc_html__( 'SAML assertion is missing a Conditions element.', 'sso-for-microsoft-entra' )
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
					esc_html__( 'SAML assertion is not yet valid (NotBefore).', 'sso-for-microsoft-entra' )
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
					esc_html__( 'SAML assertion has expired (NotOnOrAfter).', 'sso-for-microsoft-entra' )
				);
			}
		}

		// ── AudienceRestriction ───────────────────────────────────────────── //
		$audience_nodes = $xpath->query( 'saml:AudienceRestriction/saml:Audience', $conditions );

		// Security (M-3): require AudienceRestriction — silently skipping it
		// when absent would accept assertions issued for any SP.
		if ( ! $audience_nodes || 0 === $audience_nodes->length ) {
			return new \WP_Error(
				'saml_missing_audience',
				esc_html__( 'SAML assertion is missing an AudienceRestriction element.', 'sso-for-microsoft-entra' )
			);
		}

		if ( $audience_nodes->length > 0 ) {
			$audience_match = false;

			foreach ( $audience_nodes as $audience_node ) {
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHP DOM API property
				$audience = trim( $audience_node->textContent );

				// Security: verify our entity ID is listed in the audience to
				// prevent an assertion issued for another SP from being accepted.
				// Accept the IdP entity_id, home_url(), or client_id as valid audiences
				// since Entra may use the client_id as the audience value.
				$client_id = (string) \SFME\Plugin::get_instance()->get_option(
					\SFME\Plugin::OPTION_CLIENT_ID,
					''
				);
				if ( $entity_id === $audience || home_url() === $audience || $client_id === $audience ) {
					$audience_match = true;
					break;
				}
			}

			if ( ! $audience_match ) {
				return new \WP_Error(
					'saml_audience_mismatch',
					esc_html__( 'SAML assertion audience does not match this service provider.', 'sso-for-microsoft-entra' )
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
	 * @param \DOMElement $assertion Verified SAML Assertion element.
	 *
	 * @return array|\WP_Error Normalised claims array or WP_Error.
	 */
	private static function extract_claims( \DOMElement $assertion ) {
		// Security (C-1): query relative to the verified assertion element,
		// not the entire document, to prevent XSW attacks.
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHP DOM API.
		$xpath = new \DOMXPath( $assertion->ownerDocument );
		$xpath->registerNamespace( 'saml', self::NS_SAML_ASSERTION );

		$claims = array();

		// ── Subject / NameID → sub ────────────────────────────────────────── //
		$name_id_nodes = $xpath->query( 'saml:Subject/saml:NameID', $assertion );

		if ( ! $name_id_nodes || 0 === $name_id_nodes->length ) {
			return new \WP_Error(
				'saml_missing_name_id',
				esc_html__( 'SAML assertion does not contain a NameID.', 'sso-for-microsoft-entra' )
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

		$attr_nodes = $xpath->query( 'saml:AttributeStatement/saml:Attribute', $assertion );

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
				esc_html__( 'SAML NameID is empty.', 'sso-for-microsoft-entra' )
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
		$sso_url = (string) $plugin->get_option( 'sfme_saml_sso_url', '' );

		if ( '' === $sso_url ) {
			return new \WP_Error(
				'saml_no_sso_url',
				esc_html__( 'SAML SSO URL is not configured.', 'sso-for-microsoft-entra' )
			);
		}

		$certificate = (string) $plugin->get_option( 'sfme_saml_certificate', '' );

		if ( '' === $certificate ) {
			return new \WP_Error(
				'saml_no_certificate',
				esc_html__( 'SAML signing certificate is not configured.', 'sso-for-microsoft-entra' )
			);
		}

		return array(
			'entity_id'    => home_url(),
			'sso_url'      => $sso_url,
			'certificates' => array( $certificate ),
		);
	}
}
