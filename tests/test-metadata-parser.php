<?php
/**
 * Unit tests for MicrosoftEntraSSO\XML\Metadata_Parser.
 *
 * @package MicrosoftEntraSSO\Tests
 */

use MicrosoftEntraSSO\XML\Metadata_Parser;
use PHPUnit\Framework\TestCase;

/**
 * Tests for Metadata_Parser.
 */
class Test_Metadata_Parser extends TestCase {

	// -------------------------------------------------------------------------
	// Fixture helpers
	// -------------------------------------------------------------------------

	/**
	 * Build a minimal but valid SAML 2.0 federation metadata DOMDocument.
	 *
	 * Mirrors the structure of a real Microsoft Entra federation metadata
	 * document with the non-essential parts stripped to the minimum needed
	 * for the parser under test.
	 *
	 * @param string $entity_id     EntityDescriptor@entityID value.
	 * @param string $sso_url       SingleSignOnService@Location (redirect binding).
	 * @param string $slo_url       SingleLogoutService@Location (may be empty).
	 * @param string $certificate   Base64-encoded X.509 certificate (no headers).
	 * @param string $name_id_format NameIDFormat URI (may be empty).
	 * @return string Raw XML string.
	 */
	private function build_metadata_xml(
		string $entity_id = 'https://sts.windows.net/test-tenant-id/',
		string $sso_url   = 'https://login.microsoftonline.com/test-tenant-id/saml2',
		string $slo_url   = 'https://login.microsoftonline.com/test-tenant-id/saml2',
		string $certificate = 'MIICIDCCAYmgAwIBAgIIBTk=',
		string $name_id_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
	): string {
		$slo_element = '';
		if ( '' !== $slo_url ) {
			$slo_element = sprintf(
				'<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>',
				htmlspecialchars( $slo_url, ENT_XML1, 'UTF-8' )
			);
		}

		$name_id_element = '';
		if ( '' !== $name_id_format ) {
			$name_id_element = '<md:NameIDFormat>' . htmlspecialchars( $name_id_format, ENT_XML1, 'UTF-8' ) . '</md:NameIDFormat>';
		}

		return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="{$entity_id}">
  <md:IDPSSODescriptor
      WantAuthnRequestsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{$certificate}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    {$slo_element}
    {$name_id_element}
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{$sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
XML;
	}

	/**
	 * Load an XML string into a DOMDocument.
	 *
	 * @param string $xml Raw XML.
	 * @return \DOMDocument
	 */
	private function load_dom( string $xml ): \DOMDocument {
		$doc = new \DOMDocument();
		libxml_use_internal_errors( true );
		$loaded = $doc->loadXML( $xml );
		libxml_clear_errors();

		if ( ! $loaded ) {
			$this->fail( 'Test fixture XML is not valid.' );
		}

		return $doc;
	}

	// -------------------------------------------------------------------------
	// parse() — success path
	// -------------------------------------------------------------------------

	/**
	 * parse() must extract entity_id from a well-formed metadata document.
	 */
	public function test_parse_extracts_entity_id(): void {
		$entity_id = 'https://sts.windows.net/my-tenant/';
		$doc       = $this->load_dom( $this->build_metadata_xml( $entity_id ) );

		$result = Metadata_Parser::parse( $doc );

		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'entity_id', $result );
		$this->assertSame( $entity_id, $result['entity_id'] );
	}

	/**
	 * parse() must extract sso_url from a well-formed metadata document.
	 */
	public function test_parse_extracts_sso_url(): void {
		$sso_url = 'https://login.microsoftonline.com/tenant/saml2';
		$doc     = $this->load_dom( $this->build_metadata_xml( 'https://entity.example', $sso_url ) );

		$result = Metadata_Parser::parse( $doc );

		$this->assertIsArray( $result );
		$this->assertSame( $sso_url, $result['sso_url'] );
	}

	/**
	 * parse() must extract certificates and return them as a non-empty array.
	 */
	public function test_parse_extracts_certificates(): void {
		$cert = 'MIICIDCCAYmgAwIBAgIIBTk=';
		$doc  = $this->load_dom(
			$this->build_metadata_xml(
				'https://entity.example',
				'https://sso.example',
				'',
				$cert
			)
		);

		$result = Metadata_Parser::parse( $doc );

		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'certificates', $result );
		$this->assertNotEmpty( $result['certificates'], 'Certificates array must not be empty.' );
		$this->assertContains( $cert, $result['certificates'] );
	}

	/**
	 * parse() must extract the slo_url when present.
	 */
	public function test_parse_extracts_slo_url(): void {
		$slo_url = 'https://login.microsoftonline.com/tenant/saml2/slo';
		$doc     = $this->load_dom(
			$this->build_metadata_xml(
				'https://entity.example',
				'https://sso.example',
				$slo_url
			)
		);

		$result = Metadata_Parser::parse( $doc );

		$this->assertIsArray( $result );
		$this->assertSame( $slo_url, $result['slo_url'] );
	}

	/**
	 * parse() must set slo_url to an empty string when the element is absent.
	 */
	public function test_parse_slo_url_empty_when_absent(): void {
		$doc = $this->load_dom(
			$this->build_metadata_xml(
				'https://entity.example',
				'https://sso.example',
				'' // No SLO.
			)
		);

		$result = Metadata_Parser::parse( $doc );

		$this->assertIsArray( $result );
		$this->assertSame( '', $result['slo_url'] );
	}

	/**
	 * parse() must extract the name_id_format when present.
	 */
	public function test_parse_extracts_name_id_format(): void {
		$format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
		$doc    = $this->load_dom(
			$this->build_metadata_xml(
				'https://entity.example',
				'https://sso.example',
				'',
				'MIICIDCCAYmg=',
				$format
			)
		);

		$result = Metadata_Parser::parse( $doc );

		$this->assertIsArray( $result );
		$this->assertSame( $format, $result['name_id_format'] );
	}

	/**
	 * parse() must return all five expected keys in the result array.
	 */
	public function test_parse_returns_all_required_keys(): void {
		$doc    = $this->load_dom( $this->build_metadata_xml() );
		$result = Metadata_Parser::parse( $doc );

		foreach ( array( 'entity_id', 'sso_url', 'slo_url', 'certificates', 'name_id_format' ) as $key ) {
			$this->assertArrayHasKey( $key, $result, "Result must contain key '{$key}'." );
		}
	}

	// -------------------------------------------------------------------------
	// parse() — error paths
	// -------------------------------------------------------------------------

	/**
	 * parse() must return WP_Error when entityID is missing.
	 */
	public function test_parse_returns_wp_error_when_entity_id_missing(): void {
		$xml = <<<XML
<?xml version="1.0"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://sso.example"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
XML;
		$doc    = $this->load_dom( $xml );
		$result = Metadata_Parser::parse( $doc );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'metadata_missing_entity_id', $result->get_error_code() );
	}

	/**
	 * parse() must return WP_Error when no SSO URL is present.
	 */
	public function test_parse_returns_wp_error_when_sso_url_missing(): void {
		$xml = <<<XML
<?xml version="1.0"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://entity.example">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIICIDCCAYmg=</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <!-- No SingleSignOnService -->
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
XML;
		$doc    = $this->load_dom( $xml );
		$result = Metadata_Parser::parse( $doc );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'metadata_missing_sso_url', $result->get_error_code() );
	}

	/**
	 * parse() must return WP_Error when no signing certificates are present.
	 */
	public function test_parse_returns_wp_error_when_no_certificates(): void {
		$xml = <<<XML
<?xml version="1.0"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://entity.example">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <!-- No KeyDescriptor -->
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://sso.example"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
XML;
		$doc    = $this->load_dom( $xml );
		$result = Metadata_Parser::parse( $doc );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'metadata_missing_certificate', $result->get_error_code() );
	}

	/**
	 * parse() must handle whitespace in certificates and strip it.
	 */
	public function test_parse_strips_whitespace_from_certificate(): void {
		// Certificate with line breaks as would appear in real XML.
		$cert_with_whitespace = "MIICIDCCAYmg\nAwIBAgIIBTk=\n  ";
		$cert_normalised      = 'MIICIDCCAYmgAwIBAgIIBTk='; // preg_replace( '/\s+/', '' ).

		$xml = <<<XML
<?xml version="1.0"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://entity.example">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{$cert_with_whitespace}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://sso.example"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
XML;
		$doc    = $this->load_dom( $xml );
		$result = Metadata_Parser::parse( $doc );

		$this->assertIsArray( $result );
		$this->assertContains( $cert_normalised, $result['certificates'] );
	}

	/**
	 * parse() of a document with no IDPSSODescriptor must return WP_Error.
	 */
	public function test_parse_empty_idp_descriptor_returns_error(): void {
		$xml = <<<XML
<?xml version="1.0"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://entity.example">
  <!-- No IDPSSODescriptor -->
</md:EntityDescriptor>
XML;
		$doc    = $this->load_dom( $xml );
		$result = Metadata_Parser::parse( $doc );

		// Will fail on missing SSO URL or certificate — both are WP_Error.
		$this->assertInstanceOf( WP_Error::class, $result );
	}
}
