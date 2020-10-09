package com.onelogin.saml2.test.util;

import static com.onelogin.saml2.util.Util.ASSERTION_SIGNATURE_XPATH;
import static com.onelogin.saml2.util.Util.RESPONSE_SIGNATURE_XPATH;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.joda.time.DateTime;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.SchemaFactory;
import com.onelogin.saml2.util.Util;

/**
 * Tests the com.onelogin.saml2.util.Util class
 */
public class UtilsTest {

	@Rule
	public ExpectedException expectedEx = ExpectedException.none();

	/**
	 * Tests the loadXML method for XXE/XEE attacks
	 * Case: Use of ENTITY
	 * 
	 * @see com.onelogin.saml2.util.Util#loadXML
	 */
	@Test
	public void testLoadXMLForAttacks1() {
		String attackVector = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>" +
							  "<!DOCTYPE foo [" +
							  "<!ELEMENT foo ANY >" +
							  "<!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>";

		Document res = Util.loadXML(attackVector);
		assertNull(res);
	}

	/**
	 * Tests the loadXML method of the Saml2XMLUtils for XXE/XEE attacks
	 * Case: Use of ENTITY
	 * 
	 * @see com.onelogin.saml2.util.Util#loadXML
	 */
	@Test
	public void testLoadXMLForAttacks2() {
		String attackVector = "<?xml version=\"1.0\"?>" +
				"<!DOCTYPE results [<!ENTITY harmless \"completely harmless\">]>" +
				"<results>" +
				"<result>This result is &harmless;</result>" +
				"</results>";

		Document res = Util.loadXML(attackVector);
		assertNull(res);

	}

	/**
	 * Tests the loadXML method of the Saml2XMLUtils for XXE/XEE attacks
	 * Case: Use of DTD
	 *
	 * @see com.onelogin.saml2.util.Util#loadXML
	 */
	@Test
	public void testLoadXMLForAttacks3() {
		String attackVector = "<?xml version=\"1.0\"?>" +
				"<!DOCTYPE results [" +
				"<!ELEMENT results (result+)>" +
				"<!ELEMENT result (#PCDATA)>" +
				"]>" +
				"<results>" +
				"<result>test</result>" +
				"</results>";

		Document res = Util.loadXML(attackVector);
		assertNull(res);
	}

	/**
	 * Tests the loadXML method
	 * Case: Bad formatted XML
	 *
	 * @see com.onelogin.saml2.util.Util#loadXML
	 */
	@Test
	public void testLoadXMLBadXML() {
		String metadataUnloaded = "<xml><EntityDescriptor>";
		Document result = Util.loadXML(metadataUnloaded);
		assertNull(result);
	}

	/**
	 * Tests the loadXML method 
	 * Case: Valid XML
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#loadXML
	 */
	@Test
	public void testLoadXML() throws URISyntaxException, IOException {
		String metadataInvalid = Util.getFileAsString("data/metadata/noentity_metadata_settings1.xml");
		Document result = Util.loadXML(metadataInvalid);
		assertTrue(result instanceof Document);

		String metadataOk = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		result = Util.loadXML(metadataOk);
		assertTrue(result instanceof Document);
	}

	/**
	 * Tests the ValidateXML method
	 * Case: Invalidates bad formatted XML
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLBadFormat() throws Exception {
		String metadataUnloaded = "<xml><EntityDescriptor>";
		Document docMetadataUnloaded = Util.loadXML(metadataUnloaded);
		boolean isValid = Util.validateXML(docMetadataUnloaded, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertFalse(isValid);
	}

	/**
	 * Tests the ValidateXML method
	 * Case: Invalidates XML without Entity
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLNoentity() throws Exception {
		String metadataInvalid = Util.getFileAsString("data/metadata/noentity_metadata_settings1.xml");
		Document docMetadataInvalid = Util.loadXML(metadataInvalid);
		boolean isValid = Util.validateXML(docMetadataInvalid, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertFalse(isValid);
	}

	/**
	 * Tests the ValidateXML method
	 * Case: Invalidates an invalid XML
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLInvalid() throws Exception {
		String metadataValid = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		String metadataInvalid = metadataValid.replace("/md:EntityDescriptor", "/md:EntityDescriptor2");
		Document docMetadataInvalid = Util.loadXML(metadataInvalid);
		boolean isValid = Util.validateXML(docMetadataInvalid, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertFalse(isValid);
	}
	
	/**
	 * Tests the ValidateXML method
	 * Case: Invalidates XML with bad order
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLMetadataBadOrder() throws Exception {
		String metadataBadOrder = Util.getFileAsString("data/metadata/metadata_bad_order_settings1.xml");
		Document docMetadataBadOrder = Util.loadXML(metadataBadOrder);
		boolean isValid = Util.validateXML(docMetadataBadOrder, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertFalse(isValid);
	}

	/**
	 * Tests the ValidateXML method
	 * Case: Validates against wrong schema
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLMetadataWrongSchema() throws Exception {
		String metadataOk = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		Document docMetadataOk = Util.loadXML(metadataOk);
		boolean isValid = Util.validateXML(docMetadataOk, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0);
		assertFalse(isValid);
	}
	
	/**
	 * Tests the ValidateXML method for
	 * Case: Validates expired XML Metadata
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLExpiredMetadata() throws Exception {
		String metadataExpired = Util.getFileAsString("data/metadata/expired_metadata_settings1.xml");
		Document docExpiredMetadata = Util.loadXML(metadataExpired);
		boolean isValid = Util.validateXML(docExpiredMetadata, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertTrue(isValid);
	}

	/**
	 * Tests the ValidateXML method
	 * Case: Validates valid metadata
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLMetadataOk() throws Exception {
		String metadataOk = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		Document docMetadataOk = Util.loadXML(metadataOk);
		boolean isValid = Util.validateXML(docMetadataOk, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertTrue(isValid);
	}

	/**
	 * Tests the ValidateXML method
	 * Case: Validates valid SAMLResponse
	 * 
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLSAMLResponse() throws Exception {
		String responseOk = new String(Base64.decodeBase64(Util.getFileAsString("data/responses/valid_response.xml.base64")));
		Document docResponseOk = Util.loadXML(responseOk);
		boolean isValid = Util.validateXML(docResponseOk, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0);
		assertTrue(isValid);
	}
	
	/**
	 * Tests the ValidateXML method
	 * Case: Validates valid signed metadata
	 * 
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLSignedMetadataSettings1() throws Exception {
		String signedmetadata = Util.getFileAsString("data/metadata/signed_metadata_settings1.xml");
		Document docSignedmetadata = Util.loadXML(signedmetadata);
		boolean isValid = Util.validateXML(docSignedmetadata, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertTrue(isValid);
	}
	
	/**
	 * Tests the convertDocumentToString method
	 * Case: Convert a Document object in String with c14n
     *
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#convertDocumentToString
	 */
	@Test
	public void testConvertDocumentToStringWithc14n() throws URISyntaxException, IOException {
		String responseOk = new String(Base64.decodeBase64(Util.getFileAsString("data/responses/valid_response.xml.base64")));
		Document docResponseOk = Util.loadXML(responseOk);
		String responseString = Util.convertDocumentToString(docResponseOk , true);
		assertNotNull(responseString);
		assertTrue(responseString.length() == 6855);
	}
	
	/**
	 * Tests the convertDocumentToString method
	 * Case: Convert a Document object in String without c14n
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#convertDocumentToString
	 */
	@Test
	public void testConvertDocumentToStringWithoutc14n() throws URISyntaxException, IOException {
		String responseOk = new String(Base64.decodeBase64(Util.getFileAsString("data/responses/valid_response.xml.base64")));
		Document docResponseOk = Util.loadXML(responseOk);
		String responseString = Util.convertDocumentToString(docResponseOk , false);
		String responseString2 = Util.convertDocumentToString(docResponseOk);
		assertNotNull(responseString);		
		assertTrue(responseString.length() == 6855);
		assertTrue(responseString.contentEquals(responseString2));
	}

	/**
	 * Tests the convertStringToDocument method
	 * Case: Convert a XML String in Document object
	 *
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws URISyntaxException
     *
	 * @see com.onelogin.saml2.util.Util#convertStringToDocument
	 */
	@Test
	public void testConvertStringToDocumentOk() throws ParserConfigurationException, SAXException, IOException, URISyntaxException {
		String responseOk = new String(Base64.decodeBase64(Util.getFileAsString("data/responses/valid_response.xml.base64")));
		Document responseDom = Util.convertStringToDocument(responseOk);
		assertNotNull(responseDom);
		assertEquals("samlp:Response", responseDom.getDocumentElement().getNodeName());

		String metadataOk = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		Document metadataDom = Util.convertStringToDocument(metadataOk);
		assertEquals("md:EntityDescriptor", metadataDom.getDocumentElement().getNodeName());
	}

	/**
	 * Tests the convertStringToDocument method
	 * Case: Convert a XML String in Document object
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 *
	 * @see com.onelogin.saml2.util.Util#convertStringToDocument
	 */
	@Test(expected=SAXException.class)
	public void testConvertStringToDocumentBad() throws URISyntaxException, IOException, ParserConfigurationException, SAXException {
		String metadataValid = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		String metadataInvalid = metadataValid.replace("/md:EntityDescriptor", "/md:EntityDescriptor2");
		Document metadataDom = Util.convertStringToDocument(metadataInvalid);
		assertNull(metadataDom);
	}

	/**
	 * Tests the formatCert method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#formatCert
	 */
	@Test
	public void testFormatCert() throws IOException, URISyntaxException {
		String certWithHeads = Util.getFileAsString("data/customPath/certs/sp.crt");
		String certWithoutHeads = certWithHeads.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "");

		assertThat(certWithHeads, containsString("-----BEGIN CERTIFICATE-----"));
		assertThat(certWithHeads, containsString("-----END CERTIFICATE-----"));
		assertThat(certWithoutHeads, is(not(containsString("-----BEGIN CERTIFICATE-----"))));
		assertThat(certWithoutHeads, is(not(containsString("-----END CERTIFICATE-----"))));

		String formatCert1 = Util.formatCert(certWithHeads, true);
		assertThat(formatCert1, containsString("-----BEGIN CERTIFICATE-----"));
		assertThat(formatCert1, containsString("-----END CERTIFICATE-----"));
		assertEquals(927, formatCert1.length());

		String formatCert2 = Util.formatCert(certWithHeads, false);
		assertThat(formatCert2, is(not(containsString("-----BEGIN CERTIFICATE-----"))));
		assertThat(formatCert2, is(not(containsString("-----END CERTIFICATE-----"))));
		assertEquals(860, formatCert2.length());

		String formatCert3 = Util.formatCert(certWithoutHeads, true);
		assertThat(formatCert3, containsString("-----BEGIN CERTIFICATE-----"));
		assertThat(formatCert3, containsString("-----END CERTIFICATE-----"));
		assertEquals(927, formatCert3.length());

		String formatCert4 = Util.formatCert(certWithoutHeads, false);
		assertThat(formatCert4, is(not(containsString("-----BEGIN CERTIFICATE-----"))));
		assertThat(formatCert4, is(not(containsString("-----END CERTIFICATE-----"))));
		assertEquals(860, formatCert4.length());

		String empty1 = Util.formatCert("", false);
		String empty2 = Util.formatCert("", true);
		assertEquals("", empty1);
		assertEquals(empty1, empty2);

		String null1 = Util.formatCert(null, false);
		String null2 = Util.formatCert(null, true);
		assertEquals("", null1);
		assertEquals(null1, null2);
	}

	/**
	 * Tests the formatPrivateKey method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#formatPrivateKey
	 */
	@Test
	public void formatPrivateKey() throws IOException, URISyntaxException {
		// http://www.cryptosys.net/pki/rsakeyformats.html
		// PKCS#1
		String keyWithHeads = Util.getFileAsString("data/customPath/certs/sp.key");
		String keyWithoutHeads = keyWithHeads.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "");

		assertThat(keyWithHeads, containsString("-----BEGIN RSA PRIVATE KEY-----"));
		assertThat(keyWithHeads, containsString("-----END RSA PRIVATE KEY-----"));
		assertThat(keyWithoutHeads, is(not(containsString("-----BEGIN RSA PRIVATE KEY-----"))));
		assertThat(keyWithoutHeads, is(not(containsString("-----END RSA PRIVATE KEY-----"))));

		String formatKey1 = Util.formatPrivateKey(keyWithHeads, true);
		assertThat(formatKey1, containsString("-----BEGIN RSA PRIVATE KEY-----"));
		assertThat(formatKey1, containsString("-----END RSA PRIVATE KEY-----"));
		assertEquals(890, formatKey1.length());

		String formatKey2 = Util.formatPrivateKey(keyWithHeads, false);
		assertThat(formatKey2, is(not(containsString("-----BEGIN RSA PRIVATE KEY-----"))));
		assertThat(formatKey2, is(not(containsString("-----END RSA PRIVATE KEY-----"))));
		assertEquals(816, formatKey2.length());

		String formatKey3 = Util.formatPrivateKey(keyWithoutHeads, true);
		assertThat(formatKey3, containsString("-----BEGIN RSA PRIVATE KEY-----"));
		assertThat(formatKey3, containsString("-----END RSA PRIVATE KEY-----"));
		assertEquals(890, formatKey3.length());

		String formatKey4 = Util.formatPrivateKey(keyWithoutHeads, false);
		assertThat(formatKey4, is(not(containsString("-----BEGIN RSA PRIVATE KEY-----"))));
		assertThat(formatKey4, is(not(containsString("-----END RSA PRIVATE KEY-----"))));
		assertEquals(816, formatKey4.length());

		// PKCS#8
		String noRsaKey = Util.getFileAsString("data/customPath/certs/sp.pem");
		String noRsaKeyWithHeads = keyWithHeads.replace("-----BEGIN RSA PRIVATE KEY-----","-----BEGIN PRIVATE KEY-----").replace("-----END RSA PRIVATE KEY-----", "-----END PRIVATE KEY-----");
		String formatKey5 = Util.formatPrivateKey(noRsaKeyWithHeads, false);
		assertThat(formatKey5, is(not(containsString("-----BEGIN PRIVATE KEY-----"))));
		assertThat(formatKey5, is(not(containsString("-----END PRIVATE KEY-----"))));
		assertEquals(816, formatKey5.length());

		String formatKey6 = Util.formatPrivateKey(noRsaKeyWithHeads, true);
		assertThat(formatKey6, containsString("-----BEGIN PRIVATE KEY-----"));
		assertThat(formatKey6, containsString("-----END PRIVATE KEY-----"));
		assertEquals(882, formatKey6.length());

		String empty1 = Util.formatPrivateKey("", false);
		String empty2 = Util.formatPrivateKey("", true);
		assertEquals("", empty1);
		assertEquals(empty1, empty2);

		String null1 = Util.formatPrivateKey(null, false);
		String null2 = Util.formatPrivateKey(null, true);
		assertEquals("", null1);
		assertEquals(null1, null2);
	}
	
	/**
	 * Tests the loadCert method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws CertificateException
	 *
	 * @see com.onelogin.saml2.util.Util#loadCert
	 */
	@Test
	public void testLoadCertCert() throws URISyntaxException, IOException, CertificateException {
		String cert = Util.getFileAsString("data/customPath/certs/sp.crt");
		String certWithHeads = Util.formatCert(cert, true);
		String certWithoutHeads = Util.formatCert(cert, false);
		
		X509Certificate certObject1 = Util.loadCert(certWithHeads);
		X509Certificate certObject2 = Util.loadCert(certWithoutHeads);
		
		assertNotNull(certObject1);
		assertNotNull(certObject2);
		assertEquals(certObject1.getSigAlgName(), certObject2.getSigAlgName());
		assertEquals("X.509", certObject1.getType());
		assertEquals("X.509", certObject2.getType());
	}
	
	/**
	 * Tests load public certificate X.509 String with heads.
	 *
	 * @throws UnsupportedEncodingException
	 * @throws CertificateException
	 *
	 * @see com.onelogin.saml2.util.Util#loadCert
	 */
	@Test
	public void testLoadCertWithHeads() throws CertificateException, UnsupportedEncodingException {
		String certWithHeads = "-----BEGIN CERTIFICATE-----\n"
				+ "MIICeDCCAeGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBZMQswCQYDVQQGEwJ1czET\n"
				+ "MBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lTG9naW4gSW5jMR4wHAYD\n"
				+ "VQQDDBVqYXZhLXNhbWwuZXhhbXBsZS5jb20wHhcNMTUxMDE4MjAxMjM1WhcNMTgw\n"
				+ "NzE0MjAxMjM1WjBZMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEV\n"
				+ "MBMGA1UECgwMT25lTG9naW4gSW5jMR4wHAYDVQQDDBVqYXZhLXNhbWwuZXhhbXBs\n"
				+ "ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALvwEktX1+4y2AhEqxVw\n"
				+ "OO6HO7Wtzi3hr5becRkfLYGjNSyhzZCjI1DsNL61JSWDO3nviZd9fSkFnRC4akFU\n"
				+ "m0CS6GJ7TZe4T5o+9aowQ6N8e8cts9XPXyP6Inz7q4sD8pO2EInlfwHYPQCqFmz/\n"
				+ "SDW7cDgIC8vb0ygOsiXdreANAgMBAAGjUDBOMB0GA1UdDgQWBBTifMwN3CQ5ZOPk\n"
				+ "V5tDJsutU8teFDAfBgNVHSMEGDAWgBTifMwN3CQ5ZOPkV5tDJsutU8teFDAMBgNV\n"
				+ "HRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAG3nAEUjJaA75SkzID5FKLolsxG5\n"
				+ "TE/0HU0+yEUAVkXiqvqN4mPWq/JjoK5+uP4LEZIb4pRrCqI3iHp+vazLLYSeyV3k\n"
				+ "aGN7q35Afw8nk8WM0f7vImbQ69j1S8GQ+6E0PEI26qBLykGkMn3GUVtBBWSdpP09\n"
				+ "3NuNLJiOomnHqhqj\n"
				+ "-----END CERTIFICATE-----";
		Certificate loadedCert = Util.loadCert(certWithHeads);
		assertNotNull(loadedCert);
		assertEquals("X.509", loadedCert.getType());
	}

	/**
	 * Tests load public certificate X.509 String without heads.
	 *
	 * @throws UnsupportedEncodingException
	 * @throws CertificateException
	 *
	 * @see com.onelogin.saml2.util.Util#loadCert
	 */
	@Test
	public void testLoadCertWithoutHeads() throws CertificateException, UnsupportedEncodingException {
		String certWithoutHeads = "MIICeDCCAeGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBZMQswCQYDVQQGEwJ1czET"
				+ "MBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lTG9naW4gSW5jMR4wHAYD"
				+ "VQQDDBVqYXZhLXNhbWwuZXhhbXBsZS5jb20wHhcNMTUxMDE4MjAxMjM1WhcNMTgw"
				+ "NzE0MjAxMjM1WjBZMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEV"
				+ "MBMGA1UECgwMT25lTG9naW4gSW5jMR4wHAYDVQQDDBVqYXZhLXNhbWwuZXhhbXBs"
				+ "ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALvwEktX1+4y2AhEqxVw"
				+ "OO6HO7Wtzi3hr5becRkfLYGjNSyhzZCjI1DsNL61JSWDO3nviZd9fSkFnRC4akFU"
				+ "m0CS6GJ7TZe4T5o+9aowQ6N8e8cts9XPXyP6Inz7q4sD8pO2EInlfwHYPQCqFmz/"
				+ "SDW7cDgIC8vb0ygOsiXdreANAgMBAAGjUDBOMB0GA1UdDgQWBBTifMwN3CQ5ZOPk"
				+ "V5tDJsutU8teFDAfBgNVHSMEGDAWgBTifMwN3CQ5ZOPkV5tDJsutU8teFDAMBgNV"
				+ "HRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAG3nAEUjJaA75SkzID5FKLolsxG5"
				+ "TE/0HU0+yEUAVkXiqvqN4mPWq/JjoK5+uP4LEZIb4pRrCqI3iHp+vazLLYSeyV3k"
				+ "aGN7q35Afw8nk8WM0f7vImbQ69j1S8GQ+6E0PEI26qBLykGkMn3GUVtBBWSdpP09"
				+ "3NuNLJiOomnHqhqj";
		Certificate loadedCert = Util.loadCert(certWithoutHeads);
		assertNotNull(loadedCert);
		assertEquals("X.509", loadedCert.getType());
	}

	/**
	 * Tests the loadPrivateKey method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 *
	 * @see com.onelogin.saml2.util.Util#loadPrivateKey
	 */
	@Test
	public void testLoadPrivateKeyPKCS8() throws URISyntaxException, IOException, GeneralSecurityException {
		String key = Util.getFileAsString("data/customPath/certs/sp.pem");
		String keyWithHeads = Util.formatPrivateKey(key, true);
		String keyWithoutHeads = Util.formatPrivateKey(key, false);

		PrivateKey keyObject1 = Util.loadPrivateKey(keyWithHeads);
		PrivateKey keyObject2 = Util.loadPrivateKey(keyWithoutHeads);
		
		assertNotNull(keyObject1);
		assertNotNull(keyObject2);
		assertEquals(keyObject1.getClass(), keyObject2.getClass()); 
		assertEquals(keyObject1.getAlgorithm(), keyObject2.getAlgorithm());
	}
	

	/**
	 * Tests the loadPrivateKey method
	 *
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws IOException
	 *
	 * @see com.onelogin.saml2.util.Util#loadPrivateKey
	 */
	
	@Test(expected=InvalidKeySpecException.class)
	public void testLoadPrivateKeyPKCS1() throws URISyntaxException, GeneralSecurityException, IOException {
		String key = Util.getFileAsString("data/customPath/certs/sp.key");
		
		// PKCS1 format not supported 
		PrivateKey keyObject1 = Util.loadPrivateKey(key);
		assertNull(keyObject1);
	}

	/**
	 * Tests the loadPrivateKey method
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameIdData
	 */
	@Test
	public void testGetNameIdDataWrongKey() throws Exception {
		String keyString = Util.getFileAsString("data/misc/sp3.key");
		
		expectedEx.expect(Exception.class);
		expectedEx.expectMessage("algid parse error, not a sequence");
		Util.loadPrivateKey(keyString);
	}
	
	/**
	 * Tests load Private Key String with heads.
	 *
	 * @throws IOException
	 * @throws GeneralSecurityException
	 *
	 * @see com.onelogin.saml2.util.Util#loadPrivateKey
	 */
	@Test
	public void testLoadPrivateKeyWithHeads() throws GeneralSecurityException, IOException {
		String keyWithHeads = "-----BEGIN PRIVATE KEY-----\n"
				+ "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALvwEktX1+4y2AhE\n"
				+ "qxVwOO6HO7Wtzi3hr5becRkfLYGjNSyhzZCjI1DsNL61JSWDO3nviZd9fSkFnRC4\n"
				+ "akFUm0CS6GJ7TZe4T5o+9aowQ6N8e8cts9XPXyP6Inz7q4sD8pO2EInlfwHYPQCq\n"
				+ "Fmz/SDW7cDgIC8vb0ygOsiXdreANAgMBAAECgYA7VPVRl+/xoVeWdKdWY1F17Her\n"
				+ "Sa23ynI2vQ8TkUY6kR3ucz6ElRxHJesY8fNCPoX+XuMfUly7IKyPZMkWyvEgDPo7\n"
				+ "J5mYqP5VsTK0Li4AwR/BA93Aw6gaX7/EYi3HjBh8QdNSt4fi9yOea/hv04yfR9Lx\n"
				+ "/a5fvQIyhqaDtT2QeQJBAOnCgnxnj70/sv9UsFPa8t1OGdAfXtOgEoklh1F2NR9j\n"
				+ "id6FPw5E98eCpdZ00MfRrmUavgqg6Y4swZISyzJIjGMCQQDN0YNsC4S+eJJM6aOC\n"
				+ "pupKluWE/cCWB01UQYekyXH7OdUtl49NlKEUPBSAvtaLMuMKlTNOjlPrx4Q+/c5i\n"
				+ "0vTPAkEA5H7CR9J/OZETaewhc8ZYkaRvLPYNHjWhCLhLXoB6itUkhgOfUFZwEXAO\n"
				+ "pOOI1VmL675JN2B1DAmJqTx/rQYnWwJBAMx3ztsAmnBq8dTM6y65ydouDHhRawjg\n"
				+ "2jbRHwNbSQvuyVSQ08Gb3WZvxWKdtB/3fsydqqnpBYAf5sZ5eJZ+wssCQAOiIKnh\n"
				+ "dYe+RBbBwykzjUqtzEmt4fwCFE8tD4feEx77D05j5f7u7KYh1mL0G2zIbnUryi7j\n"
				+ "wc4ye98VirRpZ1w=\n"
				+ "-----END PRIVATE KEY-----";
		PrivateKey loadedKey = Util.loadPrivateKey(keyWithHeads);
		assertNotNull(loadedKey);
	}

	/**
	 * Tests load Private Key String without heads.
	 *
	 * @throws IOException
	 * @throws GeneralSecurityException
	 *
	 * @see com.onelogin.saml2.util.Util#loadCert
	 */
	@Test
	public void testLoadPrivateKeyWithoutHeads() throws GeneralSecurityException, IOException {
		String keyWithoutHeads = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALvwEktX1+4y2AhE"
				+ "qxVwOO6HO7Wtzi3hr5becRkfLYGjNSyhzZCjI1DsNL61JSWDO3nviZd9fSkFnRC4"
				+ "akFUm0CS6GJ7TZe4T5o+9aowQ6N8e8cts9XPXyP6Inz7q4sD8pO2EInlfwHYPQCq"
				+ "Fmz/SDW7cDgIC8vb0ygOsiXdreANAgMBAAECgYA7VPVRl+/xoVeWdKdWY1F17Her"
				+ "Sa23ynI2vQ8TkUY6kR3ucz6ElRxHJesY8fNCPoX+XuMfUly7IKyPZMkWyvEgDPo7"
				+ "J5mYqP5VsTK0Li4AwR/BA93Aw6gaX7/EYi3HjBh8QdNSt4fi9yOea/hv04yfR9Lx"
				+ "/a5fvQIyhqaDtT2QeQJBAOnCgnxnj70/sv9UsFPa8t1OGdAfXtOgEoklh1F2NR9j"
				+ "id6FPw5E98eCpdZ00MfRrmUavgqg6Y4swZISyzJIjGMCQQDN0YNsC4S+eJJM6aOC"
				+ "pupKluWE/cCWB01UQYekyXH7OdUtl49NlKEUPBSAvtaLMuMKlTNOjlPrx4Q+/c5i"
				+ "0vTPAkEA5H7CR9J/OZETaewhc8ZYkaRvLPYNHjWhCLhLXoB6itUkhgOfUFZwEXAO"
				+ "pOOI1VmL675JN2B1DAmJqTx/rQYnWwJBAMx3ztsAmnBq8dTM6y65ydouDHhRawjg"
				+ "2jbRHwNbSQvuyVSQ08Gb3WZvxWKdtB/3fsydqqnpBYAf5sZ5eJZ+wssCQAOiIKnh"
				+ "dYe+RBbBwykzjUqtzEmt4fwCFE8tD4feEx77D05j5f7u7KYh1mL0G2zIbnUryi7j"
				+ "wc4ye98VirRpZ1w=";
		PrivateKey loadedKey = Util.loadPrivateKey(keyWithoutHeads);
		assertNotNull(loadedKey);
	}

	/**
	 * Tests the calculateX509Fingerprint method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws CertificateException
	 *
	 * @see com.onelogin.saml2.util.Util#calculateX509Fingerprint
	 */
	@Test
	public void testCalculateX509Fingerprint() throws URISyntaxException, IOException, CertificateException {
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String fingerprint = Util.calculateX509Fingerprint(cert);
		String fingerprint2 = Util.calculateX509Fingerprint(cert, null);
		String fingerprint3 = Util.calculateX509Fingerprint(cert, "");
		String fingerprintSha1 = Util.calculateX509Fingerprint(cert, "SHA-1");
		String fingerprintSha1_2 = Util.calculateX509Fingerprint(cert, "sha1");
		String fingerprintSha256 = Util.calculateX509Fingerprint(cert, "SHA-256");
		String fingerprintSha256_2 = Util.calculateX509Fingerprint(cert, "sha256");
		String fingerprintSha384 = Util.calculateX509Fingerprint(cert, "SHA-384");
		String fingerprintSha384_2 = Util.calculateX509Fingerprint(cert, "sha384");
		String fingerprintSha512 = Util.calculateX509Fingerprint(cert, "SHA-512");
		String fingerprintSha512_2 = Util.calculateX509Fingerprint(cert, "sha512");
		String fingerprintInvalid = Util.calculateX509Fingerprint(cert, "SHA-XXX");

		assertEquals("afe71c28ef740bc87425be13a2263d37971da1f9", fingerprint);
		assertEquals(fingerprint, fingerprintSha1);
		assertEquals(fingerprint, fingerprintSha1_2);
		assertEquals(fingerprint2, fingerprintSha1);
		assertEquals(fingerprint3, fingerprintSha1);
		assertEquals("c51cfa06c7a49767f6eab18238eae1c56708e29264da3d11f538a12cd2c357ba", fingerprintSha256);
		assertEquals("c51cfa06c7a49767f6eab18238eae1c56708e29264da3d11f538a12cd2c357ba", fingerprintSha256_2);
		assertEquals("bc5826e6f9429247254bae5e3c650e6968a36a62d23075eb168134978d88600559c10830c28711b2c29c7947c0c2eb1d", fingerprintSha384);
		assertEquals("bc5826e6f9429247254bae5e3c650e6968a36a62d23075eb168134978d88600559c10830c28711b2c29c7947c0c2eb1d", fingerprintSha384_2);
		assertEquals("3db29251b97559c67988ea0754cb0573fc409b6f75d89282d57cfb75089539b0bbdb2dcd9ec6e032549ecbc466439d5992e18db2cf5494ca2fe1b2e16f348dff", fingerprintSha512);
		assertEquals("3db29251b97559c67988ea0754cb0573fc409b6f75d89282d57cfb75089539b0bbdb2dcd9ec6e032549ecbc466439d5992e18db2cf5494ca2fe1b2e16f348dff", fingerprintSha512_2);
		assertTrue(fingerprintInvalid.isEmpty());
	}
	
	/**
	 * Tests the convertToPem method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws CertificateException
	 *
	 * @see com.onelogin.saml2.util.Util#convertToPem
	 */
	@Test
	public void testConvertToPem() throws URISyntaxException, IOException, CertificateException {
		String cert = Util.getFileAsString("data/customPath/certs/sp.crt");
		String certWithHeads = Util.formatCert(cert, true);
		String certWithoutHeads = Util.formatCert(cert, false);

		X509Certificate certObject1 = Util.loadCert(certWithHeads);
		X509Certificate certObject2 = Util.loadCert(certWithoutHeads);

		assertNotNull(certObject1);
		assertNotNull(certObject2);
		assertEquals(Util.convertToPem(certObject1), Util.convertToPem(certObject2));
	}

	/**
	 * Tests the loadResource method
	 * @throws IOException 
	 *
	 * @see com.onelogin.saml2.util.Util#getFileAsString
	 */
	@Test
	public void testgetFileAsStringSuccess() throws IOException {
		String string = Util.getFileAsString("config/config.certfile.properties");
		assertNotNull(string);
	}

	/**
	 * Tests the loadResource method
	 *
	 * @throws IOException
	 *
	 * @see com.onelogin.saml2.util.Util#getFileAsString
	 */
	@Test(expected=FileNotFoundException.class)
	public void testLoadResourceFail() throws IOException {
		String string = Util.getFileAsString("invalid_path");
		assertNull(string);
	}	
	
	/**
	 * Tests the base64decodedInflated method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#base64decodedInflated
	 */
	@Test
	public void testBase64decodedInflated() throws URISyntaxException, IOException {
		String authNRequest = Util.getFileAsString("data/requests/authn_request.xml"); 
		String encodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.base64");
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");

		assertThat(authNRequest.toString(), equalTo(Util.base64decodedInflated(encodedAuthNRequest).toString()));
		assertThat(authNRequest.toString(), equalTo(Util.base64decodedInflated(deflatedEncodedAuthNRequest).toString()));
	}

	/**
	 * Tests the base64decodedInflated method
	 * Case: Long certs
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#base64decodedInflated
	 */
	@Test
	public void testBase64decodedInflated2() throws URISyntaxException, IOException {
		String samlResponse = Util.getFileAsString("data/responses/response_long_cert.xml");
		String deflatedEncodedsamlResponse = Util.getFileAsString("data/responses/response_long_cert.xml.deflated.base64");

		assertThat(samlResponse.toString(), equalTo(Util.base64decodedInflated(deflatedEncodedsamlResponse).toString()));
	}
	
	/**
	 * Tests the deflatedBase64encoded method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#deflatedBase64encoded
	 */
	@Test
	public void testDeflatedBase64encoded() throws URISyntaxException, IOException {
		String authNRequest = Util.getFileAsString("data/requests/authn_request.xml"); 
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");

		assertThat(Util.deflatedBase64encoded(authNRequest).toString(), equalTo(deflatedEncodedAuthNRequest.toString()));
	}
	
	/**
	 * Tests the base64encoder method
	 *
	 * @throws IOException 
	 * @throws URISyntaxException 
	 * 
	 * @see com.onelogin.saml2.util.Util#base64encoder
	 */
	@Test
	public void testBase64encoder() throws URISyntaxException, IOException {
		String authNRequest = Util.getFileAsString("data/requests/authn_request.xml"); 
		String encodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.base64");
		
		assertThat(Util.base64encoder(authNRequest).toString(), equalTo(encodedAuthNRequest.toString()));
	}
	
	/**
	 * Tests the base64decoder method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#base64decoder
	 */
	@Test
	public void testBase64decoder() throws URISyntaxException, IOException {
		String authNRequest = Util.getFileAsString("data/requests/authn_request.xml"); 
		String encodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.base64");
		
		assertThat(authNRequest.toString(), equalTo(new String(Util.base64decoder(encodedAuthNRequest))));
	}
	
	/**
	 * Tests the urlEncoder method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#urlEncoder
	 */
	@Test
	public void testUrlEncoder() throws URISyntaxException, IOException {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		
		assertEquals("pVNNj9owEL3vr4h8hxCSCmJtkCjbDyQKKdAeeqm8zqRryR%2Bpx9ml%2F752YFv3sBy2cxzPzHvz3vgWmZIdXfbuQe%2FhZw%2FokpOSGunwUJHeamoYCqSaKUDqOD0sP23odDyhnTXOcCNJsr6ryPfd9t1m92G9zSZ5MZ2Xk5LdAy%2BmRcvezPPprJ2Vxawo5wVJvoJFYXRF%2FBTfjNjDWqNj2vnUJCtGWTbK8mOW0bykefGNJO%2BN5TCwrEjLJEJoqxmieIQ%2FmfrC563QjdA%2FrpO%2FPxch%2FXg81qN6dziSZIkI1nlmK6OxV2APYB8Fhy%2F7TUUenOtomsKJqU7CmBuVMo5kcZP4uA1y0WETGwl4nQJ7hrsMCXFBEU03jpEUONYwx85gaYQW4Xd06zHWd7WRgv96jY9eZsXc9eqQEc2oHUppF6xEB9qR5FAH%2FM89k6IVYCsSbeDFldI8rSww5x1ztveGpf%2BQv9wfNIPP3gIHp1dd48qojlmB4cI8Be4ifc9GxQgr6X3YQ%2FtftoW42sMpDzg%2BHa72ydjmL6X0RU6LyO8XBFrcPD%2FHn3jxGw%3D%3D", Util.urlEncoder(deflatedEncodedAuthNRequest));
		assertEquals(null, Util.urlEncoder(null));
	}
	
	/**
	 * Tests the urlDecoder method
	 *
	 * @throws IOException 
	 * @throws URISyntaxException 
	 * 
	 * @see com.onelogin.saml2.util.Util#urlDecoder
	 */
	@Test
	public void testUrlDecoder() throws URISyntaxException, IOException {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		
		assertEquals(deflatedEncodedAuthNRequest, Util.urlDecoder("pVNNj9owEL3vr4h8hxCSCmJtkCjbDyQKKdAeeqm8zqRryR%2Bpx9ml%2F752YFv3sBy2cxzPzHvz3vgWmZIdXfbuQe%2FhZw%2FokpOSGunwUJHeamoYCqSaKUDqOD0sP23odDyhnTXOcCNJsr6ryPfd9t1m92G9zSZ5MZ2Xk5LdAy%2BmRcvezPPprJ2Vxawo5wVJvoJFYXRF%2FBTfjNjDWqNj2vnUJCtGWTbK8mOW0bykefGNJO%2BN5TCwrEjLJEJoqxmieIQ%2FmfrC563QjdA%2FrpO%2FPxch%2FXg81qN6dziSZIkI1nlmK6OxV2APYB8Fhy%2F7TUUenOtomsKJqU7CmBuVMo5kcZP4uA1y0WETGwl4nQJ7hrsMCXFBEU03jpEUONYwx85gaYQW4Xd06zHWd7WRgv96jY9eZsXc9eqQEc2oHUppF6xEB9qR5FAH%2FM89k6IVYCsSbeDFldI8rSww5x1ztveGpf%2BQv9wfNIPP3gIHp1dd48qojlmB4cI8Be4ifc9GxQgr6X3YQ%2FtftoW42sMpDzg%2BHa72ydjmL6X0RU6LyO8XBFrcPD%2FHn3jxGw%3D%3D"));		
		assertEquals(null, Util.urlDecoder(null));
	}
	
	/**
	 * Tests the sign method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 *
	 * @see com.onelogin.saml2.util.Util#sign
	 */
	@Test
	public void testSign() throws URISyntaxException, IOException, GeneralSecurityException {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String signAlgorithm = Constants.RSA_SHA1;
		String spPrivateKey = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(spPrivateKey);
		String expectedSign = "lRsULuIIPLmpfvlJ7VQq6Vg5HWMKxLbCeVdQ3GvBRXsT+MIrYUwAY13oH9kx6hvEGCOyte8xAsVea8/WSFhZ84Oawm+2DRXz52Gs+N+RWDZ9uoT4yTXimZk71rpXc1Bqy7o/ZOJh51S3wqph2KEgBTqf2cBFjYiLz2/OSl2w4qE=";
		assertEquals(expectedSign, Util.base64encoder(Util.sign(deflatedEncodedAuthNRequest, key, signAlgorithm)));
		assertEquals(expectedSign, Util.base64encoder(Util.sign(deflatedEncodedAuthNRequest, key, null)));

		String expectedSign_2 = "DPnI7fef7Mm2Y3hriCWKlwvt0TOEdPaQR5yG/JXvtka/55ihHi0j8IjtiwvYNwO6AuIiru6LYKLnVv8x2Kf9Fb/myNx6I/+SwpKZkAQ10Ukpb0/oE4Cage6WDM3gtKukJmHPzJlUgWjB+no+9g4A4kt3Mq3n1UDWhfqDk508+fE=";
		String signAlgorithm_2 = Constants.RSA_SHA256;
		assertEquals(expectedSign_2, Util.base64encoder(Util.sign(deflatedEncodedAuthNRequest, key, signAlgorithm_2)));
	}
	
	/**
	 * Tests the signatureAlgConversion method
	 * 
	 * @see com.onelogin.saml2.util.Util#signatureAlgConversion
	 */
	@Test
	public void testSignatureAlgConversion() {
		assertEquals("SHA1withDSA", Util.signatureAlgConversion(Constants.DSA_SHA1));
		assertEquals("SHA1withRSA", Util.signatureAlgConversion(Constants.RSA_SHA1));
		assertEquals("SHA1withRSA", Util.signatureAlgConversion(null));
		assertEquals("SHA256withRSA", Util.signatureAlgConversion(Constants.RSA_SHA256));
		assertEquals("SHA384withRSA", Util.signatureAlgConversion(Constants.RSA_SHA384));
		assertEquals("SHA512withRSA", Util.signatureAlgConversion(Constants.RSA_SHA512));
	}
	
	/**
	 * Tests the validateSign method
	 * Case: Exception due invalid document
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws CertificateException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 *
	 * @see com.onelogin.saml2.util.Util#validateSign
	 */
	@Test
	public void testValidateSignInvalidsInputs() throws URISyntaxException, IOException, CertificateException, ParserConfigurationException, SAXException {
		String responseStr = Util.getFileAsString("data/responses/signed_message_response.xml.base64");
		String samlResponseStr = new String(Util.base64decoder(responseStr));
		Document samlResponseDocument = Util.loadXML(samlResponseStr);

		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String fingerprint_c1_sha1 = "afe71c28ef740bc87425be13a2263d37971da1f9";
		String fingerprint_c1_sha256 = "c51cfa06c7a49767f6eab18238eae1c56708e29264da3d11f538a12cd2c357ba";

		String certString_2 = Util.getFileAsString("certs/certificate1");
		X509Certificate cert_2 = Util.loadCert(certString_2);
		String fingerprint_c2_sha1 = "c51985d947f1be57082025050846eb27f6cab783";

		// No doc
		assertFalse(Util.validateSign(null, cert, null, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(null, cert, null, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(null, cert, null, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(null, cert, null, null, ASSERTION_SIGNATURE_XPATH));

		// No cert & no fingerprint
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, null, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, null, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, null, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, null, null, ASSERTION_SIGNATURE_XPATH));

		// Wrong cert
		assertFalse(Util.validateSign(samlResponseDocument, cert_2, null, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, cert_2, null, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, cert_2, null, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, cert_2, null, "SHA-1", ASSERTION_SIGNATURE_XPATH));

		// Wrong fingerprint
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c2_sha1, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c2_sha1, null, ASSERTION_SIGNATURE_XPATH));

		// Wrong fingerprint alg
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c1_sha256, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c1_sha1, "SHA-256", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c1_sha256, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c1_sha1, "SHA-256", ASSERTION_SIGNATURE_XPATH));

		// Reference validation failed
		NamedNodeMap attrs = samlResponseDocument.getFirstChild().getAttributes();
		Node nodeAttr = attrs.getNamedItem("ID");		
		nodeAttr.setTextContent("pfxc3d2b542-0f7e-8767-8e87-5b0dc6913375-alter");
		assertFalse(Util.validateSign(samlResponseDocument, cert, null, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c2_sha1, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-256", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, cert, null, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c2_sha1, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlResponseDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-256", ASSERTION_SIGNATURE_XPATH));


		// Element changed
		String signedAssertionStr = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");
		String samlSignedAssertionStr = new String(Util.base64decoder(signedAssertionStr));
		Document samlSignedAssertionDocument = Util.loadXML(samlSignedAssertionStr);
		Node audience = samlSignedAssertionDocument.getElementsByTagName("saml:Audience").item(0);
		audience.setTextContent("http://sp.example.com/metadata.php");
		assertFalse(Util.validateSign(samlSignedAssertionDocument, cert, null, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedAssertionDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedAssertionDocument, (X509Certificate) null, fingerprint_c2_sha1, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedAssertionDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-256", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedAssertionDocument, cert, null, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedAssertionDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedAssertionDocument, (X509Certificate) null, fingerprint_c2_sha1, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedAssertionDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-256", ASSERTION_SIGNATURE_XPATH));


		// Manipulated Node fails
		String doubleSignedResponseStr = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");
		String samlDoubleSignedResponseStr = new String(Util.base64decoder(doubleSignedResponseStr));
		Document samlDoubleSignedResponseDocument = Util.loadXML(samlDoubleSignedResponseStr);
		Node assertionElement = (Node) samlDoubleSignedResponseDocument.getFirstChild().getFirstChild().getNextSibling().getNextSibling();
		assertFalse(Util.validateSignNode(assertionElement, cert, null, null));

		// No Signature
		String noSignatureStr = Util.getFileAsString("data/responses/invalids/no_signature.xml.base64");
		String samlNoSignatureStr = new String(Util.base64decoder(noSignatureStr));
		Document samlNoSignatureDocument = Util.loadXML(samlNoSignatureStr);
		assertFalse(Util.validateSign(samlNoSignatureDocument, cert, null, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoSignatureDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoSignatureDocument, (X509Certificate) null, fingerprint_c2_sha1, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoSignatureDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-256", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoSignatureDocument, cert, null, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoSignatureDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoSignatureDocument, (X509Certificate) null, fingerprint_c2_sha1, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoSignatureDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-256", ASSERTION_SIGNATURE_XPATH));


		// No key
		String noKeyStr = Util.getFileAsString("data/responses/invalids/no_key.xml.base64");
		String samlNoKeyStr = new String(Util.base64decoder(noKeyStr));
		Document samlNoKeyDocument = Util.loadXML(samlNoKeyStr);
		assertFalse(Util.validateSign(samlNoKeyDocument, cert, null, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoKeyDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoKeyDocument, (X509Certificate) null, fingerprint_c2_sha1, null, RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoKeyDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-256", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoKeyDocument, cert, null, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoKeyDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoKeyDocument, (X509Certificate) null, fingerprint_c2_sha1, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlNoKeyDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-256", ASSERTION_SIGNATURE_XPATH));


		// Signature Wrapping Attack
		String sigAttackStr = Util.getFileAsString("data/responses/invalids/signature_wrapping_attack.xml.base64");
		String samlSigAttackStr = new String(Util.base64decoder(sigAttackStr));
		Document samlSigAttackDocument = Util.loadXML(samlSigAttackStr);
		assertFalse(Util.validateSign(samlSigAttackDocument, cert, null, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSigAttackDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSigAttackDocument, (X509Certificate) null, fingerprint_c2_sha1, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSigAttackDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-256", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSigAttackDocument, cert, null, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSigAttackDocument, (X509Certificate) null, fingerprint_c2_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSigAttackDocument, (X509Certificate) null, fingerprint_c2_sha1, null, ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSigAttackDocument, (X509Certificate) null, fingerprint_c1_sha256, "SHA-256", ASSERTION_SIGNATURE_XPATH));
	}

	/**
	 * Tests the validateSign method
	 * Case: Exception due invalid document
	 *
	 * @throws IOException 
	 * @throws URISyntaxException 
	 * @throws CertificateException
	 *
	 * @see com.onelogin.saml2.util.Util#validateSign
	 */
	@Test
	public void testValidateSign() throws URISyntaxException, IOException, CertificateException {
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String fingerprint_sha1 = "afe71c28ef740bc87425be13a2263d37971da1f9";
		String fingerprint_sha256 = "c51cfa06c7a49767f6eab18238eae1c56708e29264da3d11f538a12cd2c357ba";
		String fingerprint_sha1_uppercase = "AFE71C28EF740BC87425BE13A2263D37971DA1F9";
		String fingerprint_sha256_uppercase = "C51CFA06C7A49767F6EAB18238EAE1C56708E29264DA3D11F538A12CD2C357BA";

		// Signed Response
		String signedResponseStr = Util.getFileAsString("data/responses/signed_message_response.xml.base64");
		String samlSignedResponseStr = new String(Util.base64decoder(signedResponseStr));
		Document samlSignedResponseDocument = Util.loadXML(samlSignedResponseStr);

		assertTrue(Util.validateSign(samlSignedResponseDocument, cert, null, null, RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedResponseDocument, (X509Certificate) null, fingerprint_sha1, null, RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedResponseDocument, (X509Certificate) null, fingerprint_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedResponseDocument, (X509Certificate) null, fingerprint_sha256, "SHA-256", RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedResponseDocument, (X509Certificate) null, fingerprint_sha1_uppercase, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedResponseDocument, (X509Certificate) null, fingerprint_sha256_uppercase, "SHA-256", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedResponseDocument, (X509Certificate) null, fingerprint_sha256, "SHA-256", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedResponseDocument, cert, null, null, ""));
		assertFalse(Util.validateSign(samlSignedResponseDocument, (X509Certificate) null, null, null, ""));

		// Signed Assertion Response
		String signedAssertionStr = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");
		String samlSignedAssertionStr = new String(Util.base64decoder(signedAssertionStr));
		Document samlSignedAssertionDocument = Util.loadXML(samlSignedAssertionStr);

		assertTrue(Util.validateSign(samlSignedAssertionDocument, cert, null, null, ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedAssertionDocument, (X509Certificate) null, fingerprint_sha1, null, ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedAssertionDocument, (X509Certificate) null, fingerprint_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedAssertionDocument, (X509Certificate) null, fingerprint_sha1_uppercase, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedAssertionDocument, (X509Certificate) null, fingerprint_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));

		// Double Signed Response
		String doubleSignedResponseStr = Util.getFileAsString("data/responses/double_signed_response.xml.base64");
		String samlDoubleSignedResponseStr = new String(Util.base64decoder(doubleSignedResponseStr));
		Document samlDoubleSignedResponseDocument = Util.loadXML(samlDoubleSignedResponseStr);

		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, cert, null, null, ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, cert, null, null, RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (X509Certificate) null, fingerprint_sha1, null, ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (X509Certificate) null, fingerprint_sha1, null, RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (X509Certificate) null, fingerprint_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (X509Certificate) null, fingerprint_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (X509Certificate) null, fingerprint_sha1_uppercase, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (X509Certificate) null, fingerprint_sha1_uppercase, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (X509Certificate) null, fingerprint_sha256, "SHA-256", ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (X509Certificate) null, fingerprint_sha256, "SHA-256", RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (X509Certificate) null, fingerprint_sha256_uppercase, "SHA-256", ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (X509Certificate) null, fingerprint_sha256_uppercase, "SHA-256", RESPONSE_SIGNATURE_XPATH));
	}

	/**
	 * Tests the validateSign method
	 * Case: Exception due invalid document
	 *
	 * @throws IOException 
	 * @throws URISyntaxException 
	 * @throws CertificateException
	 *
	 * @see com.onelogin.saml2.util.Util#validateSign
	 */
	@Test
	public void testValidateSignWilthMultiCert() throws URISyntaxException, IOException, CertificateException {
		String[] certListString = new String[] {
													Util.getFileAsString("data/customPath/certs/sp.crt"),
													Util.getFileAsString("certs/certificate1"),
													Util.getFileAsString("certs/certificate2"),
													Util.getFileAsString("certs/certificate3")
												};
		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		for (String certString : certListString) {
			certList.add(Util.loadCert(certString));
		}
		String fingerprint_sha1 = "afe71c28ef740bc87425be13a2263d37971da1f9";
		String fingerprint_sha256 = "c51cfa06c7a49767f6eab18238eae1c56708e29264da3d11f538a12cd2c357ba";

		// Signed Response
		String signedResponseStr = Util.getFileAsString("data/responses/signed_message_response.xml.base64");
		String samlSignedResponseStr = new String(Util.base64decoder(signedResponseStr));
		Document samlSignedResponseDocument = Util.loadXML(samlSignedResponseStr);

		assertTrue(Util.validateSign(samlSignedResponseDocument, certList, null, null, RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedResponseDocument, (List<X509Certificate>) null, fingerprint_sha1, null, RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedResponseDocument, (List<X509Certificate>) null, fingerprint_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedResponseDocument, (List<X509Certificate>) null, fingerprint_sha256, "SHA-256", RESPONSE_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedResponseDocument, (List<X509Certificate>) null, fingerprint_sha256, "SHA-256", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedResponseDocument, certList, null, null, ""));
		assertFalse(Util.validateSign(samlSignedResponseDocument, (List<X509Certificate>) null, null, null, ""));

		// Signed Assertion Response
		String signedAssertionStr = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");
		String samlSignedAssertionStr = new String(Util.base64decoder(signedAssertionStr));
		Document samlSignedAssertionDocument = Util.loadXML(samlSignedAssertionStr);
		
		assertTrue(Util.validateSign(samlSignedAssertionDocument, certList, null, null, ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedAssertionDocument, (List<X509Certificate>) null, fingerprint_sha1, null, ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlSignedAssertionDocument, (List<X509Certificate>) null, fingerprint_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertFalse(Util.validateSign(samlSignedAssertionDocument, (List<X509Certificate>) null, fingerprint_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));

		// Double Signed Response
		String doubleSignedResponseStr = Util.getFileAsString("data/responses/double_signed_response.xml.base64");
		String samlDoubleSignedResponseStr = new String(Util.base64decoder(doubleSignedResponseStr));
		Document samlDoubleSignedResponseDocument = Util.loadXML(samlDoubleSignedResponseStr);

		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, certList, null, null, ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, certList, null, null, RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (List<X509Certificate>) null, fingerprint_sha1, null, ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (List<X509Certificate>) null, fingerprint_sha1, null, RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (List<X509Certificate>) null, fingerprint_sha1, "SHA-1", ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (List<X509Certificate>) null, fingerprint_sha1, "SHA-1", RESPONSE_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (List<X509Certificate>) null, fingerprint_sha256, "SHA-256", ASSERTION_SIGNATURE_XPATH));
		assertTrue(Util.validateSign(samlDoubleSignedResponseDocument, (List<X509Certificate>) null, fingerprint_sha256, "SHA-256", RESPONSE_SIGNATURE_XPATH));
	}

	/**
	 * Tests the validateMetadataSign method
	 * Case: Exception due invalid document
	 *
	 * @throws IOException 
	 * @throws URISyntaxException 
	 * @throws CertificateException
	 *
	 * @see com.onelogin.saml2.util.Util#validateMetadataSign
	 */
	@Test
	public void testValidateMetadataSign() throws URISyntaxException, IOException, CertificateException {
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String fingerprint_sha1 = "afe71c28ef740bc87425be13a2263d37971da1f9";
		String fingerprint_sha256 = "c51cfa06c7a49767f6eab18238eae1c56708e29264da3d11f538a12cd2c357ba";

		// Unsigned Metadata
		String unsignedMetadataStr = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		Document unsignedMetadataDocument = Util.loadXML(unsignedMetadataStr);
		assertFalse(Util.validateMetadataSign(unsignedMetadataDocument, cert, null, null));
		assertFalse(Util.validateMetadataSign(unsignedMetadataDocument, null, fingerprint_sha1, null));
		assertFalse(Util.validateMetadataSign(unsignedMetadataDocument, null, fingerprint_sha1, "SHA-1"));
		assertFalse(Util.validateMetadataSign(unsignedMetadataDocument, null, fingerprint_sha256, "SHA-256"));

		// Signed Metadata
		String signedMetadataStr = Util.getFileAsString("data/metadata/signed_metadata_settings1.xml");
		Document signedMetadataDocument = Util.loadXML(signedMetadataStr);
		assertTrue(Util.validateMetadataSign(signedMetadataDocument, cert, null, null));
		assertTrue(Util.validateMetadataSign(signedMetadataDocument, null, fingerprint_sha1, null));
		assertTrue(Util.validateMetadataSign(signedMetadataDocument, null, fingerprint_sha1, "SHA-1"));
		assertTrue(Util.validateMetadataSign(signedMetadataDocument, null, fingerprint_sha256, "SHA-256"));		
	}
	
	/**
	 * Tests the decryptElement method
	 * Case: Encrypted NameId
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#decryptElement
	 */
	@Test
	public void testDecryptElementNameId() throws URISyntaxException, IOException, GeneralSecurityException, XPathExpressionException {
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);

		String responseNameIdEnc = Util.base64decodedInflated(Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64"));
		Document responseNameIdEncDoc = Util.loadXML(responseNameIdEnc);
		NodeList EncryptedNameIdNodes = Util.query(responseNameIdEncDoc, ".//saml:EncryptedID");
		NodeList EncryptedDataNodes = Util.query(responseNameIdEncDoc, "./xenc:EncryptedData", EncryptedNameIdNodes.item(0));
		Element encryptedData = (Element) EncryptedDataNodes.item(0);
		assertEquals("xenc:EncryptedData", encryptedData.getNodeName());
		Util.decryptElement(encryptedData, key);
		assertEquals("saml:NameID", EncryptedNameIdNodes.item(0).getFirstChild().getNodeName());
	}

	/**
	 * Tests the decryptElement method
	 * Case: Encrypted NameId with wrong private key
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#decryptElement
	 */
	@Test
	public void testDecryptElementNameIdWrongKey() throws URISyntaxException, IOException, GeneralSecurityException, XPathExpressionException {
		String keyString = "-----BEGIN PRIVATE KEY-----\n"
				+ "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALvwEktX1+4y2AhE\n"
				+ "qxVwOO6HO7Wtzi3hr5becRkfLYGjNSyhzZCjI1DsNL61JSWDO3nviZd9fSkFnRC4\n"
				+ "akFUm0CS6GJ7TZe4T5o+9aowQ6N8e8cts9XPXyP6Inz7q4sD8pO2EInlfwHYPQCq\n"
				+ "Fmz/SDW7cDgIC8vb0ygOsiXdreANAgMBAAECgYA7VPVRl+/xoVeWdKdWY1F17Her\n"
				+ "Sa23ynI2vQ8TkUY6kR3ucz6ElRxHJesY8fNCPoX+XuMfUly7IKyPZMkWyvEgDPo7\n"
				+ "J5mYqP5VsTK0Li4AwR/BA93Aw6gaX7/EYi3HjBh8QdNSt4fi9yOea/hv04yfR9Lx\n"
				+ "/a5fvQIyhqaDtT2QeQJBAOnCgnxnj70/sv9UsFPa8t1OGdAfXtOgEoklh1F2NR9j\n"
				+ "id6FPw5E98eCpdZ00MfRrmUavgqg6Y4swZISyzJIjGMCQQDN0YNsC4S+eJJM6aOC\n"
				+ "pupKluWE/cCWB01UQYekyXH7OdUtl49NlKEUPBSAvtaLMuMKlTNOjlPrx4Q+/c5i\n"
				+ "0vTPAkEA5H7CR9J/OZETaewhc8ZYkaRvLPYNHjWhCLhLXoB6itUkhgOfUFZwEXAO\n"
				+ "pOOI1VmL675JN2B1DAmJqTx/rQYnWwJBAMx3ztsAmnBq8dTM6y65ydouDHhRawjg\n"
				+ "2jbRHwNbSQvuyVSQ08Gb3WZvxWKdtB/3fsydqqnpBYAf5sZ5eJZ+wssCQAOiIKnh\n"
				+ "dYe+RBbBwykzjUqtzEmt4fwCFE8tD4feEx77D05j5f7u7KYh1mL0G2zIbnUryi7j\n"
				+ "wc4ye98VirRpZ1w=\n"
				+ "-----END PRIVATE KEY-----";
		PrivateKey key = Util.loadPrivateKey(keyString);
		
		String responseNameIdEnc = Util.base64decodedInflated(Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64"));
		Document responseNameIdEncDoc = Util.loadXML(responseNameIdEnc);
		NodeList EncryptedNameIdNodes = Util.query(responseNameIdEncDoc, ".//saml:EncryptedID");
		NodeList EncryptedDataNodes = Util.query(responseNameIdEncDoc, "./xenc:EncryptedData", EncryptedNameIdNodes.item(0));
		Element encryptedData = (Element) EncryptedDataNodes.item(0);
		assertEquals("xenc:EncryptedData", encryptedData.getNodeName());
		Util.decryptElement(encryptedData, key);
		assertNotEquals("saml:NameID", EncryptedNameIdNodes.item(0).getFirstChild().getNodeName());
		assertEquals("xenc:EncryptedData", EncryptedNameIdNodes.item(0).getFirstChild().getNodeName());
	}

	/**
	 * Tests the decryptElement method
	 * Case: Encrypted Assertion
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#decryptElement
	 */
	@Test
	public void testDecryptElementAssertion() throws URISyntaxException, IOException, GeneralSecurityException, XPathExpressionException {
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);

		String responseAssertionEnc = Util.base64decodedInflated(Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64"));
		Document responseAssertionEncDoc = Util.loadXML(responseAssertionEnc);
		NodeList EncryptedAssertionNodes = Util.query(responseAssertionEncDoc, ".//saml:EncryptedAssertion");
		NodeList EncryptedDataNodes = Util.query(responseAssertionEncDoc, "./xenc:EncryptedData", EncryptedAssertionNodes.item(0));
		Element encryptedData = (Element) EncryptedDataNodes.item(0);
		assertEquals("xenc:EncryptedData", encryptedData.getNodeName());
		Util.decryptElement(encryptedData, key);
		assertEquals("saml:Assertion", EncryptedAssertionNodes.item(0).getFirstChild().getNodeName());
	}

	/**
	 * Tests the decryptElement method
	 * Case: Encrypted Assertion
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#decryptElement
	 */
	@Test
	public void testDecryptElementAssertionWrongKey() throws URISyntaxException, IOException, GeneralSecurityException, XPathExpressionException {
		String keyString = "-----BEGIN PRIVATE KEY-----\n"
				+ "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALvwEktX1+4y2AhE\n"
				+ "qxVwOO6HO7Wtzi3hr5becRkfLYGjNSyhzZCjI1DsNL61JSWDO3nviZd9fSkFnRC4\n"
				+ "akFUm0CS6GJ7TZe4T5o+9aowQ6N8e8cts9XPXyP6Inz7q4sD8pO2EInlfwHYPQCq\n"
				+ "Fmz/SDW7cDgIC8vb0ygOsiXdreANAgMBAAECgYA7VPVRl+/xoVeWdKdWY1F17Her\n"
				+ "Sa23ynI2vQ8TkUY6kR3ucz6ElRxHJesY8fNCPoX+XuMfUly7IKyPZMkWyvEgDPo7\n"
				+ "J5mYqP5VsTK0Li4AwR/BA93Aw6gaX7/EYi3HjBh8QdNSt4fi9yOea/hv04yfR9Lx\n"
				+ "/a5fvQIyhqaDtT2QeQJBAOnCgnxnj70/sv9UsFPa8t1OGdAfXtOgEoklh1F2NR9j\n"
				+ "id6FPw5E98eCpdZ00MfRrmUavgqg6Y4swZISyzJIjGMCQQDN0YNsC4S+eJJM6aOC\n"
				+ "pupKluWE/cCWB01UQYekyXH7OdUtl49NlKEUPBSAvtaLMuMKlTNOjlPrx4Q+/c5i\n"
				+ "0vTPAkEA5H7CR9J/OZETaewhc8ZYkaRvLPYNHjWhCLhLXoB6itUkhgOfUFZwEXAO\n"
				+ "pOOI1VmL675JN2B1DAmJqTx/rQYnWwJBAMx3ztsAmnBq8dTM6y65ydouDHhRawjg\n"
				+ "2jbRHwNbSQvuyVSQ08Gb3WZvxWKdtB/3fsydqqnpBYAf5sZ5eJZ+wssCQAOiIKnh\n"
				+ "dYe+RBbBwykzjUqtzEmt4fwCFE8tD4feEx77D05j5f7u7KYh1mL0G2zIbnUryi7j\n"
				+ "wc4ye98VirRpZ1w=\n"
				+ "-----END PRIVATE KEY-----";
		PrivateKey key = Util.loadPrivateKey(keyString);

		String responseAssertionEnc = Util.base64decodedInflated(Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64"));
		Document responseAssertionEncDoc = Util.loadXML(responseAssertionEnc);
		NodeList EncryptedAssertionNodes = Util.query(responseAssertionEncDoc, ".//saml:EncryptedAssertion");
		NodeList EncryptedDataNodes = Util.query(responseAssertionEncDoc, "./xenc:EncryptedData", EncryptedAssertionNodes.item(0));
		Element encryptedData = (Element) EncryptedDataNodes.item(0);
		assertEquals("xenc:EncryptedData", encryptedData.getNodeName());
		Util.decryptElement(encryptedData, key);
		assertEquals("xenc:EncryptedData", EncryptedAssertionNodes.item(0).getFirstChild().getNodeName());
		assertNotEquals("saml:Assertion", EncryptedAssertionNodes.item(0).getFirstChild().getNodeName());
	}

	/**
	 * Tests the decryptElement method
	 * Case: No EncMethod 
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#decryptElement
	 */
	@Test
	public void testDecryptElementNoMethod() throws URISyntaxException, IOException, GeneralSecurityException, XPathExpressionException {
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);

		String encResponseNoMethod = Util.base64decodedInflated(Util.getFileAsString("data/responses/invalids/encrypted_nameID_without_EncMethod.xml.base64"));
		Document encResponseNoMethodDoc = Util.loadXML(encResponseNoMethod);
		NodeList EncryptedIdNodes = Util.query(encResponseNoMethodDoc, ".//saml:EncryptedID");
		NodeList EncryptedDataNodes = Util.query(encResponseNoMethodDoc, "./xenc:EncryptedData", EncryptedIdNodes.item(0));
		Element encryptedData = (Element) EncryptedDataNodes.item(0);
		assertEquals("xenc:EncryptedData", encryptedData.getNodeName());
		Util.decryptElement(encryptedData, key);
		assertNotEquals("saml:NameID", EncryptedIdNodes.item(0).getFirstChild().getNodeName());
	}

	/**
	 * Tests the decryptElement method
	 * Case: No Keyinfo 
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#decryptElement
	 */
	@Test
	public void testDecryptElementNoKeyinfo() throws URISyntaxException, IOException, GeneralSecurityException, XPathExpressionException {
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);

		String encResponseNoMethod = Util.base64decodedInflated(Util.getFileAsString("data/responses/invalids/encrypted_nameID_without_keyinfo.xml.base64"));
		Document encResponseNoMethodDoc = Util.loadXML(encResponseNoMethod);
		NodeList EncryptedIdNodes = Util.query(encResponseNoMethodDoc, ".//saml:EncryptedID");
		NodeList EncryptedDataNodes = Util.query(encResponseNoMethodDoc, "./xenc:EncryptedData", EncryptedIdNodes.item(0));
		Element encryptedData = (Element) EncryptedDataNodes.item(0);
		assertEquals("xenc:EncryptedData", encryptedData.getNodeName());
		Util.decryptElement(encryptedData, key);
		assertNotEquals("saml:NameID", EncryptedIdNodes.item(0).getFirstChild().getNodeName());
	}

	/**
	 * Tests the copyDocument method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws ParserConfigurationException
	 *
	 * @see com.onelogin.saml2.util.Util#copyDocument
	 */
	@Test
	public void testCopyDocument() throws URISyntaxException, IOException, ParserConfigurationException {
		// Signed Response
		String signedResponseStr = Util.getFileAsString("data/responses/signed_message_response.xml.base64");
		String samlSignedResponseStr = new String(Util.base64decoder(signedResponseStr));
		Document samlSignedResponseDocument = Util.loadXML(samlSignedResponseStr);
		Document copiedSamlSignedResponseDocument = Util.copyDocument(samlSignedResponseDocument);
		assertThat(Util.convertDocumentToString(samlSignedResponseDocument), equalTo(Util.convertDocumentToString(copiedSamlSignedResponseDocument)));

		// AuthNReq
		String authNRequest = Util.getFileAsString("data/requests/authn_request.xml");
		Document authNRequestDoc = Util.loadXML(authNRequest);
		Document copiedAuthNRequestDoc = Util.copyDocument(authNRequestDoc);
		assertThat(Util.convertDocumentToString(authNRequestDoc), equalTo(Util.convertDocumentToString(copiedAuthNRequestDoc)));

		// Logout Request
		String logoutRequest = Util.getFileAsString("data/logout_requests/logout_request.xml");
		Document logoutRequestDoc = Util.loadXML(logoutRequest);
		Document copiedLogoutRequestDoc = Util.copyDocument(logoutRequestDoc);
		assertThat(Util.convertDocumentToString(logoutRequestDoc), equalTo(Util.convertDocumentToString(copiedLogoutRequestDoc)));

		// Logout Response
		String logoutResponse = Util.getFileAsString("data/logout_responses/logout_response.xml");
		Document logoutResponseDoc = Util.loadXML(logoutResponse);
		Document copiedLogoutResponseDoc = Util.copyDocument(logoutResponseDoc);
		assertThat(Util.convertDocumentToString(logoutResponseDoc), equalTo(Util.convertDocumentToString(copiedLogoutResponseDoc)));

		// Metadata
		String metadata = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		Document metadataDoc = Util.loadXML(metadata);
		Document copiedMetadataDoc = Util.copyDocument(metadataDoc);
		assertThat(Util.convertDocumentToString(metadataDoc), equalTo(Util.convertDocumentToString(copiedMetadataDoc)));
	}

	/**
	 * Tests the addSign method
	 * Case: Try sign doc = null
	 *
	 * @throws IOException
	 * @throws URISyntaxException 
	 * @throws GeneralSecurityException
	 * @throws ParserConfigurationException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#addSign
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testAddSignDocNull() throws URISyntaxException, IOException, GeneralSecurityException, ParserConfigurationException, XPathExpressionException, XMLSecurityException {
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String signAlgorithmSha1 = Constants.RSA_SHA1;
		
		String docSigned = Util.addSign(null, key, cert, signAlgorithmSha1);
	}

	/**
	 * Tests the addSign method
	 * Case: Try sign getDocumentElement = null
	 *
	 * @throws IOException
	 * @throws URISyntaxException 
	 * @throws GeneralSecurityException
	 * @throws ParserConfigurationException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#addSign
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testAddSignDocEmpty() throws URISyntaxException, IOException, GeneralSecurityException, ParserConfigurationException, XPathExpressionException, XMLSecurityException {
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String signAlgorithmSha1 = Constants.RSA_SHA1;
		
		Document emptyDoc = mock(Document.class);
	    when(emptyDoc.getDocumentElement()).thenReturn(null);
		
		String docSigned = Util.addSign(emptyDoc, key, cert, signAlgorithmSha1);
	}
	
	/**
	 * Tests the addSign method
	 * Case: Try sign node = null
	 *
	 * @throws IOException
	 * @throws URISyntaxException 
	 * @throws GeneralSecurityException
	 * @throws ParserConfigurationException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#addSign
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testAddSignNodeNull() throws URISyntaxException, IOException, GeneralSecurityException, ParserConfigurationException, XPathExpressionException, XMLSecurityException {
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String signAlgorithmSha1 = Constants.RSA_SHA1;
		Node node = null;
		
		String docSigned = Util.addSign(node, key, cert, signAlgorithmSha1);
	}	
	
	/**
	 * Tests the addSign method
	 * Case: Try sign key = null
	 *
	 * @throws IOException 
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws ParserConfigurationException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#addSign
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testAddSignKeyNull() throws URISyntaxException, IOException, GeneralSecurityException, ParserConfigurationException, XPathExpressionException, XMLSecurityException {
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String signAlgorithmSha1 = Constants.RSA_SHA1;
		String authNRequest = Util.getFileAsString("data/requests/authn_request.xml");
		Document authNRequestDoc = Util.loadXML(authNRequest);

		String authNRequestSigned = Util.addSign(authNRequestDoc, null, cert, signAlgorithmSha1);
	}

	/**
	 * Tests the addSign method
	 * Case: Invalid signAlgorithm
	 *
	 * @throws IOException 
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws ParserConfigurationException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#addSign
	 */
	@Test(expected=XMLSignatureException.class)
	public void testAddSignInvalidSigAlg() throws URISyntaxException, IOException, GeneralSecurityException, ParserConfigurationException, XPathExpressionException, XMLSecurityException {
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String authNRequest = Util.getFileAsString("data/requests/authn_request.xml");
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		Document authNRequestDoc = Util.loadXML(authNRequest);

		String authNRequestSigned = Util.addSign(authNRequestDoc, key, cert, "invalid_signAlgorithm");
	}
	
	
	/**
	 * Tests the addSign method
	 * Case: Try sign cert = null
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws ParserConfigurationException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.util.Util#addSign
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testAddSignCertNull() throws URISyntaxException, IOException, GeneralSecurityException, ParserConfigurationException, XPathExpressionException, XMLSecurityException {
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String signAlgorithmSha1 = Constants.RSA_SHA1;
		String authNRequest = Util.getFileAsString("data/requests/authn_request.xml");
		Document authNRequestDoc = Util.loadXML(authNRequest);

		String authNRequestSigned = Util.addSign(authNRequestDoc, key, null, signAlgorithmSha1);
	}

	/**
	 * Tests the addSign method
	 * Case: Sign Doc
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws ParserConfigurationException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException 
	 *
	 * @see com.onelogin.saml2.util.Util#addSign
	 */
	@Test
	public void testAddSignDoc() throws URISyntaxException, IOException, GeneralSecurityException, ParserConfigurationException, XPathExpressionException, XMLSecurityException {
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String signAlgorithmSha1 = Constants.RSA_SHA1;
		String signAlgorithmSha256 = Constants.RSA_SHA256;
		String digestAlgorithmSha1 = Constants.SHA1;
		String digestAlgorithmSha512 = Constants.SHA512;

		// AuthNReq
		String authNRequest = Util.getFileAsString("data/requests/authn_request.xml");
		Document authNRequestDoc = Util.loadXML(authNRequest);
		String authNRequestSigned = Util.addSign(authNRequestDoc, key, cert, signAlgorithmSha1);
		assertThat(authNRequestSigned, containsString("<ds:SignatureValue>"));

		Document authNRequestSignedDoc = Util.loadXML(authNRequestSigned);
		Node ds_signature_authn = authNRequestSignedDoc.getFirstChild().getFirstChild().getNextSibling().getNextSibling();
		assertEquals("ds:Signature", ds_signature_authn.getNodeName());

		// Check with signAlg not provided
		Document authNRequestDoc_2 = Util.loadXML(authNRequest);
		String authNRequestSigned_2 = Util.addSign(authNRequestDoc_2, key, cert, null);
		
		Document authNRequestDoc_3 = Util.loadXML(authNRequest);
		String authNRequestSigned_3 = Util.addSign(authNRequestDoc_3, key, cert, "");

		assertThat(authNRequestSigned.toString(), equalTo(authNRequestSigned_2.toString()));
		assertThat(authNRequestSigned.toString(), equalTo(authNRequestSigned_3.toString()));
		
		// No ID
		String authNRequestNoID = authNRequest.replace("_ONELOGIN103428909abec424fa58327f79474984", "");
		Document authNRequesNoIDtDoc = Util.loadXML(authNRequestNoID);
		String authNRequestNoIDSigned = Util.addSign(authNRequesNoIDtDoc, key, cert, signAlgorithmSha1);
		assertThat(authNRequestNoIDSigned, containsString("<ds:SignatureValue>"));
		
		// Logout Request
		String logoutRequest = Util.getFileAsString("data/logout_requests/logout_request.xml");
		Document logoutRequestDoc = Util.loadXML(logoutRequest);
		String logoutRequestSigned = Util.addSign(logoutRequestDoc, key, cert, signAlgorithmSha256, digestAlgorithmSha512);
		assertThat(logoutRequestSigned, containsString("<ds:SignatureValue>"));

		Document logoutRequestSignedDoc = Util.loadXML(logoutRequestSigned);
		assertEquals("samlp:LogoutRequest", logoutRequestSignedDoc.getFirstChild().getNodeName());
		Node ds_signature_logout_request = logoutRequestSignedDoc.getFirstChild().getFirstChild().getNextSibling().getNextSibling();
		assertEquals("ds:Signature", ds_signature_logout_request.getNodeName());
		Node canonization_logout_request_signed = ds_signature_logout_request.getFirstChild().getFirstChild();
		assertEquals("ds:CanonicalizationMethod", canonization_logout_request_signed.getNodeName());
		assertEquals(Constants.C14NEXC, canonization_logout_request_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
		Node signature_method_logout_request_signed = ds_signature_logout_request.getFirstChild().getFirstChild().getNextSibling();
		assertEquals("ds:SignatureMethod", signature_method_logout_request_signed.getNodeName());
		assertEquals(signAlgorithmSha256, signature_method_logout_request_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
		Node digest_method_logout_request_signed = ds_signature_logout_request.getFirstChild().getFirstChild().getNextSibling().getNextSibling().getFirstChild().getNextSibling();
		assertEquals("ds:DigestMethod", digest_method_logout_request_signed.getNodeName());
		assertEquals(digestAlgorithmSha512, digest_method_logout_request_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());

		// Logout Response
		String logoutResponse = Util.getFileAsString("data/logout_responses/logout_response.xml");
		Document logoutResponseDoc = Util.loadXML(logoutResponse);
		String logoutResponseSigned = Util.addSign(logoutResponseDoc, key, cert, signAlgorithmSha1);
		assertThat(logoutResponseSigned, containsString("<ds:SignatureValue>"));

		Document logoutResponseSignedDoc = Util.loadXML(logoutResponseSigned);
		assertEquals("samlp:LogoutResponse", logoutResponseSignedDoc.getFirstChild().getNodeName());
		Node ds_signature_logout_response = logoutResponseSignedDoc.getFirstChild().getFirstChild().getNextSibling().getNextSibling();;
		assertEquals("ds:Signature", ds_signature_logout_response.getNodeName());
		Node canonization_logout_response_signed = ds_signature_logout_response.getFirstChild().getFirstChild();
		assertEquals("ds:CanonicalizationMethod", canonization_logout_response_signed.getNodeName());
		assertEquals(Constants.C14NEXC, canonization_logout_response_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
		Node signature_method_logout_response_signed = ds_signature_logout_response.getFirstChild().getFirstChild().getNextSibling();
		assertEquals("ds:SignatureMethod", signature_method_logout_response_signed.getNodeName());
		assertEquals(signAlgorithmSha1, signature_method_logout_response_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
		Node digest_method_logout_response_signed = ds_signature_logout_response.getFirstChild().getFirstChild().getNextSibling().getNextSibling().getFirstChild().getNextSibling();
		assertEquals("ds:DigestMethod", digest_method_logout_response_signed.getNodeName());
		assertEquals(digestAlgorithmSha1, digest_method_logout_response_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());

		// Metadata
		String metadata = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		Document metadataDoc = Util.loadXML(metadata);
		String metadataSigned = Util.addSign(metadataDoc, key, cert, signAlgorithmSha1);
		assertThat(metadataSigned, containsString("<ds:SignatureValue>"));

		Document metadataSignedDoc = Util.loadXML(metadataSigned);
		assertEquals("md:EntityDescriptor", metadataSignedDoc.getFirstChild().getNodeName());
		Node ds_signature_metadata = metadataSignedDoc.getFirstChild().getFirstChild();
		assertEquals("ds:Signature", ds_signature_metadata.getNodeName());
		Node canonization_metadata_signed = ds_signature_metadata.getFirstChild().getFirstChild();
		assertEquals("ds:CanonicalizationMethod", canonization_metadata_signed.getNodeName());
		assertEquals(Constants.C14NEXC, canonization_metadata_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
		Node signature_method_metadata_signed = ds_signature_metadata.getFirstChild().getFirstChild().getNextSibling();
		assertEquals("ds:SignatureMethod", signature_method_metadata_signed.getNodeName());
		assertEquals(signAlgorithmSha1, signature_method_metadata_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
		Node digest_method_metadata_signed = ds_signature_metadata.getFirstChild().getFirstChild().getNextSibling().getNextSibling().getFirstChild().getNextSibling();
		assertEquals("ds:DigestMethod", digest_method_metadata_signed.getNodeName());
		assertEquals(digestAlgorithmSha1, digest_method_metadata_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());

		String metadata_entities = Util.getFileAsString("data/metadata/metadata_entities.xml");
		Document metadataEntitiesDoc = Util.loadXML(metadata_entities);
		String metadataEntitiesSigned = Util.addSign(metadataEntitiesDoc, key, cert, signAlgorithmSha256, digestAlgorithmSha512);
		assertThat(metadataEntitiesSigned, containsString("<ds:SignatureValue>"));

		Document metadataEntitiesSignedDoc = Util.loadXML(metadataEntitiesSigned);
		assertEquals("EntitiesDescriptor", metadataEntitiesSignedDoc.getFirstChild().getNodeName());
		Node ds_signature_metadata_entities = metadataEntitiesSignedDoc.getFirstChild().getFirstChild();
		assertEquals("ds:Signature", ds_signature_metadata_entities.getNodeName());
		Node canonization_metadata_entities_signed = ds_signature_metadata_entities.getFirstChild().getFirstChild();
		assertEquals("ds:CanonicalizationMethod", canonization_metadata_entities_signed.getNodeName());
		assertEquals(Constants.C14NEXC, canonization_metadata_entities_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
		Node signature_method_metadata_entities_signed = ds_signature_metadata_entities.getFirstChild().getFirstChild().getNextSibling();
		assertEquals("ds:SignatureMethod", signature_method_metadata_entities_signed.getNodeName());
		assertEquals(signAlgorithmSha256, signature_method_metadata_entities_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
		Node digest_method_metadata_entities_signed = ds_signature_metadata_entities.getFirstChild().getFirstChild().getNextSibling().getNextSibling().getFirstChild().getNextSibling();
		assertEquals("ds:DigestMethod", digest_method_metadata_entities_signed.getNodeName());
		assertEquals(digestAlgorithmSha512, digest_method_metadata_entities_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
	}

	/**
	 * Tests the addSign method
	 * Case: Sign Node
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws GeneralSecurityException
	 * @throws ParserConfigurationException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException 
	 *
	 * @see com.onelogin.saml2.util.Util#addSign
	 */
	@Test
	public void testAddSignNode() throws URISyntaxException, IOException, GeneralSecurityException, ParserConfigurationException, XPathExpressionException, XMLSecurityException {
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String signAlgorithmSha1 = Constants.RSA_SHA1;
		
		String authNRequest = Util.getFileAsString("data/requests/authn_request.xml");
		Document authNRequestDoc = Util.loadXML(authNRequest);
		Node node = authNRequestDoc.getFirstChild();
		String authNRequestSigned = Util.addSign(node, key, cert, signAlgorithmSha1);
		assertThat(authNRequestSigned, containsString("<ds:SignatureValue>"));
		
		Document authNRequestSignedDoc = Util.loadXML(authNRequestSigned);
		Node ds_signature = authNRequestSignedDoc.getFirstChild().getFirstChild().getNextSibling().getNextSibling();
		assertEquals("ds:Signature", ds_signature.getNodeName());
	}
	
	/**
	 * Tests the validateBinarySignature method
	 *
	 * @throws IOException 
	 * @throws URISyntaxException 
	 * @throws CertificateException 
	 * @throws SignatureException
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * 
	 * @see com.onelogin.saml2.util.Util#validateBinarySignature
	 */
	@Test
	public void testValidateBinarySignature() throws URISyntaxException, IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		String certString = "-----BEGIN CERTIFICATE-----MIICeDCCAeGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBZMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lTG9naW4gSW5jMR4wHAYDVQQDDBVqYXZhLXNhbWwuZXhhbXBsZS5jb20wHhcNMTUxMDE4MjAxMjM1WhcNMTgwNzE0MjAxMjM1WjBZMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lTG9naW4gSW5jMR4wHAYDVQQDDBVqYXZhLXNhbWwuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALvwEktX1+4y2AhEqxVwOO6HO7Wtzi3hr5becRkfLYGjNSyhzZCjI1DsNL61JSWDO3nviZd9fSkFnRC4akFUm0CS6GJ7TZe4T5o+9aowQ6N8e8cts9XPXyP6Inz7q4sD8pO2EInlfwHYPQCqFmz/SDW7cDgIC8vb0ygOsiXdreANAgMBAAGjUDBOMB0GA1UdDgQWBBTifMwN3CQ5ZOPkV5tDJsutU8teFDAfBgNVHSMEGDAWgBTifMwN3CQ5ZOPkV5tDJsutU8teFDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAG3nAEUjJaA75SkzID5FKLolsxG5TE/0HU0+yEUAVkXiqvqN4mPWq/JjoK5+uP4LEZIb4pRrCqI3iHp+vazLLYSeyV3kaGN7q35Afw8nk8WM0f7vImbQ69j1S8GQ+6E0PEI26qBLykGkMn3GUVtBBWSdpP093NuNLJiOomnHqhqj-----END CERTIFICATE-----";
		X509Certificate cert = Util.loadCert(certString);
		
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String relayState = "http://example.com";
		String signAlgorithmSha1 = Constants.RSA_SHA1;
		String signAlgorithmSha256 = Constants.RSA_SHA256;
		String SignatureSha1 = "FqFJi9aIut9Gp/SUyLcj4ewwnU4ajjhfWpdr8pc4w//9m0QB1hzDUHR7YmKxXB6rrRuX7iy9CJy+o7zzhz2pTr0PHHE9mvFPsyk/mas9e2ZGUeLS2OzMPHYwJCdOg4uLrbqybWGKy0AgoDqTpAfpkQVxuunVKTj4pOPXGx156Oo=";
		String SignatureSha256 = "PJoiwvBgKnRefzaYMaPqOTvlia7EhFoRrc+tFlJCi557VEpG0oY1x8YTmkOxC+oI0zWyQ0RiXA65q7hv1xyYgGnSFdMKr5s+qeD4+1BjPxEGwXVU6+gTX0gg2+UL+1o4YpoVTQ1aKSO85uyBEGO20WnK2zETuGA/Wgl1VBSxNSw=";
		
		String signedQuerySha1 = "SAMLRequest=" + Util.urlEncoder(deflatedEncodedAuthNRequest)
								+"&RelayState=" + Util.urlEncoder(relayState)
								+"&SigAlg=" + Util.urlEncoder(signAlgorithmSha1);
		String signedQuerySha256 = "SAMLRequest=" + Util.urlEncoder(deflatedEncodedAuthNRequest)
		+"&RelayState=" + Util.urlEncoder(relayState)
		+"&SigAlg=" + Util.urlEncoder(signAlgorithmSha256);
		
		assertTrue(Util.validateBinarySignature(signedQuerySha1, Util.base64decoder(SignatureSha1), cert, signAlgorithmSha1));
		assertFalse(Util.validateBinarySignature(signedQuerySha256, Util.base64decoder(SignatureSha1), cert, signAlgorithmSha1));
		assertFalse(Util.validateBinarySignature(signedQuerySha1, Util.base64decoder(SignatureSha256), cert, signAlgorithmSha1));
		
		assertTrue(Util.validateBinarySignature(signedQuerySha256, Util.base64decoder(SignatureSha256), cert, signAlgorithmSha256));
		assertFalse(Util.validateBinarySignature(signedQuerySha1, Util.base64decoder(SignatureSha256), cert, signAlgorithmSha256));
		assertFalse(Util.validateBinarySignature(signedQuerySha256, Util.base64decoder(SignatureSha256), cert, signAlgorithmSha1));
	}

	/**
	 * Tests the generateNameId method
	 * Case: Exception
	 *
	 * @throws IOException 
	 * @throws URISyntaxException 
	 * @throws CertificateException 
	 * 
	 * @see com.onelogin.saml2.util.Util#generateNameId
	 */
	@Test
	public void testGenerateNameIdException() throws URISyntaxException, IOException, CertificateException {
        String nameId = Util.generateNameId(null, null, null);
        assertNull(nameId);
	}
	
	/**
	 * Tests the generateNameId method
	 *
	 * @throws IOException 
	 * @throws URISyntaxException 
	 * @throws CertificateException 
	 * 
	 * @see com.onelogin.saml2.util.Util#generateNameId
	 */
	@Test
	public void testGenerateNameId() throws URISyntaxException, IOException, CertificateException {
        String nameIdValue = "ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde";
        String entityId = "http://stuff.com/endpoints/metadata.php";
        String nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
        
        String nameId = Util.generateNameId(nameIdValue, entityId, nameIDFormat);
        
        String expectedNameId = "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\" SPNameQualifier=\"http://stuff.com/endpoints/metadata.php\">ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>";
        assertEquals(expectedNameId, nameId);
        
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String nameIdEnc = Util.generateNameId(nameIdValue, entityId, nameIDFormat, cert);
		
		assertThat(nameIdEnc, containsString("<saml:EncryptedID><xenc:EncryptedData"));
		assertThat(nameIdEnc, containsString("<xenc:EncryptedKey"));
		assertThat(nameIdEnc, containsString("http://www.w3.org/2001/04/xmlenc#aes128-cbc"));
		assertThat(nameIdEnc, containsString("http://www.w3.org/2001/04/xmlenc#rsa-1_5"));
	}

	/**
	 * Tests the generateNameId method
	 *
	 * @throws IOException 
	 * @throws URISyntaxException 
	 * @throws CertificateException 
	 *
	 * @see com.onelogin.saml2.util.Util#generateNameId
	 */
	@Test
	public void testGenerateNameIdWithoutFormat() throws URISyntaxException, IOException, CertificateException {
        String nameIdValue = "ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde";
        String nameId = Util.generateNameId(nameIdValue);

        String expectedNameId = "<saml:NameID>ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>";
        assertEquals(expectedNameId, nameId);        
	}

	/**
	 * Tests the generateUniqueID method
	 *
	 * * @see com.onelogin.saml2.util.Util#generateUniqueID
	 */
	@Test
	public void testGenerateUniqueID() {
		String s1 = Util.generateUniqueID();
		assertThat(s1, startsWith(Util.UNIQUE_ID_PREFIX));
	}

	/**
	 * Tests the generateUniqueID method
	 * 
	 * @see com.onelogin.saml2.util.Util#generateUniqueID
	 */
	@Test
	public void testGenerateUniqueID_withCustomPrefix() {
		String s1 = Util.generateUniqueID(Util.UNIQUE_ID_PREFIX);

		assertThat(s1, startsWith(Util.UNIQUE_ID_PREFIX));
		assertTrue(s1.length() > 40);
		
		String s2 = Util.generateUniqueID(Util.UNIQUE_ID_PREFIX);
		String s3 = Util.generateUniqueID("_");
		assertThat(s3, startsWith("_"));

		assertNotEquals(s1, s2);
		assertNotEquals(s1, s3);
		assertNotEquals(s2, s3);
	}

	/**
	 * Tests that generateUniqueID method uses default prefix when given null
	 */
	@Test
	public void testGenerateUniqueID_usesDefaultOnNull() {
		String s1 = Util.generateUniqueID(null);
		assertThat(s1, startsWith(Util.UNIQUE_ID_PREFIX));
	}

	/**
	 * Tests that generateUniqueID method uses default prefix when given empty String
	 */
	@Test
	public void testGenerateUniqueID_usesDefaultOnEmpty() {
		String s1 = Util.generateUniqueID("");
		assertThat(s1, startsWith(Util.UNIQUE_ID_PREFIX));
	}

	/**
	 * Tests the parseDuration method
	 * 
	 * @throws Exception 
	 * 
	 * @see com.onelogin.saml2.util.Util#parseDuration
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testParseDurationException() throws Exception {
		long timestamp = 1393876825L;// 2014-03-03 21:00:25
		long parsedDuration = Util.parseDuration("aaa", timestamp);
	}
	
	/**
	 * Tests the parseDuration method
	 * 
	 * @throws Exception 
	 * 
	 * @see com.onelogin.saml2.util.Util#parseDuration
	 */
	@Test
	public void testParseDuration() throws Exception {
		String duration = "PT1393462294S";
		long timestamp = 1393876825L;// 2014-03-03 21:00:25

		long parsedDuration = Util.parseDuration(duration, timestamp);
		assertEquals(2787339119L, parsedDuration);

		long parsedDuration2 = Util.parseDuration(duration);
		assertTrue(parsedDuration2 > parsedDuration);

		String newDuration = "P1Y1M";
		long parsedDuration4 = Util.parseDuration(newDuration, timestamp);
		assertEquals(1428091225L, parsedDuration4);

		String negDuration = "-P14M";
		long parsedDuration5 = Util.parseDuration(negDuration, timestamp);
		assertEquals(1357243225L, parsedDuration5);

		try {
			String invalidDuration = "PT1Y";
			Util.parseDuration(invalidDuration);
		} catch (IllegalArgumentException anIllegalArgumentException) {
			assertThat(anIllegalArgumentException.getMessage(), is("Invalid format: \"PT1Y\" is malformed at \"1Y\""));
		}
	}

	/**
	 * Tests the getExpireTime method
	 * 
	 * @see com.onelogin.saml2.util.Util#getCurrentTimeStamp
	 */
	@Test
	public void testGetCurrentTimeStamp() {
		Date currentDate = new Date();
		Long dt = currentDate.getTime() / 1000;
		Long dt2 = Util.getCurrentTimeStamp();
	    assertTrue(dt2 - dt <= 3);
	}

	/**
	 * Tests the getExpireTime method
	 * 
	 * @see com.onelogin.saml2.util.Util#getExpireTime
	 */
	@Test
	public void testGetExpireTime() {
		long num = 1291955971L; // 1455405963
		long num2 = 3311642371L;

		assertEquals(0, Util.getExpireTime(null, null));
		assertEquals(0, Util.getExpireTime("", ""));

		assertEquals(num, (long)Util.getExpireTime(null, num));
		assertEquals(num, (long)Util.getExpireTime("", num));

		assertEquals(num2, (long)Util.getExpireTime(null, num2));
		assertEquals(num2, (long)Util.getExpireTime("", num2));

		assertEquals(num, (long)Util.getExpireTime(null, "2010-12-10T04:39:31Z"));
		assertEquals(num, (long)Util.getExpireTime("", "2010-12-10T04:39:31Z"));

		assertEquals(num2, (long)Util.getExpireTime(null, "2074-12-10T04:39:31Z"));
		assertEquals(num2, (long)Util.getExpireTime("", "2074-12-10T04:39:31Z"));

		assertEquals(num, (long)Util.getExpireTime("PT360000S", "2010-12-10T04:39:31Z"));
		assertNotEquals(num2, (long)Util.getExpireTime("PT360000S", "2074-12-10T04:39:31Z"));

		long x = Util.getExpireTime("PT360000S", num);
		assertEquals(num, (long)Util.getExpireTime("PT360000S", num));
		assertNotEquals(num2, (long)Util.getExpireTime("PT360000S", num2));

		assertNotEquals(0, (long)Util.getExpireTime("PT360000S", null));
	}
    
	/**
	 * Tests the formatDateTime method
	 * 
	 * @see com.onelogin.saml2.util.Util#formatDateTime
	 */
	@Test
	public void testFormatDateTime() {
		long time = 1386650371L;
		String datetime = "2013-12-10T04:39:31Z";
		String parsedTime = Util.formatDateTime(time * 1000); // Time in Mills
		assertEquals(datetime, parsedTime);
	}
	
	/**
	 * Tests the parseDateTime method
	 * 
	 * @see com.onelogin.saml2.util.Util#parseDateTime
	 */
	@Test
	public void testParseDateTime() {
		long time = 1386650371L;
		String datetime = "2013-12-10T04:39:31Z";
		DateTime parsedTime = Util.parseDateTime(datetime);
		assertEquals(time, parsedTime.getMillis() / 1000);
		
		// Now test if toolkit supports miliseconds
		String datetime2 = "2013-12-10T04:39:31.120Z";
		DateTime parsedTime2 = Util.parseDateTime(datetime2);
		assertEquals(time, parsedTime2.getMillis() / 1000);
	}
	
	/**
	 * Tests Query method
	 *
	 * @throws XPathExpressionException
	 * @throws IOException 
	 * @throws URISyntaxException 
	 *
	 * @see com.onelogin.saml2.util.Util#query
	 */
	@Test
	public void testQuery() throws XPathExpressionException, URISyntaxException, IOException {
		String responseCoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		String response = Util.base64decodedInflated(responseCoded);
		Document dom = Util.loadXML(response);

		NodeList assertionNodes = Util.query(dom, "/samlp:Response/saml:Assertion", null);
		assertEquals(1, assertionNodes.getLength());
		Node assertion = assertionNodes.item(0);
		assertEquals("saml:Assertion", assertion.getNodeName());

		NodeList attributeStatementNodes = Util.query(dom,
				"/samlp:Response/saml:Assertion/saml:AttributeStatement", null);
		assertEquals(1, attributeStatementNodes.getLength());
		Node attributeStatement = attributeStatementNodes.item(0);
		assertEquals("saml:AttributeStatement", attributeStatement.getNodeName());

		NodeList attributeStatementNodes2 = Util.query(dom, "./saml:AttributeStatement", assertion);
		assertEquals(1, attributeStatementNodes2.getLength());
		Node attributeStatement2 = attributeStatementNodes2.item(0);
		assertEquals(attributeStatement, attributeStatement2);

		NodeList signatureResNodes = Util.query(dom, "/samlp:Response/ds:Signature", null);
		assertEquals(1, signatureResNodes.getLength());
		Node signatureRes = signatureResNodes.item(0);
		assertEquals("ds:Signature", signatureRes.getNodeName());

		NodeList signatureNodes = Util.query(dom, "/samlp:Response/saml:Assertion/ds:Signature", null);
		assertEquals(1, signatureNodes.getLength());
		Node signature = signatureNodes.item(0);
		assertEquals("ds:Signature", signature.getNodeName());

		NodeList signatureNodes2 = Util.query(dom, "./ds:Signature", assertion);
		assertEquals(1, signatureNodes2.getLength());
		Node signature2 = signatureNodes2.item(0);
		assertEquals(signature.getTextContent(), signature2.getTextContent());
		assertNotEquals(signatureRes.getTextContent(), signature2.getTextContent());

		NodeList signatureNodes3 = Util.query(dom, "./ds:SignatureValue", assertion);
		assertEquals(0, signatureNodes3.getLength());

		NodeList signatureNodes4 = Util.query(dom, "./ds:Signature/ds:SignatureValue", assertion);
		assertEquals(1, signatureNodes4.getLength());

		NodeList signatureNodes5 = Util.query(dom, ".//ds:SignatureValue", assertion);
		assertEquals(1, signatureNodes5.getLength());
		
		String encryptedAssertionResponseCoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		String encryptedAssertionResponse = Util.base64decodedInflated(encryptedAssertionResponseCoded);
		Document dom2 = Util.loadXML(encryptedAssertionResponse);
		
		NodeList encryptAssertionNode = Util.query(dom2, "/samlp:Response/saml:EncryptedAssertion");
		assertEquals(1, encryptAssertionNode.getLength());
		
		NodeList encryptedDataNode = Util.query(dom2, ".//xenc:EncryptedData");
		assertEquals(1, encryptedDataNode.getLength());

		NodeList encryptedDataNode_2 = Util.query(dom2, "./xenc:EncryptedData", encryptAssertionNode.item(0));
		assertEquals(1, encryptedDataNode_2.getLength());
		
		// Test saml2 / samlp2
		String response_2 = response.replace("<saml:","<saml2:").replace("</saml:","</saml2:").replace("xmlns:saml=","xmlns:saml2=");
		response_2 = response_2.replace("<samlp:","<samlp2:").replace("</samlp:","</samlp2:").replace("xmlns:samlp=","xmlns:samlp2=");
		Document dom_2 = Util.loadXML(response_2);
		
		NodeList assertionNodes_2 = Util.query(dom_2, "/samlp:Response/saml:Assertion", null);
		assertEquals(1, assertionNodes_2.getLength());
		Node assertion_2 = assertionNodes_2.item(0);
		assertEquals("saml2:Assertion", assertion_2.getNodeName());
	}

}
