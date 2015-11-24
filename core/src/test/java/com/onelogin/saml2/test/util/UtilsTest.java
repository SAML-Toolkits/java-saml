package com.onelogin.saml2.test.util;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXParseException;

import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.util.SchemaFactory;
import com.onelogin.saml2.util.Util;

/**
 * Tests the com.onelogin.saml2.util.Util class
 */
public class UtilsTest {

	/**
	 * Tests the loadXML method for XXE/XEE attacks
	 * Case: Use of ENTITY
	 *
	 * @throws XMLEntityException
	 * 
	 * @see com.onelogin.saml2.util.Util#loadXML
	 */
	@Test
	public void testLoadXMLForAttacks1() throws XMLEntityException {

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
	 * @throws XMLEntityException 
	 * 
	 * @see com.onelogin.saml2.util.Util#loadXML
	 */
	@Test
	public void testLoadXMLForAttacks2() throws XMLEntityException {

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
	 * @throws XMLEntityException 
	 *
	 * @see com.onelogin.saml2.util.Util#loadXML
	 */
	@Test
	public void testLoadXMLForAttacks3() throws XMLEntityException {

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
	 * @throws ParserConfigurationException 
	 * @throws XMLEntityException 
	 * @throws IOException 
	 * @throws URISyntaxException
	 * 
	 * @see com.onelogin.saml2.util.Util#loadXML
	 */
	@Test
	public void testLoadXMLBadXML() throws ParserConfigurationException, XMLEntityException, IOException,
			URISyntaxException {

		String metadataUnloaded = "<xml><EntityDescriptor>";
		Document result = Util.loadXML(metadataUnloaded);
		assertNull(result);
	}

	/**
	 * Tests the loadXML method 
	 * Case: Valid XML
	 *
	 * @throws ParserConfigurationException 
	 * @throws XMLEntityException 
	 * @throws IOException 
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.util.Util#loadXML
	 */
	@Test
	public void testLoadXML() throws ParserConfigurationException, XMLEntityException, IOException,
			URISyntaxException {

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
	 * @throws XMLEntityException
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLBadFormat() throws XMLEntityException, Exception {
		String metadataUnloaded = "<xml><EntityDescriptor>";
		Document docMetadataUnloaded = Util.loadXML(metadataUnloaded);
		boolean isValid = Util.validateXML(docMetadataUnloaded, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertFalse(isValid);
	}

	/**
	 * Tests the ValidateXML method
	 * Case: Invalidates XML without Entity
	 *
	 * @throws XMLEntityException 
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLNoentity() throws XMLEntityException, Exception {
		String metadataInvalid = Util.getFileAsString("data/metadata/noentity_metadata_settings1.xml");
		Document docMetadataInvalid = Util.loadXML(metadataInvalid);
		boolean isValid = Util.validateXML(docMetadataInvalid, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertFalse(isValid);
	}

	/**
	 * Tests the ValidateXML method
	 * Case: Invalidates XML with bad order
	 * 
	 * @throws XMLEntityException
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLMetadataBadOrder() throws XMLEntityException, Exception {
		String metadataBadOrder = Util.getFileAsString("data/metadata/metadata_bad_order_settings1.xml");
		Document docMetadataBadOrder = Util.loadXML(metadataBadOrder);
		boolean isValid = Util.validateXML(docMetadataBadOrder, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertFalse(isValid);
	}

	/**
	 * Tests the ValidateXML method for
	 * Case: Validates expired XML Metadata
	 *
	 * @throws XMLEntityException 
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLExpiredMetadata() throws XMLEntityException, Exception {
		String metadataExpired = Util.getFileAsString("data/metadata/expired_metadata_settings1.xml");
		Document docExpiredMetadata = Util.loadXML(metadataExpired);
		boolean isValid = Util.validateXML(docExpiredMetadata, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertTrue(isValid);
	}

	/**
	 * Tests the ValidateXML method
	 * Case: Validates valid metadata
	 * 
	 * @throws XMLEntityException
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLMetadataOk() throws XMLEntityException, Exception {
		String metadataOk = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		Document docMetadataOk = Util.loadXML(metadataOk);
		boolean isValid = Util.validateXML(docMetadataOk, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertTrue(isValid);
	}

	/**
	 * Tests the ValidateXML method
	 * Case: Validates valid SAMLResponse
	 * 
	 * @throws XMLEntityException
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLSAMLResponse() throws XMLEntityException, Exception {
		String responseOk = new String(Base64.decodeBase64(Util.getFileAsString("data/responses/valid_response.xml.base64")));
		Document docResponseOk = Util.loadXML(responseOk);
		boolean isValid = Util.validateXML(docResponseOk, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0);
		assertTrue(isValid);
	}
	
	/**
	 * Tests the ValidateXML method
	 * Case: Validates valid signed metadata
	 * 
	 * @throws XMLEntityException
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.util.Util#validateXML
	 */
	@Test
	public void testValidateXMLSignedMetadataSettings1() throws XMLEntityException, Exception {
		String metadataBadOrder = Util.getFileAsString("data/metadata/signed_metadata_settings1.xml");
		Document docMetadataBadOrder = Util.loadXML(metadataBadOrder);
		boolean isValid = Util.validateXML(docMetadataBadOrder, SchemaFactory.SAML_SCHEMA_METADATA_2_0);
		assertTrue(isValid);
	}
	
	/**
	 * Tests the parseDuration method of
	 * 
	 * @throws Exception 
	 */
	@Test
	public void testParseDuration1() throws Exception {
		String duration = "PT1393462294S";
		long timestamp = 1393876825L;// 2014-03-03 21:00:25

		long parsedDuration = Util.parseDuration(duration, timestamp);
		assertEquals(2787339119L, parsedDuration);

		long parsedDuration2 = Util.parseDuration(duration);
		assertTrue(parsedDuration2 > parsedDuration);

		String newDuration = "P1Y1M";
		long parsedDuration4 = Util.parseDuration(newDuration, timestamp);
		assertEquals(1428087625L, parsedDuration4);

		String negDuration = "-P14M";
		long parsedDuration5 = Util.parseDuration(negDuration, timestamp);
		assertEquals(1357243225, parsedDuration5);

		try {
			String invalidDuration = "PT1Y";
			Util.parseDuration(invalidDuration);
		} catch (IllegalArgumentException anIllegalArgumentException) {
			assertThat(anIllegalArgumentException.getMessage(), is("Invalid format: \"PT1Y\" is malformed at \"1Y\""));
		}
	}

	/**
	 * Tests load public certificate X.509 String with heads.
	 *
	 * @throws UnsupportedEncodingException 
	 * @throws CertificateException 
	 */
	@Test
	public void testLoadCertWithHeads() throws CertificateException, UnsupportedEncodingException {
		String certWithHeads = "-----BEGIN CERTIFICATE-----\n"
				+ "MIIDBDCCAm2gAwIBAgIJAK8dGINfkSTHMA0GCSqGSIb3DQEBBQUAMGAxCzAJBgNV\n"
				+ "BAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzETMBEG\n"
				+ "A1UEChMKR29vZ2xlIEluYzEXMBUGA1UEAxMOd3d3Lmdvb2dsZS5jb20wHhcNMDgx\n"
				+ "MDA4MDEwODMyWhcNMDkxMDA4MDEwODMyWjBgMQswCQYDVQQGEwJVUzELMAkGA1UE\n"
				+ "CBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBJ\n"
				+ "bmMxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n"
				+ "ADCBiQKBgQDQUV7ukIfIixbokHONGMW9+ed0E9X4m99I8upPQp3iAtqIvWs7XCbA\n"
				+ "bGqzQH1qX9Y00hrQ5RRQj8OI3tRiQs/KfzGWOdvLpIk5oXpdT58tg4FlYh5fbhIo\n"
				+ "VoVn4GvtSjKmJFsoM8NRtEJHL1aWd++dXzkQjEsNcBXwQvfDb0YnbQIDAQABo4HF\n"
				+ "MIHCMB0GA1UdDgQWBBSm/h1pNY91bNfW08ac9riYzs3cxzCBkgYDVR0jBIGKMIGH\n"
				+ "gBSm/h1pNY91bNfW08ac9riYzs3cx6FkpGIwYDELMAkGA1UEBhMCVVMxCzAJBgNV\n"
				+ "BAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUg\n"
				+ "SW5jMRcwFQYDVQQDEw53d3cuZ29vZ2xlLmNvbYIJAK8dGINfkSTHMAwGA1UdEwQF\n"
				+ "MAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAYpHTr3vQNsHHHUm4MkYcDB20a5KvcFoX\n"
				+ "gCcYtmdyd8rh/FKeZm2me7eQCXgBfJqQ4dvVLJ4LgIQiU3R5ZDe0WbW7rJ3M9ADQ\n"
				+ "FyQoRJP8OIMYW3BoMi0Z4E730KSLRh6kfLq4rK6vw7lkH9oynaHHWZSJLDAp17cP\n" + "j+6znWkN9/g=\n"
				+ "-----END CERTIFICATE-----";
		Certificate loadedCert = Util.loadCert(certWithHeads);
		assertNotNull(loadedCert);
		assertEquals(loadedCert.getType(), "X.509");
	}

	/**
	 * Tests load public certificate X.509 String without heads.
	 *
	 * @throws UnsupportedEncodingException 
	 * @throws CertificateException 
	 */
	@Test
	public void testLoadCertWithoutHeads() throws CertificateException, UnsupportedEncodingException {
		String certWithoutHeads = "MIIDBDCCAm2gAwIBAgIJAK8dGINfkSTHMA0GCSqGSIb3DQEBBQUAMGAxCzAJBgNV\n"
				+ "BAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzETMBEG"
				+ "A1UEChMKR29vZ2xlIEluYzEXMBUGA1UEAxMOd3d3Lmdvb2dsZS5jb20wHhcNMDgx"
				+ "MDA4MDEwODMyWhcNMDkxMDA4MDEwODMyWjBgMQswCQYDVQQGEwJVUzELMAkGA1UE"
				+ "CBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBJ"
				+ "bmMxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GN"
				+ "ADCBiQKBgQDQUV7ukIfIixbokHONGMW9+ed0E9X4m99I8upPQp3iAtqIvWs7XCbA"
				+ "bGqzQH1qX9Y00hrQ5RRQj8OI3tRiQs/KfzGWOdvLpIk5oXpdT58tg4FlYh5fbhIo"
				+ "VoVn4GvtSjKmJFsoM8NRtEJHL1aWd++dXzkQjEsNcBXwQvfDb0YnbQIDAQABo4HF"
				+ "MIHCMB0GA1UdDgQWBBSm/h1pNY91bNfW08ac9riYzs3cxzCBkgYDVR0jBIGKMIGH"
				+ "gBSm/h1pNY91bNfW08ac9riYzs3cx6FkpGIwYDELMAkGA1UEBhMCVVMxCzAJBgNV"
				+ "BAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUg"
				+ "SW5jMRcwFQYDVQQDEw53d3cuZ29vZ2xlLmNvbYIJAK8dGINfkSTHMAwGA1UdEwQF"
				+ "MAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAYpHTr3vQNsHHHUm4MkYcDB20a5KvcFoX"
				+ "gCcYtmdyd8rh/FKeZm2me7eQCXgBfJqQ4dvVLJ4LgIQiU3R5ZDe0WbW7rJ3M9ADQ"
				+ "FyQoRJP8OIMYW3BoMi0Z4E730KSLRh6kfLq4rK6vw7lkH9oynaHHWZSJLDAp17cP"
				+ "j+6znWkN9/g=";
		Certificate loadedCert = Util.loadCert(certWithoutHeads);
		assertNotNull(loadedCert);
		assertEquals(loadedCert.getType(), "X.509");
	}
	
	@Test
	public void testQuery() {
		try {
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

		} catch (DOMException e) {
			e.printStackTrace();
			assertTrue(false);
		} catch (Exception e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}
}
