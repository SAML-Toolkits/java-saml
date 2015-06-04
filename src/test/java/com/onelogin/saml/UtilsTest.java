package com.onelogin.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Scanner;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


public class UtilsTest {


	/**
	 * Tests the loadXML method of the com.onelogin.saml.Utils
	 *
	 * @covers Utils.loadXML
	 */
	@Test
	public void testXMLAttacks()
	{
		try{

			String attackXXE = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>" +
					"<!DOCTYPE foo [" + 
					"<!ELEMENT foo ANY >" +
					"<!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>";
			try {
				Utils.loadXML(attackXXE);
				assertTrue(false);
			} catch (Exception e) {
				assertEquals("Detected use of ENTITY in XML, disabled to prevent XXE/XEE attacks", e.getMessage());
			}

			String xmlWithDTD = "<?xml version=\"1.0\"?>" +
					"<!DOCTYPE results [" +
					"<!ELEMENT results (result+)>" +
					"<!ELEMENT result (#PCDATA)>" +
					"]>" +
					"<results>" +
					"<result>test</result>" +
					"</results>";

			Document res2 =Utils.loadXML(xmlWithDTD);
			assertNull(res2);


			String attackXEE = "<?xml version=\"1.0\"?>" +
					"<!DOCTYPE results [<!ENTITY harmless \"completely harmless\">]>" +
					"<results>" +
					"<result>This result is &harmless;</result>" +
					"</results>";
			try {
				Utils.loadXML(attackXEE);
				assertTrue(false);
			} catch (Exception e) {
				assertEquals("Detected use of ENTITY in XML, disabled to prevent XXE/XEE attacks", e.getMessage());
			}
		}catch(DOMException e){
			e.printStackTrace();
			assertTrue(false);
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
			assertTrue(false);
		} catch (Exception e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}

	/**
	 * Tests the loadXML method of the com.onelogin.saml.Utils
	 *
	 * @covers Utils.loadXML
	 */
	@Test
	public void testLoadXML()
	{
		try{

			String metadataUnloaded = "<xml><EntityDescriptor>";
			boolean xmlvalidation = Utils.loadXML(metadataUnloaded) instanceof Document;
			assertFalse(xmlvalidation);

			String metadataInvalid = getFile("metadata/noentity_metadata_settings1.xml");
			xmlvalidation = Utils.loadXML(metadataInvalid) instanceof Document;
			assertTrue(xmlvalidation);

			String metadataOk = getFile("metadata/metadata_settings1.xml");
			xmlvalidation = Utils.loadXML(metadataOk) instanceof Document;
			assertTrue(xmlvalidation);

			String samlResponse = getFile("responses/open_saml_response.xml");
			xmlvalidation = Utils.loadXML(samlResponse) instanceof Document;
			assertTrue(xmlvalidation);

		}catch(DOMException e){
			e.printStackTrace();
			assertTrue(false);
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
			assertTrue(false);
		} catch (Exception e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}

	/**
	 * Tests the validateXML method of the com.onelogin.saml.Utils
	 *
	 * @covers Utils.validateXML
	 */
	@Test
	public void testValidateXML()
	{
		try{
			try{
				String metadataUnloaded = "<xml><EntityDescriptor>";
				Document docMetadataUnloaded = Utils.loadXML(metadataUnloaded);
				Utils.validateXML(docMetadataUnloaded, "saml-schema-metadata-2.0.xsd");
			}
			catch (Throwable ex){
				assertTrue(ex instanceof Exception);
			}

			try{
				String metadataInvalid = getFile("metadata/noentity_metadata_settings1.xml");
				Document docMetadataInvalid = Utils.loadXML(metadataInvalid);
				Utils.validateXML(docMetadataInvalid, "saml-schema-metadata-2.0.xsd");
			}
			catch(Throwable ex){
				assertTrue(ex instanceof Error);
			}

			String metadataExpired = getFile("metadata/expired_metadata_settings1.xml");
			Document docMetadataExpired = Utils.loadXML(metadataExpired);
			Document doc = Utils.validateXML(docMetadataExpired, "saml-schema-metadata-2.0.xsd");
			assertTrue(doc instanceof Document);
			assertNotNull(doc);

			String metadataOk = getFile("metadata/metadata_settings1.xml");
			Document docMetadataOk = Utils.loadXML(metadataOk);
			Document doc2 = Utils.validateXML(docMetadataOk, "saml-schema-metadata-2.0.xsd");
			assertTrue(doc2 instanceof Document);
			assertNotNull(doc2);
		}catch(DOMException e){
			//e.printStackTrace();
			assertTrue(false);
		} catch (ParserConfigurationException e) {
			//e.printStackTrace();
			assertTrue(false);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Tests the query method of the com.onelogin.saml.Utils
	 *
	 * covers Utils.query
	 */
	@Test
	public void testQuery()
	{
		try{
			String responseCoded = getFile("responses/valid_response.xml.base64");
			Base64 base64 = new Base64();
			byte[] decodedB = base64.decode(responseCoded);
			String response = new String(decodedB);
			Document dom = Utils.loadXML(response);

			NodeList assertionNodes = Utils.query(dom, "/samlp:Response/saml:Assertion", null);
			assertEquals(1, assertionNodes.getLength());
			Node assertion = assertionNodes.item(0);
			assertEquals("saml:Assertion", assertion.getNodeName());

			NodeList attributeStatementNodes = Utils.query(dom, "/samlp:Response/saml:Assertion/saml:AttributeStatement", null);
			assertEquals(1, attributeStatementNodes.getLength());
			Node attributeStatement = attributeStatementNodes.item(0);
			assertEquals("saml:AttributeStatement", attributeStatement.getNodeName());

			NodeList attributeStatementNodes2 = Utils.query(dom, "./saml:AttributeStatement", assertion);
			assertEquals(1, attributeStatementNodes2.getLength());
			Node attributeStatement2 = attributeStatementNodes2.item(0);
			assertEquals(attributeStatement, attributeStatement2);

			NodeList signatureResNodes = Utils.query(dom, "/samlp:Response/ds:Signature", null);
			assertEquals(1, signatureResNodes.getLength());
			Node signatureRes= signatureResNodes.item(0);
			assertEquals("ds:Signature", signatureRes.getNodeName());

			NodeList signatureNodes = Utils.query(dom, "/samlp:Response/saml:Assertion/ds:Signature", null);
			assertEquals(1, signatureNodes.getLength());
			Node signature = signatureNodes.item(0);
			assertEquals("ds:Signature", signature.getNodeName());

			NodeList signatureNodes2 = Utils.query(dom, "./ds:Signature", assertion);
			assertEquals(1, signatureNodes2.getLength());
			Node signature2 = signatureNodes2.item(0);
			assertEquals(signature.getTextContent(), signature2.getTextContent());
			assertNotEquals(signatureRes.getTextContent(), signature2.getTextContent());

			NodeList signatureNodes3 = Utils.query(dom, "./ds:SignatureValue", assertion);
			assertEquals(0, signatureNodes3.getLength());

			NodeList signatureNodes4 = Utils.query(dom, "./ds:Signature/ds:SignatureValue", assertion);
			assertEquals(1, signatureNodes4.getLength());

			NodeList signatureNodes5 = Utils.query(dom, ".//ds:SignatureValue", assertion);
			assertEquals(1, signatureNodes5.getLength());

		}catch(DOMException e){
			e.printStackTrace();
			assertTrue(false);
		} catch (Exception e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}

	/**
	 * Tests the validateSign method of the com.onelogin.saml.Utils
	 *
	 */
	@Test
	public void testValidateSign()
	{
		try{
			String certificate = "MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXM"+
					"gU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITA"+
					"fBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQs"+
					"wCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQ"+
					"xGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSq"+
					"GSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcP"+
					"sIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1ED"+
					"wXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRX"+
					"F+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFV"+
					"K2QarQ4/67OZfHd7R+POBXhophSMv1ZOo";
			CertificateFactory fty = CertificateFactory.getInstance("X.509");
			ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(certificate.getBytes()));
			Certificate cert = fty.generateCertificate(bais);

			String responseCoded = getFile("responses/signed_message_response.xml.base64");
			Base64 base64 = new Base64();
			byte[] decodedB = base64.decode(responseCoded);
			String response = new String(decodedB);
			Document dom = Utils.loadXML(response);

			NodeList signatureResNodes = Utils.query(dom, "/samlp:Response/ds:Signature", null);
			assertEquals(1, signatureResNodes.getLength());
			assertTrue(Utils.validateSign(signatureResNodes.item(0), cert));
			try {
				assertFalse(Utils.validateSign(dom.getChildNodes().item(0), cert));
				assertTrue(false);
			} catch (Exception e) {
				assertTrue(e.getMessage().contains("invalid Signature"));
			}
			
			responseCoded = getFile("responses/invalids/no_key.xml.base64");
			base64 = new Base64();
			decodedB = base64.decode(responseCoded);
			response = new String(decodedB);
			dom = Utils.loadXML(response);

			NodeList signatureNoKey = Utils.query(dom, "/samlp:Response/saml:Assertion/ds:Signature", null);
			assertEquals(1, signatureNoKey.getLength());
			try {
				assertFalse(Utils.validateSign(signatureNoKey.item(0), cert));
				assertTrue(false);
			} catch (Exception e) {
				assertTrue(true);
			}

		}catch(DOMException e){
			e.printStackTrace();
			assertTrue(false);
		} catch (Exception e) {
			e.printStackTrace();
			assertTrue(false);
		}

	}


	private String getFile(String fileName) {

		StringBuilder result = new StringBuilder("");

		//Get file from resources folder
		ClassLoader classLoader = getClass().getClassLoader();
		File file = new File(classLoader.getResource(fileName).getFile());

		try (Scanner scanner = new Scanner(file)) {

			while (scanner.hasNextLine()) {
				String line = scanner.nextLine();
				result.append(line).append("\n");
			}

			scanner.close();

		} catch (IOException e) {
			e.printStackTrace();
		}

		return result.toString();

	}

}
