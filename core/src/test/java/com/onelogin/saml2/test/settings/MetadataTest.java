package com.onelogin.saml2.test.settings;


import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNull;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Test;

import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.model.AttributeConsumingService;
import com.onelogin.saml2.model.RequestedAttribute;
import com.onelogin.saml2.settings.Metadata;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.SchemaFactory;
import com.onelogin.saml2.util.Util;

/**
 * Tests the com.onelogin.saml2.Metadata class
 */
public class MetadataTest {
	/**
	 * Tests the constructor method of Metadata
	 *
	 * @throws Exception
	 * @see com.onelogin.saml2.settings.Metadata
	 */
	@Test
	public void testMetadata() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Metadata metadataObj = new Metadata(settings);
		String metadataStr = metadataObj.getMetadataString();
		Document metadataDoc = Util.loadXML(metadataStr);

		assertTrue(metadataDoc instanceof Document);

		assertEquals("md:EntityDescriptor", metadataDoc.getDocumentElement().getNodeName());
		assertEquals("md:SPSSODescriptor", metadataDoc.getDocumentElement().getFirstChild().getNodeName());

		assertTrue(Util.validateXML(metadataDoc, SchemaFactory.SAML_SCHEMA_METADATA_2_0));

		assertThat(metadataStr, containsString("<md:SPSSODescriptor"));
		assertThat(metadataStr, containsString("entityID=\"http://localhost:8080/java-saml-jspsample/metadata.jsp\""));
		assertThat(metadataStr, containsString("AuthnRequestsSigned=\"false\""));
		assertThat(metadataStr, containsString("WantAssertionsSigned=\"false\""));
		assertThat(metadataStr, not(containsString("<md:KeyDescriptor use=\"signing\">")));
		assertThat(metadataStr, containsString("<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/java-saml-jspsample/acs.jsp\" index=\"1\"/>"));
		assertThat(metadataStr, containsString("<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/java-saml-jspsample/sls.jsp\"/>"));
		assertThat(metadataStr, containsString("<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"));
	}

	/**
	 * Tests the constructor method of Metadata (Expiration)
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws Error
	 * @see com.onelogin.saml2.settings.Metadata
	 */
	@Test
	public void testMetadataExpiration() throws IOException, CertificateEncodingException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Metadata metadataObj = new Metadata(settings, null, null);
		String metadataStr = metadataObj.getMetadataString();

		Calendar validUntilTime = Calendar.getInstance();
		validUntilTime.add(Calendar.DAY_OF_YEAR, 2);
		String validUntilStr = "validUntil=\"" + Util.formatDateTime(validUntilTime.getTimeInMillis()) + "\"";

		assertThat(metadataStr, not(containsString("cacheDuration")));
		assertThat(metadataStr, not(containsString(validUntilStr)));

		String validUntilStr2 = "validUntil=\"" + Util.formatDateTime(validUntilTime.getTimeInMillis()) + "\"";
		Metadata metadataObj2 = new Metadata(settings, validUntilTime, 36000);
		String metadataStr2 = metadataObj2.getMetadataString();

		assertThat(metadataStr2, containsString("cacheDuration=\"PT36000S\""));
		assertThat(metadataStr2, containsString(validUntilStr2));
	}

	/**
	 * Tests the toContactsXml method of Metadata
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws Error
	 * @see com.onelogin.saml2.settings.Metadata#toContactsXml
	 */
	@Test
	public void testToContactsXml() throws IOException, CertificateEncodingException, Error {
		Saml2Settings settings = getSettingFromAllProperties();
		Metadata metadataObj = new Metadata(settings);
		String metadataStr = metadataObj.getMetadataString();

		String contactStr = "<md:ContactPerson contactType=\"technical\"><md:GivenName>Technical Guy</md:GivenName><md:EmailAddress>technical@example.com</md:EmailAddress></md:ContactPerson><md:ContactPerson contactType=\"support\"><md:GivenName>Support Guy</md:GivenName><md:EmailAddress>support@example.com</md:EmailAddress></md:ContactPerson>";
		assertThat(metadataStr, containsString(contactStr));

		Saml2Settings settings2 = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Metadata metadataObj2 = new Metadata(settings2);
		String metadataStr2 = metadataObj2.getMetadataString();

		assertThat(metadataStr2, not(containsString(contactStr)));
	}

	/**
	 * Tests the toOrganizationXml method of Metadata (Expiration)
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws Error
	 * @see com.onelogin.saml2.settings.Metadata#toOrganizationXml
	 */
	@Test
	public void testToOrganizationXml() throws IOException, CertificateEncodingException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		Metadata metadataObj = new Metadata(settings);
		String metadataStr = metadataObj.getMetadataString();

		String orgStr = "<md:Organization><md:OrganizationName xml:lang=\"en\">SP Java</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"en\">SP Java Example</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"en\">http://sp.example.com</md:OrganizationURL></md:Organization>";
		assertThat(metadataStr, containsString(orgStr));

		Saml2Settings settings2 = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Metadata metadataObj2 = new Metadata(settings2);
		String metadataStr2 = metadataObj2.getMetadataString();

		assertThat(metadataStr2, not(containsString(orgStr)));
	}

	/**
	 * Tests the toOrganizationXml method of Metadata without any "lang" attribute
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws Error
	 * @see com.onelogin.saml2.settings.Metadata#toOrganizationXml
	 */
	@Test
	public void testToNonLocalizedOrganizationXml() throws IOException, CertificateEncodingException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.org.properties").build();
		Metadata metadataObj = new Metadata(settings);
		String metadataStr = metadataObj.getMetadataString();

		String orgStr = "<md:Organization><md:OrganizationName xml:lang=\"en\">SP Java</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"en\">SP Java Example</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"en\">http://sp.example.com</md:OrganizationURL></md:Organization>";
		assertThat(metadataStr, containsString(orgStr));

		Saml2Settings settings2 = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Metadata metadataObj2 = new Metadata(settings2);
		String metadataStr2 = metadataObj2.getMetadataString();

		assertThat(metadataStr2, not(containsString(orgStr)));
	}


	/**
	 * Tests the toOrganizationXml method of Metadata using a non default "lang" attribute
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws Error
	 * @see com.onelogin.saml2.settings.Metadata#toOrganizationXml
	 */
	@Test
	public void testToLocalizedOrganizationXml() throws IOException, CertificateEncodingException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.org.localized.properties").build();
		Metadata metadataObj = new Metadata(settings);
		String metadataStr = metadataObj.getMetadataString();

		String orgStr = "<md:Organization><md:OrganizationName xml:lang=\"fr\">SP Java</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"fr\">SP Exemple Java</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"fr\">http://sp.example.com/fr</md:OrganizationURL></md:Organization>";
		assertThat(metadataStr, containsString(orgStr));

		Saml2Settings settings2 = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Metadata metadataObj2 = new Metadata(settings2);
		String metadataStr2 = metadataObj2.getMetadataString();

		assertThat(metadataStr2, not(containsString(orgStr)));
	}

	/**
	 * Tests the toSLSXml method of Metadata
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws Error
	 * @see com.onelogin.saml2.settings.Metadata#toSLSXml
	 */
	@Test
	public void testToSLSXml() throws IOException, CertificateEncodingException, Error {
		Saml2Settings settings = getSettingFromAllProperties();
		Metadata metadataObj = new Metadata(settings);
		String metadataStr = metadataObj.getMetadataString();

		String slsStr = "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/java-saml-jspsample/sls.jsp\"/>";

		assertThat(metadataStr, containsString(slsStr));

		Saml2Settings settings2 = new SettingsBuilder().fromFile("config/config.minnosls.properties").build();
		Metadata metadataObj2 = new Metadata(settings2);
		String metadataStr2 = metadataObj2.getMetadataString();

		assertThat(metadataStr2, not(containsString(slsStr)));
	}

	/**
	 * Tests the toX509KeyDescriptorsXML method of Metadata
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws Error
	 * @see com.onelogin.saml2.settings.Metadata#toX509KeyDescriptorsXML
	 */
	@Test
	public void testToX509KeyDescriptorsXML() throws IOException, CertificateEncodingException, Error {
		Saml2Settings settings = getSettingFromAllProperties();
		Metadata metadataObj = new Metadata(settings);
		String metadataStr = metadataObj.getMetadataString();

		String keyDescriptorSignStr = "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICeDCCAeGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBZMQswCQYDVQQGEwJ1czET";
		String keyDescriptorEncStr = "<md:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICeDCCAeGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBZMQswCQYDVQQGEwJ1czET";

		int keyDescriptorSignStrCount = metadataStr.split(keyDescriptorSignStr).length - 1;
		int keyDescriptorEncStrCount = metadataStr.split(keyDescriptorEncStr).length - 1;

		assertThat(metadataStr, containsString(keyDescriptorSignStr));
		assertThat(metadataStr, containsString(keyDescriptorEncStr));

		assertEquals(2, keyDescriptorEncStrCount);
		assertEquals(2, keyDescriptorSignStrCount);

		Saml2Settings settings2 = new SettingsBuilder().fromFile("config/config.minnosls.properties").build();
		Metadata metadataObj2 = new Metadata(settings2);
		String metadataStr2 = metadataObj2.getMetadataString();

		assertThat(metadataStr2, not(containsString(keyDescriptorSignStr)));
		assertThat(metadataStr2, not(containsString(keyDescriptorEncStr)));
	}

	/**
	 * Tests the toX509KeyDescriptorsXML method of Metadata
	 * Case: Check where to add or not md:KeyDescriptor encryption
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws Error
	 * @see com.onelogin.saml2.settings.Metadata#toX509KeyDescriptorsXML
	 */
	@Test
	public void testToX509KeyDescriptorsXMLEncryption() throws IOException, CertificateEncodingException, Error {
		Saml2Settings settings = getSettingFromAllProperties();
		String keyDescriptorEncStr = "<md:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICeDCCAeGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBZMQswCQYDVQQGEwJ1czET";

		settings.setWantAssertionsEncrypted(false);
		settings.setWantNameIdEncrypted(false);
		Metadata metadataObj = new Metadata(settings);
		String metadataStr = metadataObj.getMetadataString();
		assertThat(metadataStr, not(containsString(keyDescriptorEncStr)));

		settings.setWantAssertionsEncrypted(true);
		settings.setWantNameIdEncrypted(false);
		metadataObj = new Metadata(settings);
		metadataStr = metadataObj.getMetadataString();
		assertThat(metadataStr, containsString(keyDescriptorEncStr));

		settings.setWantAssertionsEncrypted(false);
		settings.setWantNameIdEncrypted(true);
		metadataObj = new Metadata(settings);
		metadataStr = metadataObj.getMetadataString();
		assertThat(metadataStr, containsString(keyDescriptorEncStr));

		settings.setWantAssertionsEncrypted(true);
		settings.setWantNameIdEncrypted(true);
		metadataObj = new Metadata(settings);
		metadataStr = metadataObj.getMetadataString();
		assertThat(metadataStr, containsString(keyDescriptorEncStr));
	}

	/**
	 * Tests the getAttributeConsumingServiceXml method of Metadata
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws Error
	 * @see com.onelogin.saml2.settings.Metadata#getAttributeConsumingServiceXml
	 */
	@Test
	public void testGetAttributeConsumingServiceXml() throws IOException, CertificateEncodingException, Error {
		Saml2Settings settings = getSettingFromAllProperties();

		AttributeConsumingService attributeConsumingService = new AttributeConsumingService("Test Service", "Test Service Desc");
		RequestedAttribute requestedAttribute = new RequestedAttribute("Email", "Email", true, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", null);
		RequestedAttribute requestedAttribute2 = new RequestedAttribute("FirstName", null, true, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", null);
		RequestedAttribute requestedAttribute3 = new RequestedAttribute("LastName", null, true, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", null);

		attributeConsumingService.addRequestedAttribute(requestedAttribute);
		attributeConsumingService.addRequestedAttribute(requestedAttribute2);
		attributeConsumingService.addRequestedAttribute(requestedAttribute3);

		Metadata metadataObj = new Metadata(settings, null, null, attributeConsumingService);
		String metadataStr = metadataObj.getMetadataString();

		String headerStr = "<md:AttributeConsumingService index=\"1\">";
		String sNameStr = "<md:ServiceName xml:lang=\"en\">Test Service</md:ServiceName>";
		String sDescStr = "<md:ServiceDescription xml:lang=\"en\">Test Service Desc</md:ServiceDescription>";
		String reqAttr1Str = "<md:RequestedAttribute Name=\"Email\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" FriendlyName=\"Email\" isRequired=\"true\" />";
		String reqAttr2Str = "<md:RequestedAttribute Name=\"FirstName\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" isRequired=\"true\" />";
		String reqAttr3Str = "<md:RequestedAttribute Name=\"LastName\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" isRequired=\"true\" />";
		String footerStr = "</md:AttributeConsumingService>";

		assertThat(metadataStr, containsString(headerStr));
		assertThat(metadataStr, containsString(sNameStr));
		assertThat(metadataStr, containsString(sDescStr));
		assertThat(metadataStr, containsString(reqAttr1Str));
		assertThat(metadataStr, containsString(reqAttr2Str));
		assertThat(metadataStr, containsString(reqAttr3Str));
		assertThat(metadataStr, containsString(footerStr));
	}

	/**
	 * Tests the getAttributeConsumingServiceXml method of Metadata
	 * Case: AttributeConsumingService Multiple AttributeValue
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 * @throws Error
	 * @see com.onelogin.saml2.settings.Metadata#getAttributeConsumingServiceXml
	 */
	@Test
	public void testGetAttributeConsumingServiceXmlWithMultipleAttributeValue() throws IOException, CertificateEncodingException, Error {
		Saml2Settings settings = getSettingFromAllProperties();

		AttributeConsumingService attributeConsumingService = new AttributeConsumingService("Test Service", "Test Service Desc");
		List<String> attrValues = new ArrayList<String>();
		attrValues.add("userType");
		attrValues.add("admin");
		RequestedAttribute requestedAttribute = new RequestedAttribute("userType", null, false, "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", attrValues);
		RequestedAttribute requestedAttribute2 = new RequestedAttribute("urn:oid:0.9.2342.19200300.100.1.1", "uid", true, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", null);

		attributeConsumingService.addRequestedAttribute(requestedAttribute);
		attributeConsumingService.addRequestedAttribute(requestedAttribute2);

		Metadata metadataObj = new Metadata(settings, null, null, attributeConsumingService);
		String metadataStr = metadataObj.getMetadataString();

		String headerStr = "<md:AttributeConsumingService index=\"1\">";
		String sNameStr = "<md:ServiceName xml:lang=\"en\">Test Service</md:ServiceName>";
		String sDescStr = "<md:ServiceDescription xml:lang=\"en\">Test Service Desc</md:ServiceDescription>";
		String reqAttr1Str = "<md:RequestedAttribute Name=\"userType\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\" isRequired=\"false\">";
		String reqAttr1Atr1Str = "<saml:AttributeValue xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">userType</saml:AttributeValue>";
		String reqAttr1Attr2Str = "<saml:AttributeValue xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">admin</saml:AttributeValue>";
		String reqAttr2Str = "<md:RequestedAttribute Name=\"urn:oid:0.9.2342.19200300.100.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" FriendlyName=\"uid\" isRequired=\"true\" />";
		String footerStr = "</md:AttributeConsumingService>";

		assertThat(metadataStr, containsString(headerStr));
		assertThat(metadataStr, containsString(sNameStr));
		assertThat(metadataStr, containsString(sDescStr));
		assertThat(metadataStr, containsString(reqAttr1Str));
		assertThat(metadataStr, containsString(reqAttr1Atr1Str));
		assertThat(metadataStr, containsString(reqAttr1Attr2Str));
		assertThat(metadataStr, containsString(reqAttr2Str));
		assertThat(metadataStr, containsString(footerStr));
	}

	/**
	 * Tests the signMetadata method of Metadata
	 * Case imported metadata
	 *
	 * @throws IOException
	 * @throws GeneralSecurityException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 * @see com.onelogin.saml2.settings.Metadata#signMetadata
	 */
	@Test
	public void testSignImportedMetadata() throws IOException, GeneralSecurityException, XPathExpressionException, XMLSecurityException {
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String signAlgorithmSha1 = Constants.RSA_SHA1;
		String digestAlgorithmSha1 = Constants.SHA1;

		String metadata = Util.getFileAsString("data/metadata/metadata_settings1.xml");
		String metadataSigned = Metadata.signMetadata(metadata, key, cert, signAlgorithmSha1);
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
	}

	/**
	 * Tests the signMetadata method of Metadata
	 * Case generated metadata
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws GeneralSecurityException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 * @see com.onelogin.saml2.settings.Metadata#signMetadata
	 */
	@Test
	public void testSigngeneratedMetadata() throws Error, IOException, GeneralSecurityException, XPathExpressionException, XMLSecurityException {
		Saml2Settings settings = getSettingFromAllProperties();
		String certString = Util.getFileAsString("data/customPath/certs/sp.crt");
		X509Certificate cert = Util.loadCert(certString);
		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String signAlgorithmSha256 = Constants.RSA_SHA256;
		String digestAlgorithmSha512 = Constants.SHA512;

		Metadata metadataObj = new Metadata(settings);
		String metadata = metadataObj.getMetadataString();
		String metadataSigned = Metadata.signMetadata(metadata, key, cert, signAlgorithmSha256, digestAlgorithmSha512);
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
		assertEquals(signAlgorithmSha256, signature_method_metadata_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
		Node digest_method_metadata_signed = ds_signature_metadata.getFirstChild().getFirstChild().getNextSibling().getNextSibling().getFirstChild().getNextSibling();
		assertEquals("ds:DigestMethod", digest_method_metadata_signed.getNodeName());
		assertEquals(digestAlgorithmSha512, digest_method_metadata_signed.getAttributes().getNamedItem("Algorithm").getNodeValue());
	}

	private Saml2Settings getSettingFromAllProperties() throws Error, IOException {
		return new SettingsBuilder().fromFile("config/config.all.properties").build();
	}

	@Test
	public void shouldIncludeValidUntilAndDuration() throws CertificateEncodingException, Error, IOException {
		//given
		Saml2Settings saml2Settings = getSettingFromAllProperties();

		//when
		Integer cacheDuration = 123;
		Calendar validUntil = Calendar.getInstance();
		Metadata metadata = new Metadata(saml2Settings, validUntil, cacheDuration);
		String metadataString = metadata.getMetadataString();

		//then
		Document metadataSignedDoc = Util.loadXML(metadataString);
		Node validUntilNode = metadataSignedDoc.getFirstChild().getAttributes().getNamedItem("validUntil");
		Node cacheDurationNode = metadataSignedDoc.getFirstChild().getAttributes().getNamedItem("cacheDuration");
		assertEquals("should set valid until attribute", Util.formatDateTime(validUntil.getTimeInMillis()), validUntilNode.getTextContent());
		assertEquals("should set cache duration attribute", "PT123S", cacheDurationNode.getTextContent());

	}

	@Test
	public void shouldIgnoreValidUntil() throws CertificateEncodingException, Error, IOException {
		//given
		Saml2Settings saml2Settings = getSettingFromAllProperties();

		//when
		Integer cacheDuration = 123;
		Calendar validUntil = Calendar.getInstance();
		Metadata metadata = new Metadata(saml2Settings, null, cacheDuration);
		String metadataString = metadata.getMetadataString();

		//then
		Document metadataSignedDoc = Util.loadXML(metadataString);
		Node validUntilNode = metadataSignedDoc.getFirstChild().getAttributes().getNamedItem("validUntil");
		Node cacheDurationNode = metadataSignedDoc.getFirstChild().getAttributes().getNamedItem("cacheDuration");
		assertNull("should not set valid until attribute", validUntilNode);
		assertEquals("should set cache duration attribute", "PT123S", cacheDurationNode.getTextContent());
	}

	@Test
	public void shouldIgnoreCacheDuration() throws CertificateEncodingException, Error, IOException {
		//given
		Saml2Settings saml2Settings = getSettingFromAllProperties();

		//when
		Integer cacheDuration = 123;
		Calendar validUntil = Calendar.getInstance();
		Metadata metadata = new Metadata(saml2Settings, validUntil, null);
		String metadataString = metadata.getMetadataString();

		//then
		Document metadataSignedDoc = Util.loadXML(metadataString);
		Node validUntilNode = metadataSignedDoc.getFirstChild().getAttributes().getNamedItem("validUntil");
		Node cacheDurationNode = metadataSignedDoc.getFirstChild().getAttributes().getNamedItem("cacheDuration");
		assertEquals("should set valid until attribute", Util.formatDateTime(validUntil.getTimeInMillis()), validUntilNode.getTextContent());
		assertNull("should not set cache duration attribute", cacheDurationNode);

	}
}
