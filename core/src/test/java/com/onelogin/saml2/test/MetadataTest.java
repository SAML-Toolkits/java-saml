package com.onelogin.saml2.test;


import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;


import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.Calendar;

import org.w3c.dom.Document;
import org.junit.Test;

import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.Metadata;
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
	 * 
	 * @see com.onelogin.saml2.Metadata
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
		assertThat(metadataStr, containsString("<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified</md:NameIDFormat>"));
	}

	/**
	 * Tests the constructor method of Metadata (Expiration)
     *
	 * @throws IOException 
	 * @throws CertificateEncodingException 
	 *
	 * @see com.onelogin.saml2.Metadata
	 */
	@Test
	public void testMetadataExpiration() throws IOException, CertificateEncodingException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Metadata metadataObj = new Metadata(settings);
		String metadataStr = metadataObj.getMetadataString();

		Calendar validUntilTime = Calendar.getInstance();
		validUntilTime.add(Calendar.DAY_OF_YEAR, 2);
		String  validUntilStr = "validUntil=\"" + Util.formatDateTime(validUntilTime.getTimeInMillis()) + "\""; 

		assertThat(metadataStr, containsString("cacheDuration=\"PT604800S\""));
		assertThat(metadataStr, containsString(validUntilStr));

		validUntilTime.add(Calendar.DAY_OF_YEAR, 2);
		String  validUntilStr2 = "validUntil=\"" + Util.formatDateTime(validUntilTime.getTimeInMillis()) + "\"";
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
	 *
	 * @see com.onelogin.saml2.Metadata.toContactsXml
	 */
	@Test
	public void testToContactsXml() throws IOException, CertificateEncodingException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
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
	 *
	 * @see com.onelogin.saml2.Metadata.toOrganizationXml
	 */
	@Test
	public void testToOrganizationXml() throws IOException, CertificateEncodingException {
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
	 * Tests the toSLSXml method of Metadata
	 *
	 * @throws IOException
	 * @throws CertificateEncodingException
	 *
	 * @see com.onelogin.saml2.Metadata.toSLSXml
	 */
	@Test
	public void testToSLSXml() throws IOException, CertificateEncodingException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
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
	 *
	 * @see com.onelogin.saml2.Metadata.toX509KeyDescriptorsXML
	 */
	@Test
	public void testToX509KeyDescriptorsXML() throws IOException, CertificateEncodingException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		Metadata metadataObj = new Metadata(settings);
		String metadataStr = metadataObj.getMetadataString();

		String keyDescriptorSignStr = "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICeDCCAeGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBZMQswCQYDVQQGEwJ1czET";
		String keyDescriptorEncStr = "<md:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICeDCCAeGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBZMQswCQYDVQQGEwJ1czET";

		assertThat(metadataStr, containsString(keyDescriptorSignStr));
		assertThat(metadataStr, containsString(keyDescriptorEncStr));

		Saml2Settings settings2 = new SettingsBuilder().fromFile("config/config.minnosls.properties").build();
		Metadata metadataObj2 = new Metadata(settings2);
		String metadataStr2 = metadataObj2.getMetadataString();

		assertThat(metadataStr2, not(containsString(keyDescriptorSignStr)));
		assertThat(metadataStr2, not(containsString(keyDescriptorEncStr)));
	}
}
