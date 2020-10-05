package com.onelogin.saml2.test.settings;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import java.io.IOException;
import java.util.Calendar;
import java.util.List;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.settings.Metadata;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.SchemaFactory;
import com.onelogin.saml2.util.Util;

/**
 * Tests the com.onelogin.saml2.settings.Saml2Settings class
 */
public class Saml2SettingsTest {

	/**
	 * Tests the isStrict and setStrict methods of the Saml2Settings
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#isStrict
	 * @see com.onelogin.saml2.settings.Saml2Settings#setStrict
	 */
	@Test
	public void testIsStrict() {
		Saml2Settings settings = new Saml2Settings();
		
		assertTrue(settings.isStrict());
		settings.setStrict(false);
		assertFalse(settings.isStrict());
		settings.setStrict(true);
		assertTrue(settings.isStrict());
	}

	/**
	 * Tests the isDebugActive and setDebug methods of the Saml2Settings
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#isDebugActive
	 * @see com.onelogin.saml2.settings.Saml2Settings#setDebug
	 */
	@Test
	public void testIsDebugActive() {
		Saml2Settings settings = new Saml2Settings();
		
		assertFalse(settings.isDebugActive());
		settings.setDebug(true);
		assertTrue(settings.isDebugActive());
		settings.setDebug(false);
		assertFalse(settings.isDebugActive());
	}
	
	/**
	 * Tests the checkIdPSettings method of the Saml2Settings
	 * Case: Check that all possible IdP errors are found
	 *
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#checkIdPSettings
	 */
	@Test
	public void testCheckIdPSettingsAllErrors() throws IOException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.idperrors.properties").build();
		List<String> settingsErrors = settings.checkIdPSettings();
		assertFalse(settingsErrors.isEmpty());
		assertThat(settingsErrors, hasItem("idp_entityId_not_found"));
		assertThat(settingsErrors, hasItem("idp_sso_url_invalid"));
		assertThat(settingsErrors, hasItem("idp_cert_or_fingerprint_not_found_and_required"));
		assertThat(settingsErrors, hasItem("idp_cert_not_found_and_required"));
	}

	/**
	 * Tests the checkIdPSettings method of the Saml2Settings
	 * Case: No IdP Errors
	 *
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#checkIdPSettings
	 */
	@Test
	public void testCheckIdPSettingsOk() throws IOException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		List<String> settingsErrors = settings.checkIdPSettings();
		assertTrue(settingsErrors.isEmpty());
	}

	/**
	 * Tests the checkSPSettings method of the Saml2Settings
	 * Case: Check that all possible IdP errors are found
	 *
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#checkSPSettings
	 */
	@Test
	public void testCheckSPSettingsAllErrors() throws IOException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.sperrors.properties").build();
		List<String> settingsErrors = settings.checkSPSettings();
		assertFalse(settingsErrors.isEmpty());
		assertThat(settingsErrors, hasItem("sp_entityId_not_found"));
		assertThat(settingsErrors, hasItem("sp_acs_not_found"));
		assertThat(settingsErrors, hasItem("sp_cert_not_found_and_required"));
		assertThat(settingsErrors, hasItem("contact_not_enought_data"));
		assertThat(settingsErrors, hasItem("organization_not_enought_data"));
	}

	/**
	 * Tests the checkSPSettings method of the Saml2Settings
	 * Case: No SP Errors
	 *
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#checkSPSettings
	 */
	@Test
	public void testCheckSPSettingsOk() throws IOException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		List<String> settingsErrors = settings.checkSPSettings();
		assertTrue(settingsErrors.isEmpty());
	}

	/**
	 * Tests the checkSettings method of the Saml2Settings
	 * Case: Check that all possible errors are found
	 *
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#checkSettings
	 */
	@Test
	public void testCheckSettingsAllErrors() throws IOException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.allerrors.properties").build();
		List<String> settingsErrors = settings.checkSettings();
		assertFalse(settingsErrors.isEmpty());
		assertThat(settingsErrors, hasItem("sp_entityId_not_found"));
		assertThat(settingsErrors, hasItem("sp_acs_not_found"));
		assertThat(settingsErrors, hasItem("sp_cert_not_found_and_required"));
		assertThat(settingsErrors, hasItem("contact_not_enought_data"));
		assertThat(settingsErrors, hasItem("organization_not_enought_data"));
		assertThat(settingsErrors, hasItem("idp_entityId_not_found"));
		assertThat(settingsErrors, hasItem("idp_sso_url_invalid"));
		assertThat(settingsErrors, hasItem("idp_cert_or_fingerprint_not_found_and_required"));
		assertThat(settingsErrors, hasItem("idp_cert_not_found_and_required"));
	}

	/**
	 * Tests the checkSettings method of the Saml2Settings
	 * Case: Check IdP errors
	 *
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#checkSettings
	 */
	@Test
	public void testCheckSettingsIdPErrors() throws IOException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.idperrors.properties").build();
		List<String> settingsErrors = settings.checkSettings();
		assertFalse(settingsErrors.isEmpty());
		assertThat(settingsErrors, hasItem("idp_entityId_not_found"));
		assertThat(settingsErrors, hasItem("idp_sso_url_invalid"));
		assertThat(settingsErrors, hasItem("idp_cert_or_fingerprint_not_found_and_required"));
		assertThat(settingsErrors, hasItem("idp_cert_not_found_and_required"));
		
		settings.setSPValidationOnly(true);
		settingsErrors = settings.checkSettings();
		assertTrue(settingsErrors.isEmpty());
	}

	/**
	 * Tests the checkIdpSettings method of the {@link Saml2Settings}
	 * Case: Multiple certs defined.
	 * 
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.settings.Saml2Settings#checkIdPSettings
	 */
	@Test
	public void testCheckIdpMultipleCertSettings () throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min_idp_multicert.properties").build();
		List<String> settingsErrors = settings.checkSettings();
		assertTrue(settingsErrors.isEmpty());
	}

	/**
	 * Tests the checkSettings method of the Saml2Settings
	 * Case: No SP Errors
	 *
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#checkSettings
	 */
	@Test
	public void testCheckSettingsOk() throws IOException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		List<String> settingsErrors = settings.checkSettings();
		assertTrue(settingsErrors.isEmpty());
	}

	/**
	 * Tests the getSPMetadata method of the Saml2Settings
	 * * Case Unsigned metadata
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#getSPMetadata
	 */
	@Test
	public void testGetSPMetadataUnsigned() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		String metadataStr = settings.getSPMetadata();

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
	 * Tests the getSPMetadata method of the Saml2Settings
	 * * Case Unsigned metadata No SLS
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#getSPMetadata
	 */
	@Test
	public void testGetSPMetadataUnsignedNoSLS() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.minnosls.properties").build();

		String metadataStr = settings.getSPMetadata();

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
		assertThat(metadataStr, not(containsString("<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/java-saml-jspsample/sls.jsp\"/>"))); 
		assertThat(metadataStr, containsString("<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"));
	}
	
	/**
	 * Tests the getSPMetadata method of the Saml2Settings
	 * * Case Signed metadata
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#getSPMetadata
	 */
	@Test
	public void testGetSPMetadataSigned() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();

		String metadataStr = settings.getSPMetadata();

		Document metadataDoc = Util.loadXML(metadataStr);
		assertTrue(metadataDoc instanceof Document);
		assertEquals("ds:Signature", metadataDoc.getDocumentElement().getFirstChild().getNodeName());
		Node ds_signature_metadata = metadataDoc.getFirstChild().getFirstChild();

		assertEquals(Constants.C14NEXC, ds_signature_metadata.getFirstChild().getFirstChild().getAttributes().getNamedItem("Algorithm").getNodeValue());
		
		assertEquals(Constants.RSA_SHA512, ds_signature_metadata.getFirstChild().getFirstChild().getNextSibling().getAttributes().getNamedItem("Algorithm").getNodeValue());
		assertEquals(Constants.SHA1, ds_signature_metadata.getFirstChild().getFirstChild().getNextSibling().getNextSibling().getFirstChild().getNextSibling().getAttributes().getNamedItem("Algorithm").getNodeValue());

		assertEquals("md:SPSSODescriptor", metadataDoc.getDocumentElement().getFirstChild().getNextSibling().getNodeName());
		
		assertTrue(Util.validateXML(metadataDoc, SchemaFactory.SAML_SCHEMA_METADATA_2_0));
		
		assertThat(metadataStr, containsString("<md:SPSSODescriptor"));
		assertThat(metadataStr, containsString("entityID=\"http://localhost:8080/java-saml-jspsample/metadata.jsp\""));
		assertThat(metadataStr, containsString("AuthnRequestsSigned=\"true\""));
		assertThat(metadataStr, containsString("WantAssertionsSigned=\"true\""));

		String keyDescriptorSigningText = "<md:KeyDescriptor use=\"signing\">";
		int keyDescriptorSignStrCount = metadataStr.split(keyDescriptorSigningText).length - 1;
		assertThat(metadataStr, containsString(keyDescriptorSigningText));
		assertEquals(2, keyDescriptorSignStrCount);

		assertThat(metadataStr, containsString("<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/java-saml-jspsample/acs.jsp\" index=\"1\">"));
		assertThat(metadataStr, containsString("<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/java-saml-jspsample/sls.jsp\">")); 
		assertThat(metadataStr, containsString("<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"));
	}
	
	/**
	 * Tests the validateMetadata method of the Saml2Settings
	 * Case Valid
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#validateMetadata
	 */
	@Test
	public void testValidateMetadataValid() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		String metadataStr = settings.getSPMetadata();
		
		List<String> errors = Saml2Settings.validateMetadata(metadataStr);
		assertTrue(errors.isEmpty());
	}

	/**
	 * Tests the validateMetadata method of the Saml2Settings
	 * Case Invalid: Invalid XML
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#validateMetadata
	 */
	@Test
	public void testValidateMetadataInvalidXML() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		String metadataStr = settings.getSPMetadata();
		metadataStr = metadataStr.replace("md:EntityDescriptor", "md:EntityDescriptor2");

		List<String> errors = Saml2Settings.validateMetadata(metadataStr);
		assertFalse(errors.isEmpty());
		assertTrue(errors.contains("Invalid SAML Metadata. Not match the saml-schema-metadata-2.0.xsd"));
	}
	
	/**
	 * Tests the validateMetadata method of the Saml2Settings
	 * Case Invalid: noEntityDescriptor_xml
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#validateMetadata
	 */
	@Test
	public void testValidateMetadataNoDescriptor() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		String metadataStr = "<md:EntitiesDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" Name=\"https://your-federation.org/metadata/federation-name.xml\">" + settings.getSPMetadata() + "</md:EntitiesDescriptor>";

		List<String> errors = Saml2Settings.validateMetadata(metadataStr);
		assertFalse(errors.isEmpty());
		assertTrue(errors.contains("noEntityDescriptor_xml"));
	}

	/**
	 * Test that Unique ID prefix is read
	 *
	 * @throws Exception
	 */
	@Test
	public void testGivenUniqueIDPrefixIsUsed() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();

		assertEquals("EXAMPLE", settings.getUniqueIDPrefix());
	}

	/**
	 * Test that "_" value is ok for Unique ID prefix
	 *
	 * @throws Exception
	 */
	@Test
	public void testUniqueIDPrefixIsUsed() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min_uniqueid.properties").build();

		assertEquals("_", settings.getUniqueIDPrefix());
	}

	/**
	 * Tests that if property Unique ID prefix is unset, default value is used
	 * @throws Exception
	 */
	@Test
	public void testUniqueIDPrefixUsesDefaultWhenNotSet() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		assertEquals("ONELOGIN_", settings.getUniqueIDPrefix());
	}

	/**
	 * Tests the validateMetadata method of the Saml2Settings
	 * Case Invalid: onlySPSSODescriptor_allowed_xml
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#validateMetadata
	 */
	@Test
	public void testValidateMetadataNoSP() throws Exception {
		String metadataStr = Util.getFileAsString("data/metadata/idp_metadata.xml");

		List<String> errors = Saml2Settings.validateMetadata(metadataStr);
		assertFalse(errors.isEmpty());
		assertTrue(errors.contains("onlySPSSODescriptor_allowed_xml"));
	}

	/**
	 * Tests the validateMetadata method of the Saml2Settings
	 * Case Invalid: expired_xml
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.settings.Saml2Settings#validateMetadata
	 */
	@Test
	public void testValidateMetadataExpired() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Calendar validUntilTime = Calendar.getInstance();
		validUntilTime.add(Calendar.DAY_OF_YEAR, -2);
		
		Metadata metadataObj = new Metadata(settings, validUntilTime, null);
		String metadataStr = metadataObj.getMetadataString();
		metadataStr = metadataStr.replace("cacheDuration=\"PT604800S\"", "");

		List<String> errors = Saml2Settings.validateMetadata(metadataStr);
		assertFalse(errors.isEmpty());
		assertTrue(errors.contains("expired_xml"));
	}
}
