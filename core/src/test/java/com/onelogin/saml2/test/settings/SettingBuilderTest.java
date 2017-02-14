package com.onelogin.saml2.test.settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.model.Contact;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

/**
 * Tests the com.onelogin.saml2.settings.SettingsBuilder class
 */
public class SettingBuilderTest {

	@Rule
	public ExpectedException expectedEx = ExpectedException.none();

	/**
	 * Tests SettingsBuilder fromFile method
	 * Case: config file not found
	 *
	 * @throws IOException 
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromFile
	 */
	@Test
	public void testLoadFromFileNotExist() throws IOException, SettingsException, Error {
		expectedEx.expect(Error.class);
		expectedEx.expectMessage("properties file 'config/config.notfound.properties' not found in the classpath");
		
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.notfound.properties").build();
		assertNull(setting);
	}

	/**
	 * Tests SettingsBuilder fromFile method
	 * Case: empty config file
	 *
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws URISyntaxException 
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromFile
	 */
	@Test
	public void testLoadFromFileEmpty() throws IOException, CertificateException, URISyntaxException, SettingsException, Error {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.empty.properties").build();

		assertFalse(setting.isDebugActive());
		assertFalse(setting.isStrict());

		assertTrue(setting.getSpEntityId().isEmpty());
		assertNull(setting.getSpAssertionConsumerServiceUrl());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", setting.getSpAssertionConsumerServiceBinding());
		assertNull(setting.getSpSingleLogoutServiceUrl());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", setting.getSpSingleLogoutServiceBinding());
		assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", setting.getSpNameIDFormat());

		assertTrue(setting.getIdpEntityId().isEmpty());
		assertNull(setting.getIdpSingleSignOnServiceUrl());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", setting.getIdpSingleSignOnServiceBinding());
		assertNull(setting.getIdpSingleLogoutServiceUrl());
		assertNull(setting.getIdpSingleLogoutServiceResponseUrl());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", setting.getIdpSingleLogoutServiceBinding());
		assertNull(setting.getIdpx509cert());
		assertNull(setting.getIdpCertFingerprint());
		assertEquals("sha1", setting.getIdpCertFingerprintAlgorithm());

		assertFalse(setting.getNameIdEncrypted());
		assertFalse(setting.getAuthnRequestsSigned());
		assertFalse(setting.getLogoutRequestSigned());
		assertFalse(setting.getLogoutResponseSigned());
		assertFalse(setting.getWantMessagesSigned());
		assertFalse(setting.getWantAssertionsSigned());
		assertFalse(setting.getWantAssertionsEncrypted());
		assertFalse(setting.getWantNameIdEncrypted());
		assertTrue(setting.getRequestedAuthnContext().isEmpty());
		assertEquals("exact", setting.getRequestedAuthnContextComparison());
		assertTrue(setting.getWantXMLValidation());
		assertEquals(Constants.RSA_SHA1, setting.getSignatureAlgorithm());
		assertFalse(setting.getSignMetadata());

		assertNull(setting.getOrganization());
		assertTrue(setting.getContacts().isEmpty());
	}

	/**
	 * Tests SettingsBuilder fromFile method
	 * Case: minimum settings config file
	 *
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws URISyntaxException 
	 * @throws SettingsException 
	 * @throws Error 
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromFile
	 */
	@Test
	public void testLoadFromFileMinProp() throws IOException, CertificateException, URISyntaxException, SettingsException, Error {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.min.properties").build();

		assertFalse(setting.isDebugActive());
		assertFalse(setting.isStrict());

		assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp", setting.getSpEntityId());
		assertEquals("http://localhost:8080/java-saml-jspsample/acs.jsp", setting.getSpAssertionConsumerServiceUrl().toString());
		assertEquals(setting.getSpAssertionConsumerServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		assertEquals("http://localhost:8080/java-saml-jspsample/sls.jsp", setting.getSpSingleLogoutServiceUrl().toString());
		assertEquals(setting.getSpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals(setting.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

		assertEquals("http://idp.example.com/", setting.getIdpEntityId());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting.getIdpSingleSignOnServiceUrl().toString());
		assertEquals(setting.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceUrl().toString());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceResponseUrl().toString());
		assertEquals(setting.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertNotNull(setting.getIdpx509cert());
		assertEquals(Util.loadCert(Util.getFileAsString("certs/certificate1")), setting.getIdpx509cert());
		assertNull(setting.getIdpCertFingerprint());
		assertEquals("sha1", setting.getIdpCertFingerprintAlgorithm());

		assertFalse(setting.getNameIdEncrypted());
		assertFalse(setting.getAuthnRequestsSigned());
		assertFalse(setting.getLogoutRequestSigned());
		assertFalse(setting.getLogoutResponseSigned());
		assertFalse(setting.getWantMessagesSigned());
		assertFalse(setting.getWantAssertionsSigned());
		assertFalse(setting.getWantAssertionsEncrypted());
		assertFalse(setting.getWantNameIdEncrypted());
		assertTrue(setting.getRequestedAuthnContext().isEmpty());
		assertEquals("exact", setting.getRequestedAuthnContextComparison());
		assertTrue(setting.getWantXMLValidation());
		assertEquals(Constants.RSA_SHA1, setting.getSignatureAlgorithm());
		assertFalse(setting.getSignMetadata());

		assertNull(setting.getOrganization());
		assertTrue(setting.getContacts().isEmpty());
	}

	/**
	 * Tests SettingsBuilder fromFile method
	 * Case: all settings config file
	 *
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws URISyntaxException 
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromFile
	 */
	@Test
	public void testLoadFromFileAllProp() throws IOException, CertificateException, URISyntaxException, SettingsException, Error {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.all.properties").build();

		assertTrue(setting.isDebugActive());
		assertTrue(setting.isStrict());

		assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp", setting.getSpEntityId());
		assertEquals("http://localhost:8080/java-saml-jspsample/acs.jsp", setting.getSpAssertionConsumerServiceUrl().toString());
		assertEquals(setting.getSpAssertionConsumerServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		assertEquals("http://localhost:8080/java-saml-jspsample/sls.jsp", setting.getSpSingleLogoutServiceUrl().toString());
		assertEquals(setting.getSpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals(setting.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

		assertEquals("http://idp.example.com/", setting.getIdpEntityId());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting.getIdpSingleSignOnServiceUrl().toString());
		assertEquals(setting.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceUrl().toString());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutServiceResponse.php", setting.getIdpSingleLogoutServiceResponseUrl().toString());
		assertEquals(setting.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertNotNull(setting.getIdpx509cert());
		assertEquals(Util.loadCert(Util.getFileAsString("certs/certificate1")), setting.getIdpx509cert());
		assertEquals("4b6f70bb2cab82c86a8270f71a880b62e25bc2b3", setting.getIdpCertFingerprint());
		assertEquals("sha1", setting.getIdpCertFingerprintAlgorithm());

		assertTrue(setting.getNameIdEncrypted());
		assertTrue(setting.getAuthnRequestsSigned());
		assertTrue(setting.getLogoutRequestSigned());
		assertTrue(setting.getLogoutResponseSigned());
		assertTrue(setting.getWantMessagesSigned());
		assertTrue(setting.getWantAssertionsSigned());
		assertTrue(setting.getWantAssertionsEncrypted());
		assertTrue(setting.getWantNameIdEncrypted());

		List<String> reqAuthContext = new ArrayList<String>();
		reqAuthContext.add("urn:oasis:names:tc:SAML:2.0:ac:classes:urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
		assertEquals(reqAuthContext, setting.getRequestedAuthnContext());
		assertEquals("exact", setting.getRequestedAuthnContextComparison());
		assertTrue(setting.getWantXMLValidation());
		assertEquals(Constants.RSA_SHA512, setting.getSignatureAlgorithm());
		assertTrue(setting.getSignMetadata());

		Organization org = new Organization("SP Java", "SP Java Example", "http://sp.example.com");
		assertTrue(org.equalsTo(setting.getOrganization()));

		List<Contact> contacts = setting.getContacts();
		assertEquals(2, contacts.size());
		Contact c1 = contacts.get(0);
		assertEquals("technical", c1.getContactType());
		assertEquals("technical@example.com", c1.getEmailAddress());
		assertEquals("Technical Guy", c1.getGivenName());
		Contact c2 = contacts.get(1);
		assertEquals("support", c2.getContactType());
		assertEquals("support@example.com", c2.getEmailAddress());
		assertEquals("Support Guy", c2.getGivenName());
	}

	/**
	 * Tests SettingsBuilder fromFile method
	 * Case: settings config file with certificate string
	 *
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws URISyntaxException 
	 * @throws SettingsException 
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromFile
	 */
	@Test
	public void testLoadFromFileCertString() throws IOException, CertificateException, URISyntaxException, SettingsException, Error {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.certstring.properties").build();

		assertFalse(setting.isDebugActive());
		assertFalse(setting.isStrict());

		assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp", setting.getSpEntityId());
		assertEquals("http://localhost:8080/java-saml-jspsample/acs.jsp", setting.getSpAssertionConsumerServiceUrl().toString());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", setting.getSpAssertionConsumerServiceBinding());
		assertEquals("http://localhost:8080/java-saml-jspsample/sls.jsp", setting.getSpSingleLogoutServiceUrl().toString());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", setting.getSpSingleLogoutServiceBinding());
		assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", setting.getSpNameIDFormat());

		assertEquals("http://idp.example.com/", setting.getIdpEntityId());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting.getIdpSingleSignOnServiceUrl().toString());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", setting.getIdpSingleSignOnServiceBinding());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceUrl().toString());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceResponseUrl().toString());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", setting.getIdpSingleLogoutServiceBinding());
		assertEquals(Util.loadCert(Util.getFileAsString("certs/certificate1")), setting.getIdpx509cert());

		assertFalse(setting.getNameIdEncrypted());
		assertFalse(setting.getAuthnRequestsSigned());
		assertFalse(setting.getLogoutRequestSigned());
		assertFalse(setting.getLogoutResponseSigned());
		assertFalse(setting.getWantMessagesSigned());
		assertFalse(setting.getWantAssertionsSigned());
		assertFalse(setting.getWantAssertionsEncrypted());
		assertFalse(setting.getWantNameIdEncrypted());
		assertTrue(setting.getRequestedAuthnContext().isEmpty());
		assertEquals("exact", setting.getRequestedAuthnContextComparison());
		assertTrue(setting.getWantXMLValidation());
		assertEquals(Constants.RSA_SHA1, setting.getSignatureAlgorithm());
		assertFalse(setting.getSignMetadata());

		Organization org = new Organization("SP Java", "SP Java Example", "http://sp.example.com");
		assertTrue(org.equalsTo(setting.getOrganization()));
		
		assertTrue(setting.getContacts().isEmpty());
	}

	/**
	 * Tests SettingsBuilder fromFile method
	 * Case: settings config file with invalid contact info (not all required fields)
	 *
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws URISyntaxException 
	 * @throws SettingsException 
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromFile
	 */
	@Test
	public void testLoadFromFileContactString() throws IOException, CertificateException, URISyntaxException, SettingsException, Error {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.invalidcontacts.properties").build();

		assertFalse(setting.isDebugActive());
		assertFalse(setting.isStrict());

		assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp", setting.getSpEntityId());
		assertEquals("http://localhost:8080/java-saml-jspsample/acs.jsp", setting.getSpAssertionConsumerServiceUrl().toString());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", setting.getSpAssertionConsumerServiceBinding());
		assertEquals("http://localhost:8080/java-saml-jspsample/sls.jsp", setting.getSpSingleLogoutServiceUrl().toString());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", setting.getSpSingleLogoutServiceBinding());
		assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", setting.getSpNameIDFormat());

		assertEquals("http://idp.example.com/", setting.getIdpEntityId());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting.getIdpSingleSignOnServiceUrl().toString());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", setting.getIdpSingleSignOnServiceBinding());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceUrl().toString());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceResponseUrl().toString());
		assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", setting.getIdpSingleLogoutServiceBinding());
		assertEquals(Util.loadCert(Util.getFileAsString("certs/certificate1")), setting.getIdpx509cert());

		assertFalse(setting.getNameIdEncrypted());
		assertFalse(setting.getAuthnRequestsSigned());
		assertFalse(setting.getLogoutRequestSigned());
		assertFalse(setting.getLogoutResponseSigned());
		assertFalse(setting.getWantMessagesSigned());
		assertFalse(setting.getWantAssertionsSigned());
		assertFalse(setting.getWantAssertionsEncrypted());
		assertFalse(setting.getWantNameIdEncrypted());
		assertTrue(setting.getRequestedAuthnContext().isEmpty());
		assertEquals("exact", setting.getRequestedAuthnContextComparison());
		assertTrue(setting.getWantXMLValidation());
		assertEquals(Constants.RSA_SHA1, setting.getSignatureAlgorithm());
		assertFalse(setting.getSignMetadata());

		Organization org = new Organization("SP Java", "SP Java Example", "http://sp.example.com");
		assertTrue(org.equalsTo(setting.getOrganization()));

		List<Contact> contacts = setting.getContacts();
		assertEquals(2, contacts.size());
		Contact c1 = contacts.get(0);
		assertEquals("technical", c1.getContactType());
		assertTrue(c1.getGivenName().isEmpty());
		assertEquals("technical@example.com", c1.getEmailAddress());
		Contact c2 = contacts.get(1);
		assertEquals("support", c2.getContactType());
		assertEquals("Support Guy", c2.getGivenName());
		assertTrue(c2.getEmailAddress().isEmpty());
	}
	
	/**
	 * Tests SettingsBuilder fromFile method
	 * Case: settings config file with invalids SP cert/private key
	 *
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws URISyntaxException 
	 * @throws SettingsException 
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromFile
	 */
	@Test
	public void testLoadFromFileInvalidSPCerts() throws IOException, CertificateException, URISyntaxException, SettingsException, Error {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.invalidspcertstring.properties").build();
		
		assertNull(setting.getSPkey());
		assertNull(setting.getSPcert());
	}

	/**
	 * Tests SettingsBuilder fromFile method
	 * Case: Compress
	 *
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws URISyntaxException 
	 * @throws SettingsException 
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromFile
	 */
	@Test
	public void testCompression() throws IOException, CertificateException, URISyntaxException, SettingsException, Error {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.min.properties").build();

		assertTrue(setting.isCompressRequestEnabled());
		assertTrue(setting.isCompressResponseEnabled());

		setting = new SettingsBuilder().fromFile("config/config.compress.properties").build();
		assertTrue(setting.isCompressRequestEnabled());
		assertTrue(setting.isCompressResponseEnabled());

		setting = new SettingsBuilder().fromFile("config/config.nocompress.properties").build();
		assertFalse(setting.isCompressRequestEnabled());
		assertFalse(setting.isCompressResponseEnabled());
	}
	
	/**
	 * Tests SettingsBuilder fromFile method
	 * Case: settings config file with some empty values
	 *
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws URISyntaxException 
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromFile
	 */
	@Test
	public void testLoadFromFileSomeEmptyProp() throws IOException, CertificateException, URISyntaxException, Error {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.somevaluesempty.properties").build();

		assertTrue(setting.isDebugActive());
		assertTrue(setting.isStrict());

		assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp", setting.getSpEntityId());
		assertEquals("http://localhost:8080/java-saml-jspsample/acs.jsp", setting.getSpAssertionConsumerServiceUrl().toString());
		assertEquals(setting.getSpAssertionConsumerServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		assertEquals("http://localhost:8080/java-saml-jspsample/sls.jsp", setting.getSpSingleLogoutServiceUrl().toString());
		assertEquals(setting.getSpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals(setting.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

		assertEquals("http://idp.example.com/", setting.getIdpEntityId());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting.getIdpSingleSignOnServiceUrl().toString());
		assertEquals(setting.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceUrl().toString());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceResponseUrl().toString());
		assertEquals(setting.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertNull(setting.getIdpx509cert());
		assertEquals("4b6f70bb2cab82c86a8270f71a880b62e25bc2b3", setting.getIdpCertFingerprint());
		assertEquals("sha1", setting.getIdpCertFingerprintAlgorithm());

		assertTrue(setting.getNameIdEncrypted());
		assertTrue(setting.getAuthnRequestsSigned());
		assertTrue(setting.getLogoutRequestSigned());
		assertTrue(setting.getLogoutResponseSigned());
		assertTrue(setting.getWantMessagesSigned());
		assertTrue(setting.getWantAssertionsSigned());
		assertTrue(setting.getWantAssertionsEncrypted());
		assertTrue(setting.getWantNameIdEncrypted());
		assertTrue(setting.getRequestedAuthnContext().isEmpty());
		assertEquals("exact", setting.getRequestedAuthnContextComparison());
		assertTrue(setting.getWantXMLValidation());
		assertEquals(Constants.RSA_SHA1, setting.getSignatureAlgorithm());
		assertTrue(setting.getSignMetadata());

		assertNull(setting.getOrganization());
		assertTrue(setting.getContacts().isEmpty());
	}

	/**
	 * Tests SettingsBuilder fromFile method
	 * Case: settings config file with different values
	 *
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws URISyntaxException 
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromFile
	 */
	@Test
	public void testLoadFromFileDifferentProp() throws IOException, CertificateException, URISyntaxException, Error {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.different.properties").build();

		assertTrue(setting.isDebugActive());
		assertTrue(setting.isStrict());

		assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp", setting.getSpEntityId());
		assertEquals("http://localhost:8080/java-saml-jspsample/acs.jsp", setting.getSpAssertionConsumerServiceUrl().toString());
		assertEquals(setting.getSpAssertionConsumerServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		assertEquals("http://localhost:8080/java-saml-jspsample/sls.jsp", setting.getSpSingleLogoutServiceUrl().toString());
		assertEquals(setting.getSpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals(setting.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

		assertEquals("http://idp.example.com/", setting.getIdpEntityId());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting.getIdpSingleSignOnServiceUrl().toString());
		assertEquals(setting.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertNull(setting.getIdpSingleLogoutServiceUrl());
		assertNull(setting.getIdpSingleLogoutServiceResponseUrl());
		assertEquals(setting.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertNull(setting.getIdpx509cert());
		assertEquals("00d84fd17802a1f1edd9a03447ca1d3a6c2101a610a164ab898b880d01c44190", setting.getIdpCertFingerprint());
		assertEquals("sha256", setting.getIdpCertFingerprintAlgorithm());

		assertTrue(setting.getNameIdEncrypted());
		assertTrue(setting.getAuthnRequestsSigned());
		assertTrue(setting.getLogoutRequestSigned());
		assertTrue(setting.getLogoutResponseSigned());
		assertTrue(setting.getWantMessagesSigned());
		assertTrue(setting.getWantAssertionsSigned());
		assertTrue(setting.getWantAssertionsEncrypted());
		assertTrue(setting.getWantNameIdEncrypted());
		List<String> reqAuthContext = new ArrayList<String>();
		reqAuthContext.add("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
		reqAuthContext.add("urn:oasis:names:tc:SAML:2.0:ac:classes:urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
		assertEquals(reqAuthContext, setting.getRequestedAuthnContext());
		assertEquals("minimum", setting.getRequestedAuthnContextComparison());
		assertTrue(setting.getWantXMLValidation());
		assertEquals(Constants.RSA_SHA512, setting.getSignatureAlgorithm());
		assertTrue(setting.getSignMetadata());

		Organization org = new Organization("SP Java", "", "");
		assertTrue(org.equalsTo(setting.getOrganization()));

		List<Contact> contacts = setting.getContacts();
		assertEquals(2, contacts.size());
		Contact c1 = contacts.get(0);
		assertEquals("technical", c1.getContactType());
		assertTrue(c1.getEmailAddress().isEmpty());
		assertEquals("Technical Guy", c1.getGivenName());
		Contact c2 = contacts.get(1);
		assertEquals("support", c2.getContactType());
		assertEquals("support@example.com", c2.getEmailAddress());
		assertTrue(c2.getGivenName().isEmpty());
	}

	/**
	 * Tests SettingsBuilder fromProperties method
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws CertificateException
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder#fromProperties
	 */
	@Test
	public void testFromProperties() throws IOException, Error, CertificateException {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Base64 encoder = new Base64(64);
		String x509cert = new String(encoder.encode(setting.getIdpx509cert().getEncoded()));
		
		Properties prop = new Properties();
		prop.setProperty(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY, setting.getIdpEntityId());
		prop.setProperty(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY, setting.getIdpSingleSignOnServiceUrl().toString());
		prop.setProperty(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, setting.getIdpSingleLogoutServiceUrl().toString());
		prop.setProperty(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY , x509cert);
		prop.setProperty(SettingsBuilder.SP_ENTITYID_PROPERTY_KEY, setting.getSpEntityId());
		prop.setProperty(SettingsBuilder.SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY, setting.getSpAssertionConsumerServiceUrl().toString());
		prop.setProperty(SettingsBuilder.SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, setting.getSpSingleLogoutServiceUrl().toString());
		
		Saml2Settings setting2 = new SettingsBuilder().fromProperties(prop).build();

		assertFalse(setting2.isDebugActive());
		assertFalse(setting2.isStrict());

		assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp", setting2.getSpEntityId());
		assertEquals("http://localhost:8080/java-saml-jspsample/acs.jsp", setting2.getSpAssertionConsumerServiceUrl().toString());
		assertEquals(setting2.getSpAssertionConsumerServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		assertEquals("http://localhost:8080/java-saml-jspsample/sls.jsp", setting2.getSpSingleLogoutServiceUrl().toString());
		assertEquals(setting2.getSpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals(setting2.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

		assertEquals("http://idp.example.com/", setting2.getIdpEntityId());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting2.getIdpSingleSignOnServiceUrl().toString());
		assertEquals(setting2.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting2.getIdpSingleLogoutServiceUrl().toString());
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting2.getIdpSingleLogoutServiceResponseUrl().toString());
		assertEquals(setting2.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertNotNull(setting2.getIdpx509cert());
		assertEquals(Util.loadCert(Util.getFileAsString("certs/certificate1")), setting2.getIdpx509cert());
		assertNull(setting2.getIdpCertFingerprint());
		assertEquals("sha1", setting2.getIdpCertFingerprintAlgorithm());

		assertFalse(setting2.getNameIdEncrypted());
		assertFalse(setting2.getAuthnRequestsSigned());
		assertFalse(setting2.getLogoutRequestSigned());
		assertFalse(setting2.getLogoutResponseSigned());
		assertFalse(setting2.getWantMessagesSigned());
		assertFalse(setting2.getWantAssertionsSigned());
		assertFalse(setting2.getWantAssertionsEncrypted());
		assertFalse(setting2.getWantNameIdEncrypted());
		assertTrue(setting2.getRequestedAuthnContext().isEmpty());
		assertEquals("exact", setting2.getRequestedAuthnContextComparison());
		assertTrue(setting2.getWantXMLValidation());
		assertEquals(Constants.RSA_SHA1, setting2.getSignatureAlgorithm());
		assertFalse(setting2.getSignMetadata());

		assertNull(setting2.getOrganization());
		assertTrue(setting2.getContacts().isEmpty());
	}
	
	/**
	 * Tests SettingsBuilder constructor
	 * Case: settings config file with certificate loaded from file
	 *
	 * @throws IOException
	 *
	 * @see com.onelogin.saml2.settings.SettingsBuilder
	 */
	/*
	@Test
	public void testLoadFromFileCertFile() throws IOException {
		new SettingsBuilder().fromFile("config/config.certfile.properties").build();
	}
	*/
}

