package com.onelogin.saml2.test;


import static java.util.Collections.singletonMap;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.matches;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.w3c.dom.Document;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.authn.AuthnRequestParams;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.factory.SamlMessageFactory;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.logout.LogoutRequest;
import com.onelogin.saml2.logout.LogoutRequestParams;
import com.onelogin.saml2.logout.LogoutResponse;
import com.onelogin.saml2.logout.LogoutResponseParams;
import com.onelogin.saml2.model.KeyStoreSettings;
import com.onelogin.saml2.model.SamlResponseStatus;
import com.onelogin.saml2.servlet.ServletUtils;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

public class AuthTest {

	@Rule
	public ExpectedException expectedEx = ExpectedException.none();

	private String getSAMLRequestFromURL(String url) throws URISyntaxException, UnsupportedEncodingException {
		String xml = "";
		URI uri = new URI(url);
		String query = uri.getQuery();
		String[] pairs = query.split("&");
		for (String pair : pairs) {
	        int idx = pair.indexOf("=");
	        if (pair.substring(0, idx).equals("SAMLRequest")) {
	        	xml = Util.base64decodedInflated(pair.substring(idx + 1));
	        }
	    }
		return xml;
	}

	/**
	 * Returns KeyStore details from src/test/resources for testing
	 * 
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private KeyStoreSettings getKeyStoreSettings() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		String storePassword = "changeit";
		String keyStoreFile = "src/test/resources/keystore/oneloginTestKeystore.jks";
		String alias = "keywithpassword";
		String keyPassword = "keypassword";

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream(keyStoreFile), storePassword.toCharArray());
		return new KeyStoreSettings(ks, alias, keyPassword);
	}

	/**
	 * Tests the constructor of Auth
	 * Case: No parameters
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructor() throws IOException, SettingsException, Error {
		Auth auth = new Auth();
		assertTrue(auth.getSettings() != null);

		Saml2Settings settings = new SettingsBuilder().fromFile("onelogin.saml.properties").build();
		assertEquals(settings.getIdpEntityId(), auth.getSettings().getIdpEntityId());
		assertEquals(settings.getSpEntityId(), auth.getSettings().getSpEntityId());
		assertNull(auth.getLastRequestId());
	}

	/**
	 * Tests the constructor of Auth
	 * Case: filename path provided
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructorWithFilename() throws IOException, SettingsException, Error {
		Auth auth = new Auth("config/config.min.properties");
		assertTrue(auth.getSettings() != null);

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		assertEquals(settings.getIdpEntityId(), auth.getSettings().getIdpEntityId());
		assertEquals(settings.getSpEntityId(), auth.getSettings().getSpEntityId());
	}
	
	/**
     * Tests the constructor of Auth
     * Case: filename and KeyStore
     *
     * @throws SettingsException
     * @throws IOException
     * @throws Error
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     *
     * @see com.onelogin.saml2.Auth
     */
	@Test
	public void testConstructorWithFilenameAndKeyStore() throws IOException, SettingsException, Error, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        
		Auth auth = new Auth("config/config.min.properties", getKeyStoreSettings());
		assertTrue(auth.getSettings() != null);
		assertTrue(auth.getSettings().getSPcert() != null);
		assertTrue(auth.getSettings().getSPkey() != null);
		
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties", getKeyStoreSettings()).build();
		assertEquals(settings.getSPcert(), auth.getSettings().getSPcert());
		assertEquals(settings.getSPkey(), auth.getSettings().getSPkey());
	}

	/**
	 * Tests the constructor of Auth
	 * Case: HttpServletRequest and HttpServletResponse provided
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructorWithReqRes() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Auth auth = new Auth(request, response);
		assertTrue(auth.getSettings() != null);

		Saml2Settings settings = new SettingsBuilder().fromFile("onelogin.saml.properties").build();
		assertEquals(settings.getIdpEntityId(), auth.getSettings().getIdpEntityId());
		assertEquals(settings.getSpEntityId(), auth.getSettings().getSpEntityId());
	}
	
	/**
	 * Tests the constructor of Auth
	 * Case: KeyStore and HttpServletRequest and HttpServletResponse provided
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 * @throws KeyStoreException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructorWithReqResAndKeyStore() throws IOException, SettingsException, URISyntaxException, Error, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);

		Auth auth = new Auth(getKeyStoreSettings(), request, response);
		assertTrue(auth.getSettings() != null);
		assertTrue(auth.getSettings().getSPcert() != null);
		assertTrue(auth.getSettings().getSPkey() != null);

		Saml2Settings settings = new SettingsBuilder().fromFile("onelogin.saml.properties", getKeyStoreSettings()).build();
		assertEquals(settings.getSPkey(), auth.getSettings().getSPkey());
		assertEquals(settings.getSPcert(), auth.getSettings().getSPcert());
	}
	
	/**
	 * Tests the constructor of Auth
	 * Case: filename, HttpServletRequest and HttpServletResponse provided
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructorWithFilenameReqRes() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Auth auth = new Auth("config/config.min.properties", request, response);
		assertTrue(auth.getSettings() != null);

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		assertEquals(settings.getIdpEntityId(), auth.getSettings().getIdpEntityId());
		assertEquals(settings.getSpEntityId(), auth.getSettings().getSpEntityId());
	}

	/**
	 * Tests the constructor of Auth
	 * Case: settings, HttpServletRequest and HttpServletResponse provided
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructorWithSettingsReqRes() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertEquals(settings.getIdpEntityId(), auth.getSettings().getIdpEntityId());
		assertEquals(settings.getSpEntityId(), auth.getSettings().getSpEntityId());
	}

	/**
	 * Tests the constructor of Auth
	 * Case: settings, HttpServletRequest and HttpServletResponse provided
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructorInvalidSettings() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.sperrors.properties").build();
		
		expectedEx.expect(SettingsException.class);
		expectedEx.expectMessage("Invalid settings: sp_entityId_not_found, sp_acs_not_found, sp_cert_not_found_and_required, contact_not_enough_data, contact_type_invalid, organization_not_enough_data, idp_cert_or_fingerprint_not_found_and_required, idp_cert_not_found_and_required");
		new Auth(settings, request, response);
	}

	/**
	 * Tests the getSettings method of Auth
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#getSettings
	 */
	@Test
	public void testGetSettings() throws IOException, SettingsException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("onelogin.saml.properties").build();
		Auth auth = new Auth();
		assertEquals(settings.getIdpEntityId(), auth.getSettings().getIdpEntityId());
		assertEquals(settings.getSpEntityId(), auth.getSettings().getSpEntityId());
		assertEquals(settings.getIdpCertFingerprint(), auth.getSettings().getIdpCertFingerprint());
		assertEquals(settings.getIdpCertFingerprintAlgorithm(), auth.getSettings().getIdpCertFingerprintAlgorithm());
		assertEquals(settings.getContacts().toString(), auth.getSettings().getContacts().toString());
		assertEquals(settings.getOrganization(), auth.getSettings().getOrganization());
		assertEquals(settings.getIdpSingleSignOnServiceUrl().toString(), auth.getSettings().getIdpSingleSignOnServiceUrl().toString());
		assertEquals(settings.getIdpSingleLogoutServiceUrl().toString(), auth.getSettings().getIdpSingleLogoutServiceUrl().toString());
		assertEquals(settings.getIdpSingleLogoutServiceResponseUrl().toString(), auth.getSettings().getIdpSingleLogoutServiceResponseUrl().toString());
		assertEquals(settings.getIdpx509cert().hashCode(), auth.getSettings().getIdpx509cert().hashCode());
		assertEquals(settings.getSpAssertionConsumerServiceUrl().toString(), auth.getSettings().getSpAssertionConsumerServiceUrl().toString());
		assertEquals(settings.getSpSingleLogoutServiceUrl().toString(), auth.getSettings().getSpSingleLogoutServiceUrl().toString());
	}

	/**
	 * Tests the setStrict method of Auth
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#setStrict
	 */
	@Test
	public void testSetStrict() throws IOException, SettingsException, URISyntaxException, Error {
		Auth auth = new Auth();

		auth.setStrict(false);
		assertFalse(auth.getSettings().isStrict());

		auth.setStrict(true);
		assertTrue(auth.getSettings().isStrict());
	}

	/**
	 * Tests the isDebugActive method of Auth
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#isDebugActive
	 */
	@Test
	public void testIsDebugActive() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpServletRequest request = mock(HttpServletRequest.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setDebug(false);

		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isDebugActive());

		settings.setDebug(true);
		auth = new Auth(settings, request, response);
		assertTrue(auth.isDebugActive());
	}

	/**
	 * Tests the getSSOurl method of Auth
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#getSSOurl
	 */
	@Test
	public void testGetSSOurl() throws URISyntaxException, IOException, SettingsException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Auth auth = new Auth(settings, request, response);
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", auth.getSSOurl());
	}

	/**
	 * Tests the getSLOurl method of Auth
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#getSLOurl
	 */
	@Test
	public void testGetSLOurl() throws URISyntaxException, IOException, SettingsException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Auth auth = new Auth(settings, request, response);
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", auth.getSLOurl());
	}


	/**
	 * Tests the getSLOResponseUrl method of Auth
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#getSLOResponseUrl
	 */
	@Test
	public void testGetSLOResponseUrl() throws URISyntaxException, IOException, SettingsException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();

		Auth auth = new Auth(settings, request, response);
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutServiceResponse.php", auth.getSLOResponseUrl());
	}

	/**
	 * Tests the getSLOResponseUrl method of Auth. Verifies a null value will return the same output as getSLOurl()
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#getSLOResponseUrl
	 */
	@Test
	public void testGetSLOResponseUrlNull() throws URISyntaxException, IOException, SettingsException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Auth auth = new Auth(settings, request, response);
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", auth.getSLOResponseUrl());
	}

	/**
	 * Tests the processResponse method of Auth
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processResponse
	 */
	@Test
	public void testProcessNoResponse() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		try {
			auth.processResponse();
		} catch (Error e) {
			assertEquals("SAML Response not found, Only supported HTTP_POST Binding", e.getMessage());
		}
		assertFalse(auth.isAuthenticated());
		assertFalse(auth.getErrors().isEmpty());
		List<String> expectedErrors = new ArrayList<String>();
		expectedErrors.add("invalid_binding");
		assertEquals(expectedErrors, auth.getErrors());
	}

	/**
	 * Tests the processResponse and getAttributes methods of Auth
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processResponse
	 * @see com.onelogin.saml2.Auth#getAttributes
	 * @see com.onelogin.saml2.Auth#getAttribute
	 * @see com.onelogin.saml2.Auth#getAttributesName
	 */
	@Test
	public void testProcessResponse() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processResponse();
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getAttributes().isEmpty());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth2 = new Auth(settings, request, response);

		HashMap<String, List<String>> expectedAttributes = new LinkedHashMap<String, List<String>>();
		List<String> attrValues = new ArrayList<String>();
		attrValues.add("smartin");
		List<String> attrValues2 = new ArrayList<String>();
		attrValues2.add("smartin@yaco.es");
		List<String> attrValues3 = new ArrayList<String>();
		attrValues3.add("user");
		attrValues3.add("admin");
		List<String> attrValues4 = new ArrayList<String>();
		attrValues4.add("Sixto3");
		List<String> attrValues5 = new ArrayList<String>();
		attrValues5.add("Martin2");
		expectedAttributes.put("uid", attrValues);
		expectedAttributes.put("mail", attrValues2);
		expectedAttributes.put("cn", attrValues4);
		expectedAttributes.put("sn", attrValues5);
		expectedAttributes.put("eduPersonAffiliation", attrValues3);
		List<String> keys = new ArrayList<String>(expectedAttributes.keySet());

		assertFalse(auth2.isAuthenticated());
		assertTrue(auth2.getErrors().isEmpty());
		auth2.processResponse();
		assertTrue(auth2.isAuthenticated());
		assertFalse(auth2.getAttributes().isEmpty());
		assertEquals(expectedAttributes, auth2.getAttributes());
		assertEquals(attrValues, auth2.getAttribute("uid"));
		assertEquals(attrValues2, auth2.getAttribute("mail"));
		assertEquals(attrValues3, auth2.getAttribute("eduPersonAffiliation"));
		assertEquals(keys, auth2.getAttributesName());
	}

	/**
	 * Tests the processResponse methods of Auth
	 * Case: process Response, status code Responder and sub status
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessResponseStatusResponder() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("https://example.com/opensso/Consumer/metaAlias/sp"));
		when(request.getSession()).thenReturn(session);

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/status_code_and_sub_status_code_responder_and_msg.xml.base64");
		Document samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processResponse();
		verify(session, times(0)).invalidate();
		assertFalse(auth.getErrors().isEmpty());
		assertEquals("The status code of the Response was not Success, was urn:oasis:names:tc:SAML:2.0:status:Responder -> something_is_wrong", auth.getLastErrorReason());
		assertTrue(auth.getErrors().contains("response_not_success"));
		assertTrue(auth.getErrors().contains(Constants.STATUS_RESPONDER));
		assertTrue(auth.getErrors().contains(Constants.STATUS_AUTHNFAILED));
	}

	/**
	 * Tests the processSLO methods of Auth
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLONoMessage() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		try {
			auth.processSLO();
		} catch (Error e) {
			assertEquals("SAML LogoutRequest/LogoutResponse not found. Only supported HTTP_REDIRECT Binding", e.getMessage());
		}
		assertFalse(auth.isAuthenticated());
		assertFalse(auth.getErrors().isEmpty());
		List<String> expectedErrors = new ArrayList<String>();
		expectedErrors.add("invalid_binding");
		assertEquals(expectedErrors, auth.getErrors());
	}

	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutRequest, keep session
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLORequestKeepSession() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLRequest", new String[]{samlRequestEncoded}));
		
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO(true, null);
		verify(response).sendRedirect(matches("http:\\/\\/idp.example.com\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SAMLResponse=(.)*"));
		verify(session, times(0)).invalidate();
		assertTrue(auth.getErrors().isEmpty());
	}

	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutRequest, remove session
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLORequestRemoveSession() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLRequest", new String[]{samlRequestEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO();
		verify(response).sendRedirect(matches("http:\\/\\/idp.example.com\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SAMLResponse=(.)*"));
		verify(session, times(1)).invalidate();
		assertTrue(auth.getErrors().isEmpty());
	}

	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutRequest, remove session, no stay
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLORequestStay() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLRequest", new String[]{samlRequestEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO(false, null);
		verify(response).sendRedirect(matches("http:\\/\\/idp.example.com\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SAMLResponse=(.)*"));
		verify(session, times(1)).invalidate();
		assertTrue(auth.getErrors().isEmpty());
	}

	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutRequest, remove session, stay = false
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLORequestStayFalse() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLRequest", new String[]{samlRequestEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		String target = auth.processSLO(false, null, false);
		verify(response).sendRedirect(matches("http:\\/\\/idp.example.com\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SAMLResponse=(.)*"));
		verify(response, times(1)).sendRedirect(matches("http:\\/\\/idp.example.com\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SAMLResponse=(.)*"));
		verify(session, times(1)).invalidate();
		assertTrue(auth.getErrors().isEmpty());
		assertThat(target, startsWith("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php?SAMLResponse="));
	}

	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutRequest, remove session, stay = true
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLORequestStayTrue() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLRequest", new String[]{samlRequestEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		String target = auth.processSLO(false, null, true);
		verify(response, times(0)).sendRedirect(matches("http:\\/\\/idp.example.com\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SAMLResponse=(.)*"));
		verify(session, times(1)).invalidate();
		assertTrue(auth.getErrors().isEmpty());
		assertThat(target, startsWith("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php?SAMLResponse="));
	}

	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutRequest, with RelayState and sign response
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLORequestSignRes() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);
		String relayState = "http://localhost:8080/expected.jsp";
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		Map<String, String[]> paramsAsArray = new HashMap<>();
		paramsAsArray.put("SAMLRequest", new String[]{samlRequestEncoded});
		paramsAsArray.put("RelayState", new String[]{relayState});
		when(request.getParameterMap()).thenReturn(paramsAsArray);
		when(request.getParameter("RelayState")).thenReturn(relayState);
		
		
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		settings.setWantMessagesSigned(false);
		settings.setLogoutResponseSigned(true);
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO();
		verify(response).sendRedirect(matches("http:\\/\\/idp.example.com\\/simplesaml\\/saml2\\/idp\\/SingleLogoutServiceResponse.php\\?SAMLResponse=(.)*&RelayState=http%3A%2F%2Flocalhost%3A8080%2Fexpected.jsp&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha512&Signature=(.)*"));
		verify(session, times(1)).invalidate();
		assertTrue(auth.getErrors().isEmpty());
	}
	
	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutRequest invalid 
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLORequestInvalid() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/sls.jsp"));
		when(request.getSession()).thenReturn(session);

		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLRequest", new String[]{samlRequestEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(true);
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO();		
		verify(session, times(0)).invalidate();
		assertFalse(auth.getErrors().isEmpty());
		assertTrue(auth.getErrors().contains("invalid_logout_request"));
		assertThat(auth.getLastErrorReason(), containsString("The LogoutRequest was received at"));
		assertTrue(auth.getLastValidationException() instanceof ValidationError);
	}

	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutResponse, keep session
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLOResponseKeepSession() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO(true, null);
		verify(session, times(0)).invalidate();
		assertTrue(auth.getErrors().isEmpty());
	}

	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutResponse, remove session
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLOResponseRemoveSession() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO();
		verify(session, times(1)).invalidate();
		assertTrue(auth.getErrors().isEmpty());
	}

	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutResponse, status code Responder
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLOResponseWrongRequestId() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(true);
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO(false, "wrong_request_id");
		verify(session, times(0)).invalidate();
		assertTrue(auth.getErrors().contains("invalid_logout_response"));
		assertEquals("The InResponseTo of the Logout Response: ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e, does not match the ID of the Logout request sent by the SP: wrong_request_id", auth.getLastErrorReason());
	}

	/**
	 * Tests the processSLO methods of Auth
	 * Case: process LogoutResponse, status code Responder
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#processSLO
	 */
	@Test
	public void testProcessSLOResponseStatusResponder() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/invalids/status_code_responder.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO();
		verify(session, times(0)).invalidate();
		assertFalse(auth.getErrors().isEmpty());
		assertTrue(auth.getErrors().contains("logout_not_success"));
		assertTrue(auth.getErrors().contains(Constants.STATUS_RESPONDER));
	}

	/**
	 * Tests the isAuthenticated method of Auth
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#isAuthenticated
	 * @see com.onelogin.saml2.Auth#getErrors
	 * @see com.onelogin.saml2.Auth#getLastErrorReason
	 */
	@Test
	public void testIsAuthenticated() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response4.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processResponse();
		assertFalse(auth.isAuthenticated());
		assertFalse(auth.getErrors().isEmpty());
		List<String> expectedErrors = new ArrayList<String>();
		expectedErrors.add("invalid_response");
		assertEquals(expectedErrors, auth.getErrors());
		assertEquals("SAML Response must contain 1 Assertion.", auth.getLastErrorReason());
		assertTrue(auth.getLastValidationException() instanceof ValidationError);

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth2 = new Auth(settings, request, response);
		assertFalse(auth2.isAuthenticated());
		assertTrue(auth2.getErrors().isEmpty());
		auth2.processResponse();
		assertFalse(auth2.isAuthenticated());
		assertFalse(auth2.getErrors().isEmpty());
		expectedErrors = new ArrayList<String>();
		expectedErrors.add("invalid_response");
		assertEquals(expectedErrors, auth2.getErrors());
		assertThat(auth2.getLastErrorReason(), containsString("Invalid issuer in the Assertion/Response"));
		assertTrue(auth2.getLastValidationException() instanceof ValidationError);

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth3 = new Auth(settings, request, response);
		assertFalse(auth3.isAuthenticated());
		assertTrue(auth3.getErrors().isEmpty());
		auth3.processResponse();
		assertTrue(auth3.isAuthenticated());
		assertTrue(auth3.getErrors().isEmpty());
		assertNull(auth3.getLastErrorReason());
		assertNull(auth3.getLastValidationException());
	}

	/**
	 * Tests the getNameID method of Auth
	 * Case: get nameid from a SAMLResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#getNameId
	 */
	@Test
	public void testGetNameID() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertNull(auth.getNameId());
		auth.processResponse();
		assertFalse(auth.isAuthenticated());
		assertNull(auth.getNameId());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth2 = new Auth(settings, request, response);
		assertNull(auth2.getNameId());
		auth2.processResponse();
		assertTrue(auth2.isAuthenticated());
		assertEquals("492882615acf31c8096b627245d76ae53036c090", auth2.getNameId());

		samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("https://pitbulk.no-ip.org/newonelogin/demo1/index.php?acs"));
		settings.setStrict(false);
		Auth auth3 = new Auth(settings, request, response);
		assertNull(auth3.getNameId());
		auth3.processResponse();
		assertTrue(auth3.isAuthenticated());
		assertEquals("2de11defd199f8d5bb63f9b7deb265ba5c675c10", auth3.getNameId());
	}

	/**
	 * Tests the getNameIdFormat method of Auth
	 * Case: get nameid format from a SAMLResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#getNameIdFormat
	 */
	@Test
	public void testGetNameIdFormat() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertNull(auth.getNameIdFormat());
		auth.processResponse();
		assertFalse(auth.isAuthenticated());
		assertNull(auth.getNameIdFormat());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth2 = new Auth(settings, request, response);
		assertNull(auth2.getNameIdFormat());
		auth2.processResponse();
		assertTrue(auth2.isAuthenticated());
		assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", auth2.getNameIdFormat());

		samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("https://pitbulk.no-ip.org/newonelogin/demo1/index.php?acs"));
		settings.setStrict(false);
		Auth auth3 = new Auth(settings, request, response);
		assertNull(auth3.getNameIdFormat());
		auth3.processResponse();
		assertTrue(auth3.isAuthenticated());
		assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", auth3.getNameIdFormat());
	}

	/**
	 * Tests the getNameIdNameQualifier method of Auth
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#getNameIdNameQualifier
	 */
	@Test
	public void testGetNameIdNameQualifier() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertNull(auth.getNameIdNameQualifier());
		auth.processResponse();
		assertFalse(auth.isAuthenticated());
		assertNull(auth.getNameIdNameQualifier());
		
		
		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response_with_namequalifier.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth2 = new Auth(settings, request, response);
		assertNull(auth2.getNameIdNameQualifier());
		auth2.processResponse();
		assertTrue(auth2.isAuthenticated());
		assertEquals("example.com", auth2.getNameIdNameQualifier());
	}

	/**
	 * Tests the getNameIdSPNameQualifier method of Auth
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#getNameIdSPNameQualifier
	 */
	@Test
	public void testGetNameIdSPNameQualifier() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertNull(auth.getNameIdSPNameQualifier());
		auth.processResponse();
		assertFalse(auth.isAuthenticated());
		assertNull(auth.getNameIdSPNameQualifier());
		
		
		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response_with_namequalifier.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth2 = new Auth(settings, request, response);
		assertNull(auth2.getNameIdSPNameQualifier());
		auth2.processResponse();
		assertTrue(auth2.isAuthenticated());
		assertEquals(settings.getSpEntityId(), auth2.getNameIdSPNameQualifier());
	}
	
	/**
	 * Tests the getNameId method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test
	public void testGetNameIDEncWithNoKey() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.mywithnocert.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("https://pitbulk.no-ip.org/newonelogin/demo1/index.php?acs"));
		settings.setStrict(false);

		expectedEx.expect(SettingsException.class);
		expectedEx.expectMessage("Invalid settings: idp_cert_not_found_and_required");
		Auth auth = new Auth(settings, request, response);
	}

	/**
	 * Tests the getAttributes method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getAttributes
	 */
	@Test
	public void testOnlyRetrieveAssertionWithIDThatMatchesSignatureReference() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrapped_response_2.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);

		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("SAML Response could not be processed");
		auth.processResponse();
	}

	/**
	 * Tests the getSessionIndex method of Auth
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#getSessionIndex
	 */
	@Test
	public void testGetSessionIndex() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertNull(auth.getSessionIndex());
		auth.processResponse();
		assertFalse(auth.isAuthenticated());
		assertNull(auth.getSessionIndex());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth2 = new Auth(settings, request, response);
		assertNull(auth2.getSessionIndex());
		auth2.processResponse();
		assertTrue(auth2.isAuthenticated());
		assertEquals("_6273d77b8cde0c333ec79d22a9fa0003b9fe2d75cb", auth2.getSessionIndex());
	}

	@Test
	public void testGetAssertionDetails() throws Exception {
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpServletRequest request = mock(HttpServletRequest.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		auth.processResponse();

		assertThat(auth.getLastAssertionId(), is("pfxb26bb203-4e9d-8e74-a46e-def275ff4c7b"));
		assertThat(auth.getLastAssertionNotOnOrAfter(), contains(Instant.parse("2053-08-23T06:57:01Z")));
	}

	/**
	 * Tests the getSessionExpiration method of Auth
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#getSessionExpiration
	 */
	@Test
	public void testGetSessionExpiration() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertNull(auth.getSessionExpiration());
		auth.processResponse();
		assertFalse(auth.isAuthenticated());
		assertNull(auth.getSessionExpiration());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth2 = new Auth(settings, request, response);
		assertNull(auth2.getSessionExpiration());
		auth2.processResponse();
		assertTrue(auth2.isAuthenticated());
		assertEquals(2639545021000L, auth2.getSessionExpiration().toEpochMilli());
	}

	/**
	 * Tests the login method of Auth
	 * Case: Login with no parameters
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLogin() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setAuthnRequestsSigned(false);
		Auth auth = new Auth(settings, request, response);
		auth.login();
		verify(response).sendRedirect(matches("https:\\/\\/pitbulk.no-ip.org\\/simplesaml\\/saml2\\/idp\\/SSOService.php\\?SAMLRequest=(.)*&RelayState=http%3A%2F%2Flocalhost%3A8080%2Finitial.jsp"));
		assertThat(auth.getLastRequestId(), startsWith(Util.UNIQUE_ID_PREFIX));
	}

	/**
	 * Tests the login method of Auth
	 * Case: Login with relayState
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLoginWithRelayState() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setAuthnRequestsSigned(false);

		Auth auth = new Auth(settings, request, response);
		String relayState = "http://localhost:8080/expected.jsp";
		auth.login(relayState);
		verify(response).sendRedirect(matches("https:\\/\\/pitbulk.no-ip.org\\/simplesaml\\/saml2\\/idp\\/SSOService.php\\?SAMLRequest=(.)*&RelayState=http%3A%2F%2Flocalhost%3A8080%2Fexpected.jsp"));
	}

	/**
	 * Tests the login method of Auth
	 * Case: Login with empty relayState - no relayState appended
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLoginWithoutRelayState() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setAuthnRequestsSigned(false);

		Auth auth = new Auth(settings, request, response);
		auth.login("");
		final ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
		verify(response).sendRedirect(urlCaptor.capture());
		assertThat(urlCaptor.getValue(), startsWith("https://pitbulk.no-ip.org/simplesaml/saml2/idp/SSOService.php?SAMLRequest="));
		assertThat(urlCaptor.getValue(), not(containsString("&RelayState=")));
	}

	/**
	 * Tests the login method of Auth
	 * Case: Login with extra parameters
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLoginWithExtraParameters() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setAuthnRequestsSigned(false);

		Auth auth = new Auth(settings, request, response);
		Map<String, String> extraParameters = new HashMap<String, String>();
		extraParameters.put("parameter1", "xxx");
		String target = auth.login("", new AuthnRequestParams(false, false, false), true, extraParameters);
		assertThat(target, startsWith("https://pitbulk.no-ip.org/simplesaml/saml2/idp/SSOService.php?SAMLRequest="));
		assertThat(target, containsString("&parameter1=xxx"));
	}

	/**
	 * Tests the login method of Auth
	 * Case: Login with stay enabled
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLoginStay() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setAuthnRequestsSigned(false);

		Auth auth = new Auth(settings, request, response);
		String target = auth.login("", new AuthnRequestParams(false, false, false), true);
		assertThat(target, startsWith("https://pitbulk.no-ip.org/simplesaml/saml2/idp/SSOService.php?SAMLRequest="));
		assertThat(target, not(containsString("&RelayState=")));

		String relayState = "http://localhost:8080/expected.jsp";
		target = auth.login(relayState, new AuthnRequestParams(false, false, false), true);
		assertThat(target, startsWith("https://pitbulk.no-ip.org/simplesaml/saml2/idp/SSOService.php?SAMLRequest="));
		assertThat(target, containsString("&RelayState=http%3A%2F%2Flocalhost%3A8080%2Fexpected.jsp"));		
	}

	/**
	 * Tests the login method of Auth
	 * Case: Login with Subject enabled
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLoginSubject() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Auth auth = new Auth(settings, request, response);
		String target = auth.login("", new AuthnRequestParams(false, false, false), true);
		assertThat(target, startsWith("http://idp.example.com/simplesaml/saml2/idp/SSOService.php?SAMLRequest="));
		String authNRequestStr = getSAMLRequestFromURL(target);
		assertThat(authNRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authNRequestStr, not(containsString("<saml:Subject")));

		target = auth.login("", new AuthnRequestParams(false, false, false, "testuser@example.com"), true);
		assertThat(target, startsWith("http://idp.example.com/simplesaml/saml2/idp/SSOService.php?SAMLRequest="));
		authNRequestStr = getSAMLRequestFromURL(target);
		assertThat(authNRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authNRequestStr, containsString("<saml:Subject"));
		assertThat(authNRequestStr, containsString("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">testuser@example.com</saml:NameID>"));
		assertThat(authNRequestStr, containsString("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"));

		settings = new SettingsBuilder().fromFile("config/config.emailaddressformat.properties").build();
		auth = new Auth(settings, request, response);
		target = auth.login("", new AuthnRequestParams(false, false, false, "testuser@example.com"), true);
		assertThat(target, startsWith("http://idp.example.com/simplesaml/saml2/idp/SSOService.php?SAMLRequest="));
		authNRequestStr = getSAMLRequestFromURL(target);
		assertThat(authNRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authNRequestStr, containsString("<saml:Subject"));
		assertThat(authNRequestStr, containsString("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">testuser@example.com</saml:NameID>"));
		assertThat(authNRequestStr, containsString("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"));

	}

	/**
	 * Tests the login method of Auth
	 * Case: Signed Login but no sp key
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLoginSignedFail() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setAuthnRequestsSigned(true);
		settings.setSignatureAlgorithm(Constants.RSA_SHA1);

		expectedEx.expect(SettingsException.class);
		expectedEx.expectMessage("Invalid settings: sp_cert_not_found_and_required");
		Auth auth = new Auth(settings, request, response);
	}
	
	/**
	 * Tests the login method of Auth
	 * Case: Signed Login
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLoginSigned() throws IOException, SettingsException, URISyntaxException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setAuthnRequestsSigned(true);
		settings.setSignatureAlgorithm(Constants.RSA_SHA1);
		Auth auth = new Auth(settings, request, response);
		String relayState = "http://localhost:8080/expected.jsp";
		auth.login(relayState);
		verify(response).sendRedirect(matches("https:\\/\\/pitbulk.no-ip.org\\/simplesaml\\/saml2\\/idp\\/SSOService.php\\?SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&SAMLRequest=(.)*&RelayState=http%3A%2F%2Flocalhost%3A8080%2Fexpected.jsp&Signature=(.)*"));

		settings.setSignatureAlgorithm(Constants.SHA512);
		Auth auth2 = new Auth(settings, request, response);
		auth2.login(relayState);
		verify(response).sendRedirect(matches("https:\\/\\/pitbulk.no-ip.org\\/simplesaml\\/saml2\\/idp\\/SSOService.php\\?SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&SAMLRequest=(.)*&RelayState=http%3A%2F%2Flocalhost%3A8080%2Fexpected.jsp&Signature=(.)*"));
	}

	/**
	 * Tests the logout method of Auth
	 * Case: Logout with no parameters
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test
	public void testLogout() throws IOException, SettingsException, XMLEntityException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setLogoutRequestSigned(false);
		Auth auth = new Auth(settings, request, response);
		auth.logout();

		verify(response).sendRedirect(matches("https:\\/\\/pitbulk.no-ip.org\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SAMLRequest=(.)*&RelayState=http%3A%2F%2Flocalhost%3A8080%2Finitial.jsp"));
		assertThat(auth.getLastRequestId(), startsWith(Util.UNIQUE_ID_PREFIX));
	}

	/**
	 * Tests the logout method of Auth
	 * Case: Logout with no parameters
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test
	public void testLogoutWithExtraParameters() throws IOException, SettingsException, XMLEntityException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setLogoutRequestSigned(false);
		Auth auth = new Auth(settings, request, response);
		Map<String, String> extraParameters = new HashMap<String, String>();
		extraParameters.put("parameter1", "xxx");
		String target = auth.logout("", new LogoutRequestParams(), true, extraParameters);
		assertThat(target, startsWith("https://pitbulk.no-ip.org/simplesaml/saml2/idp/SingleLogoutService.php?SAMLRequest="));
		assertThat(target, containsString("&parameter1=xxx"));
	}

	/**
	 * Tests the logout method of Auth
	 * Case: Logout with RelayState
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test
	public void testLogoutWithRelayState() throws IOException, SettingsException, XMLEntityException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setLogoutRequestSigned(false);

		Auth auth = new Auth(settings, request, response);
		String relayState = "http://localhost:8080/expected.jsp";
		auth.logout(relayState);

		verify(response).sendRedirect(matches("https:\\/\\/pitbulk.no-ip.org\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SAMLRequest=(.)*&RelayState=http%3A%2F%2Flocalhost%3A8080%2Fexpected.jsp"));
	}

	/**
	 * Tests the logout method of Auth
	 * Case: Logout with empty RelayState - no RelayState appended
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test
	public void testLogoutWithoutRelayState() throws IOException, SettingsException, XMLEntityException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setLogoutRequestSigned(false);

		Auth auth = new Auth(settings, request, response);
		auth.logout("");

		final ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
		verify(response).sendRedirect(urlCaptor.capture());
		assertThat(urlCaptor.getValue(), startsWith("https://pitbulk.no-ip.org/simplesaml/saml2/idp/SingleLogoutService.php?SAMLRequest="));
		assertThat(urlCaptor.getValue(), not(containsString("&RelayState=")));
	}

	/**
	 * Tests the logout method of Auth
	 * Case: Logout Stay
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test
	public void testLogoutStay() throws IOException, SettingsException, XMLEntityException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setLogoutRequestSigned(false);

		Auth auth = new Auth(settings, request, response);
		String target = auth.logout("", new LogoutRequestParams(), true);
		assertThat(target, startsWith("https://pitbulk.no-ip.org/simplesaml/saml2/idp/SingleLogoutService.php?SAMLRequest="));
		assertThat(target, not(containsString("&RelayState=")));
		
		String relayState = "http://localhost:8080/expected.jsp";
		target = auth.logout(relayState, new LogoutRequestParams(), true);
		assertThat(target, startsWith("https://pitbulk.no-ip.org/simplesaml/saml2/idp/SingleLogoutService.php?SAMLRequest="));
		assertThat(target, containsString("&RelayState=http%3A%2F%2Flocalhost%3A8080%2Fexpected.jsp"));
	}
	
	/**
	 * Tests the logout method of Auth
	 * Case: Signed Logout but no sp key
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test
	public void testLogoutSignedFail() throws IOException, SettingsException, XMLEntityException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setLogoutRequestSigned(true);
		settings.setSignatureAlgorithm(Constants.RSA_SHA1);

		expectedEx.expect(SettingsException.class);
		expectedEx.expectMessage("Invalid settings: sp_cert_not_found_and_required");
		Auth auth = new Auth(settings, request, response);
	}
	
	/**
	 * Tests the logout method of Auth
	 * Case: Signed Logout
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test
	public void testLogoutSigned() throws IOException, SettingsException, XMLEntityException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setLogoutRequestSigned(true);
		settings.setSignatureAlgorithm(Constants.RSA_SHA1);
		Auth auth = new Auth(settings, request, response);
		String relayState = "http://localhost:8080/expected.jsp";
		auth.logout(relayState);
		verify(response).sendRedirect(matches("https:\\/\\/pitbulk.no-ip.org\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&SAMLRequest=(.)*&RelayState=http%3A%2F%2Flocalhost%3A8080%2Fexpected.jsp&Signature=(.)*"));

		settings.setSignatureAlgorithm(Constants.SHA512);
		Auth auth2 = new Auth(settings, request, response);
		auth2.logout(relayState);
		verify(response).sendRedirect(matches("https:\\/\\/pitbulk.no-ip.org\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&SAMLRequest=(.)*&RelayState=http%3A%2F%2Flocalhost%3A8080%2Fexpected.jsp&Signature=(.)*"));
	}

	/**
	 * Tests the buildRequestSignature method
	 * Case invalid SP cert/private key
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test
	public void testBuildRequestSignatureInvalidSP() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String relayState = "http://example.com";
		String signAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

		Auth auth = new Auth("config/config.invalidspcertstring.properties");
		
		expectedEx.expect(SettingsException.class);
		expectedEx.expectMessage("Trying to sign the SAMLRequest but can't load the SP private key");
		auth.buildRequestSignature(deflatedEncodedAuthNRequest, relayState, signAlgorithm);
	}

	/**
	 * Tests the buildRequestSignature method
	 * Case RsaSha1
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test
	public void testBuildRequestSignatureRsaSha1() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String relayState = "http://example.com";
		String signAlgorithm = Constants.RSA_SHA1;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildRequestSignature(deflatedEncodedAuthNRequest, relayState, signAlgorithm);
		String expectedSignature = "FqFJi9aIut9Gp/SUyLcj4ewwnU4ajjhfWpdr8pc4w//9m0QB1hzDUHR7YmKxXB6rrRuX7iy9CJy+o7zzhz2pTr0PHHE9mvFPsyk/mas9e2ZGUeLS2OzMPHYwJCdOg4uLrbqybWGKy0AgoDqTpAfpkQVxuunVKTj4pOPXGx156Oo=";
		assertEquals(expectedSignature, signature);

		String signature_2 = auth.buildRequestSignature(deflatedEncodedAuthNRequest, relayState, null);
		assertEquals(expectedSignature, signature_2);
	}

	/**
	 * Tests the buildRequestSignature method
	 * Case DsaSha1. Alg. not supported 
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testBuildRequestSignatureDsaSha1() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String relayState = "http://example.com";
		String signAlgorithm = Constants.DSA_SHA1;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildRequestSignature(deflatedEncodedAuthNRequest, relayState, signAlgorithm);
	}
	
	/**
	 * Tests the buildRequestSignature method
	 * Case RsaSha256
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test
	public void testBuildRequestSignatureRsaSha256() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String relayState = "http://example.com";
		String signAlgorithm = Constants.RSA_SHA256;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildRequestSignature(deflatedEncodedAuthNRequest, relayState, signAlgorithm);
		String expectedSignature = "PJoiwvBgKnRefzaYMaPqOTvlia7EhFoRrc+tFlJCi557VEpG0oY1x8YTmkOxC+oI0zWyQ0RiXA65q7hv1xyYgGnSFdMKr5s+qeD4+1BjPxEGwXVU6+gTX0gg2+UL+1o4YpoVTQ1aKSO85uyBEGO20WnK2zETuGA/Wgl1VBSxNSw=";
		assertEquals(expectedSignature, signature);
	}
	
	/**
	 * Tests the buildRequestSignature method
	 * Case RsaSha384
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test
	public void testBuildRequestSignatureRsaSha384() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String relayState = "http://example.com";
		String signAlgorithm = Constants.RSA_SHA384;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildRequestSignature(deflatedEncodedAuthNRequest, relayState, signAlgorithm);
		String expectedSignature = "rO7eswxuPsk/QPDLaZRHziTx8ndVXMDMfEsJI6ZSQDqVo0ZaHgOJJ8GC8UWcJrGg2qFrsl2mTozMh1Iqi5oBb2GSWTEC/WRAb/qnNi/02yLrLtoop1YfXb7yl0StpXoM0MwWeoPBroEyqdK+qcu2eWSOwrogffepVfcgghtUwo0=";
		assertEquals(expectedSignature, signature);
	}
	
	/**
	 * Tests the buildRequestSignature method
	 * Case RsaSha512
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test
	public void testBuildRequestSignatureRsaSha512() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String relayState = "http://example.com";		
		String signAlgorithm = Constants.RSA_SHA512;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildRequestSignature(deflatedEncodedAuthNRequest, relayState, signAlgorithm);
		String expectedSignature = "HbaAEGjXBtgvJA+JkZ74maWV/61SqgDd8gw2FmSziiMXyCV62KDA1BoSn/91/8yNepqpP9JQk+1VKnQxNpL1NgQuy/mWmXc/JseNT0UQ4Uy5Mp1QfMMBDM9hs+cfseCYr3aJJumlpjZ8xS2Oou1e4y5g8ZWfaXHJ86N+IaywcOI=";
		assertEquals(expectedSignature, signature);
	}

	/**
	 * Tests the buildResponseSignature method
	 * Case RsaSha1
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildResponseSignature
	 */
	@Test
	public void testBuildResponseSignatureRsaSha1() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedLogoutResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		String relayState = "http://example.com";
		String signAlgorithm = Constants.RSA_SHA1;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildResponseSignature(deflatedEncodedLogoutResponse, relayState, signAlgorithm);
		String expectedSignature = "aCaiL+HwDdYMbzfEZugqqce87LBodp968USja0j8dsTzOdi6Cwc3emae/974ilUraRG19iggMVVe1XX+Y8PgxQ3iKsAVxyjZnlrArNp1ofSXgDvIqJi0EILOwHFC5Y6XUlsGLrFePmv8GfCxk0fKeVZSscfQTuxSMop6DNJ4lpQ=";
		assertEquals(expectedSignature, signature);

		String signature_2 = auth.buildResponseSignature(deflatedEncodedLogoutResponse, relayState, null);
		assertEquals(expectedSignature, signature_2);
	}

	/**
	 * Tests the buildResponseSignature method
	 * Case DsaSha1. Alg. not supported 
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildResponseSignature
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testBuildResponseSignatureDsaSha1() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedLogoutResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		String relayState = "http://example.com";
		String signAlgorithm = Constants.DSA_SHA1;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildResponseSignature(deflatedEncodedLogoutResponse, relayState, signAlgorithm);
	}
	
	/**
	 * Tests the buildResponseSignature method
	 * Case RsaSha256
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildResponseSignature
	 */
	@Test
	public void testBuildResponseSignatureRsaSha256() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedLogoutResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		String relayState = "http://example.com";
		String signAlgorithm = Constants.RSA_SHA256;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildResponseSignature(deflatedEncodedLogoutResponse, relayState, signAlgorithm);
		String expectedSignature = "XcEbaZ6BsmaHwDedzLu/t1lKr3I2Qu4ctIZKqz8OFSPGoZh40gLIPX4RBl71Fv6uFdf9xCyXxI27xoC1CV23xNZsWjK89502xcy3vPQvTWo03r9WA92Gu1+/d1JIpE5xX2xBBjLlOxwdi/aYhTHtzo0PChI2zjL5nkziM/uIv2E=";
		assertEquals(expectedSignature, signature);
	}
	
	/**
	 * Tests the buildResponseSignature method
	 * Case RsaSha384
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildResponseSignature
	 */
	@Test
	public void testBuildResponseSignatureRsaSha384() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedLogoutResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		String relayState = "http://example.com";
		String signAlgorithm = Constants.RSA_SHA384;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildResponseSignature(deflatedEncodedLogoutResponse, relayState, signAlgorithm);
		String expectedSignature = "R+maoS+UmFkiPu0kkwqz2WnkPfMA9upqWVwvVhTQvhrmmc3Gcfm77cAyjnDilFYwKx4xfQhO9PTqd0zviPRx8F+9VaiVKrmEloKfQuHGB1IjdtP8S8X9YRk+dXoegZAFvr9lmrcB9qP6xn1QW3NeMLgRCvWSWa82CBtrvT9K5Ko=";
		assertEquals(expectedSignature, signature);
	}
	
	/**
	 * Tests the buildResponseSignature method
	 * Case RsaSha512
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildResponseSignature
	 */
	@Test
	public void testBuildResponseSignatureRsaSha512() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedLogoutResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		String relayState = "http://example.com";		
		String signAlgorithm = Constants.RSA_SHA512;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildResponseSignature(deflatedEncodedLogoutResponse, relayState, signAlgorithm);
		String expectedSignature = "FUxepHZ0j7YWbZYrbXsgebGg37Ne4d7grp/Jdk8j/vvgbOplyyhgsEUzt5K9+7B3OGM+rN5YFHcz5EbCtBfXugy+RJLa893Ih6oKr0wRoOh3/79EGKmnzR1aUyDguhNUuQW0AG3/Fz+CzrKL9HK6+im6F/6YwOVRT7FzBsZxtXs=";
		assertEquals(expectedSignature, signature);
	}
	
	/**
	 * Tests the buildSignature method
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#buildSignature
	 */
	@Test
	public void testBuildSignature() throws URISyntaxException, IOException, SettingsException, Error {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String deflatedEncodedLogoutResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		String relayState = "http://example.com";		
		String signAlgorithm = Constants.RSA_SHA1;

		Auth auth = new Auth("config/config.certstring.properties");
		String signature = auth.buildResponseSignature(deflatedEncodedAuthNRequest, relayState, signAlgorithm);
		String expectedSignature = "Cn5jkeZLdsMh4P+ALWfywHe8lADcRPKBYabYuenagBvp1CIYUNsN5T4oP+rtY+8ia09N5Xbi7wCW6hX5ZDihBi/AHznnjRRKdYGXOL9Oe/cNE48bqQRRyTMN27zBEXU9yKysOqTwhDXWDxXXzXafYULr+cTSSXTmllt42o9t/60=";
		assertEquals(expectedSignature, signature);

		signature = auth.buildResponseSignature(deflatedEncodedAuthNRequest, relayState, null);
		assertEquals(expectedSignature, signature);

		signature = auth.buildResponseSignature(deflatedEncodedLogoutResponse, relayState, signAlgorithm);
		expectedSignature = "aCaiL+HwDdYMbzfEZugqqce87LBodp968USja0j8dsTzOdi6Cwc3emae/974ilUraRG19iggMVVe1XX+Y8PgxQ3iKsAVxyjZnlrArNp1ofSXgDvIqJi0EILOwHFC5Y6XUlsGLrFePmv8GfCxk0fKeVZSscfQTuxSMop6DNJ4lpQ=";
		assertEquals(expectedSignature, signature);

		signature = auth.buildResponseSignature(deflatedEncodedLogoutResponse, relayState, null);
		assertEquals(expectedSignature, signature);

		signature = auth.buildResponseSignature(deflatedEncodedAuthNRequest, null, signAlgorithm);
		expectedSignature = "cEDK6FQ70KNGdsOSnUYhA64bmv2iNlW81/EiqTM/b31kYBIk74CjgOHwfPBwC6KbC8rUTvr4IFY1lxvl3cwWByYwLf7uDaCCXdkb6lxApk6EF7xprdnTOXnl7hi+nOULn8uPlr1HpJtcbaJXKIcaN1PbOuLqgHAB4FZcJjRTg5A=";
		assertEquals(expectedSignature, signature);

		signature = auth.buildResponseSignature(deflatedEncodedLogoutResponse, null, signAlgorithm);
		expectedSignature = "DVI+U7dkn1MeFNUC+WimGRhm3SolakG9aBPsRv7AihNzDBZQLVs1IQC3uB4Em6XUqWlfmTiJsNoAlCB2gWn3aryTtg77Dgl2yMhsrkfMB0Nq7PS+0xKP9aveSN5Ac3BlGov6sbQr62Vgqxu4KnpKkv+5fAgZZDoIdgDn5vyiPgc=";
		assertEquals(expectedSignature, signature);

		signature = auth.buildResponseSignature(deflatedEncodedAuthNRequest, null, null);
		expectedSignature = "cEDK6FQ70KNGdsOSnUYhA64bmv2iNlW81/EiqTM/b31kYBIk74CjgOHwfPBwC6KbC8rUTvr4IFY1lxvl3cwWByYwLf7uDaCCXdkb6lxApk6EF7xprdnTOXnl7hi+nOULn8uPlr1HpJtcbaJXKIcaN1PbOuLqgHAB4FZcJjRTg5A=";
		assertEquals(expectedSignature, signature);

		signature = auth.buildResponseSignature(deflatedEncodedAuthNRequest, null, "");
		assertEquals(expectedSignature, signature);

		signature = auth.buildResponseSignature(deflatedEncodedLogoutResponse, null, null);
		expectedSignature = "DVI+U7dkn1MeFNUC+WimGRhm3SolakG9aBPsRv7AihNzDBZQLVs1IQC3uB4Em6XUqWlfmTiJsNoAlCB2gWn3aryTtg77Dgl2yMhsrkfMB0Nq7PS+0xKP9aveSN5Ac3BlGov6sbQr62Vgqxu4KnpKkv+5fAgZZDoIdgDn5vyiPgc=";
		assertEquals(expectedSignature, signature);

		signature = auth.buildResponseSignature(deflatedEncodedLogoutResponse, null, "");
		assertEquals(expectedSignature, signature);

		signature = auth.buildRequestSignature(deflatedEncodedAuthNRequest, "", signAlgorithm);
		expectedSignature = "NS/yZ0WkHHtPU6LBWioxTzFsATJC6k7D8PcmBuM4NcC1klHSX5gmgDJdGs+7ee433RxhsTRLDNXJnXInAFG5iqZQK/Jps1aqx9iCAwfC4GCJs605e/hw3UXWKKo1lKxwE4Zu6eJ0TsMQ2gj/5qLezQL98CgqmFHLhvNgGJZcG6U=";
		assertEquals(expectedSignature, signature);

		signature = auth.buildRequestSignature(deflatedEncodedLogoutResponse, "", signAlgorithm);
		expectedSignature = "GiO58DZMcRb8QR+dxUvn9bp5tIp2Eal8+tvOAEbYoAX6+7TMO8tTkpPjRD60pG+SMYjTC+lXQHygX2AXcO5ZQj8snfqx94C3dCOP7gLKOowFcaD0TunmnFCBx6qLv2cOleS9PSx49BSZJiGuffNcfgvTvsyqGwC2EatPP2+AxDM=";
		assertEquals(expectedSignature, signature);
	}

	/**
	 * Tests the getLastRequestXML method
	 * Case We can get most recently constructed SAML AuthNRequest
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#getLastRequestXML
	 */
	@Test
	public void testGetLastAuthNRequest() throws IOException, SettingsException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Auth auth = new Auth(settings, request, response);
		String targetSSOURL = auth.login(null, new AuthnRequestParams(false, false, false), true);
		String authNRequestXML = auth.getLastRequestXML();
		assertThat(targetSSOURL, containsString(Util.urlEncoder(Util.deflatedBase64encoded(authNRequestXML))));
		
		assertThat(authNRequestXML, containsString("ID=\"" + auth.getLastRequestId() + "\""));
		assertThat(authNRequestXML, containsString("IssueInstant=\"" + Util.formatDateTime(auth.getLastRequestIssueInstant().getTimeInMillis()) + "\""));
	}

	/**
	 * Tests the getLastRequestXML method
	 * Case We can get most recently processed LogoutRequest.
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.Auth#getLastRequestXML
	 */
	@Test
	public void testGetLastLogoutRequestSent() throws IOException, SettingsException, XMLEntityException, Error {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Auth auth = new Auth(settings, request, response);
		String targetSLOURL = auth.logout(null, new LogoutRequestParams(), true);
		String logoutRequestXML = auth.getLastRequestXML();
		assertThat(targetSLOURL, containsString(Util.urlEncoder(Util.deflatedBase64encoded(logoutRequestXML))));

		assertThat(logoutRequestXML, containsString("ID=\"" + auth.getLastRequestId() + "\""));
		assertThat(logoutRequestXML, containsString("IssueInstant=\"" + Util.formatDateTime(auth.getLastRequestIssueInstant().getTimeInMillis()) + "\""));
	}

	/**
	 * Tests the getLastRequestXML method
	 * Case We can get most recently processed LogoutRequest
	 *
	 * @throws Exception 
	 *
	 * @see com.onelogin.saml2.Auth#getLastRequestXML
	 */
	@Test
	public void testGetLastLogoutRequestReceived() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLRequest", new String[]{samlRequestEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		auth.processSLO();
		String logoutRequestXML =  auth.getLastRequestXML();
		assertThat(logoutRequestXML, containsString("<samlp:LogoutRequest"));
	}

	/**
	 * Tests the getLastResponseXML method
	 * Case We can get most recently processed SAML Response
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.Auth#getLastResponseXML
	 */
	@Test
	public void testGetLastSAMLResponse() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		auth.processResponse();
		String samlResponseXML =  auth.getLastResponseXML();
		assertThat(samlResponseXML, containsString("<samlp:Response"));
		
		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth2 = new Auth(settings, request, response);
		auth2.processResponse();
		samlResponseXML =  auth2.getLastResponseXML();
		assertThat(samlResponseXML, containsString("<samlp:Response"));
		assertThat(samlResponseXML, containsString("<saml:Assertion"));
	}

	/**
	 * Tests the getLastResponseXML method
	 * Case We can get most recently processed LogoutResponse
	 *
	 * @throws Exception 
	 *
	 * @see com.onelogin.saml2.Auth#getLastResponseXML
	 */
	@Test
	public void testGetLastLogoutResponseSent() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLRequest", new String[]{samlRequestEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setStrict(false);
		Auth auth = new Auth(settings, request, response);
		auth.processSLO(true, null);
		String logoutResponseXML =  auth.getLastResponseXML();
		assertThat(logoutResponseXML, containsString("<samlp:LogoutResponse"));
	}

	/**
	 * Tests the getLastResponseXML method
	 * Case We can get most recently processed LogoutResponse
	 *
	 * @throws Exception 
	 *
	 * @see com.onelogin.saml2.Auth#getLastResponseXML
	 */
	@Test
	public void testGetLastLogoutResponseReceived() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));
		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		auth.processSLO();
		String logoutResponseXML =  auth.getLastResponseXML();
		assertThat(logoutResponseXML, containsString("<samlp:LogoutResponse"));
	}
	
	private static class FactoryInvokedException extends RuntimeException {
	}
	
	/**
	 * Tests that the SAML message factory gets invoked by Auth for AuthnRequests and the right parameters are passed to it.
	 *
	 * @throws Exception 
	 *
	 * @see com.onelogin.saml2.Auth#setAuthnRequestFactory(com.onelogin.saml2.factory.SamlOutgoingMessageFactory)
	 */
	@Test(expected = FactoryInvokedException.class)
	public void testAuthnRequestFactory() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);

		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		final AuthnRequestParams params =  new AuthnRequestParams(false, false, false);
		
		class AuthnRequestEx extends AuthnRequest {
			public AuthnRequestEx(Saml2Settings sett, AuthnRequestParams par) {
				super(sett, par);
				assertSame(settings, sett);
				assertSame(params, par);
				throw new FactoryInvokedException();
			}
		}
		
		Auth auth = new Auth(settings, request, response);
		auth.setSamlMessageFactory(new SamlMessageFactory() {
			@Override
			public AuthnRequest createAuthnRequest(Saml2Settings settings, AuthnRequestParams params) {
				return new AuthnRequestEx(settings, params);
			}
		});
		auth.login(params);
	}

	/**
	 * Tests that the SAML message factory gets invoked by Auth for SamlResponses and the right parameters are passed to it.
	 *
	 * @throws Exception 
	 *
	 * @see com.onelogin.saml2.Auth#setSamlResponseFactory(com.onelogin.saml2.factory.SamlReceivedMessageFactory)
	 */
	@Test(expected = FactoryInvokedException.class)
	public void testSamlResponseFactory() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		
		class SamlResponseEx extends SamlResponse {
			public SamlResponseEx(Saml2Settings sett, HttpRequest req) throws Exception {
				super(sett, req);
				assertSame(settings, sett);
				assertEquals(ServletUtils.makeHttpRequest(request), req);
				throw new FactoryInvokedException();
			}
		}
		
		Auth auth = new Auth(settings, request, response);
		auth.setSamlMessageFactory(new SamlMessageFactory() {
			@Override
			public SamlResponse createSamlResponse(Saml2Settings settings, HttpRequest request) throws Exception {
				return new SamlResponseEx(settings, request);
			}
		});
		auth.processResponse();
	}

	/**
	 * Tests that the SAML message factory gets invoked by Auth for outgoing LogoutRequests and the right parameters are passed to it.
	 *
	 * @throws Exception 
	 *
	 * @see com.onelogin.saml2.Auth#setOutgoingLogoutRequestFactory(com.onelogin.saml2.factory.SamlOutgoingMessageFactory)
	 */
	@Test(expected = FactoryInvokedException.class)
	public void testOutgoingLogoutRequestFactory() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);

		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		final LogoutRequestParams params =  new LogoutRequestParams();
		
		class LogoutRequestEx extends LogoutRequest {
			
			public LogoutRequestEx(Saml2Settings sett, LogoutRequestParams par) {
				super(sett, par);
				assertSame(settings, sett);
				assertSame(params, par);
				throw new FactoryInvokedException();
			}
			
		}
		
		Auth auth = new Auth(settings, request, response);
		auth.setSamlMessageFactory(new SamlMessageFactory() {
			@Override
			public LogoutRequest createOutgoingLogoutRequest(Saml2Settings settings, LogoutRequestParams params) {
				return new LogoutRequestEx(settings, params);
			}
		});
		auth.logout(null, params);
	}
	
	/**
	 * Tests that the SAML message factory gets invoked by Auth for incoming LogoutRequests and the right parameters are passed to it.
	 *
	 * @throws Exception 
	 *
	 * @see com.onelogin.saml2.Auth#setReceivedLogoutRequestFactory(com.onelogin.saml2.factory.SamlReceivedMessageFactory)
	 */
	@Test(expected = FactoryInvokedException.class)
	public void testIncomingLogoutRequestFactory() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLRequest", new String[]{samlRequestEncoded}));
		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		
		class LogoutRequestEx extends LogoutRequest {

			public LogoutRequestEx(Saml2Settings sett, HttpRequest req) {
				super(sett, req);
				assertSame(settings, sett);
				assertEquals(ServletUtils.makeHttpRequest(request), req);
				throw new FactoryInvokedException();
			}
			
		}
		
		Auth auth = new Auth(settings, request, response);
		auth.setSamlMessageFactory(new SamlMessageFactory() {
			@Override
			public LogoutRequest createIncomingLogoutRequest(Saml2Settings settings, HttpRequest request)
			            throws Exception {
				return new LogoutRequestEx(settings, request);
			}
		});
		auth.processSLO();
	}

	/**
	 * Tests that the SAML message factory gets invoked by Auth for outgoing LogoutResponses and the right parameters are passed to it.
	 *
	 * @throws Exception 
	 *
	 * @see com.onelogin.saml2.Auth#setOutgoingLogoutResponseFactory(com.onelogin.saml2.factory.SamlOutgoingMessageFactory)
	 */
	@Test(expected = FactoryInvokedException.class)
	public void testOutgoingLogoutResponseFactory() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLRequest", new String[]{samlRequestEncoded}));
		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		
		class LogoutResponseEx extends LogoutResponse {

			public LogoutResponseEx(Saml2Settings sett, LogoutResponseParams par) {
				super(sett, par);
				assertSame(settings, sett);
				assertEquals("ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e", par.getInResponseTo());
				SamlResponseStatus responseStatus = par.getResponseStatus();
				assertEquals(Constants.STATUS_SUCCESS, responseStatus.getStatusCode());
				assertNull(responseStatus.getSubStatusCode());
				assertNull(responseStatus.getStatusMessage());
				throw new FactoryInvokedException();
			}
			
		}
		
		Auth auth = new Auth(settings, request, response);
		auth.setSamlMessageFactory(new SamlMessageFactory() {
			@Override
			public LogoutResponse createOutgoingLogoutResponse(Saml2Settings settings,
			            LogoutResponseParams params) {
				return new LogoutResponseEx(settings, params);
			}
		});
		auth.processSLO(false, null);
	}

	/**
	 * Tests that the SAML message factory gets invoked by Auth for incoming LogoutResponses and the right parameters are passed to it.
	 *
	 * @throws Exception 
	 *
	 * @see com.onelogin.saml2.Auth#setReceivedLogoutResponseFactory(com.onelogin.saml2.factory.SamlReceivedMessageFactory)
	 */
	@Test(expected = FactoryInvokedException.class)
	public void testIncomingLogoutResponseFactory() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpSession session = mock(HttpSession.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		when(request.getSession()).thenReturn(session);

		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		
		class LogoutResponseEx extends LogoutResponse {

			public LogoutResponseEx(Saml2Settings sett, HttpRequest req) {
				super(sett, req);
				assertSame(settings, sett);
				assertEquals(ServletUtils.makeHttpRequest(request), req);
				throw new FactoryInvokedException();
			}
			
		}
		
		Auth auth = new Auth(settings, request, response);
		auth.setSamlMessageFactory(new SamlMessageFactory() {
			@Override
			public LogoutResponse createIncomingLogoutResponse(Saml2Settings settings, HttpRequest request) {
				return new LogoutResponseEx(settings, request);
			}
		});
		auth.processSLO();
	}
}
