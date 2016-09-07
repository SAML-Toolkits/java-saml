package com.onelogin.saml2.test;


import static java.util.Collections.singletonMap;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.matches;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.joda.time.Instant;
import org.junit.Test;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

public class AuthTest {

	/**
	 * Tests the constructor of Auth
	 * Case: No parameters
	 *
	 * @throws SettingsException
	 * @throws IOException
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructor() throws IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructorWithFilename() throws IOException, SettingsException {
		Auth auth = new Auth("config/config.min.properties");
		assertTrue(auth.getSettings() != null);

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		assertEquals(settings.getIdpEntityId(), auth.getSettings().getIdpEntityId());
		assertEquals(settings.getSpEntityId(), auth.getSettings().getSpEntityId());
	}

	/**
	 * Tests the constructor of Auth
	 * Case: HttpServletRequest and HttpServletResponse provided
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructorWithReqRes() throws IOException, SettingsException, URISyntaxException {
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
	 * Case: filename, HttpServletRequest and HttpServletResponse provided
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructorWithFilenameReqRes() throws IOException, SettingsException, URISyntaxException {
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
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test
	public void testConstructorWithSettingsReqRes() throws IOException, SettingsException, URISyntaxException {
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
	 *
	 * @see com.onelogin.saml2.Auth
	 */
	@Test(expected=SettingsException.class)
	public void testConstructorInvalidSettings() throws IOException, SettingsException, URISyntaxException {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.sperrors.properties").build();
		Auth auth = new Auth(settings, request, response);
	}

	/**
	 * Tests the getSettings method of Auth
	 *
	 * @throws SettingsException
	 * @throws IOException
	 *
	 * @see com.onelogin.saml2.Auth#getSettings
	 */
	@Test
	public void testGetSettings() throws IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Auth#setStrict
	 */
	@Test
	public void testSetStrict() throws IOException, SettingsException, URISyntaxException {
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
	 *
	 * @see com.onelogin.saml2.Auth#isDebugActive
	 */
	@Test
	public void testIsDebugActive() throws IOException, SettingsException, URISyntaxException {
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
	 *
	 * @see com.onelogin.saml2.Auth#getSSOurl
	 */
	@Test
	public void testGetSSOurl() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Auth#getSLOurl
	 */
	@Test
	public void testGetSLOurl() throws URISyntaxException, IOException, SettingsException {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		Auth auth = new Auth(settings, request, response);
		assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", auth.getSLOurl());
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
		} catch (IllegalArgumentException e) {
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

		HashMap<String, List<String>> expectedAttributes = new HashMap<String, List<String>>();
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
		expectedAttributes.put("eduPersonAffiliation", attrValues3);
		expectedAttributes.put("cn", attrValues4);
		expectedAttributes.put("sn", attrValues5);
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
		} catch (IllegalArgumentException e) {
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
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequestEncoded);
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
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequestEncoded);
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
		when(request.getParameter("RelayState")).thenReturn("http://localhost:8080/expected.jsp");

		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequestEncoded);
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		settings.setWantMessagesSigned(false);
		settings.setLogoutResponseSigned(true);
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO();
		verify(response).sendRedirect(matches("http:\\/\\/idp.example.com\\/simplesaml\\/saml2\\/idp\\/SingleLogoutService.php\\?SAMLResponse=(.)*&RelayState=http%3A%2F%2Flocalhost%3A8080%2Fexpected.jsp&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha512&Signature=(.)*"));
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
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequestEncoded);
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
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
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
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
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
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(true);
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO(false, "wrong_request_id");
		verify(session, times(0)).invalidate();
		assertTrue(auth.getErrors().contains("invalid_logout_response"));
		assertEquals("The InResponseTo of the Logout Response: ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e, does not match the ID of the Logout request sent by the SP:: wrong_request_id", auth.getLastErrorReason());
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
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		Auth auth = new Auth(settings, request, response);
		assertFalse(auth.isAuthenticated());
		assertTrue(auth.getErrors().isEmpty());
		auth.processSLO();
		verify(session, times(0)).invalidate();
		assertFalse(auth.getErrors().isEmpty());
		assertTrue(auth.getErrors().contains("logout_not_success"));
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
		assertThat(auth2.getLastErrorReason(), containsString("The response was received at"));		

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		Auth auth3 = new Auth(settings, request, response);
		assertFalse(auth3.isAuthenticated());
		assertTrue(auth3.getErrors().isEmpty());
		auth3.processResponse();
		assertTrue(auth3.isAuthenticated());
		assertTrue(auth3.getErrors().isEmpty());
		assertNull(auth3.getLastErrorReason());
	}

	/**
	 * Tests the getNameID method of Auth
	 * Case: get nameid from a SAMLResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.Auth#getNameID
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
	 * Tests the getNameId method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test(expected=SettingsException.class)
	public void testGetNameIDEncWithNoKey() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.mywithnocert.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("https://pitbulk.no-ip.org/newonelogin/demo1/index.php?acs"));
		settings.setStrict(false);
		Auth auth = new Auth(settings, request, response);
		assertNull(auth.getNameId());
		auth.processResponse();
		assertFalse(auth.isAuthenticated());
		assertNull(auth.getNameId());
	}

	/**
	 * Tests the getAttributes method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getAttributes
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testOnlyRetrieveAssertionWithIDThatMatchesSignatureReference() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrapped_response_2.xml.base64");
		when(request.getParameterMap()).thenReturn(singletonMap("SAMLResponse", new String[]{samlResponseEncoded}));
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Auth auth = new Auth(settings, request, response);
		auth.processResponse();
		assertFalse(auth.isAuthenticated());
		assertFalse("root@example.com".equals(auth.getNameId()));
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

		assertThat(auth.getLastAssertionId(), is("pfxeac87197-11cb-ec12-c181-ae739b54debe"));
		assertThat(auth.getLastAssertionNotOnOrAfter(), contains(new Instant("2023-08-23T06:57:01Z")));
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
		assertEquals(1692773821000L, auth2.getSessionExpiration().getMillis());
	}

	/**
	 * Tests the login method of Auth
	 * Case: Login with no parameters
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLogin() throws IOException, SettingsException, URISyntaxException {
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
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLoginWithRelayState() throws IOException, SettingsException, URISyntaxException {
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
	 * Case: Signed Login but no sp key
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test(expected=Exception.class)
	public void testLoginSignedFail() throws IOException, SettingsException, URISyntaxException {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");		
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setAuthnRequestsSigned(true);
		settings.setSignatureAlgorithm(Constants.RSA_SHA1);
		Auth auth = new Auth(settings, request, response);
		String relayState = "http://localhost:8080/expected.jsp";
		auth.login(relayState);
	}
	
	/**
	 * Tests the login method of Auth
	 * Case: Signed Login
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.Auth#login
	 */
	@Test
	public void testLoginSigned() throws IOException, SettingsException, URISyntaxException {
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
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test
	public void testLogout() throws IOException, SettingsException, XMLEntityException {
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
	 * Case: Logout with RelayState
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test
	public void testLogoutWithRelayState() throws IOException, SettingsException, XMLEntityException {
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
	 * Case: Signed Logout but no sp key
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test(expected=Exception.class)
	public void testLogoutSignedFail() throws IOException, SettingsException, XMLEntityException {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(request.getScheme()).thenReturn("http");
		when(request.getServerPort()).thenReturn(8080);
		when(request.getServerName()).thenReturn("localhost");		
		when(request.getRequestURI()).thenReturn("/initial.jsp");

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setLogoutRequestSigned(true);
		settings.setSignatureAlgorithm(Constants.RSA_SHA1);
		Auth auth = new Auth(settings, request, response);
		String relayState = "http://localhost:8080/expected.jsp";
		auth.logout(relayState);
	}
	
	/**
	 * Tests the logout method of Auth
	 * Case: Signed Logout
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.Auth#logout
	 */
	@Test
	public void testLogoutSigned() throws IOException, SettingsException, XMLEntityException {
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
	 *
	 * @see com.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testBuildRequestSignatureInvalidSP() throws URISyntaxException, IOException, SettingsException {
		String deflatedEncodedAuthNRequest = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String relayState = "http://example.com";
		String signAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

		Auth auth = new Auth("config/config.invalidspcertstring.properties");
		String signature = auth.buildRequestSignature(deflatedEncodedAuthNRequest, relayState, signAlgorithm);
	}

	/**
	 * Tests the buildRequestSignature method
	 * Case RsaSha1
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws SettingsException
	 *
	 * @see ccom.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test
	public void testBuildRequestSignatureRsaSha1() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testBuildRequestSignatureDsaSha1() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Authl#buildRequestSignature
	 */
	@Test
	public void testBuildRequestSignatureRsaSha256() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test
	public void testBuildRequestSignatureRsaSha384() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Auth#buildRequestSignature
	 */
	@Test
	public void testBuildRequestSignatureRsaSha512() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see ccom.onelogin.saml2.Auth#buildResponseSignature
	 */
	@Test
	public void testBuildResponseSignatureRsaSha1() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Auth#buildResponseSignature
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testBuildResponseSignatureDsaSha1() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Authl#buildResponseSignature
	 */
	@Test
	public void testBuildResponseSignatureRsaSha256() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Auth#buildResponseSignature
	 */
	@Test
	public void testBuildResponseSignatureRsaSha384() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Auth#buildResponseSignature
	 */
	@Test
	public void testBuildResponseSignatureRsaSha512() throws URISyntaxException, IOException, SettingsException {
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
	 *
	 * @see com.onelogin.saml2.Auth#buildSignature
	 */
	@Test
	public void testBuildSignature() throws URISyntaxException, IOException, SettingsException {
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
	}
	
}
