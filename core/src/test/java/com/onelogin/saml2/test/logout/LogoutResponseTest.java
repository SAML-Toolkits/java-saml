package com.onelogin.saml2.test.logout;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.powermock.api.support.membermodification.MemberMatcher.method;

import java.io.IOException;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPathExpressionException;

import org.junit.Rule;
import org.junit.Test;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.rule.PowerMockRule;

import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.logout.LogoutResponse;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Util;
import com.onelogin.saml2.util.Constants;

@PrepareForTest({LogoutResponse.class})
public class LogoutResponseTest {

	@Rule
	public PowerMockRule rule = new PowerMockRule();

	/**
	 * Tests the constructor, the build and the getEncodedLogoutResponse method of LogoutResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#getEncodedLogoutResponse
	 */
	@Test
	public void testGetEncodedLogoutResponseSimulated() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		String logoutResponseString = Util.getFileAsString("data/logout_responses/logout_response.xml");

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer( "/"));

		LogoutResponse logoutResponseBuilder = PowerMockito.spy(new LogoutResponse(settings, request));
 		PowerMockito.when(logoutResponseBuilder, method(LogoutResponse.class, "getLogoutResponseXml")).withNoArguments().thenReturn(
 				logoutResponseString);

 		logoutResponseBuilder.build();

		String expectedLogoutResponseStringBase64 = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		String logoutResponseStringBase64 = logoutResponseBuilder.getEncodedLogoutResponse();

		assertEquals(logoutResponseStringBase64, expectedLogoutResponseStringBase64);

		LogoutResponse logoutResponse = PowerMockito.spy(new LogoutResponse(settings, request));
 		PowerMockito.when(logoutResponse, method(LogoutResponse.class, "getLogoutResponseXml")).withNoArguments().thenReturn(
 				logoutResponseString);
 		logoutResponseStringBase64 = logoutResponse.getEncodedLogoutResponse();
 		assertEquals(logoutResponseStringBase64, expectedLogoutResponseStringBase64);
	}

	/**
	 * Tests the constructor
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws URISyntaxException
	 * 
	 * @see com.onelogin.saml2.logout.LogoutResponse
	 */
	@Test
	public void testConstructor() throws IOException, XMLEntityException, URISyntaxException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		when(request.getRequestURL()).thenReturn(new StringBuffer( "/"));

		String expectedLogoutResponseStringBase64 = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		String logoutResponseStringBase64 = logoutResponse.getEncodedLogoutResponse();
		assertEquals(logoutResponseStringBase64, expectedLogoutResponseStringBase64);
	}

	/**
	 * Tests the build method of LogoutResponse
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws URISyntaxException
	 * 
	 * @see com.onelogin.saml2.logout.LogoutResponse#build
	 */
	@Test
	public void testBuild() throws IOException, XMLEntityException, URISyntaxException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer( "/"));

		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertFalse(logoutResponse.isValid());
		assertEquals("SAML Logout Response is not loaded", logoutResponse.getError());
		logoutResponse.build();
		String logoutRequestStringBase64 = logoutResponse.getEncodedLogoutResponse();
		assertFalse(logoutRequestStringBase64.isEmpty());

		String logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutResponse"));
		assertThat(logoutRequestStr, not(containsString("InResponseTo=")));
		
		LogoutResponse logoutResponse2 = new LogoutResponse(settings, request);
		logoutResponse2.build("inResponseValue");
		logoutRequestStringBase64 = logoutResponse2.getEncodedLogoutResponse();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutResponse"));
		assertThat(logoutRequestStr, containsString("InResponseTo=\"inResponseValue\""));
	}

	/**
	 * Tests the getStatus method of LogoutResponse
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#getStatus
	 */
	@Test
	public void testGestStatus() throws IOException, URISyntaxException, XMLEntityException, XPathExpressionException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		when(request.getRequestURL()).thenReturn(new StringBuffer( "/"));
		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertEquals(Constants.STATUS_SUCCESS, logoutResponse.getStatus());

		samlResponse = Util.getFileAsString("data/logout_responses/invalids/no_status.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		logoutResponse = new LogoutResponse(settings, request);
		assertNull(logoutResponse.getStatus());
	}

	/**
	 * Tests the getIssuer method of LogoutResponse
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#getIssuer
	 */
	@Test
	public void testGetIssuer() throws IOException, URISyntaxException, XMLEntityException, XPathExpressionException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		when(request.getRequestURL()).thenReturn(new StringBuffer( "/"));
		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		String expectedIssuer = "http://idp.example.com/";
		assertEquals(expectedIssuer, logoutResponse.getIssuer());
		
		String logoutRequestStr = Util.base64decodedInflated(samlResponse);
		logoutRequestStr = logoutRequestStr.replace("<saml:Issuer>http://idp.example.com/</saml:Issuer>", "");
		samlResponse = Util.deflatedBase64encoded(logoutRequestStr);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		logoutResponse = new LogoutResponse(settings, request);
		assertNull(logoutResponse.getIssuer());		
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: No SAML Logout Response
	 *
	 * @throws XMLEntityException
	 * @throws IOException
	 * 
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsValidNoResponse() throws XMLEntityException, IOException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn("");
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));

		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertFalse(logoutResponse.isValid());
		assertEquals("SAML Logout Response is not loaded", logoutResponse.getError());

		when(request.getParameter("SAMLResponse")).thenReturn(null);
		logoutResponse = new LogoutResponse(settings, request);
		assertFalse(logoutResponse.isValid());
		assertEquals("SAML Logout Response is not loaded", logoutResponse.getError());		
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: Case invalid request Id
	 *
	 * @throws XMLEntityException
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsInValidRequestId() throws XMLEntityException, IOException, URISyntaxException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		
		settings.setStrict(false);
		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		assertTrue(logoutResponse.isValid("invalid_request_id"));
		
		settings.setStrict(true);
		logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		assertFalse(logoutResponse.isValid("invalid_request_id"));
		assertThat(logoutResponse.getError(), containsString("The InResponseTo of the Logout Response"));
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: Case invalid Issuer
	 *
	 * @throws XMLEntityException
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsInValidIssuer() throws XMLEntityException, IOException, URISyntaxException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponse = Util.getFileAsString("data/logout_responses/invalids/invalid_issuer.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		
		settings.setStrict(false);
		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(true);
		assertFalse(logoutResponse.isValid());
		assertEquals("Invalid issuer in the Logout Response", logoutResponse.getError());		
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: Case invalid xml
	 *
	 * @throws XMLEntityException
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsInValidWrongXML() throws XMLEntityException, IOException, URISyntaxException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponse = Util.getFileAsString("data/logout_responses/invalids/invalid_xml.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));

		settings.setWantXMLValidation(true);
		settings.setStrict(false);
		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(true);
		logoutResponse = new LogoutResponse(settings, request);
		assertFalse(logoutResponse.isValid());
		assertEquals("Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd", logoutResponse.getError());

		settings.setWantXMLValidation(false);
		logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());
		
		settings.setStrict(false);
		logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: Case invalid Destination
	 *
	 * @throws XMLEntityException
	 * @throws IOException
	 * @throws URISyntaxException
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsInValidDestination() throws XMLEntityException, IOException, URISyntaxException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));

		settings.setStrict(false);
		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(true);
		assertFalse(logoutResponse.isValid());
		assertThat(logoutResponse.getError(), containsString("The LogoutResponse was received at"));
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsValid() throws URISyntaxException, IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));

		settings.setStrict(true);
		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertFalse(logoutResponse.isValid());

		settings.setStrict(false);
		logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		settings.setStrict(true);
		logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(false);
		logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsInValidSign() throws URISyntaxException, IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setStrict(false);
		settings.setWantMessagesSigned(true);

		String samlResponse = "fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A";
		String relayState = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php";
		String sigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
		String signature = "vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA=";
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		when(request.getParameter("RelayState")).thenReturn(relayState);
		when(request.getParameter("SigAlg")).thenReturn(sigAlg);
		when(request.getParameter("Signature")).thenReturn(signature);
		when(request.getRequestURL()).thenReturn(new StringBuffer("https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls"));

		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(true);
		logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(false);
		String signature2 = "vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333=";
		when(request.getParameter("Signature")).thenReturn(signature2);
		logoutResponse = new LogoutResponse(settings, request);
		assertFalse(logoutResponse.isValid());
		assertEquals("Signature validation failed. Logout Response rejected", logoutResponse.getError());

		when(request.getParameter("Signature")).thenReturn(signature);
		when(request.getParameter("SigAlg")).thenReturn(null);
		logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		when(request.getParameter("Signature")).thenReturn(null);
		logoutResponse = new LogoutResponse(settings, request);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(true);
		logoutResponse = new LogoutResponse(settings, request);
		assertFalse(logoutResponse.isValid());
		assertEquals("The Message of the Logout Response is not signed and the SP requires it", logoutResponse.getError());

		when(request.getParameter("Signature")).thenReturn(signature);
		settings = new SettingsBuilder().fromFile("config/config.mywithnocert.properties").build();
		logoutResponse = new LogoutResponse(settings, request);
		assertFalse(logoutResponse.isValid());
		assertEquals("In order to validate the sign on the Logout Response, the x509cert of the IdP is required", logoutResponse.getError());
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: No SAML Logout Response
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * 
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsValidNoLogoutResponse() throws IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn("");
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));

		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertFalse(logoutResponse.isValid());
		assertEquals("SAML Logout Response is not loaded", logoutResponse.getError());
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: No current URL
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws URISyntaxException
	 * 
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsValidNoCurrentURL() throws IOException, XMLEntityException, URISyntaxException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponse = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);

		when(request.getRequestURL()).thenReturn(new StringBuffer(""));
		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertFalse(logoutResponse.isValid());
		assertEquals("The URL of the current host was not established", logoutResponse.getError());
	}

	/**
	 * Tests the getError method of LogoutResponse
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#getError
	 */
	@Test
	public void testGetError() throws URISyntaxException, IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(true);
		String samlResponse = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponse);
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));
		LogoutResponse logoutResponse = new LogoutResponse(settings, request);
		assertNull(logoutResponse.getError());
		logoutResponse.isValid();
		assertThat(logoutResponse.getError(), containsString("The LogoutResponse was received at"));

		settings.setStrict(false);
		logoutResponse = new LogoutResponse(settings, request);
		assertNull(logoutResponse.getError());
		logoutResponse.isValid();
		assertNull(logoutResponse.getError());
	}
}