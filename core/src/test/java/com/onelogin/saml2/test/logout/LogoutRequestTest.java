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

import java.util.ArrayList;
import java.util.List;
import java.io.IOException;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPathExpressionException;

import java.security.PrivateKey;

import org.w3c.dom.Document;

import org.junit.Rule;
import org.junit.Test;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.rule.PowerMockRule;

import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.logout.LogoutRequest;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Util;

@PrepareForTest({LogoutRequest.class})
public class LogoutRequestTest {

	@Rule
	public PowerMockRule rule = new PowerMockRule();

	/**
	 * Tests the constructor and the getEncodedLogoutRequest method of LogoutRequest
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#getEncodedLogoutRequest
	 */
	@Test
	public void testGetEncodedLogoutRequestSimulated() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		String logoutRequestString = Util.getFileAsString("data/logout_requests/logout_request.xml");
		LogoutRequest logoutRequest = PowerMockito.spy(new LogoutRequest(settings));
 		PowerMockito.when(logoutRequest, method(LogoutRequest.class, "getLogoutRequestXml")).withNoArguments().thenReturn(
				logoutRequestString);

		String expectedLogoutRequestStringBase64 = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		String logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();

		assertEquals(logoutRequestStringBase64, expectedLogoutRequestStringBase64);
	}

	/**
	 * Tests the constructor and the getEncodedAuthnRequest method of LogoutRequest
	 * Case: Only settings
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest
	 */
	@Test
	public void testConstructor() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		LogoutRequest logoutRequest = new LogoutRequest(settings); 

		String logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		String logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);

		assertThat(logoutRequestStr, containsString("<samlp:LogoutRequest"));
		assertThat(logoutRequestStr, containsString("ID=\"" + logoutRequest.getId() + "\""));
		assertThat(logoutRequestStr, not(containsString("<samlp:SessionIndex>")));
	}

	/**
	 * Tests the constructor and the getEncodedAuthnRequest method of LogoutRequest
	 * Case: settings + request
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest
	 */
	@Test
	public void testConstructorWithRequest() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequest = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequest);
		when(request.getRequestURL()).thenReturn(new StringBuffer( "/"));

		LogoutRequest logoutRequest = new LogoutRequest(settings, request);

		String logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		String logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
	}

	/**
	 * Tests the constructor and the getEncodedAuthnRequest method of LogoutRequest
	 * Case: session index
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest
	 */
	@Test
	public void testConstructorWithSessionIndex() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String sessionIndex = "_51be37965feb5579d803141076936dc2e9d1d98ebf";
		LogoutRequest logoutRequest = new LogoutRequest(settings, null, null, sessionIndex); 
		String logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		String logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		String expectedSessionIndex = "<samlp:SessionIndex>_51be37965feb5579d803141076936dc2e9d1d98ebf</samlp:SessionIndex>";
		assertThat(logoutRequestStr, containsString("<samlp:LogoutRequest"));
		assertThat(logoutRequestStr, containsString(expectedSessionIndex));

		logoutRequest = new LogoutRequest(settings, null, null, null);
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutRequest"));
		assertThat(logoutRequestStr, not(containsString("<samlp:SessionIndex>")));
	}

	/**
	 * Tests the constructor and the getEncodedAuthnRequest method of LogoutRequest
	 * Case: encrypted NameId
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest
	 */
	@Test
	public void testConstructorWithEncryptedNameID() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		LogoutRequest logoutRequest = new LogoutRequest(settings); 
		String logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		String logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<saml:EncryptedID><xenc:EncryptedData"));

		settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		logoutRequest = new LogoutRequest(settings);
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, not(containsString("<saml:EncryptedID><xenc:EncryptedData")));
	}
	
	/**
	 * Tests the getNameIdData method of LogoutRequest
	 * Case: Able to get the NameIdData
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameIdData
	 */
	@Test
	public void testGetNameIdData() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		LogoutRequest logoutRequest = new LogoutRequest(settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null); 
		String logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		String logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutRequest"));
		String nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, null).toString();
		assertThat(nameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"));
		assertThat(nameIdDataStr, containsString("Value=ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c"));
		assertThat(nameIdDataStr, not(containsString("SPNameQualifier")));

		logoutRequest = new LogoutRequest(settings, null, null, null);
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutRequest"));
		
		nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, null).toString();
		assertThat(nameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:2.0:nameid-format:entity"));
		assertThat(nameIdDataStr, containsString("Value=http://idp.example.com/"));
		assertThat(nameIdDataStr, containsString("SPNameQualifier=http://localhost:8080/java-saml-jspsample/metadata.jsp"));

		// This settings file contains as IdP cert the SP cert, so I can use the getSPkey to decrypt.
		settings = new SettingsBuilder().fromFile("config/config.samecerts.properties").build();
		logoutRequest = new LogoutRequest(settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null); 
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		PrivateKey key = settings.getSPkey();
		nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, key).toString();
		assertThat(nameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"));
		assertThat(nameIdDataStr, containsString("Value=ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c"));
		assertThat(nameIdDataStr, not(containsString("SPNameQualifier")));	

  	    String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
  	    key = Util.loadPrivateKey(keyString);
		logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");
		nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, key).toString();
		assertThat(nameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"));
		assertThat(nameIdDataStr, containsString("Value=ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69"));
		assertThat(nameIdDataStr, containsString("SPNameQualifier=https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php"));
	}

	/**
	 * Tests the getId method of LogoutRequest
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#getId
	 */
	@Test
	public void testGetId() throws Exception {
		String samlRequest = Util.getFileAsString("data/logout_requests/logout_request.xml");
		String id = LogoutRequest.getId(samlRequest);
		String expectedId = "ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e";
		assertEquals(expectedId, id);

		Document samlRequestDoc = Util.loadXML(samlRequest);
		id = LogoutRequest.getId(samlRequestDoc);
		assertEquals(expectedId, id);
		
		assertNull(LogoutRequest.getId(""));
	}
	
	/**
	 * Tests the getNameIdData method of LogoutRequest
	 * Case: Not able to get the NameIdData due no private key to decrypt
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameIdData
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testGetNameIdDataNoKey() throws Exception {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");
		String nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, null).toString();
	}

	/**
	 * Tests the getNameIdData method of LogoutRequest
	 * Case: Not able to get the NameIdData due wrong private key to decrypt.
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameIdData
	 */
	@Test(expected=Exception.class)
	public void testGetNameIdDataWrongKey() throws Exception {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");
		String keyString = Util.getFileAsString("data/misc/sp3.key");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, key).toString();
	}

	/**
	 * Tests the getNameIdData method of LogoutRequest
	 * Case: Not NameId element.
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameIdData
	 */
	@Test(expected=Exception.class)
	public void testGetNameIdDataNoNameId() throws Exception {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_no_nameid.xml");
		String nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, null).toString();
	}

	/**
	 * Tests the getNameId method of LogoutRequest
	 * Case: Able to get the NameID
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameId
	 */
	@Test
	public void testGetNameId() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		LogoutRequest logoutRequest = new LogoutRequest(settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null); 
		String logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		String logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutRequest"));
		String expectedNameIdStr = "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c";
		String nameIdStr = LogoutRequest.getNameId(logoutRequestStr, null).toString();
		assertEquals(expectedNameIdStr, nameIdStr);

		logoutRequest = new LogoutRequest(settings, null, null, null);
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutRequest"));
		expectedNameIdStr = "http://idp.example.com/";
		nameIdStr = LogoutRequest.getNameId(logoutRequestStr, null).toString();
		assertEquals(expectedNameIdStr, nameIdStr);

		nameIdStr = LogoutRequest.getNameId(logoutRequestStr).toString();
		assertEquals(expectedNameIdStr, nameIdStr);

		Document logoutRequestDoc = Util.loadXML(logoutRequestStr);
		nameIdStr = LogoutRequest.getNameId(logoutRequestDoc).toString();
		assertEquals(expectedNameIdStr, nameIdStr);

		// This settings file contains as IdP cert the SP cert, so I can use the getSPkey to decrypt.
		settings = new SettingsBuilder().fromFile("config/config.samecerts.properties").build();
		logoutRequest = new LogoutRequest(settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null); 
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		PrivateKey key = settings.getSPkey();
		nameIdStr = LogoutRequest.getNameId(logoutRequestStr, key).toString();
		expectedNameIdStr = "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c";
		assertEquals(expectedNameIdStr, nameIdStr);

		String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
		key = Util.loadPrivateKey(keyString);
		logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");
		nameIdStr = LogoutRequest.getNameId(logoutRequestStr, key).toString();
		expectedNameIdStr = "ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69";
		assertEquals(expectedNameIdStr, nameIdStr);

		logoutRequestDoc = Util.loadXML(logoutRequestStr);
		nameIdStr = LogoutRequest.getNameId(logoutRequestDoc, key).toString();
		assertEquals(expectedNameIdStr, nameIdStr);
	}

	/**
	 * Tests the getNameId method of LogoutRequest
	 * Case: Not able to get the NameID due no private key to decrypt
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameId
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testGetNameIdNoKey() throws Exception {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");
		String nameIdStr = LogoutRequest.getNameId(logoutRequestStr, null).toString();
	}

	/**
	 * Tests the getNameId method of LogoutRequest
	 * Case: Not able to get the NameID due wrong private key to decrypt.
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameId
	 */
	@Test(expected=Exception.class)
	public void testGetNameIdWrongKey() throws Exception {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");
		String keyString = Util.getFileAsString("data/misc/sp3.key");
		PrivateKey key = Util.loadPrivateKey(keyString);
		String nameIdStr = LogoutRequest.getNameIdData(logoutRequestStr, key).toString();
	}

	/**
	 * Tests the getIssuer method of LogoutRequest
	 *
	 * @throws IOException
	 * @throws URISyntaxException 
	 * @throws XMLEntityException
	 * @throws XPathExpressionException 
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#getIssuer
	 */
	@Test
	public void testGetIssuer() throws URISyntaxException, IOException, XPathExpressionException, XMLEntityException {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request.xml");
		String expectedIssuer = "http://idp.example.com/";
		String issuer = LogoutRequest.getIssuer(logoutRequestStr);
		assertEquals(expectedIssuer, issuer);

		logoutRequestStr = logoutRequestStr.replace("<saml:Issuer>http://idp.example.com/</saml:Issuer>", "");
		issuer = LogoutRequest.getIssuer(logoutRequestStr);
		assertNull(issuer);
	}

	/**
	 * Tests the getSessionIndexes method of LogoutRequest
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#getSessionIndexes
	 */
	@Test
	public void testGetSessionIndexes() throws URISyntaxException, IOException, XPathExpressionException, XMLEntityException {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request.xml");
		List<String> expectedIndexes = new ArrayList<String>();
		List <String> indexes = LogoutRequest.getSessionIndexes(logoutRequestStr);
		assertEquals(expectedIndexes, indexes);

		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String sessionIndex = "_51be37965feb5579d803141076936dc2e9d1d98ebf";
		expectedIndexes.add(sessionIndex);
		LogoutRequest logoutRequest = new LogoutRequest(settings, null, null, sessionIndex); 
		String logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		indexes = LogoutRequest.getSessionIndexes(logoutRequestStr);
		assertEquals(expectedIndexes, indexes);
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: Invalid Issuer
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsInvalidIssuer() throws URISyntaxException, IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequest = Util.getFileAsString("data/logout_requests/invalids/invalid_issuer.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequest);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));

		settings.setStrict(false);
		LogoutRequest logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, request);
		assertFalse(logoutRequest.isValid());
		assertEquals("Invalid issuer in the Logout Request", logoutRequest.getError());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: Invalid XML
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsInValidWrongXML() throws URISyntaxException, IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequest = Util.getFileAsString("data/logout_requests/invalids/invalid_xml.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequest);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));

		settings.setWantXMLValidation(true);
		settings.setStrict(false);
		LogoutRequest logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, request);
		assertFalse(logoutRequest.isValid());
		assertEquals("Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd", logoutRequest.getError());

		settings.setWantXMLValidation(false);
		logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());
		
		settings.setStrict(false);
		logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: Invalid Destination
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsInvalidDestination() throws URISyntaxException, IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequest = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequest);
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));

		settings.setStrict(false);
		LogoutRequest logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, request);
		assertFalse(logoutRequest.isValid());
		assertThat(logoutRequest.getError(), containsString("The LogoutRequest was received at"));
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: Invalid NotOnOrAfter
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsInvalidNotOnOrAfter() throws URISyntaxException, IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequest = Util.getFileAsString("data/logout_requests/invalids/not_after_failed.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequest);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));

		settings.setStrict(false);
		LogoutRequest logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, request);
		assertFalse(logoutRequest.isValid());
		assertEquals("Timing issues (please check your clock settings)", logoutRequest.getError());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsValid() throws URISyntaxException, IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequest = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequest);
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));

		settings.setStrict(true);
		LogoutRequest logoutRequest = new LogoutRequest(settings, request);
		assertFalse(logoutRequest.isValid());

		settings.setStrict(false);
		logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());

		when(request.getRequestURL()).thenReturn(new StringBuffer("http://stuff.com/endpoints/endpoints/sls.php"));
		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(false);
		logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsInValidSign() throws URISyntaxException, IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setStrict(false);
		settings.setWantMessagesSigned(true);

		String samlRequest = "lVLBitswEP0Vo7tjeWzJtki8LIRCYLvbNksPewmyPc6K2pJqyXQ/v1LSQlroQi/DMJr33rwZbZ2cJysezNms/gt+X9H55G2etBOXlx1ZFy2MdMoJLWd0wvfieP/xQcCGCrsYb3ozkRvI+wjpHC5eGU2Sw35HTg3lA8hqZFwWFcMKsStpxbEsxoLXeQN9OdY1VAgk+YqLC8gdCUQB7tyKB+281D6UaF6mtEiBPudcABcMXkiyD26Ulv6CevXeOpFlVvlunb5ttEmV3ZjlnGn8YTRO5qx0NuBs8kzpAd829tXeucmR5NH4J/203I8el6gFRUqbFPJnyEV51Wq30by4TLW0/9ZyarYTxt4sBsjUYLMZvRykl1Fxm90SXVkfwx4P++T4KSafVzmpUcVJ/sfSrQZJPphllv79W8WKGtLx0ir8IrVTqD1pT2MH3QAMSs4KTvui71jeFFiwirOmprwPkYW063+5uRq4urHiiC4e8hCX3J5wqAEGaPpw9XB5JmkBdeDqSlkz6CmUXdl0Qae5kv2F/1384wu3PwE=";
		String relayState = "_1037fbc88ec82ce8e770b2bed1119747bb812a07e6";
		String sigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
		String signature = "XCwCyI5cs7WhiJlB5ktSlWxSBxv+6q2xT3c8L7dLV6NQG9LHWhN7gf8qNsahSXfCzA0Ey9dp5BQ0EdRvAk2DIzKmJY6e3hvAIEp1zglHNjzkgcQmZCcrkK9Czi2Y1WkjOwR/WgUTUWsGJAVqVvlRZuS3zk3nxMrLH6f7toyvuJc=";
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequest);
		when(request.getParameter("RelayState")).thenReturn(relayState);
		when(request.getParameter("SigAlg")).thenReturn(sigAlg);
		when(request.getParameter("Signature")).thenReturn(signature);
		when(request.getRequestURL()).thenReturn(new StringBuffer("https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls"));

		LogoutRequest logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(false);
		String signature2 = "vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333=";
		when(request.getParameter("Signature")).thenReturn(signature2);
		logoutRequest = new LogoutRequest(settings, request);
		assertFalse(logoutRequest.isValid());
		assertEquals("Signature validation failed. Logout Request rejected", logoutRequest.getError());

		when(request.getParameter("Signature")).thenReturn(signature);
		when(request.getParameter("SigAlg")).thenReturn(null);
		logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());

		when(request.getParameter("Signature")).thenReturn(null);
		logoutRequest = new LogoutRequest(settings, request);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, request);
		assertFalse(logoutRequest.isValid());
		assertEquals("The Message of the Logout Request is not signed and the SP requires it", logoutRequest.getError());

		when(request.getParameter("Signature")).thenReturn(signature);
		settings = new SettingsBuilder().fromFile("config/config.mywithnocert.properties").build();
		logoutRequest = new LogoutRequest(settings, request);
		assertFalse(logoutRequest.isValid());
		assertEquals("In order to validate the sign on the Logout Request, the x509cert of the IdP is required", logoutRequest.getError());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: No SAML Logout Request
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsValidNoLogoutRequest() throws IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLRequest")).thenReturn("");
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));

		LogoutRequest logoutRequest = new LogoutRequest(settings, request);
		assertFalse(logoutRequest.isValid());
		assertEquals("SAML Logout Request is not loaded", logoutRequest.getError());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: No current URL
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws URISyntaxException
	 * 
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsValidNoCurrentURL() throws IOException, XMLEntityException, URISyntaxException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequest = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequest);
		when(request.getRequestURL()).thenReturn(null);

		LogoutRequest logoutRequest = new LogoutRequest(settings);
		assertFalse(logoutRequest.isValid());
		assertEquals("The HttpServletRequest of the current host was not established", logoutRequest.getError());

		when(request.getRequestURL()).thenReturn(new StringBuffer(""));
		logoutRequest = new LogoutRequest(settings, request);		
		assertFalse(logoutRequest.isValid());
		assertEquals("The URL of the current host was not established", logoutRequest.getError());
	}

	/**
	 * Tests the getError method of LogoutRequest
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#getError
	 */
	@Test
	public void testGetError() throws URISyntaxException, IOException, XMLEntityException {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(true);
		String samlRequest = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLRequest")).thenReturn(samlRequest);
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));
		LogoutRequest logoutRequest = new LogoutRequest(settings, request);
		assertNull(logoutRequest.getError());
		logoutRequest.isValid();
		assertThat(logoutRequest.getError(), containsString("The LogoutRequest was received at"));

		settings.setStrict(false);
		logoutRequest = new LogoutRequest(settings, request);
		assertNull(logoutRequest.getError());
		logoutRequest.isValid();
		assertNull(logoutRequest.getError());
	}
}