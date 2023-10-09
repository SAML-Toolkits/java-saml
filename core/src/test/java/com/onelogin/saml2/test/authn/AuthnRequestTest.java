package com.onelogin.saml2.test.authn;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.authn.AuthnRequestParams;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Util;

public class AuthnRequestTest {

	/**
	 * Tests the getEncodedAuthnRequest method of AuthnRequest
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest#getEncodedAuthnRequest
	 */
	@Test
	public void testGetEncodedAuthnRequestSimulated() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		final String authnRequestString = Util.getFileAsString("data/requests/authn_request.xml");
		AuthnRequest authnRequest = new AuthnRequest(settings) {
			@Override
			public String getAuthnRequestXml() {
				return authnRequestString;
			}
		};

		String expectedAuthnRequestStringBase64Deflated = Util.getFileAsString("data/requests/authn_request.xml.deflated.base64");
		String expectedAuthnRequestStringBase64 = Util.getFileAsString("data/requests/authn_request.xml.base64");

		String authnRequestStringBase64Deflated = authnRequest.getEncodedAuthnRequest();
		assertEquals(authnRequestStringBase64Deflated, expectedAuthnRequestStringBase64Deflated);

		authnRequestStringBase64Deflated = authnRequest.getEncodedAuthnRequest(null);
		assertEquals(authnRequestStringBase64Deflated, expectedAuthnRequestStringBase64Deflated);

		authnRequestStringBase64Deflated = authnRequest.getEncodedAuthnRequest(true);
		assertEquals(authnRequestStringBase64Deflated, expectedAuthnRequestStringBase64Deflated);

		authnRequestStringBase64Deflated = authnRequest.getEncodedAuthnRequest(false);
		assertNotEquals(authnRequestStringBase64Deflated, expectedAuthnRequestStringBase64Deflated);
		assertEquals(authnRequestStringBase64Deflated,expectedAuthnRequestStringBase64);
		
		settings.setCompressRequest(true);		
		authnRequest = new AuthnRequest(settings) {
			@Override
			public String getAuthnRequestXml() {
				return authnRequestString;
			}
		};
		authnRequestStringBase64Deflated = authnRequest.getEncodedAuthnRequest(null);
		assertEquals(authnRequestStringBase64Deflated, expectedAuthnRequestStringBase64Deflated);

		settings.setCompressRequest(false);
		authnRequest = new AuthnRequest(settings) {
			@Override
			public String getAuthnRequestXml() {
				return authnRequestString;
			}
		};
		authnRequestStringBase64Deflated = authnRequest.getEncodedAuthnRequest(null);
		assertNotEquals(authnRequestStringBase64Deflated, expectedAuthnRequestStringBase64Deflated);
		assertEquals(authnRequestStringBase64Deflated, expectedAuthnRequestStringBase64);
	}

	/**
	 * Tests the getEncodedAuthnRequest method of AuthnRequest
	 * Case: Only settings provided.
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest#getEncodedAuthnRequest
	 */
	@Test
	public void testGetEncodedAuthnRequestOnlySettings() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("ProviderName=\"SP Java Example\"")));
		
		settings = new SettingsBuilder().fromFile("config/config.all.properties").build();
		authnRequest = new AuthnRequest(settings);
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("ProviderName=\"SP Java Example\""));
	}

	/**
	 * Tests the getEncodedAuthnRequest method of AuthnRequest
	 * <p>
	 * Case: Only settings provided and containing special chars.
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest#getEncodedAuthnRequest
	 */
	@Test
	public void testGetEncodedAuthnRequestOnlySettingsSpecialChars() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min_specialchars.properties").build();
		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("ProviderName=\"S&amp;P Java Example\"")));
		
		settings = new SettingsBuilder().fromFile("config/config.all_specialchars.properties").build();
		authnRequest = new AuthnRequest(settings);
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("ProviderName=\"S&amp;P Java &quot;Example&quot;\""));
	}

	/**
	 * Tests the getAuthnRequestXml method of AuthnRequest
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest#getAuthnRequestXml
	 */
	@Test
	public void testGetAuthnRequestXml() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestXML = authnRequest.getAuthnRequestXml();
		assertThat(authnRequestXML, containsString("<samlp:AuthnRequest"));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with the different values of ForceAuthn
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testForceAuthN() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("ForceAuthn=\"true\"")));

		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, false));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("ForceAuthn=\"true\"")));		

		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(true, false, false));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("ForceAuthn=\"true\""));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with the different values of IsPassive
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testIsPassive() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("IsPassive=\"true\"")));

		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, false));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("IsPassive=\"true\"")));		

		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, true, false));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("IsPassive=\"true\""));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with and without NameIDPolicy
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testNameIDPolicy() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:NameIDPolicy"));
		assertThat(authnRequestStr, containsString("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\""));

		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, false));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("<samlp:NameIDPolicy")));		

		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, true));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:NameIDPolicy"));
		assertThat(authnRequestStr, containsString("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\""));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with NameIDPolicy with and without AllowCreate
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testAllowCreate() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		// by default setNameIdPolicy=true, allowCreate=true
		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:NameIDPolicy"));
		assertThat(authnRequestStr, containsString("AllowCreate=\"true\""));

		// explicit setNameIdPolicy=true, by default allowCreate=true
		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, true));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:NameIDPolicy"));
		assertThat(authnRequestStr, containsString("AllowCreate=\"true\""));

		// explicit setNameIdPolicy=true, explicit allowCreate=true
		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, true, true));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);	
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:NameIDPolicy"));
		assertThat(authnRequestStr, containsString("AllowCreate=\"true\""));
		
		// explicit setNameIdPolicy=true, explicit allowCreate=false
		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, true, false));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:NameIDPolicy"));
		assertThat(authnRequestStr, not(containsString("AllowCreate=\"true\"")));
		
		// if setNameIdPolicy=false, by default AllowCreate missing
		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, false));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("<samlp:NameIDPolicy")));
		assertThat(authnRequestStr, not(containsString("AllowCreate=\"true\"")));
		
		// if setNameIdPolicy=false explicitly, AllowCreate missing even if explicit allowCreate=true
		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, false, true));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("<samlp:NameIDPolicy")));
		assertThat(authnRequestStr, not(containsString("AllowCreate=\"true\"")));

		// if both setNameIdPolicy=false and allowCreate=false explicitly, of course AllowCreate missing
		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, false, false));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("<samlp:NameIDPolicy")));
		assertThat(authnRequestStr, not(containsString("AllowCreate=\"true\"")));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with NameIDPolicy Encrypted
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testCreateEncPolicySAMLRequest() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.all.properties").build();

		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:NameIDPolicy"));
		assertThat(authnRequestStr, containsString("Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted\""));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with and without AuthNContext
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testAuthNContext() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		List<String> requestedAuthnContext = new ArrayList<String>();
		settings.setRequestedAuthnContext(requestedAuthnContext);

		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("<samlp:RequestedAuthnContext")));

		requestedAuthnContext.add("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
		settings.setRequestedAuthnContext(requestedAuthnContext);
		authnRequest = new AuthnRequest(settings);
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:RequestedAuthnContext Comparison=\"exact\">"));
		assertThat(authnRequestStr, containsString("<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>"));

		requestedAuthnContext.add("urn:oasis:names:tc:SAML:2.0:ac:classes:X509");
		settings.setRequestedAuthnContext(requestedAuthnContext);
		settings.setRequestedAuthnContext(requestedAuthnContext);
		authnRequest = new AuthnRequest(settings);
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:RequestedAuthnContext Comparison=\"exact\">"));
		assertThat(authnRequestStr, containsString("<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>"));
		assertThat(authnRequestStr, containsString("<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:X509</saml:AuthnContextClassRef>"));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with and without AuthNContext
	 * <p>
	 * Case: AuthnContextClassRef contains custom URN with special chars.
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testAuthNContextSpecialChars() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min_specialchars.properties").build();

		List<String> requestedAuthnContext = new ArrayList<String>();
		settings.setRequestedAuthnContext(requestedAuthnContext);

		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("<samlp:RequestedAuthnContext")));

		requestedAuthnContext.add("urn:custom:a&b");
		settings.setRequestedAuthnContext(requestedAuthnContext);
		authnRequest = new AuthnRequest(settings);
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:RequestedAuthnContext Comparison=\"exact\">"));
		assertThat(authnRequestStr, containsString("<saml:AuthnContextClassRef>urn:custom:a&amp;b</saml:AuthnContextClassRef>"));

		requestedAuthnContext.add("urn:oasis:names:tc:SAML:2.0:ac:classes:X509");
		settings.setRequestedAuthnContext(requestedAuthnContext);
		settings.setRequestedAuthnContext(requestedAuthnContext);
		authnRequest = new AuthnRequest(settings);
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<samlp:RequestedAuthnContext Comparison=\"exact\">"));
		assertThat(authnRequestStr, containsString("<saml:AuthnContextClassRef>urn:custom:a&amp;b</saml:AuthnContextClassRef>"));
		assertThat(authnRequestStr, containsString("<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:X509</saml:AuthnContextClassRef>"));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with and without Subject
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testSubject() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("<saml:Subject")));

		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, false, "testuser@example.com"));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<saml:Subject"));
		assertThat(authnRequestStr, containsString("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">testuser@example.com</saml:NameID>"));
		assertThat(authnRequestStr, containsString("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"));

		settings = new SettingsBuilder().fromFile("config/config.emailaddressformat.properties").build();
		authnRequest = new AuthnRequest(settings, new AuthnRequestParams(false, false, false, "testuser@example.com"));
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<saml:Subject"));
		assertThat(authnRequestStr, containsString("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">testuser@example.com</saml:NameID>"));
		assertThat(authnRequestStr, containsString("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with and without Subject
	 * <p>
	 * Case: subject contains special chars.
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testSubjectSpecialChars() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min_specialchars.properties").build();

		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("<saml:Subject")));

		authnRequest = new AuthnRequest(settings, false, false, false, "t&stuser@example.com");
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("<saml:Subject"));
		assertThat(authnRequestStr, containsString("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">t&amp;stuser@example.com</saml:NameID>"));
		assertThat(authnRequestStr, containsString("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"));
	}

	/**
	 * Tests the getId method of AuthnRequest
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest.getId
	 */
	@Test
	public void testGetId() throws Exception
	{
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		AuthnRequest authnRequest = new AuthnRequest(settings);
		final String authnRequestStr = Util.base64decodedInflated(authnRequest.getEncodedAuthnRequest());

		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("ID=\"" + authnRequest.getId() + "\""));
	}

	/**
	 * Tests the getId method of AuthnRequest
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest.getId
	 */
	@Test
	public void testGetIssueInstant() throws Exception
	{
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		final long start = System.currentTimeMillis();
		AuthnRequest authnRequest = new AuthnRequest(settings);
		final long end = System.currentTimeMillis();
		final String authnRequestStr = Util.base64decodedInflated(authnRequest.getEncodedAuthnRequest());

		final Calendar issueInstant = authnRequest.getIssueInstant();
		assertNotNull(issueInstant);
		final long millis = issueInstant.getTimeInMillis();
		assertTrue(millis >= start && millis <= end);
		
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("IssueInstant=\"" + Util.formatDateTime(millis) + "\""));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with and without Destination
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testAuthNDestination() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("Destination=\"http://idp.example.com/simplesaml/saml2/idp/SSOService.php\""));

		settings = new Saml2Settings();
		authnRequest = new AuthnRequest(settings);
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("Destination=\"http://idp.example.com/simplesaml/saml2/idp/SSOService.php\"")));
	}

	/**
	 * Tests the AuthnRequest Constructor
	 * The creation of a deflated SAML Request with and without Destination
	 * <p>
	 * Case: destinations contain special chars.
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest
	 */
	@Test
	public void testAuthNDestinationSpecialChars() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min_specialchars.properties").build();

		AuthnRequest authnRequest = new AuthnRequest(settings);
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		String authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, containsString("Destination=\"http://idp.example.com/simplesaml/saml2/idp/SSOService.php?a=1&amp;b=2\""));

		settings = new Saml2Settings();
		authnRequest = new AuthnRequest(settings);
		authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();
		authnRequestStr = Util.base64decodedInflated(authnRequestStringBase64);
		assertThat(authnRequestStr, containsString("<samlp:AuthnRequest"));
		assertThat(authnRequestStr, not(containsString("Destination=\"http://idp.example.com/simplesaml/saml2/idp/SSOService.php?a=1&amp;b=2\"")));
  }
	
	/**
	 * Tests the postProcessXml method of AuthnRequest
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.AuthnRequest#postProcessXml
	 */
	@Test
	public void testPostProcessXml() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		AuthnRequest authnRequest = new AuthnRequest(settings) {
			@Override
			protected String postProcessXml(String authnRequestXml, AuthnRequestParams params, Saml2Settings sett) {
				assertEquals(authnRequestXml, super.postProcessXml(authnRequestXml, params, sett));
				assertSame(settings, sett);
				return "changed";
			}
		};
		assertEquals("changed", authnRequest.getAuthnRequestXml());
	}
}
