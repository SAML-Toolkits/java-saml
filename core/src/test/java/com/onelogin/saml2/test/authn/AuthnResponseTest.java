package com.onelogin.saml2.test.authn;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.Rule;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.onelogin.saml2.model.SamlResponseStatus;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Util;
import com.onelogin.saml2.util.Constants;

public class AuthnResponseTest {

	/**
	 * Tests the constructor of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse
	 */
	@Test
	public void testConstructor() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer( "/"));

		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse instanceof SamlResponse);

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse instanceof SamlResponse);
	}

	/**
	 * Tests the constructor of SamlResponse
	 * Case: Encrypted assertion but no key
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test(expected=Exception.class)
	public void testEncryptedAssertionNokey() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
	}
	
	/**
	 * Tests the constructor of SamlResponse
	 * Case test namespaces
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse
	 */
	@Test
	public void testNamespaces() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/open_saml_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		HashMap<String, List<String>> attributes = samlResponse.getAttributes();

		assertFalse(attributes.isEmpty());

		assertTrue(attributes.containsKey("FirstName"));
		assertTrue(attributes.containsKey("LastName"));

		List<String> expectedFirstName = new ArrayList<String>();
		expectedFirstName.add("Someone");

		List<String> expectedLastName = new ArrayList<String>();
		expectedLastName.add("Special");

		assertEquals(expectedFirstName, attributes.get("FirstName"));
		assertEquals(expectedLastName, attributes.get("LastName"));
	}

	/**
	 * Tests the getNameId method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test
	public void testGetNameId() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertEquals("support@onelogin.com", samlResponse.getNameId());
		samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");

		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertEquals("2de11defd199f8d5bb63f9b7deb265ba5c675c10", samlResponse.getNameId());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertEquals("_68392312d490db6d355555cfbbd8ec95d746516f60", samlResponse.getNameId());

		settings.setWantNameId(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_nameid.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertNull(samlResponse.getNameId());
	}

	/**
	 * Tests the getNameId method of SamlResponse
	 * Case: No NameId
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test(expected=Exception.class)
	public void testGetNameIdNoNameId() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		settings.setWantNameId(true);
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_nameid.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		String nameId = samlResponse.getNameId();
	}

	/**
	 * Tests the getNameIdData method of SamlResponse
	 * Case: Not able to get the NameIdData due no private key to decrypt
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testGetNameIdDataNoKey() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		String nameId = samlResponse.getNameId();
	}

	/**
	 * Tests the getNameIdData method of SamlResponse
	 * Case: Not able to get the NameIdData due no nameID inside the EncryptedID
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test(expected=Exception.class)
	public void testGetNameIdDataWrongEncryptedData() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/response_encrypted_subconfirm_as_nameid.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		String nameId = samlResponse.getNameId();
	}

	/**
	 * Tests the getNameIdData method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameIdData
	 */
	@Test
	public void testGetNameIdData() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertEquals("{Format=urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress, Value=support@onelogin.com}", samlResponse.getNameIdData().toString());
		samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");

		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		String NameIdDataStr = samlResponse.getNameIdData().toString();
		assertThat(NameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"));
		assertThat(NameIdDataStr, containsString("Value=2de11defd199f8d5bb63f9b7deb265ba5c675c10"));
		assertThat(NameIdDataStr, containsString("SPNameQualifier=https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php"));

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		NameIdDataStr = samlResponse.getNameIdData().toString();
		assertThat(NameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:2.0:nameid-format:transient"));
		assertThat(NameIdDataStr, containsString("Value=_68392312d490db6d355555cfbbd8ec95d746516f60"));
		assertThat(NameIdDataStr, containsString("SPNameQualifier=http://stuff.com/endpoints/metadata.php"));
		
		settings.setWantNameId(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_nameid.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.getNameIdData().isEmpty());
	}

	/**
	 * Tests the getNameIdData method of SamlResponse
	 * Case: No NameId
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameIdData
	 */
	@Test(expected=Exception.class)
	public void testGetNameIdDataNoNameId() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantNameId(true);

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_nameid.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		HashMap<String,String> nameIdData = samlResponse.getNameIdData();
	}

	/**
	 * Tests the checkStatus method of SamlResponse
	 * Case Status = Success
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkStatus
	 */
	@Test
	public void testCheckStatus() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		samlResponse.checkStatus();

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		samlResponse.checkStatus();
	}

	/**
	 * Tests the checkStatus method of SamlResponse
	 * Case Status = Responder
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkStatus
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testCheckStatusResponder() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/status_code_responder.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		samlResponse.checkStatus();
	}

	/**
	 * Tests the checkStatus method of SamlResponse
	 * Case Status = Responder + Msg
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkStatus
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testCheckStatusResponderMsg() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/status_code_responder_and_msg.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		samlResponse.checkStatus();
	}

	/**
	 * Tests the checkStatus method of SamlResponse
	 * Case No Status
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkStatus
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testCheckStatusNoStatus() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_status.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		samlResponse.checkStatus();
	}

	/**
	 * Tests the checkStatus method of SamlResponse
	 * Case No StatusCode
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkStatus
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testCheckStatusNoStatusCode() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_status_code.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		samlResponse.checkStatus();
	}

	/**
	 * Tests the getStatus method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getStatus
	 */
	@Test
	public void testGetStatus() throws Exception {
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		Document samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded))); 
		SamlResponseStatus status = SamlResponse.getStatus(samlResponseDoc);
		assertEquals(Constants.STATUS_SUCCESS, status.getStatusCode());
		assertNull(status.getStatusMessage());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded))); 
		status = SamlResponse.getStatus(samlResponseDoc);
		assertEquals(Constants.STATUS_SUCCESS, status.getStatusCode());
		assertNull(status.getStatusMessage());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/status_code_responder.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded))); 
		status = SamlResponse.getStatus(samlResponseDoc);
		assertEquals(Constants.STATUS_RESPONDER, status.getStatusCode());
		assertNull(status.getStatusMessage());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/status_code_responder_and_msg.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded))); 
		status = SamlResponse.getStatus(samlResponseDoc);
		assertEquals(Constants.STATUS_RESPONDER, status.getStatusCode());
		assertEquals("something_is_wrong", status.getStatusMessage());
	}

	/**
	 * Tests the getAudiences method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getAudiences
	 */
	@Test
	public void testGetAudiences() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);

		List<String> expectedAudiences = new ArrayList<String>();
		expectedAudiences.add("{audience}");
		assertEquals(expectedAudiences, samlResponse.getAudiences());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		expectedAudiences = new ArrayList<String>();
		expectedAudiences.add("http://stuff.com/endpoints/metadata.php");
		assertEquals(expectedAudiences, samlResponse.getAudiences());
	}

	/**
	 * Tests the getIssuers method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getIssuers
	 */
	@Test
	public void testGetIssuers() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		List<String> expectedIssuers = new ArrayList<String>();
		expectedIssuers.add("https://app.onelogin.com/saml/metadata/13590");
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		expectedIssuers.remove(0);
		expectedIssuers.add("http://idp.example.com/");
		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		expectedIssuers.remove(0);
		expectedIssuers.add("https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php");

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_response.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertEquals(expectedIssuers, samlResponse.getIssuers());
	}

	/**
	 * Tests the getSessionIndex method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getSessionIndex
	 */
	@Test
	public void testGetSessionIndex() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertEquals("_531c32d283bdff7e04e487bcdbc4dd8d", samlResponse.getSessionIndex());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertEquals("_7164a9a9f97828bfdb8d0ebc004a05d2e7d873f70c", samlResponse.getSessionIndex());
	}

	/**
	 * Tests the getAttributes method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getAttributes
	 */
	@Test
	public void testGetAttributes() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		HashMap<String, List<String>> expectedAttributes = new HashMap<String, List<String>>();
		List<String> attrValues = new ArrayList<String>();
		attrValues.add("demo");
		List<String> attrValues2 = new ArrayList<String>();
		attrValues2.add("value");
		expectedAttributes.put("uid", attrValues);
		expectedAttributes.put("another_value", attrValues2);
		assertEquals(expectedAttributes, samlResponse.getAttributes());

		samlResponseEncoded = Util.getFileAsString("data/responses/response2.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.getAttributes().isEmpty());

		// Encrypted Attributes are not supported
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/encrypted_attrs.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.getAttributes().isEmpty());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testOnlyRetrieveAssertionWithIDThatMatchesSignatureReference() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrapped_response_2.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);

		String nameID = samlResponse.getNameId();
		assertFalse(samlResponse.isValid());
		assertFalse("root@example.com".equals(nameID));
	}

	/**
	 * Tests the isValid method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testDoesNotAllowSignatureWrappingAttack() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response4.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);

		assertEquals("test@onelogin.com", samlResponse.getNameId());		
		assertFalse(samlResponse.isValid());
		assertEquals("SAML Response must contain 1 Assertion.", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testDoesNotAllowSignatureWrappingAttack2() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.newattack.properties").build();
		String samlResponseEncoded = Util.base64encoder(Util.getFileAsString("data/responses/invalids/attacks/encrypted_new_attack.xml"));
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Found an invalid Signed Element. SAML Response rejected", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: signature wrapping attack - doubled SAML response body
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testDoesNotAllowSignatureWrappingAttack3() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.newattack2.properties").build();
		settings.setStrict(false);
		String samlResponseEncoded = Util.base64encoder(Util.getFileAsString("data/responses/invalids/attacks/response_with_doubled_signed_assertion.xml"));
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("https://example.com/endpoint"));

		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("SAML Response must contain 1 Assertion.", samlResponse.getError());
		// should expose only the signed data
		assertEquals("someone@example.org", samlResponse.getNameId());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: signature wrapping attack - concealed SAML response body
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testDoesNotAllowSignatureWrappingAttack4() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.newattack2.properties").build();
		settings.setStrict(false);
		String samlResponseEncoded = Util.base64encoder(Util.getFileAsString("data/responses/invalids/attacks/response_with_concealed_signed_assertion.xml"));
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("https://example.com/endpoint"));

		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("SAML Response must contain 1 Assertion.", samlResponse.getError());
		// should expose only the signed data
		assertEquals("someone@example.org", samlResponse.getNameId());
	}

	/**
	 * Tests the getSessionNotOnOrAfter method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getSessionNotOnOrAfter
	 */
	@Test
	public void testGetSessionNotOnOrAfter() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertEquals(1290203857000L, samlResponse.getSessionNotOnOrAfter().getMillis());

		samlResponseEncoded = Util.getFileAsString("data/responses/response2.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertNull(samlResponse.getSessionNotOnOrAfter());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertEquals(2696012228000L, samlResponse.getSessionNotOnOrAfter().getMillis());
	}

	/**
	 * Tests the validateNumAssertions method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#validateNumAssertions
	 */
	@Test
	public void testValidateNumAssertions() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.validateNumAssertions());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/multiple_assertions.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.validateNumAssertions());
	}

	/**
	 * Tests the validateTimestamps method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#validateTimestamps
	 */
	@Test
	public void testValidateTimestamps() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.validateTimestamps());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.validateTimestamps());

		samlResponseEncoded = Util.getFileAsString("data/responses/expired_response.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.validateTimestamps());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/not_after_failed.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.validateTimestamps());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/not_before_failed.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.validateTimestamps());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_time_condition.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.validateTimestamps());		
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: null HttpServletRequest provided
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testNullRequest() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		SamlResponse samlResponse = new SamlResponse(settings, null);
		assertFalse(samlResponse.isValid());
		assertEquals("SAML Response is not loaded", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: null HttpServletRequest provided
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testNoCurrentURL() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer(""));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("The URL of the current host was not established", samlResponse.getError());

		samlResponse.setDestinationUrl(null);
		assertFalse(samlResponse.isValid());
		assertEquals("The URL of the current host was not established", samlResponse.getError());
	}
	
	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid version
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testValidateVersion() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_saml2.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Unsupported SAML Version.", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid ID
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testValidateID() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_id.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Missing ID attribute on SAML Response.", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: expired response
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidExpired() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/expired_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Timing issues (please check your clock settings)", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: no Key
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidNoKey() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_key.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Signature validation failed. SAML Response rejected", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid multiple assertions
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidMultipleAssertions() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/multiple_assertions.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("SAML Response must contain 1 Assertion.", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid Encrypted Attrs
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidEncAttrs() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/encrypted_attrs.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("There is an EncryptedAttribute in the Response and this SP not support them", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid but contained wrong NameId
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test(expected=Exception.class)
	public void testIsValidWrongEncryptedID() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/response_encrypted_subconfirm_as_nameid.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());
		String nameId = samlResponse.getNameId();
	}
	
	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid xml
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidWrongXML() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_xml.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("https://pitbulk.no-ip.org/newonelogin/demo1/index.php?acs"));
		settings.setStrict(false);
		settings.setWantXMLValidation(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setWantXMLValidation(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		settings.setWantXMLValidation(false);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp is not a valid audience for this Response", samlResponse.getError());

		settings.setWantXMLValidation(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid Destination
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidDestination() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("/"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertThat(samlResponse.getError(), containsString("The response was received at"));

		samlResponse.setDestinationUrl("http://localhost:8080/java-saml-jspsample/acs.jsp");
		samlResponse.isValid();
		assertThat(samlResponse.getError(), not(containsString("The response was received at")));
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid audience
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidAudience() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_audience.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertThat(samlResponse.getError(), containsString("is not a valid audience for this Response"));
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid issuer
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidIssuer() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_issuer_assertion.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid issuer in the Assertion/Response", samlResponse.getError());

		settings.setStrict(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_issuer_message.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid issuer in the Assertion/Response", samlResponse.getError());
		
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid SessionIndex
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidSessionIndex() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_sessionindex.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid SubjectConfirmation
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidSubjectConfirmation() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_subjectconfirmation_method.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("A valid SubjectConfirmation was not found on this Response", samlResponse.getError());

		settings.setStrict(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_subjectconfirmation_data.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("A valid SubjectConfirmation was not found on this Response", samlResponse.getError());

		settings.setStrict(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_subjectconfirmation_inresponse.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("A valid SubjectConfirmation was not found on this Response", samlResponse.getError());

		settings.setStrict(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_subjectconfirmation_recipient.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("A valid SubjectConfirmation was not found on this Response", samlResponse.getError());

		settings.setStrict(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_subjectconfirmation_noa.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("A valid SubjectConfirmation was not found on this Response", samlResponse.getError());

		settings.setStrict(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_subjectconfirmation_nb.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("A valid SubjectConfirmation was not found on this Response", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: Datetime with Miliseconds
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testDatetimeWithMiliseconds() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response_with_miliseconds.xm.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid requestId
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidRequestId() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);

		assertTrue(samlResponse.isValid());
		assertTrue(samlResponse.isValid("invalidRequestId"));

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		assertFalse(samlResponse.isValid("invalidRequestId"));
		assertThat(samlResponse.getError(), containsString("The InResponseTo of the Response"));		
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid signing issues
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidSignIssues() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);

		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(false);		
		SamlResponse samlResponse = new SamlResponse(settings, request);		
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(false);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);

		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(false);		
		samlResponse = new SamlResponse(settings, request);		
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(false);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("The Assertion of the Response is not signed and the SP requires it", samlResponse.getError());

		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("The Message of the Response is not signed and the SP requires it", samlResponse.getError());

		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(true);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("The Assertion of the Response is not signed and the SP requires it", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid encryption issues
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidEncIssues() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		settings.setStrict(false);

		settings.setWantAssertionsEncrypted(false);
		settings.setWantNameIdEncrypted(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);		
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsEncrypted(true);
		settings.setWantNameIdEncrypted(false);
		samlResponse = new SamlResponse(settings, request);		
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsEncrypted(false);
		settings.setWantNameIdEncrypted(true);
		samlResponse = new SamlResponse(settings, request);		
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsEncrypted(true);
		settings.setWantNameIdEncrypted(true);
		samlResponse = new SamlResponse(settings, request);		
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);

		settings.setWantAssertionsEncrypted(false);
		settings.setWantNameIdEncrypted(false);
		samlResponse = new SamlResponse(settings, request);		
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsEncrypted(true);
		settings.setWantNameIdEncrypted(false);
		samlResponse = new SamlResponse(settings, request);		
		assertFalse(samlResponse.isValid());
		assertEquals("The assertion of the Response is not encrypted and the SP requires it", samlResponse.getError());

		settings.setWantAssertionsEncrypted(false);
		settings.setWantNameIdEncrypted(true);
		samlResponse = new SamlResponse(settings, request);		
		assertFalse(samlResponse.isValid());
		assertEquals("The NameID of the Response is not encrypted and the SP requires it", samlResponse.getError());

		settings.setWantAssertionsEncrypted(true);
		settings.setWantNameIdEncrypted(true);
		samlResponse = new SamlResponse(settings, request);		
		assertFalse(samlResponse.isValid());
		assertEquals("The assertion of the Response is not encrypted and the SP requires it", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid cert
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidCert() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.invalididpcertstring.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Signature validation failed. SAML Response rejected", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid response with different namespaces
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testNamespaceIsValid() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_namespaces.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid response from ADFS
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testADFSValid() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.adfs.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_adfs1.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid response
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValid() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid response validated with certfingerprint
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValid2() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.mywithnocert.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid encrypted assertion
	 *       
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValidEnc() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(false);
		String samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_encrypted_assertion.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);

		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_encrypted_assertion.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);

		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid sign response / sign assertion / both signed
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValidSign() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(false);
		String samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);

		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_response.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);

		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());		
	}

	/**
	 * Tests the processSignedElements method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#processSignedElements
	 */
	@Test
	public void testProcessSignedElementsInvalidSignElement() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(!samlResponse.processSignedElements().isEmpty());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(!samlResponse.processSignedElements().isEmpty());

		samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_response.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(!samlResponse.processSignedElements().isEmpty());

		samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.processSignedElements().isEmpty());
	}

	/**
	 * Tests the processSignedElements method of SamlResponse
	 * Case: invalid Signature Element
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#processSignedElements
	 */
	@Test(expected=Exception.class)
	public void testProcessSignedElementsInvalidSignElem() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		SamlResponse samlResponse = new SamlResponse(settings, request);
		samlResponse.processSignedElements();
	}

	/**
	 * Tests the processSignedElements method of SamlResponse
	 * Case: another invalid Signature Element
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#processSignedElements
	 */
	@Test(expected=Exception.class)
	public void testProcessSignedElementsInvalidSignElem2() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element2.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		SamlResponse samlResponse = new SamlResponse(settings, request);
		samlResponse.processSignedElements();
	}
	
	/**
	 * Tests the processSignedElements method of SamlResponse
	 * Case: invalid id
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#processSignedElements
	 */
	@Test(expected=Exception.class)
	public void testProcessSignedElementsNoId() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_assertion_id.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		SamlResponse samlResponse = new SamlResponse(settings, request);
		samlResponse.processSignedElements();
	}

	/**
	 * Tests the processSignedElements method of SamlResponse
	 * Case: duplicate reference uri
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#processSignedElements
	 */
	@Test(expected=Exception.class)
	public void testProcessSignedElementsDuplicateRef() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/duplicate_reference_uri.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		SamlResponse samlResponse = new SamlResponse(settings, request);
		samlResponse.processSignedElements();
	}
	

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid signs
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidSign() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(true);
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));

		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/triple_signed_response.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Duplicated ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/signed_assertion_response_with_2signatures.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Duplicated ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/signed_message_response_with_2signatures.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Duplicated ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid Signature Element Subject SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element2.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid Signature Element Subject SAML Response rejected", samlResponse.getError());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/duplicate_reference_uri.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Found an invalid Signed Element. SAML Response rejected", samlResponse.getError());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_assertion_id.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Signed Element must contain an ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/bad_reference.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertFalse(samlResponse.isValid());
		assertEquals("Found an invalid Signed Element. SAML Response rejected", samlResponse.getError());	
	}

	/**
	 * Tests the validateSignedElements method of SamlResponse
	 * Case: invalid signs
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#validateSignedElements
	 */
	@Test
	public void testValidateSignedElements() throws Exception {
		ArrayList<String> signedElements = new ArrayList<String>();
		String samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_response.xml.base64");
		Document samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		NodeList signNodes = Util.query(samlResponseDoc, "//ds:Signature");

		assertFalse(SamlResponse.validateSignedElements(signedElements));

		signedElements = new ArrayList<String>();
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			signedElements.add(signNode.getParentNode().getLocalName());
		}
		assertTrue(SamlResponse.validateSignedElements(signedElements));

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/triple_signed_response.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		signNodes = Util.query(samlResponseDoc, "//ds:Signature");

		signedElements = new ArrayList<String>();
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			signedElements.add(signNode.getParentNode().getLocalName());
		}
		assertFalse(SamlResponse.validateSignedElements(signedElements));

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/signed_assertion_response_with_2signatures.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		signNodes = Util.query(samlResponseDoc, "//ds:Signature");

		signedElements = new ArrayList<String>();
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			signedElements.add(signNode.getParentNode().getLocalName());
		}
		assertFalse(SamlResponse.validateSignedElements(signedElements));

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/signed_message_response_with_2signatures.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		signNodes = Util.query(samlResponseDoc, "//ds:Signature");

		signedElements = new ArrayList<String>();
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			signedElements.add(signNode.getParentNode().getLocalName());
		}
		assertFalse(SamlResponse.validateSignedElements(signedElements));

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		signNodes = Util.query(samlResponseDoc, "//ds:Signature");

		signedElements = new ArrayList<String>();
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			signedElements.add(signNode.getParentNode().getLocalName());
		}
		assertFalse(SamlResponse.validateSignedElements(signedElements));
	}
	
	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid response that has no reference URI
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValidSignWithEmptyReferenceURI() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.noreferenceuri.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(false);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_without_reference_uri.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:9001/v1/users/authorize/saml"));

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertTrue(samlResponse.isValid());
		
		HashMap<String, List<String>> attributes = samlResponse.getAttributes();
		assertFalse(attributes.isEmpty());
		String attrName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
		assertEquals("saml@user.com", attributes.get(attrName).get(0));
	}
	
	/**
	 * Tests the getError method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getError
	 */
	@Test
	public void testGetError() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setStrict(true);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response4.xml.base64");
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/java-saml-jspsample/acs.jsp"));
		SamlResponse samlResponse = new SamlResponse(settings, request);
		assertNull(samlResponse.getError());
		samlResponse.isValid();
		assertThat(samlResponse.getError(), containsString("SAML Response must contain 1 Assertion."));

		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, request);
		samlResponse.isValid();
		assertThat(samlResponse.getError(), containsString("SAML Response must contain 1 Assertion."));

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		when(request.getParameter("SAMLResponse")).thenReturn(samlResponseEncoded);
		samlResponse = new SamlResponse(settings, request);
		assertNull(samlResponse.getError());
		samlResponse.isValid();
		assertNull(samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, request);
		assertNull(samlResponse.getError());
		samlResponse.isValid();
		assertNull(samlResponse.getError());
	}
}
