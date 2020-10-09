package com.onelogin.saml2.test.authn;

import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.model.SamlResponseStatus;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

import org.hamcrest.Matchers;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.Instant;
import org.joda.time.format.ISODateTimeFormat;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class AuthnResponseTest {
	private static final String ACS_URL = "http://localhost:8080/java-saml-jspsample/acs.jsp";

	@Rule
	public ExpectedException expectedEx = ExpectedException.none();

	@Before
	public void setDateTime() {
		//All calls to Joda time check will use this timestamp as "now" value : 
		setDateTime("2020-06-01T00:00:00Z");
	}
	
	@After
	public void goBackToNormal() {
		DateTimeUtils.setCurrentMillisSystem();
	}

	/**
	 * Tests the deconstructed constructor of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse
	 */
	@Test
	public void testDeconstructedConstructor() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		final String requestURL = "/";
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertTrue(samlResponse instanceof SamlResponse);

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, requestURL, samlResponseEncoded);
		assertTrue(samlResponse instanceof SamlResponse);
	}


	/**
	 * Tests the httpRequest constructor of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse
	 */
	@Test
	public void testConstructor() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		final String requestURL = "/";
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertTrue(samlResponse instanceof SamlResponse);

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertTrue(samlResponse instanceof SamlResponse);
	}

	/**
	 * Tests that a invalid SAMLResponse with not expected elements fails
	 *
	 * @throws Exception 
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse
	 */
	@Test
	public void testOInvalidResponseWithNonExpectedElementsFail() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrapped_response_2.xml.base64");

		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("SAML Response could not be processed");
		new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
	}

	/**
	 * Tests the constructor of SamlResponse
	 * Case: Encrypted assertion but no key
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test
	public void testEncryptedAssertionNokey() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		
		expectedEx.expect(SettingsException.class);
		expectedEx.expectMessage("No private key available for decrypt, check settings");
		new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
	}

	@Test
	public void testTextWithCommentAttack() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_node_test_attack.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		HashMap<String, List<String>> attributes = samlResponse.getAttributes();
		String nameId = samlResponse.getNameId();
		assertEquals("smith", attributes.get("surname").get(0));
		assertEquals("support@onelogin.com", nameId);
	}

	/**
	 * Tests the constructor of SamlResponse
	 * Case test namespaces
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse
	 */
	@Test
	public void testNamespaces() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/open_saml_response.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
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
	 * Tests the getSAMLResponseXml method of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * 
	 * @see com.onelogin.saml2.authn.SamlResponse#getSAMLResponseXml
	 */
	@Test
	public void testGetSAMLResponseXml() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		final String requestURL = "/";
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		String samlResponseXML =  samlResponse.getSAMLResponseXml();
		assertThat(samlResponseXML, containsString("<samlp:Response"));

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		samlResponseXML =  samlResponse.getSAMLResponseXml();
		assertThat(samlResponseXML, containsString("<samlp:Response"));
		assertThat(samlResponseXML, containsString("<saml:Assertion"));
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
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("support@onelogin.com", samlResponse.getNameId());

		samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("2de11defd199f8d5bb63f9b7deb265ba5c675c10", samlResponse.getNameId());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("_68392312d490db6d355555cfbbd8ec95d746516f60", samlResponse.getNameId());

		settings.setWantNameId(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_nameid.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertNull(samlResponse.getNameId());
	}

	/**
	 * Tests the getNameIdFormat method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameIdFormat
	 */
	@Test
	public void testGetNameIdFormat() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", samlResponse.getNameIdFormat());

		samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", samlResponse.getNameIdFormat());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:transient", samlResponse.getNameIdFormat());

		settings.setWantNameId(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_nameid.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertNull(samlResponse.getNameIdFormat());
	}

	/**
	 * Tests the getNameIdNameQualifier method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameIdNameQualifier
	 */
	@Test
	public void testGetNameIdNameQualifier() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertNull(samlResponse.getNameIdNameQualifier());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response_with_namequalifier.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("example.com", samlResponse.getNameIdNameQualifier());
	}

	/**
	 * Tests the getNameIdSPNameQualifier method of SamlResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameIdSPNameQualifier
	 */
	@Test
	public void testGetNameIdSPNameQualifier() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertNull(samlResponse.getNameIdSPNameQualifier());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response_with_namequalifier.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals(settings.getSpEntityId(), samlResponse.getNameIdSPNameQualifier());
	}

	/**
	 * Tests the getNameId method of SamlResponse
	 * Case: No NameId
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test
	public void testGetNameIdNoNameId() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		settings.setWantNameId(true);
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_nameid.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("No name id found in Document.");
		samlResponse.getNameId();
	}

	/**
	 * Tests the getNameId method of SamlResponse
	 * Case: Wrong SPNameQualifier
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test
	public void testGetNameIdWrongSPNameQualifier() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		settings.setWantNameId(true);
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_spnamequalifier.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("The SPNameQualifier value mismatch the SP entityID value.");
		samlResponse.getNameId();
	}
	
	/**
	 * Tests the getNameId method of SamlResponse
	 * Case: Not able to get the NameIdData due no private key to decrypt
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test
	public void testGetNameIdNoKey() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(SettingsException.class);
		expectedEx.expectMessage("Key is required in order to decrypt the NameID");
		samlResponse.getNameId();
	}

	/**
	 * Tests the getNameId method of SamlResponse
	 * Case: The NameID value is empty 
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test
	public void testGetNameIdEmptyNameIDValue() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(false);
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/empty_nameid.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		String nameId = samlResponse.getNameId();
		assertTrue(nameId.isEmpty());
		
		settings.setStrict(true);
		SamlResponse samlResponse2 = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("An empty NameID value found");
		samlResponse2.getNameId();
	}

	/**
	 * Tests the getNameId method of SamlResponse
	 * Case: Not able to get the NameIdData due no nameID inside the EncryptedID
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameId
	 */
	@Test
	public void testGetNameIdWrongEncryptedData() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/response_encrypted_subconfirm_as_nameid.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(Exception.class);
		expectedEx.expectMessage("Not able to decrypt the EncryptedID and get a NameID");
		samlResponse.getNameId();
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
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("{Format=urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress, Value=support@onelogin.com}", samlResponse.getNameIdData().toString());

		samlResponseEncoded = Util.getFileAsString("data/responses/response_encrypted_nameid.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		String NameIdDataStr = samlResponse.getNameIdData().toString();
		assertThat(NameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"));
		assertThat(NameIdDataStr, containsString("Value=2de11defd199f8d5bb63f9b7deb265ba5c675c10"));
		assertThat(NameIdDataStr, containsString("SPNameQualifier=http://localhost:8080/java-saml-jspsample/metadata.jsp"));

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		NameIdDataStr = samlResponse.getNameIdData().toString();
		assertThat(NameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:2.0:nameid-format:transient"));
		assertThat(NameIdDataStr, containsString("Value=_68392312d490db6d355555cfbbd8ec95d746516f60"));
		assertThat(NameIdDataStr, containsString("SPNameQualifier=http://localhost:8080/java-saml-jspsample/metadata.jsp"));
		
		settings.setWantNameId(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_nameid.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.getNameIdData().isEmpty());
	}

	/**
	 * Tests the decryptAssertion method of SamlResponse
	 * Case: EncryptedAssertion with an encryptedData element with a KeyInfo
	 *       that contains a RetrievalMethod to obtain the EncryptedKey.
	 *
	 * @throws Exception
	 */
	@Test
	public void testEncryptedResponse() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.decrypt.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/response_to_decrypt.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("archit.neema@intellicus.com", samlResponse.getNameId());
	}

	/**
	 * Tests the getNameIdData method of SamlResponse
	 * Case: No NameId
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameIdData
	 */
	@Test
	public void testGetNameIdDataNoNameId() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantNameId(true);

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_nameid.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("No name id found in Document");
		samlResponse.getNameIdData();
	}

	/**
	 * Tests the getNameIdData method of SamlResponse
	 * Case: Wrong SPNameQualifier
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameIdData
	 */
	@Test
	public void testGetNameIdDataWrongSPNameQualifier() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		settings.setWantNameId(true);
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_spnamequalifier.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("The SPNameQualifier value mismatch the SP entityID value.");
		samlResponse.getNameIdData();
	}

	/**
	 * Tests the getNameIdData method of SamlResponse
	 * Case: The NameID value is empty 
	 *
	 * @throws Exception
	 * 
	 * @see com.onelogin.saml2.authn.SamlResponse#getNameIdData
	 */
	@Test
	public void testGetNameIdDataEmptyNameIDValue() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(false);
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/empty_nameid.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		Map<String, String> nameIdData = samlResponse.getNameIdData();
		assertTrue(nameIdData.get("Value").isEmpty());

		settings.setStrict(true);
		SamlResponse samlResponse2 = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("An empty NameID value found");
		samlResponse2.getNameIdData();
	}
	
	/**
	 * Tests the checkOneCondition method of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkOneCondition
	 */
	@Test
	public void checkOneCondition() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_conditions.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.checkOneCondition());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.checkOneCondition());
	}

	/**
	 * Tests the checkOneAuthnStatement method of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkOneAuthnStatement
	 */
	@Test
	public void checkOneAuthNStatement() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_authnstatement.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.checkOneAuthnStatement());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.checkOneAuthnStatement());
	}

	/**
	 * Tests the checkStatus method of SamlResponse
	 * Case Status = Success
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkStatus
	 */
	@Test
	public void testCheckStatus() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError  {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		samlResponse.checkStatus();

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		samlResponse.checkStatus();
	}

	/**
	 * Tests the checkStatus method of SamlResponse
	 * Case Status = Responder
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkStatus
	 */
	@Test
	public void testCheckStatusResponder() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/status_code_responder.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("The status code of the Response was not Success, was urn:oasis:names:tc:SAML:2.0:status:Responder");
		samlResponse.checkStatus();
	}

	/**
	 * Tests the checkStatus method of SamlResponse
	 * Case Status = Responder + Msg
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkStatus
	 */
	@Test
	public void testCheckStatusResponderMsg() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/status_code_responder_and_msg.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("The status code of the Response was not Success, was urn:oasis:names:tc:SAML:2.0:status:Responder -> something_is_wrong");
		samlResponse.checkStatus();
	}

	/**
	 * Tests the checkStatus method of SamlResponse
	 * Case No Status
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkStatus
	 */
	@Test
	public void testCheckStatusNoStatus() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_status.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Missing Status on response");
		samlResponse.checkStatus();
	}

	/**
	 * Tests the checkStatus method of SamlResponse
	 * Case No StatusCode
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#checkStatus
	 */
	@Test
	public void testCheckStatusNoStatusCode() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_status_code.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Missing Status Code on response");
		samlResponse.checkStatus();
	}

	/**
	 * Tests the getStatus method of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getStatus
	 */
	@Test
	public void testGetStatus() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
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

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/status_code_and_sub_status_code_responder_and_msg.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		status = SamlResponse.getStatus(samlResponseDoc);
		assertEquals(Constants.STATUS_RESPONDER, status.getStatusCode());
		assertEquals(Constants.STATUS_AUTHNFAILED, status.getSubStatusCode());
		assertEquals("something_is_wrong", status.getStatusMessage());
	}

	/**
	 * Tests the getAudiences method of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getAudiences
	 */
	@Test
	public void testGetAudiences() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));

		List<String> expectedAudiences = new ArrayList<String>();
		expectedAudiences.add("{audience}");
		assertEquals(expectedAudiences, samlResponse.getAudiences());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		expectedAudiences = new ArrayList<String>();
		expectedAudiences.add("http://localhost:8080/java-saml-jspsample/metadata.jsp");
		assertEquals(expectedAudiences, samlResponse.getAudiences());
	}

	/**
	 * Tests the getIssuers method of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getIssuers
	 */
	@Test
	public void testGetIssuers() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		List<String> expectedIssuers = new ArrayList<String>();
		expectedIssuers.add("http://idp.example.com/");
		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		expectedIssuers.remove(0);
		expectedIssuers.add("https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php");

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals(expectedIssuers, samlResponse.getIssuers());

		expectedIssuers = new ArrayList<String>();
		expectedIssuers.add("https://app.onelogin.com/saml/metadata/13590");
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_issuer_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals(expectedIssuers, samlResponse.getIssuers());
	}

	/**
	 * Tests the getIssuers method of SamlResponse
	 * Case: Issuer of the assertion not found
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getIssuers
	 */
	@Test
	public void testGetIssuersNoInAssertion() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_issuer_assertion.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Issuer of the Assertion not found or multiple.");
		samlResponse.getIssuers();
	}
	
	/**
	 * Tests the getSessionIndex method of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getSessionIndex
	 */
	@Test
	public void testGetSessionIndex() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("_531c32d283bdff7e04e487bcdbc4dd8d", samlResponse.getSessionIndex());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("_7164a9a9f97828bfdb8d0ebc004a05d2e7d873f70c", samlResponse.getSessionIndex());
	}

	@Test
	public void testGetAssertionDetails() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		final SamlResponse samlResponse = new SamlResponse(
				new SettingsBuilder().fromFile("config/config.my.properties").build(),
				newHttpRequest(Util.getFileAsString("data/responses/response1.xml.base64"))
		);
		final List<Instant> notOnOrAfters = samlResponse.getAssertionNotOnOrAfter();

		assertEquals("pfxa46574df-b3b0-a06a-23c8-636413198772", samlResponse.getAssertionId());
		assertThat(notOnOrAfters, contains(new Instant("2010-11-18T22:02:37Z")));

	}

	@Test
	public void testGetAssertionDetails_encrypted() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		final SamlResponse samlResponse = new SamlResponse(
				new SettingsBuilder().fromFile("config/config.my.properties").build(),
				newHttpRequest(Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64"))
		);
		final List<Instant> notOnOrAfters = samlResponse.getAssertionNotOnOrAfter();

		assertEquals("_519c2712648ee09a06d1f9a08e9e835715fea60267", samlResponse.getAssertionId());
		assertThat(notOnOrAfters, contains(new Instant("2055-06-07T20:17:08Z")));

	}

	@Test
	public void testGetAssertionDetails_multiple() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(true);

		final SamlResponse samlResponse = new SamlResponse(
				settings,
				newHttpRequest(loadSignMessageAndEncode("data/responses/invalids/invalid_subjectconfirmation_multiple_issues.xml"))
		);
		final List<Instant> notOnOrAfters = samlResponse.getAssertionNotOnOrAfter();

		assertEquals("pfx7841991c-c73f-4035-e2ee-c170c0e1d3e4", samlResponse.getAssertionId());
		assertThat(notOnOrAfters, contains(new Instant("2120-06-17T14:53:44Z"), new Instant("2010-06-17T14:53:44Z")));
	}

	/**
	 * Tests the getAttributes method of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getAttributes
	 */
	@Test
	public void testGetAttributes() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		HashMap<String, List<String>> expectedAttributes = new HashMap<String, List<String>>();
		List<String> attrValues = new ArrayList<String>();
		attrValues.add("demo");
		List<String> attrValues2 = new ArrayList<String>();
		attrValues2.add("value");
		expectedAttributes.put("uid", attrValues);
		expectedAttributes.put("another_value", attrValues2);
		assertEquals(expectedAttributes, samlResponse.getAttributes());

		samlResponseEncoded = Util.getFileAsString("data/responses/response2.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.getAttributes().isEmpty());

		// Encrypted Attributes are not supported
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/encrypted_attrs.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.getAttributes().isEmpty());
	}

	/**
	 * Tests the getAttributes method of SamlResponse
	 * Case: Duplicated names
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getAttributes
	 */
	@Test
	public void testGetAttributesDuplicatedNames() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/duplicated_attributes.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));

		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Found an Attribute element with duplicated Name");
		samlResponse.getAttributes();
	}

	/**
	 * Tests the getAttributes method of SamlResponse
	 * Case: Allow Duplicated names
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getAttributes
	 */
	@Test
	public void testGetAttributesAllowDuplicatedNames () throws IOException, Error, XPathExpressionException, ParserConfigurationException,
				SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.allowduplicatednames.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/duplicated_attributes.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));

		Map<String, List<String>> attributes = samlResponse.getAttributes();
		assertNotNull(attributes);
		assertTrue(attributes.containsKey("uid"));
		assertEquals(2, attributes.get("uid").size());
	}

	/**
	 * Tests that queryAssertion method of SamlResponse
	 * Case: Elements retrieved are covered by a Signature
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#queryAssertion
	 */
	@Test
	public void testOnlyRetrieveAssertionWithIDThatMatchesSignatureReference() throws Exception {		
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/signed_assertion_response_with_2_assertions.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("492882615acf31c8096b627245d76ae53036c090", samlResponse.getNameId());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/signed_assertion_response_with_2_assertions_differrent_order.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals("492882615acf31c8096b627245d76ae53036c090", samlResponse.getNameId());
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
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));

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

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
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
		final String requestURL = "https://example.com/endpoint";
		String samlResponseEncoded = Util.base64encoder(Util.getFileAsString("data/responses/invalids/attacks/response_with_doubled_signed_assertion.xml"));

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
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
		final String requestURL = "https://example.com/endpoint";
		String samlResponseEncoded = Util.base64encoder(Util.getFileAsString("data/responses/invalids/attacks/response_with_concealed_signed_assertion.xml"));

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("SAML Response must contain 1 Assertion.", samlResponse.getError());
		// should expose only the signed data
		assertEquals("someone@example.org", samlResponse.getNameId());
	}

	@Test
	public void testValidatesTheExpectedSignatures() throws Exception {
		// having
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(true);

		String samlResponseEncoded = Util.base64encoder(Util.getFileAsString("data/responses/invalids/attacks/response_with_spoofed_response_signature.xml"));

		// when
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));

		// then
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid Signature Element {urn:oasis:names:tc:SAML:2.0:assertion}Response SAML Response rejected", samlResponse.getError());
	}

	/**
	 * Tests the getSessionNotOnOrAfter method of SamlResponse
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getSessionNotOnOrAfter
	 */
	@Test
	public void testGetSessionNotOnOrAfter() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals(1290203857000L, samlResponse.getSessionNotOnOrAfter().getMillis());

		samlResponseEncoded = Util.getFileAsString("data/responses/response2.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertNull(samlResponse.getSessionNotOnOrAfter());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertEquals(2696012228000L, samlResponse.getSessionNotOnOrAfter().getMillis());
	}

	/**
	 * Tests the validateNumAssertions method of SamlResponse
	 *
	 * @throws ValidationError
	 * @throws IOException
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#validateNumAssertions
	 */
	@Test
	public void testValidateNumAssertions() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response1.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.validateNumAssertions());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/multiple_assertions.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.validateNumAssertions());
	}

	/**
	 * Tests the validateTimestamps method of SamlResponse
	 *
	 * @throws ValidationError
	 * @throws IOException
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#validateTimestamps
	 */
	@Test
	public void testValidateTimestamps() throws ValidationError, IOException, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.validateTimestamps());

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_encrypted_assertion.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.validateTimestamps());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_time_condition.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.validateTimestamps());		
	}

	/**
	 * Tests the validateTimestamps method of SamlResponse
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#validateTimestamps
	 */
	@Test 
	public void testValidateTimestampsExpired() throws ValidationError, XPathExpressionException, ParserConfigurationException, SAXException, IOException, SettingsException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/expired_response.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Could not validate timestamp: expired. Check system clock.");
		samlResponse.validateTimestamps();
	}
	
	/**
	 * Tests the validateTimestamps method of SamlResponse
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#validateTimestamps
	 */
	@Test
	public void testValidateTimestampsNA() throws ValidationError, XPathExpressionException, ParserConfigurationException, SAXException, IOException, SettingsException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/not_after_failed.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Could not validate timestamp: expired. Check system clock.");
		samlResponse.validateTimestamps();
	}

	/**
	 * Tests the validateTimestamps method of SamlResponse
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#validateTimestamps
	 */
	@Test
	public void testValidateTimestampsNB() throws ValidationError, XPathExpressionException, ParserConfigurationException, SAXException, IOException, SettingsException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/not_before_failed.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Could not validate timestamp: not yet valid. Check system clock.");
		samlResponse.validateTimestamps();
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: null HttpServletRequest provided
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testNullRequest() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		expectedEx.expect(NullPointerException.class);
		SamlResponse samlResponse = new SamlResponse(settings, null);
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: null HttpServletRequest provided
	 *
	 * @throws IOException
	 * @throws Error
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testNoCurrentURL() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		final String requestURL = "";
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
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
	 * @throws IOException
	 * @throws Error
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testValidateVersion() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_saml2.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Unsupported SAML Version.", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid ID
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testValidateID() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_id.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Missing ID attribute on SAML Response.", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: expired response
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidExpired() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/expired_response.xml.base64");
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Could not validate timestamp: expired. Check system clock.", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: no Key
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidNoKey() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_key.xml.base64");
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Signature validation failed. SAML Response rejected", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid multiple assertions
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidMultipleAssertions() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/multiple_assertions.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("SAML Response must contain 1 Assertion.", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid Encrypted Attrs
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidEncAttrs() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/encrypted_attrs.xml.base64");
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("There is an EncryptedAttribute in the Response and this SP does not support them", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid but contained wrong NameId
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValidWrongEncryptedID() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/response_encrypted_subconfirm_as_nameid.xml.base64");
		settings.setStrict(false);
		settings.setWantAssertionsSigned(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());
		
		expectedEx.expect(Exception.class);
		expectedEx.expectMessage("Not able to decrypt the EncryptedID and get a NameID");
		samlResponse.getNameId();
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid but contained wrong NameId
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValidWrongSPNameQualifier() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_spnamequalifier.xml.base64");
		settings.setStrict(true);
		settings.setWantAssertionsSigned(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("The SPNameQualifier value mismatch the SP entityID value.");
		samlResponse.getNameId();
	}
	
	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid xml
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidWrongXML() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		final String requestURL = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php?acs";
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_xml.xml.base64");
		settings.setStrict(false);
		settings.setWantXMLValidation(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setWantXMLValidation(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		settings.setWantXMLValidation(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp is not a valid audience for this Response", samlResponse.getError());

		settings.setWantXMLValidation(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid Destination
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidDestination() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		final String requestURL = "/";
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertThat(samlResponse.getError(), containsString("The response was received at"));

		samlResponse.setDestinationUrl(ACS_URL);
		samlResponse.isValid();
		assertThat(samlResponse.getError(), not(containsString("The response was received at")));
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: No Destination
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidNoDestination() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		final String requestURL = "/";
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/empty_destination.xml.base64");
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("The response has an empty Destination value", samlResponse.getError());
	}
	
	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid Conditions
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidConditions() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_conditions.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("The Assertion must include a Conditions element", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid Conditions
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidAuthStatement() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_authnstatement.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("The Assertion must include an AuthnStatement element", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid audience
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidAudience() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_audience.xml.base64");
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertThat(samlResponse.getError(), containsString("is not a valid audience for this Response"));
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid issuer
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidIssuer() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_issuer_assertion.xml.base64");
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid issuer in the Assertion/Response. Was 'http://invalid.issuer.example.com/', but expected 'http://idp.example.com/'", samlResponse.getError());

		settings.setStrict(false);
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_issuer_message.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());
		
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid SessionIndex
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidSessionIndex() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_sessionindex.xml.base64");
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response", samlResponse.getError());
	}

	@Test
	public void testIsValidSubjectConfirmation_noSubjectConfirmationMethod() throws Exception {
		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		final String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_subjectconfirmation_method.xml.base64");

		assertResponseValid(settings, samlResponseEncoded, false, false, "No Signature found. SAML Response rejected");
		assertResponseValid(settings, samlResponseEncoded, true, false, "A valid SubjectConfirmation was not found on this Response");
	}

	@Test
	public void testIsValidSubjectConfirmation_noSubjectConfirmationData() throws Exception {
		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		final String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_subjectconfirmation_data.xml.base64");

		assertResponseValid(settings, samlResponseEncoded, false, false, "No Signature found. SAML Response rejected");
		assertResponseValid(settings, samlResponseEncoded, true, false, "A valid SubjectConfirmation was not found on this Response");
	}

	@Test
	public void testIsValidSubjectConfirmation_invalidInResponseTo() throws Exception {
		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		final String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_subjectconfirmation_inresponse.xml.base64");

		assertResponseValid(settings, samlResponseEncoded, false, false, "No Signature found. SAML Response rejected");
		assertResponseValid(settings, samlResponseEncoded, true, false, "A valid SubjectConfirmation was not found on this Response: SubjectConfirmationData has an invalid InResponseTo value");
	}

	@Test
	public void testIsValidSubjectConfirmation_unmatchedInResponseTo() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(true);

		final String samlResponseEncoded = loadSignMessageAndEncode("data/responses/invalids/invalid_unpaired_inresponsesto.xml");

		assertResponseValid(settings, samlResponseEncoded, true, false,
				"A valid SubjectConfirmation was not found on this Response: SubjectConfirmationData has an invalid InResponseTo value");
		assertResponseValid(settings, samlResponseEncoded, false, true, null);
	}

	@Test
	public void testIsValidSubjectConfirmation_invalidRecipient() throws Exception {
		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		final String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_subjectconfirmation_recipient.xml.base64");

		assertResponseValid(settings, samlResponseEncoded, false, false, "No Signature found. SAML Response rejected");
		assertResponseValid(settings, samlResponseEncoded, true, false, "A valid SubjectConfirmation was not found on this Response: SubjectConfirmationData doesn't match a valid Recipient");
	}

	@Test
	public void testIsValidSubjectConfirmation_noLongerValid() throws Exception {
		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		final String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/invalid_subjectconfirmation_noa.xml.base64");

		assertResponseValid(settings, samlResponseEncoded, false, false, "No Signature found. SAML Response rejected");
		assertResponseValid(settings, samlResponseEncoded, true, false, "A valid SubjectConfirmation was not found on this Response: SubjectConfirmationData is no longer valid");
	}

	@Test
	public void testIsValidSubjectConfirmation_notYetValid() throws Exception {
		final Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		final String samlResponseEncoded = loadAndEncode("data/responses/invalids/invalid_subjectconfirmation_nb.xml");

		assertResponseValid(settings, samlResponseEncoded, false, false, "No Signature found. SAML Response rejected");
		assertResponseValid(settings, samlResponseEncoded, true, false, "A valid SubjectConfirmation was not found on this Response: SubjectConfirmationData is not yet valid");
	}

	@Test
	public void testIsValidSubjectConfirmation_missingRecipient() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(true);

		final String samlResponseEncoded = loadSignMessageAndEncode("data/responses/invalids/invalid_subjectconfirmation_no_recipient.xml");

		assertResponseValid(settings, samlResponseEncoded, false, true, null);
		assertResponseValid(settings, samlResponseEncoded, true, false,
				"A valid SubjectConfirmation was not found on this Response: SubjectConfirmationData doesn't contain a Recipient");
	}

	@Test
	public void testIsValidSubjectConfirmation_missingNotOnOrAfter() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(true);

		final String samlResponseEncoded = loadSignMessageAndEncode("data/responses/invalids/invalid_subjectconfirmation_no_notonorafter.xml");

		assertResponseValid(settings, samlResponseEncoded, false, true, null);
		assertResponseValid(settings, samlResponseEncoded, true, false,
				"A valid SubjectConfirmation was not found on this Response: SubjectConfirmationData doesn't contain a NotOnOrAfter attribute");
	}

	@Test
	public void testIsValidSubjectConfirmation_multipleIssues() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(true);

		final String samlResponseEncoded = loadSignMessageAndEncode("data/responses/invalids/invalid_subjectconfirmation_multiple_issues.xml");

		assertResponseValid(settings, samlResponseEncoded, false, true, null);
		assertResponseValid(settings, samlResponseEncoded, true, false,
				"A valid SubjectConfirmation was not found on this Response: " +
						"\n[0] SubjectConfirmationData doesn't contain a NotOnOrAfter attribute, " +
						"\n[1] SubjectConfirmationData doesn't contain a Recipient, " +
						"\n[2] SubjectConfirmationData is no longer valid");
	}

	@Test
	public void testIsValid_multipleThreads() throws Exception {
		// having
		final int jobCount = 100;
		final int threadCount = 5;
		final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
		final List<Throwable> errors = new CopyOnWriteArrayList<>();
		final AtomicInteger successCount = new AtomicInteger();

		// when
		for (int i = 0; i < jobCount; i++) {
			executor.submit(new Runnable() {
				@Override
				public void run() {
					try {
						Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
						settings.setWantAssertionsSigned(false);
						settings.setWantMessagesSigned(true);
						final String samlResponseEncoded = loadSignMessageAndEncode("data/responses/valid_idp_initiated_response.xml");

						assertResponseValid(settings, samlResponseEncoded, true, true, null);
						successCount.incrementAndGet();
					} catch (Throwable e) {
						errors.add(e);
					}
				}
			});
		}
		executor.shutdown();
		executor.awaitTermination(30, TimeUnit.SECONDS);

		// then
		assertThat(errors, Matchers.empty());
		assertThat(successCount.get(), is(jobCount));
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: Datetime with Miliseconds
	 *
	 * @throws Error
	 * @throws IOException
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 *

	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testDatetimeWithMiliseconds() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response_with_miliseconds.xm.base64");
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());
	}

	@Test
	public void testParseAzureB2CTimestamp() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/redacted_azure_b2c.xml.base64");
		
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);
		setDateTime("2020-07-16T07:57:00Z");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("A valid SubjectConfirmation was not found on this Response: SubjectConfirmationData doesn't match a valid Recipient", samlResponse.getError());

		setDateTime("2020-07-01T00:00:00Z");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Could not validate timestamp: not yet valid. Check system clock.", samlResponse.getError());

		setDateTime("2020-08-01T00:00:00Z");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Could not validate timestamp: expired. Check system clock.", samlResponse.getError());	
	}
	
	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid requestId
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidRequestId() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));

		assertTrue(samlResponse.isValid());
		assertTrue(samlResponse.isValid("invalidRequestId"));

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		assertFalse(samlResponse.isValid("invalidRequestId"));
		assertThat(samlResponse.getError(), containsString("The InResponseTo of the Response"));		
	}

	@Test
	public void testUnexpectedRequestId() throws Exception {
		Saml2Settings acceptingUnexpectedInResponseTo = new SettingsBuilder().fromFile("config/config.my.properties").build();
		Saml2Settings rejectingUnexpectedInResponseTo = new SettingsBuilder().fromFile("config/config.my.properties").build();
		rejectingUnexpectedInResponseTo.setRejectUnsolicitedResponsesWithInResponseTo(true);

		final String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");

		assertResponseValid(acceptingUnexpectedInResponseTo, samlResponseEncoded, true, true, null);
		assertResponseValid(rejectingUnexpectedInResponseTo, samlResponseEncoded, true, false,
				"The Response has an InResponseTo attribute: ONELOGIN_5fe9d6e499b2f0913206aab3f7191729049bb807 while no InResponseTo was expected");
	}

	@Test
	public void testMissingExpectedRequestId() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantMessagesSigned(true);
		settings.setWantAssertionsSigned(false);
		settings.setStrict(true);

		// message with no InResponseTo
		final String samlResponseEncoded = loadSignMessageAndEncode("data/responses/valid_idp_initiated_response.xml");

		final SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid("expected-id"));
		assertEquals(samlResponse.getError(), "The InResponseTo of the Response: null, does not match the ID of the AuthNRequest sent by the SP: expected-id");
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid signing issues
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidSignIssues() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");
		settings.setStrict(false);

		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(false);		
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);

		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(false);		
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("The Assertion of the Response is not signed and the SP requires it", samlResponse.getError());

		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("The Message of the Response is not signed and the SP requires it", samlResponse.getError());

		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("The Assertion of the Response is not signed and the SP requires it", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid encryption issues
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidEncIssues() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");
		settings.setStrict(false);

		settings.setWantAssertionsEncrypted(false);
		settings.setWantNameIdEncrypted(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsEncrypted(true);
		settings.setWantNameIdEncrypted(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsEncrypted(false);
		settings.setWantNameIdEncrypted(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsEncrypted(true);
		settings.setWantNameIdEncrypted(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setStrict(true);

		settings.setWantAssertionsEncrypted(false);
		settings.setWantNameIdEncrypted(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings.setWantAssertionsEncrypted(true);
		settings.setWantNameIdEncrypted(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("The assertion of the Response is not encrypted and the SP requires it", samlResponse.getError());

		settings.setWantAssertionsEncrypted(false);
		settings.setWantNameIdEncrypted(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("The NameID of the Response is not encrypted and the SP requires it", samlResponse.getError());

		settings.setWantAssertionsEncrypted(true);
		settings.setWantNameIdEncrypted(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("The assertion of the Response is not encrypted and the SP requires it", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid cert
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidCert() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.invalididpcertstring.properties").build();
		settings.setStrict(false);
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Signature validation failed. SAML Response rejected", samlResponse.getError());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid response with different namespaces
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testNamespaceIsValid() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_namespaces.xml.base64");

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid response from ADFS
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testADFSValid() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.adfs.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_adfs1.xml.base64");

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid response
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValid() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid response validated with certfingerprint
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValid2() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.mywithnocert.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid encrypted assertion
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValid_doubleSignedEncrypted() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(true);
		String samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_encrypted_assertion.xml.base64");

		assertResponseValid(settings, samlResponseEncoded, false, true, null);
		assertResponseValid(settings, samlResponseEncoded, true, true, null);
	}

	@Test
	public void testIsValid_signedResponseEncryptedAssertion() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(true);

		String samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_encrypted_assertion.xml.base64");

		assertResponseValid(settings, samlResponseEncoded, false, true, null);
		assertResponseValid(settings, samlResponseEncoded, true, true, null);
		settings.setWantAssertionsSigned(true);
		assertResponseValid(settings, samlResponseEncoded, false, true, null);
		assertResponseValid(settings, samlResponseEncoded, true, false, "The Assertion of the Response is not signed and the SP requires it");
	}

	@Test
	public void testIsValid_signedEncryptedAssertion() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(true);
		settings.setWantMessagesSigned(false);

		String samlResponseEncoded = Util.getFileAsString("data/responses/signed_encrypted_assertion.xml.base64");

		assertResponseValid(settings, samlResponseEncoded, false, true, null);
		assertResponseValid(settings, samlResponseEncoded, true, true, null);
		settings.setWantMessagesSigned(true);
		assertResponseValid(settings, samlResponseEncoded, false, true, null);
		assertResponseValid(settings, samlResponseEncoded, true, false, "The Message of the Response is not signed and the SP requires it");
	}

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid sign response / sign assertion / both signed
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValidSign() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(false);
		String samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_response.xml.base64");

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");

		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_response.xml.base64");

		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());		
	}
	
	/**
	 * Tests the isValid method of SamlResponse with idpx509certMulti
	 * Case: valid sign response / sign assertion / both signed
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValidSignWithCertMulti() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.mywithmulticert.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(false);
		String samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_response.xml.base64");

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");

		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_response.xml.base64");

		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.isValid());		
	}
	

	/**
	 * Tests the processSignedElements method of SamlResponse
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#processSignedElements
	 */
	@Test
	public void testProcessSignedElementsInvalidSignElement() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_response.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(!samlResponse.processSignedElements().isEmpty());

		samlResponseEncoded = Util.getFileAsString("data/responses/signed_assertion_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(!samlResponse.processSignedElements().isEmpty());

		samlResponseEncoded = Util.getFileAsString("data/responses/double_signed_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(!samlResponse.processSignedElements().isEmpty());

		samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertTrue(samlResponse.processSignedElements().isEmpty());
	}

	/**
	 * Tests the processSignedElements method of SamlResponse
	 * Case: invalid Signature Element
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#processSignedElements
	 */
	@Test
	public void testProcessSignedElementsInvalidSignElem() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Invalid Signature Element {urn:oasis:names:tc:SAML:2.0:assertion}Subject SAML Response rejected");
		samlResponse.processSignedElements();
	}

	/**
	 * Tests the processSignedElements method of SamlResponse
	 * Case: another invalid Signature Element
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#processSignedElements
	 */
	@Test
	public void testProcessSignedElementsInvalidSignElem2() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element2.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Invalid Signature Element {urn:oasis:names:tc:SAML:2.0:assertion}Subject SAML Response rejected");
		samlResponse.processSignedElements();
	}
	
	/**
	 * Tests the processSignedElements method of SamlResponse
	 * Case: invalid id
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#processSignedElements
	 */
	@Test
	public void testProcessSignedElementsNoId() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_assertion_id.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Signed Element must contain an ID. SAML Response rejected");
		samlResponse.processSignedElements();
	}

	/**
	 * Tests the processSignedElements method of SamlResponse
	 * Case: duplicate reference uri
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#processSignedElements
	 */
	@Test
	public void testProcessSignedElementsDuplicateRef() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/responses/invalids/duplicate_reference_uri.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		
		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("Found an invalid Signed Element. SAML Response rejected");
		samlResponse.processSignedElements();
	}
	

	/**
	 * Tests the isValid method of SamlResponse
	 * Case: invalid signs
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidSign() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError { 
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(true);
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings = new SettingsBuilder().fromFile("config/config.my.properties").build();

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/triple_signed_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Duplicated ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/signed_assertion_response_with_2signatures.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Duplicated ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/signed_message_response_with_2signatures.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Duplicated ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid Signature Element {urn:oasis:names:tc:SAML:2.0:assertion}Subject SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element2.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid Signature Element {urn:oasis:names:tc:SAML:2.0:assertion}Subject SAML Response rejected", samlResponse.getError());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/duplicate_reference_uri.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Found an invalid Signed Element. SAML Response rejected", samlResponse.getError());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_assertion_id.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Signed Element must contain an ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/bad_reference.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Found an invalid Signed Element. SAML Response rejected", samlResponse.getError());	
	}
	
	

	/**
	 * Tests the isValid method of SamlResponse with Idpx509certMulti
	 * Case: invalid signs
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsInValidSignWithCertMulti() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError { 
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(true);
		String samlResponseEncoded = Util.getFileAsString("data/responses/unsigned_response.xml.base64");

		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("No Signature found. SAML Response rejected", samlResponse.getError());

		settings = new SettingsBuilder().fromFile("config/config.mywithmulticert.properties").build();

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/triple_signed_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Duplicated ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/signed_assertion_response_with_2signatures.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Duplicated ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/signed_message_response_with_2signatures.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Duplicated ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid Signature Element {urn:oasis:names:tc:SAML:2.0:assertion}Subject SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element2.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Invalid Signature Element {urn:oasis:names:tc:SAML:2.0:assertion}Subject SAML Response rejected", samlResponse.getError());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/duplicate_reference_uri.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Found an invalid Signed Element. SAML Response rejected", samlResponse.getError());
		
		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/no_assertion_id.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Signed Element must contain an ID. SAML Response rejected", samlResponse.getError());

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/bad_reference.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertFalse(samlResponse.isValid());
		assertEquals("Found an invalid Signed Element. SAML Response rejected", samlResponse.getError());	
	}	

	/**
	 * Tests the validateSignedElements method of SamlResponse
	 * Case: invalid signs
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#validateSignedElements
	 */
	@Test
	public void testValidateSignedElements() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		ArrayList<String> signedElements = new ArrayList<String>();
		String samlResponseEncoded = Util.getFileAsString("data/responses/signed_message_response.xml.base64");
		Document samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		NodeList signNodes = Util.query(samlResponseDoc, "//ds:Signature");

		assertFalse(samlResponse.validateSignedElements(signedElements));

		signedElements = new ArrayList<String>();
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			signedElements.add("{" + signNode.getParentNode().getNamespaceURI() + "}" + signNode.getParentNode().getLocalName());
		}
		assertTrue(samlResponse.validateSignedElements(signedElements));

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/triple_signed_response.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		signNodes = Util.query(samlResponseDoc, "//ds:Signature");

		signedElements = new ArrayList<String>();
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			signedElements.add(signNode.getParentNode().getLocalName());
		}
		assertFalse(samlResponse.validateSignedElements(signedElements));

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/signed_assertion_response_with_2signatures.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		signNodes = Util.query(samlResponseDoc, "//ds:Signature");

		signedElements = new ArrayList<String>();
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			signedElements.add("{" + signNode.getParentNode().getNamespaceURI() + "}" + signNode.getParentNode().getLocalName());
		}
		assertFalse(samlResponse.validateSignedElements(signedElements));

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/signed_message_response_with_2signatures.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		signNodes = Util.query(samlResponseDoc, "//ds:Signature");

		signedElements = new ArrayList<String>();
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			signedElements.add("{" + signNode.getParentNode().getNamespaceURI() + "}" + signNode.getParentNode().getLocalName());
		}
		assertFalse(samlResponse.validateSignedElements(signedElements));

		samlResponseEncoded = Util.getFileAsString("data/responses/invalids/wrong_signed_element.xml.base64");
		samlResponseDoc = Util.loadXML(new String(Util.base64decoder(samlResponseEncoded)));
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		signNodes = Util.query(samlResponseDoc, "//ds:Signature");

		signedElements = new ArrayList<String>();
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			signedElements.add("{" + signNode.getParentNode().getNamespaceURI() + "}" + signNode.getParentNode().getLocalName());
		}
		assertFalse(samlResponse.validateSignedElements(signedElements));
	}
	
	/**
	 * Tests the isValid method of SamlResponse
	 * Case: valid response that has no reference URI
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#isValid
	 */
	@Test
	public void testIsValidSignWithEmptyReferenceURI() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.noreferenceuri.properties").build();
		settings.setWantAssertionsSigned(false);
		settings.setWantMessagesSigned(false);
		final String requestURL = "http://localhost:9001/v1/users/authorize/saml";
		String samlResponseEncoded = Util.getFileAsString("data/responses/response_without_reference_uri.xml.base64");

		settings.setStrict(false);
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertTrue(samlResponse.isValid());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(requestURL, samlResponseEncoded));
		assertTrue(samlResponse.isValid());
		
		HashMap<String, List<String>> attributes = samlResponse.getAttributes();
		assertFalse(attributes.isEmpty());
		String attrName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
		assertEquals("saml@user.com", attributes.get(attrName).get(0));
	}
	
	/**
	 * Tests the getError and getValidationException methods of SamlResponse
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.authn.SamlResponse#getError
	 */
	@Test
	public void testGetError() throws IOException, Error, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException, ValidationError {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setStrict(true);
		String samlResponseEncoded = Util.getFileAsString("data/responses/response4.xml.base64");
		SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertNull(samlResponse.getError());
		assertNull(samlResponse.getValidationException());
		samlResponse.isValid();
		assertThat(samlResponse.getError(), containsString("SAML Response must contain 1 Assertion."));
		assertTrue(samlResponse.getValidationException() instanceof ValidationError);

		settings.setStrict(false);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		samlResponse.isValid();
		assertThat(samlResponse.getError(), containsString("SAML Response must contain 1 Assertion."));
		assertTrue(samlResponse.getValidationException() instanceof ValidationError);

		samlResponseEncoded = Util.getFileAsString("data/responses/valid_response.xml.base64");
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertNull(samlResponse.getError());
		assertNull(samlResponse.getValidationException());
		samlResponse.isValid();
		assertNull(samlResponse.getError());
		assertNull(samlResponse.getValidationException());

		settings.setStrict(true);
		samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));
		assertNull(samlResponse.getError());
		assertNull(samlResponse.getValidationException());
		samlResponse.isValid();
		assertNull(samlResponse.getError());
		assertNull(samlResponse.getValidationException());
	}

	private String loadAndEncode(String path) throws Exception
	{
		return Util.base64encoder(Util.getFileAsString(path));
	}

	private String loadSignMessageAndEncode(String path) throws Exception
	{
		String samlResponse = Util.getFileAsString(path);
		final String signed = Util.addSign(Util.convertStringToDocument(samlResponse),
				Util.loadPrivateKey(Util.getFileAsString("data/customPath/certs/sp.pem")),
				Util.loadCert(Util.getFileAsString("data/customPath/certs/sp.crt")), Constants.RSA_SHA1);
		return Util.base64encoder(signed);
	}

	private void assertResponseValid(Saml2Settings settings, String samlResponseEncoded, boolean strict, boolean expectedValid, String expectedError) throws Exception
	{
		settings.setStrict(strict);
		final SamlResponse samlResponse = new SamlResponse(settings, newHttpRequest(samlResponseEncoded));

		assertEquals(expectedValid, samlResponse.isValid());
		assertEquals(expectedError, samlResponse.getError());
	}

	private static HttpRequest newHttpRequest(String samlResponseEncoded) {
		return newHttpRequest(ACS_URL, samlResponseEncoded);
	}

	private static HttpRequest newHttpRequest(String requestURL, String samlResponseEncoded) {
		return new HttpRequest(requestURL, (String)null).addParameter("SAMLResponse", samlResponseEncoded);
	}
	
	private void setDateTime(String ISOTimeStamp) {
		DateTime dateTime = ISODateTimeFormat.dateTimeNoMillis().withZoneUTC().parseDateTime(ISOTimeStamp);
		DateTimeUtils.setCurrentMillisFixed(dateTime.toDate().getTime());
	}
}

