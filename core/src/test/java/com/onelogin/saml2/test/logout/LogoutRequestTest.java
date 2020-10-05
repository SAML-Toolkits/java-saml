package com.onelogin.saml2.test.logout;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.io.IOException;
import java.net.URISyntaxException;

import javax.xml.xpath.XPathExpressionException;

import java.security.PrivateKey;

import org.w3c.dom.Document;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.onelogin.saml2.logout.LogoutRequest;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.test.NaiveUrlEncoder;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

public class LogoutRequestTest {

	@Rule
	public ExpectedException expectedEx = ExpectedException.none();

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

		final String logoutRequestString = Util.getFileAsString("data/logout_requests/logout_request.xml");
		LogoutRequest logoutRequest = new LogoutRequest(settings) {
			@Override
			public String getLogoutRequestXml() {
				return logoutRequestString;
			}
		};

		String expectedLogoutRequestStringBase64Deflated = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		String expectedLogoutRequestStringBase64 = Util.getFileAsString("data/logout_requests/logout_request.xml.base64");

		String logoutRequestStringBase64Deflated = logoutRequest.getEncodedLogoutRequest();
		assertEquals(logoutRequestStringBase64Deflated, expectedLogoutRequestStringBase64Deflated);

		logoutRequestStringBase64Deflated = logoutRequest.getEncodedLogoutRequest(null);
		assertEquals(logoutRequestStringBase64Deflated, expectedLogoutRequestStringBase64Deflated);

		logoutRequestStringBase64Deflated = logoutRequest.getEncodedLogoutRequest(true);
		assertEquals(logoutRequestStringBase64Deflated, expectedLogoutRequestStringBase64Deflated);

		logoutRequestStringBase64Deflated = logoutRequest.getEncodedLogoutRequest(false);
		assertNotEquals(logoutRequestStringBase64Deflated, expectedLogoutRequestStringBase64Deflated);
		assertEquals(logoutRequestStringBase64Deflated,expectedLogoutRequestStringBase64);

		settings.setCompressRequest(true);
		logoutRequest = new LogoutRequest(settings) {
			@Override
			public String getLogoutRequestXml() {
				return logoutRequestString;
			}
		};
		logoutRequestStringBase64Deflated = logoutRequest.getEncodedLogoutRequest(null);
		assertEquals(logoutRequestStringBase64Deflated, expectedLogoutRequestStringBase64Deflated);

		settings.setCompressRequest(false);
		logoutRequest = new LogoutRequest(settings) {
			@Override
			public String getLogoutRequestXml() {
				return logoutRequestString;
			}
		};
		logoutRequestStringBase64Deflated = logoutRequest.getEncodedLogoutRequest(null);
		assertNotEquals(logoutRequestStringBase64Deflated, expectedLogoutRequestStringBase64Deflated);
		assertEquals(logoutRequestStringBase64Deflated, expectedLogoutRequestStringBase64);
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

		final String requestURL = "/";
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");

		LogoutRequest logoutRequest = new LogoutRequest(settings, newHttpRequest(requestURL, samlRequestEncoded));

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
	 * Tests the getLogoutRequestXml method of LogoutRequest
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#getLogoutRequestXml
	 */
	@Test
	public void testGetLogoutRequestXml() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		LogoutRequest logoutRequest = new LogoutRequest(settings);
		String logoutRequestXML = logoutRequest.getLogoutRequestXml();
		assertThat(logoutRequestXML, containsString("<samlp:LogoutRequest"));

		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request.xml.base64");
		String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlRequestEncoded);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		logoutRequestXML = logoutRequest.getLogoutRequestXml();
		assertThat(logoutRequestXML, containsString("<samlp:LogoutRequest"));

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
		assertThat(nameIdDataStr, containsString("Value=ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c"));
		assertThat(nameIdDataStr, not(containsString("SPNameQualifier")));

		logoutRequest = new LogoutRequest(settings, null, null, null);
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutRequest"));

		nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, null).toString();
		assertThat(nameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:2.0:nameid-format:entity"));
		assertThat(nameIdDataStr, containsString("Value=http://idp.example.com/"));
		assertThat(nameIdDataStr, not(containsString("SPNameQualifier=http://localhost:8080/java-saml-jspsample/metadata.jsp")));

		// This settings file contains as IdP cert the SP cert, so I can use the getSPkey to decrypt.
		settings = new SettingsBuilder().fromFile("config/config.samecerts.properties").build();
		logoutRequest = new LogoutRequest(settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null);
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		PrivateKey key = settings.getSPkey();
		nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, key).toString();
		assertThat(nameIdDataStr, containsString("Value=ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c"));
		assertThat(nameIdDataStr, not(containsString("SPNameQualifier")));

		logoutRequest = new LogoutRequest(settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null, "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress");
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, key).toString();
		assertThat(nameIdDataStr, containsString("urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"));
		assertThat(nameIdDataStr, containsString("Value=ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c"));
		assertThat(nameIdDataStr, not(containsString("SPNameQualifier")));

  	    String keyString = Util.getFileAsString("data/customPath/certs/sp.pem");
  	    key = Util.loadPrivateKey(keyString);
		logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");
		nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, key).toString();
		assertThat(nameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"));
		assertThat(nameIdDataStr, containsString("Value=ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69"));
		assertThat(nameIdDataStr, containsString("SPNameQualifier=https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php"));

		settings = new SettingsBuilder().fromFile("config/config.emailaddressformat.properties").build();
		logoutRequest = new LogoutRequest(settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null);
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutRequest"));
		nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, null).toString();
		assertThat(nameIdDataStr, containsString("Value=ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c"));
		assertThat(nameIdDataStr, containsString("Format=urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"));
		assertThat(nameIdDataStr, not(containsString("SPNameQualifier")));

		logoutRequest = new LogoutRequest(settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null, Constants.NAMEID_PERSISTENT, settings.getIdpEntityId(), settings.getSpEntityId());
		logoutRequestStringBase64 = logoutRequest.getEncodedLogoutRequest();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutRequest"));
		nameIdDataStr = LogoutRequest.getNameIdData(logoutRequestStr, null).toString();
		assertThat(nameIdDataStr, containsString("Value=ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c"));
		assertThat(nameIdDataStr, containsString("Format=" + Constants.NAMEID_PERSISTENT));
		assertThat(nameIdDataStr, containsString("NameQualifier=" + settings.getIdpEntityId()));
		assertThat(nameIdDataStr, containsString("SPNameQualifier=" + settings.getSpEntityId()));
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
	@Test
	public void testGetNameIdDataNoKey() throws Exception {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");

		expectedEx.expect(SettingsException.class);
		expectedEx.expectMessage("Key is required in order to decrypt the NameID");
		LogoutRequest.getNameIdData(logoutRequestStr, null).toString();
	}

	/**
	 * Tests the getNameIdData method of LogoutRequest
	 * Case: Not able to get the NameIdData due wrong private key to decrypt.
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameIdData
	 */
	@Test
	public void testGetNameIdDataWrongKey() throws Exception {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");
		String keyString = Util.getFileAsString("data/misc/sp4.key");
		PrivateKey key = Util.loadPrivateKey(keyString);

		expectedEx.expect(Exception.class);
		expectedEx.expectMessage("Not able to decrypt the EncryptedID and get a NameID");
		LogoutRequest.getNameIdData(logoutRequestStr, key).toString();
	}

	/**
	 * Tests the getNameIdData method of LogoutRequest
	 * Case: Not NameId element.
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameIdData
	 */
	@Test
	public void testGetNameIdDataNoNameId() throws Exception {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_no_nameid.xml");

		expectedEx.expect(ValidationError.class);
		expectedEx.expectMessage("No name id found in Logout Request.");
		LogoutRequest.getNameIdData(logoutRequestStr, null).toString();
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
	@Test
	public void testGetNameIdNoKey() throws Exception {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");

		expectedEx.expect(SettingsException.class);
		expectedEx.expectMessage("Key is required in order to decrypt the NameID");
		LogoutRequest.getNameId(logoutRequestStr, null).toString();
	}

	/**
	 * Tests the getNameId method of LogoutRequest
	 * Case: Not able to get the NameID due wrong private key to decrypt.
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#getNameId
	 */
	@Test
	public void testGetNameIdWrongKey() throws Exception {
		String logoutRequestStr = Util.getFileAsString("data/logout_requests/logout_request_encrypted_nameid.xml");
		String keyString = Util.getFileAsString("data/misc/sp4.key");
		PrivateKey key = Util.loadPrivateKey(keyString);

		expectedEx.expect(Exception.class);
		expectedEx.expectMessage("Not able to decrypt the EncryptedID and get a NameID");
		LogoutRequest.getNameIdData(logoutRequestStr, key).toString();
	}

	/**
	 * Tests the getIssuer method of LogoutRequest
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XPathExpressionException
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#getIssuer
	 */
	@Test
	public void testGetIssuer() throws URISyntaxException, IOException, XPathExpressionException {
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
	 * @throws XPathExpressionException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#getSessionIndexes
	 */
	@Test
	public void testGetSessionIndexes() throws URISyntaxException, IOException, XPathExpressionException, XMLEntityException, Error {
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
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsInvalidIssuer() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/invalids/invalid_issuer.xml.base64");
		final String requestURL = "http://stuff.com/endpoints/endpoints/sls.php";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlRequestEncoded);

		settings.setStrict(false);
		LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertFalse(logoutRequest.isValid());
		assertEquals("Invalid issuer in the Logout Request. Was 'https://example.hello.com/access/saml', but expected 'http://idp.example.com/'", logoutRequest.getError());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: Invalid XML
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsInValidWrongXML() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/invalids/invalid_xml.xml.base64");
		final String requestURL = "http://stuff.com/endpoints/endpoints/sls.php";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlRequestEncoded);

		settings.setWantXMLValidation(true);
		settings.setStrict(false);
		LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertFalse(logoutRequest.isValid());
		assertEquals("Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd", logoutRequest.getError());

		settings.setWantXMLValidation(false);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(false);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: Invalid Destination
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsInvalidDestination() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		final String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlRequestEncoded);

		settings.setStrict(false);
		LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertFalse(logoutRequest.isValid());
		assertThat(logoutRequest.getError(), containsString("The LogoutRequest was received at"));
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: Invalid NotOnOrAfter
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsInvalidNotOnOrAfter() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/invalids/not_after_failed.xml.base64");
		final String requestURL = "http://stuff.com/endpoints/endpoints/sls.php";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlRequestEncoded);

		settings.setStrict(false);
		LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertFalse(logoutRequest.isValid());
		assertEquals("Could not validate timestamp: expired. Check system clock.", logoutRequest.getError());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsValid() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlRequestEncoded);

		settings.setStrict(true);
		LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
		assertFalse(logoutRequest.isValid());

		settings.setStrict(false);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		requestURL = "http://stuff.com/endpoints/endpoints/sls.php";
		httpRequest = newHttpRequest(requestURL, samlRequestEncoded);

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(false);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());
	}

	@Test
	public void testIsInValidSign_defaultUrlEncode() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.knownIdpPrivateKey.properties").build();
		settings.setStrict(true);
		settings.setWantMessagesSigned(true);

		final String requestURL = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls";
		String samlRequestEncoded = "lVLBitswEP0Vo7tjeWzJtki8LIRCYLvbNksPewmyPc6K2pJqyXQ/v1LSQlroQi/DMJr33rwZbZ2cJysezNms/gt+X9H55G2etBOXlx1ZFy2MdMoJLWd0wvfieP/xQcCGCrsYb3ozkRvI+wjpHC5eGU2Sw35HTg3lA8hqZFwWFcMKsStpxbEsxoLXeQN9OdY1VAgk+YqLC8gdCUQB7tyKB+281D6UaF6mtEiBPudcABcMXkiyD26Ulv6CevXeOpFlVvlunb5ttEmV3ZjlnGn8YTRO5qx0NuBs8kzpAd829tXeucmR5NH4J/203I8el6gFRUqbFPJnyEV51Wq30by4TLW0/9ZyarYTxt4sBsjUYLMZvRykl1Fxm90SXVkfwx4P++T4KSafVzmpUcVJ/sfSrQZJPphllv79W8WKGtLx0ir8IrVTqD1pT2MH3QAMSs4KTvui71jeFFiwirOmprwPkYW063+5uRq4urHiiC4e8hCX3J5wqAEGaPpw9XB5JmkBdeDqSlkz6CmUXdl0Qae5kv2F/1384wu3PwE=";
		String relayState = "_1037fbc88ec82ce8e770b2bed1119747bb812a07e6";
		String sigAlg = Constants.SHA256;

		String queryString = "SAMLRequest=" + Util.urlEncoder(samlRequestEncoded);
		queryString += "&RelayState=" + Util.urlEncoder(relayState);
		queryString += "&SigAlg=" + Util.urlEncoder(sigAlg);

		//This signature is based on the query string above
		String signature = "cxDTcLRHhXJKGYcjZE2RRz5p7tVg/irNimq48KkJ0n10wiGwAmuzUByxEm4OHbetDrHGtxI5ygjrR0/HcrD8IkYyI5Ie4r5tJYkfdtpUrvOQ7khbBvP9GzEbZIrz7eH1ALdCDchORaRB/cs6v+OZbBj5uPTrN//wOhZl2k9H2xVW/SYy17jDoIKh/wvqtQ9FF+h2UxdUEhxeB/UUXOC6nVLMo+RGaamSviYkUE1Zu1tmalO+F6FivNQ31T/TkqzWz0KEjmnFs3eKbHakPVuUHpDQm7Gf2gBS1TXwVQsL7e2axtvv4RH5djlq1Z2WH2V+PwGOkIvLxf3igGUSR1A8bw==";

		HttpRequest httpRequest = new HttpRequest(requestURL, queryString)
				.addParameter("SAMLRequest", samlRequestEncoded)
				.addParameter("RelayState", relayState)
				.addParameter("SigAlg", sigAlg)
				.addParameter("Signature", signature);

		LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue("Signature validation failed", logoutRequest.isValid());
	}

	@Test
	public void testIsInValidSign_naiveUrlEncoding() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.knownIdpPrivateKey.properties").build();
		settings.setStrict(true);
		settings.setWantMessagesSigned(true);

		final String requestURL = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls";
		String samlRequestEncoded = "lVLBitswEP0Vo7tjeWzJtki8LIRCYLvbNksPewmyPc6K2pJqyXQ/v1LSQlroQi/DMJr33rwZbZ2cJysezNms/gt+X9H55G2etBOXlx1ZFy2MdMoJLWd0wvfieP/xQcCGCrsYb3ozkRvI+wjpHC5eGU2Sw35HTg3lA8hqZFwWFcMKsStpxbEsxoLXeQN9OdY1VAgk+YqLC8gdCUQB7tyKB+281D6UaF6mtEiBPudcABcMXkiyD26Ulv6CevXeOpFlVvlunb5ttEmV3ZjlnGn8YTRO5qx0NuBs8kzpAd829tXeucmR5NH4J/203I8el6gFRUqbFPJnyEV51Wq30by4TLW0/9ZyarYTxt4sBsjUYLMZvRykl1Fxm90SXVkfwx4P++T4KSafVzmpUcVJ/sfSrQZJPphllv79W8WKGtLx0ir8IrVTqD1pT2MH3QAMSs4KTvui71jeFFiwirOmprwPkYW063+5uRq4urHiiC4e8hCX3J5wqAEGaPpw9XB5JmkBdeDqSlkz6CmUXdl0Qae5kv2F/1384wu3PwE=";
		String relayState = "_1037fbc88ec82ce8e770b2bed1119747bb812a07e6";
		String sigAlg = Constants.SHA256;

		String queryString = "SAMLRequest=" + NaiveUrlEncoder.encode(samlRequestEncoded);
		queryString += "&RelayState=" + NaiveUrlEncoder.encode(relayState);
		queryString += "&SigAlg=" + NaiveUrlEncoder.encode(sigAlg);

		//This signature is based on the query string above
		String signatureNaiveEncoding = "Gj2mUq6RBPAPXI9VjDDlwAxueSEBlOfgpWKLpsQbqIp+2XPFtC/vPAZpuPjHCDNNnAI3WKZa4l8ijwQBTqQwKz88k9gTx6vcLxPl2L4SrWdLOokiGrIVYJ+0sK2hapHHMa7WzGiTgpeTuejHbD4ptneaRXl4nrJAEo0WJ/rNTSWbJpnb+ENtgBnsfkmj+6z1KFY70ruo7W/vme21Jg+4XNfBSGl6LLSjEnZHJG0ET80HKvJEZayv4BQGZ3MShcSMyab/w+rLfDvDRA5RcRxw+NHOXo/kxZ3qhpa6daOwG69+PiiWmusmB2gaSq6jy2L55zFks9a36Pt5l5fYA2dE4g==";

		HttpRequest httpRequest = new HttpRequest(requestURL, queryString)
				.addParameter("SAMLRequest", samlRequestEncoded)
				.addParameter("RelayState", relayState)
				.addParameter("SigAlg", sigAlg)
				.addParameter("Signature", signatureNaiveEncoding);

		LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue("Signature validation failed", logoutRequest.isValid());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsInValidSign() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setStrict(false);
		settings.setWantMessagesSigned(true);

		final String requestURL = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls";
		String samlRequestEncoded = "lVLBitswEP0Vo7tjeWzJtki8LIRCYLvbNksPewmyPc6K2pJqyXQ/v1LSQlroQi/DMJr33rwZbZ2cJysezNms/gt+X9H55G2etBOXlx1ZFy2MdMoJLWd0wvfieP/xQcCGCrsYb3ozkRvI+wjpHC5eGU2Sw35HTg3lA8hqZFwWFcMKsStpxbEsxoLXeQN9OdY1VAgk+YqLC8gdCUQB7tyKB+281D6UaF6mtEiBPudcABcMXkiyD26Ulv6CevXeOpFlVvlunb5ttEmV3ZjlnGn8YTRO5qx0NuBs8kzpAd829tXeucmR5NH4J/203I8el6gFRUqbFPJnyEV51Wq30by4TLW0/9ZyarYTxt4sBsjUYLMZvRykl1Fxm90SXVkfwx4P++T4KSafVzmpUcVJ/sfSrQZJPphllv79W8WKGtLx0ir8IrVTqD1pT2MH3QAMSs4KTvui71jeFFiwirOmprwPkYW063+5uRq4urHiiC4e8hCX3J5wqAEGaPpw9XB5JmkBdeDqSlkz6CmUXdl0Qae5kv2F/1384wu3PwE=";
		String relayState = "_1037fbc88ec82ce8e770b2bed1119747bb812a07e6";
		String sigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
		String signature = "XCwCyI5cs7WhiJlB5ktSlWxSBxv+6q2xT3c8L7dLV6NQG9LHWhN7gf8qNsahSXfCzA0Ey9dp5BQ0EdRvAk2DIzKmJY6e3hvAIEp1zglHNjzkgcQmZCcrkK9Czi2Y1WkjOwR/WgUTUWsGJAVqVvlRZuS3zk3nxMrLH6f7toyvuJc=";

		HttpRequest httpRequest = new HttpRequest(requestURL, (String)null)
						.addParameter("SAMLRequest", samlRequestEncoded)
						.addParameter("RelayState", relayState)
						.addParameter("SigAlg", sigAlg)
						.addParameter("Signature", signature);

		LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(false);
		String signature2 = "vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333=";
		httpRequest = httpRequest.removeParameter("Signature")
								 .addParameter("Signature", signature2);

		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertFalse(logoutRequest.isValid());
		assertEquals("Signature validation failed. Logout Request rejected", logoutRequest.getError());

		httpRequest = httpRequest.removeParameter("Signature")
								 .addParameter("Signature", signature)
								 .removeParameter("SigAlg");

		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		httpRequest = httpRequest.removeParameter("Signature");
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertTrue(logoutRequest.isValid());

		settings.setStrict(true);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertFalse(logoutRequest.isValid());
		assertEquals("The Message of the Logout Request is not signed and the SP requires it", logoutRequest.getError());

		httpRequest = httpRequest.addParameter("Signature", signature);
		settings = new SettingsBuilder().fromFile("config/config.mywithnocert.properties").build();
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertFalse(logoutRequest.isValid());
		assertEquals("In order to validate the sign on the Logout Request, the x509cert of the IdP is required", logoutRequest.getError());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: No SAML Logout Request
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsValidNoLogoutRequest() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequestEncoded = "";
		final String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlRequestEncoded);

		LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
		assertFalse(logoutRequest.isValid());
		assertEquals("SAML Logout Request is not loaded", logoutRequest.getError());
	}

	/**
	 * Tests the isValid method of LogoutRequest
	 * Case: No current URL
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#isValid
	 */
	@Test
	public void testIsValidNoCurrentURL() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");

		LogoutRequest logoutRequest = new LogoutRequest(settings, null);
		assertFalse(logoutRequest.isValid());
		assertEquals("The HttpRequest of the current host was not established", logoutRequest.getError());

		final String requestURL = "";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlRequestEncoded);

		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertFalse(logoutRequest.isValid());
		assertEquals("The URL of the current host was not established", logoutRequest.getError());
	}

	/**
	 * Tests the getError and getValidationException methods of LogoutRequest
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutRequest#getError
	 */
	@Test
	public void testGetError() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(true);
		String samlRequestEncoded = Util.getFileAsString("data/logout_requests/logout_request_deflated.xml.base64");
		final String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlRequestEncoded);

		LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
		assertNull(logoutRequest.getError());
		assertNull(logoutRequest.getValidationException());
		logoutRequest.isValid();
		assertThat(logoutRequest.getError(), containsString("The LogoutRequest was received at"));
		assertTrue(logoutRequest.getValidationException() instanceof ValidationError);

		settings.setStrict(false);
		logoutRequest = new LogoutRequest(settings, httpRequest);
		assertNull(logoutRequest.getError());
		assertNull(logoutRequest.getValidationException());
		logoutRequest.isValid();
		assertNull(logoutRequest.getError());
		assertNull(logoutRequest.getValidationException());
	}

	private static HttpRequest newHttpRequest(String requestURL, String samlRequestEncoded) {
		return new HttpRequest(requestURL, (String)null).addParameter("SAMLRequest", samlRequestEncoded);
	}
}
