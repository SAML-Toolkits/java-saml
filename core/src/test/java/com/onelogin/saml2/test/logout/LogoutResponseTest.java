package com.onelogin.saml2.test.logout;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import com.onelogin.saml2.exception.ValidationError;
import java.io.IOException;
import java.net.URISyntaxException;

import javax.xml.xpath.XPathExpressionException;

import org.junit.Test;

import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.logout.LogoutResponse;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.test.NaiveUrlEncoder;
import com.onelogin.saml2.util.Util;
import com.onelogin.saml2.util.Constants;

public class LogoutResponseTest {

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
		final String logoutResponseString = Util.getFileAsString("data/logout_responses/logout_response.xml");
		final String requestURL = "/";
		HttpRequest httpRequest = new HttpRequest(requestURL, (String)null);

		LogoutResponse logoutResponseBuilder = new LogoutResponse(settings, httpRequest) {
			@Override
			public String getLogoutResponseXml() {
				return logoutResponseString;
			}
		};

 		logoutResponseBuilder.build();

		String expectedLogoutResponseStringBase64Deflated = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		String expectedLogoutResponseStringBase64 = Util.getFileAsString("data/logout_responses/logout_response.xml.base64");

		String logoutResponseStringBase64Deflated = logoutResponseBuilder.getEncodedLogoutResponse();
		assertEquals(logoutResponseStringBase64Deflated, expectedLogoutResponseStringBase64Deflated);

		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest) {
			@Override
			public String getLogoutResponseXml() {
				return logoutResponseString;
			}
		};
		logoutResponseStringBase64Deflated = logoutResponse.getEncodedLogoutResponse();
 		assertEquals(logoutResponseStringBase64Deflated, expectedLogoutResponseStringBase64Deflated);

 		logoutResponseStringBase64Deflated = logoutResponse.getEncodedLogoutResponse(null);
		assertEquals(logoutResponseStringBase64Deflated, expectedLogoutResponseStringBase64Deflated);

		logoutResponseStringBase64Deflated = logoutResponse.getEncodedLogoutResponse(true);
		assertEquals(logoutResponseStringBase64Deflated, expectedLogoutResponseStringBase64Deflated);

		logoutResponseStringBase64Deflated = logoutResponse.getEncodedLogoutResponse(false);
		assertNotEquals(logoutResponseStringBase64Deflated, expectedLogoutResponseStringBase64Deflated);
		assertEquals(logoutResponseStringBase64Deflated,expectedLogoutResponseStringBase64);

		settings.setCompressResponse(true);
		logoutResponse = new LogoutResponse(settings, httpRequest) {
			@Override
			public String getLogoutResponseXml() {
				return logoutResponseString;
			}
		};
		logoutResponseStringBase64Deflated = logoutResponse.getEncodedLogoutResponse(null);
		assertEquals(logoutResponseStringBase64Deflated, expectedLogoutResponseStringBase64Deflated);

		settings.setCompressResponse(false);
		logoutResponse = new LogoutResponse(settings, httpRequest) {
			@Override
			public String getLogoutResponseXml() {
				return logoutResponseString;
			}
		};
		logoutResponseStringBase64Deflated = logoutResponse.getEncodedLogoutResponse(null);
		assertNotEquals(logoutResponseStringBase64Deflated, expectedLogoutResponseStringBase64Deflated);
		assertEquals(logoutResponseStringBase64Deflated, expectedLogoutResponseStringBase64);
	}

	/**
	 * Tests the constructor
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse
	 */
	@Test
	public void testConstructor() throws IOException, XMLEntityException, URISyntaxException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		final String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlResponseEncoded);
		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);

		String expectedLogoutResponseStringBase64 = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		String logoutResponseStringBase64 = logoutResponse.getEncodedLogoutResponse();
		assertEquals(logoutResponseStringBase64, expectedLogoutResponseStringBase64);
	}

	/**
	 * Tests the build method of LogoutResponse
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#build
	 */
	@Test
	public void testBuild() throws IOException, XMLEntityException, URISyntaxException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();

		final String requestURL = "/";
		HttpRequest httpRequest = new HttpRequest(requestURL, (String)null);

		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertFalse(logoutResponse.isValid());
		assertEquals("SAML Logout Response is not loaded", logoutResponse.getError());
		logoutResponse.build();
		String logoutRequestStringBase64 = logoutResponse.getEncodedLogoutResponse();
		assertFalse(logoutRequestStringBase64.isEmpty());

		String logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutResponse"));
		assertThat(logoutRequestStr, not(containsString("InResponseTo=")));

		LogoutResponse logoutResponse2 = new LogoutResponse(settings, httpRequest);
		logoutResponse2.build("inResponseValue");
		logoutRequestStringBase64 = logoutResponse2.getEncodedLogoutResponse();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutResponse"));
		assertThat(logoutRequestStr, containsString("InResponseTo=\"inResponseValue\""));
		assertThat(logoutRequestStr, containsString("StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\""));

		LogoutResponse logoutResponse3 = new LogoutResponse(settings, httpRequest);
		logoutResponse3.build("inResponseValue", Constants.STATUS_REQUEST_DENIED);
		logoutRequestStringBase64 = logoutResponse3.getEncodedLogoutResponse();
		logoutRequestStr = Util.base64decodedInflated(logoutRequestStringBase64);
		assertThat(logoutRequestStr, containsString("<samlp:LogoutResponse"));
		assertThat(logoutRequestStr, containsString("InResponseTo=\"inResponseValue\""));
		assertThat(logoutRequestStr, containsString("StatusCode Value=\"" + Constants.STATUS_REQUEST_DENIED + "\""));
	}

	/**
	 * Tests the getLogoutResponseXml method of LogoutResponse
	 *
	 * @throws Exception
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#getLogoutResponseXml
	 */
	@Test
	public void testGetLogoutRequestXml() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		LogoutResponse logoutResponse = new LogoutResponse(settings, null);
		logoutResponse.build();
		String logoutResponseXML = logoutResponse.getLogoutResponseXml();
		assertThat(logoutResponseXML, containsString("<samlp:LogoutResponse"));

		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response.xml.base64");
		String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlResponseEncoded);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		logoutResponseXML = logoutResponse.getLogoutResponseXml();
		assertThat(logoutResponseXML, containsString("<samlp:LogoutResponse"));

	}

	/**
	 * Tests the getStatus method of LogoutResponse
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#getStatus
	 */
	@Test
	public void testGestStatus() throws IOException, URISyntaxException, XMLEntityException, XPathExpressionException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		final String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlResponseEncoded);
		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertEquals(Constants.STATUS_SUCCESS, logoutResponse.getStatus());

		samlResponseEncoded = Util.getFileAsString("data/logout_responses/invalids/no_status.xml.base64");
		httpRequest = newHttpRequest(requestURL, samlResponseEncoded);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertNull(logoutResponse.getStatus());
	}

	/**
	 * Tests the getIssuer method of LogoutResponse
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 * @throws XPathExpressionException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#getIssuer
	 */
	@Test
	public void testGetIssuer() throws IOException, URISyntaxException, XMLEntityException, XPathExpressionException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		final String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlResponseEncoded);
		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		String expectedIssuer = "http://idp.example.com/";
		assertEquals(expectedIssuer, logoutResponse.getIssuer());

		String logoutRequestStr = Util.base64decodedInflated(samlResponseEncoded);
		logoutRequestStr = logoutRequestStr.replace("<saml:Issuer>http://idp.example.com/</saml:Issuer>", "");
		samlResponseEncoded = Util.deflatedBase64encoded(logoutRequestStr);
		httpRequest = newHttpRequest(requestURL, samlResponseEncoded);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertNull(logoutResponse.getIssuer());
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: No SAML Logout Response
	 *
	 * @throws XMLEntityException
	 * @throws IOException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsValidNoResponse() throws XMLEntityException, IOException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		final String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, "");

		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertFalse(logoutResponse.isValid());
		assertEquals("SAML Logout Response is not loaded", logoutResponse.getError());

		httpRequest = new HttpRequest(requestURL, (String)null);
		logoutResponse = new LogoutResponse(settings, httpRequest);
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
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsInValidRequestId() throws XMLEntityException, IOException, URISyntaxException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		final String requestURL = "http://stuff.com/endpoints/endpoints/sls.php";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlResponseEncoded);

		settings.setStrict(false);
		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());

		assertTrue(logoutResponse.isValid("invalid_request_id"));

		settings.setStrict(true);
		logoutResponse = new LogoutResponse(settings, httpRequest);
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
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsInValidIssuer() throws XMLEntityException, IOException, URISyntaxException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/invalids/invalid_issuer.xml.base64");
		final String requestURL = "http://stuff.com/endpoints/endpoints/sls.php";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlResponseEncoded);

		settings.setStrict(false);
		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(true);
		assertFalse(logoutResponse.isValid());
		assertEquals("Invalid issuer in the Logout Response. Was 'http://invalid.example.com/', but expected 'http://idp.example.com/'", logoutResponse.getError());
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: Case invalid xml
	 *
	 * @throws XMLEntityException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsInValidWrongXML() throws XMLEntityException, IOException, URISyntaxException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/invalids/invalid_xml.xml.base64");
		final String requestURL = "http://stuff.com/endpoints/endpoints/sls.php";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlResponseEncoded);

		settings.setWantXMLValidation(true);
		settings.setStrict(false);
		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(true);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertFalse(logoutResponse.isValid());
		assertEquals("Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd", logoutResponse.getError());

		settings.setWantXMLValidation(false);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(false);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: Case invalid Destination
	 *
	 * @throws XMLEntityException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsInValidDestination() throws XMLEntityException, IOException, URISyntaxException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		final String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlResponseEncoded);

		settings.setStrict(false);
		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
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
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsValid() throws URISyntaxException, IOException, XMLEntityException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlResponseEncoded);

		settings.setStrict(true);
		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertFalse(logoutResponse.isValid());

		settings.setStrict(false);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());

		requestURL = "http://stuff.com/endpoints/endpoints/sls.php";
		httpRequest = newHttpRequest(requestURL, samlResponseEncoded);
		settings.setStrict(true);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(false);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());
	}

	@Test
	public void testIsInValidSign_defaultUrlEncode() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.knownIdpPrivateKey.properties").build();
		settings.setStrict(true);
		settings.setWantMessagesSigned(true);

		final String requestURL = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls";
		String samlResponseEncoded = "fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A";
		String relayState = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php";
		String sigAlg = Constants.SHA256;

		String queryString = "SAMLResponse=" + Util.urlEncoder(samlResponseEncoded);
		queryString += "&RelayState=" + Util.urlEncoder(relayState);
		queryString += "&SigAlg=" + Util.urlEncoder(sigAlg);

		//This signature is based on the query string above
		String signature = "czxEy2WDRZS1U4b2PQFpE4KRhRs8jt5bBKdTFx5oIXpte6qtm0Lk/5lzw/2S6Y1NJpj5DJvSLJvylgNE+RYfJR1GX0zQplm2dZYtlo7CZUyfS3JCLsWviEtPXaon+8Z0lQQkPt4yxCf9v8Qd0pvxHglTUCK/sU0NXnZQdpSxxfsaNCcjQf5gTg/gj8oI7xdrnamBPFtsaH6tAirkjGMoYS4Otju3mcrdcNBIHG40wrffUDnE83Jw4AOFCp8Vsf0zPTQOQsxS4HF4VS78OvGn7jLi2MdabeAQcK5+tP3mUB4vO8AAt8QbkEEiWQbcvA9i1Ezma92CdNYgaf4B3JYpPA==";

		HttpRequest httpRequest = new HttpRequest(requestURL, queryString)
				.addParameter("SAMLResponse", samlResponseEncoded)
				.addParameter("RelayState", relayState)
				.addParameter("SigAlg", sigAlg)
				.addParameter("Signature", signature);

		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue("Signature validation failed", logoutResponse.isValid());
	}

	@Test
	public void testIsInValidSign_naiveUrlEncoding() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.knownIdpPrivateKey.properties").build();
		settings.setStrict(true);
		settings.setWantMessagesSigned(true);

		final String requestURL = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls";
		String samlResponseEncoded = "fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A";
		String relayState = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php";
		String sigAlg = Constants.SHA256;

		String queryString = "SAMLResponse=" + NaiveUrlEncoder.encode(samlResponseEncoded);
		queryString += "&RelayState=" + NaiveUrlEncoder.encode(relayState);
		queryString += "&SigAlg=" + NaiveUrlEncoder.encode(sigAlg);

		//This signature is based on the query string above
		String signature = "eSoTB+0GA/HfncASEFk7ONHbB3+9YrOBgK9xUyRoCDY97oXw49JYoXOL07kHrVvbngKmKFNx5fnYtDaL8WCe5LfRRgjJz1LLacriHn2ggeMmY/fTaXPoy2zQW0Fv1H362QXicTWQXgWFS5cJAIcBa2I7TLgNwXsMgjdBF2hyacW0IwfkAceGiBwDDTy6XIBAZk2Ff7w5lbZh+fa5JLNKrbvoveJk2NS3KK6INYO7UW5hukWz2cpzbHsx9lfxUJi8/ZCwUtFWZ4rdXVN+Qiw5y8S2eE2BIEfFmz7IfvrMRXa2la/rXFQfmteQo+N1sO3K1YZyoT/aA3k36glXvnj3kw==";

		HttpRequest httpRequest = new HttpRequest(requestURL, queryString)
				.addParameter("SAMLResponse", samlResponseEncoded)
				.addParameter("RelayState", relayState)
				.addParameter("SigAlg", sigAlg)
				.addParameter("Signature", signature);

		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue("Signature validation failed", logoutResponse.isValid());
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsInValidSign() throws URISyntaxException, IOException, XMLEntityException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.my.properties").build();
		settings.setStrict(false);
		settings.setWantMessagesSigned(true);

		final String requestURL = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls";
		String samlResponseEncoded = "fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A";
		String relayState = "https://pitbulk.no-ip.org/newonelogin/demo1/index.php";
		String sigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
		String signature = "vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA=";

		HttpRequest httpRequest = new HttpRequest(requestURL, (String)null)
				.addParameter("SAMLResponse", samlResponseEncoded)
				.addParameter("RelayState", relayState)
				.addParameter("SigAlg", sigAlg)
				.addParameter("Signature", signature);

		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(true);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(false);
		String signature2 = "vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333=";
		httpRequest = httpRequest.removeParameter("Signature")
					  			 .addParameter("Signature", signature2);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertFalse(logoutResponse.isValid());
		assertEquals("Signature validation failed. Logout Response rejected", logoutResponse.getError());

		httpRequest = httpRequest.removeParameter("Signature")
								 .addParameter("Signature", signature)
								 .removeParameter("SigAlg");
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());

		httpRequest = httpRequest.removeParameter("Signature");
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertTrue(logoutResponse.isValid());

		settings.setStrict(true);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertFalse(logoutResponse.isValid());
		assertEquals("The Message of the Logout Response is not signed and the SP requires it", logoutResponse.getError());

		httpRequest = httpRequest.addParameter("Signature", signature);
		settings = new SettingsBuilder().fromFile("config/config.mywithnocert.properties").build();
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertFalse(logoutResponse.isValid());
		assertEquals("In order to validate the sign on the Logout Response, the x509cert of the IdP is required", logoutResponse.getError());
	}

	/**
	 * Tests the isValid method of LogoutResponse
	 * Case: No SAML Logout Response
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#isValid
	 */
	@Test
	public void testIsValidNoLogoutResponse() throws IOException, XMLEntityException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		final String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, "");

		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertFalse(logoutResponse.isValid());
		assertEquals("SAML Logout Response is not loaded", logoutResponse.getError());
	}

	/**
	 * Tests the getError and getValidationException methods of LogoutResponse
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws XMLEntityException
	 * @throws Error
	 *
	 * @see com.onelogin.saml2.logout.LogoutResponse#getError
	 */
	@Test
	public void testGetError() throws URISyntaxException, IOException, XMLEntityException, Error {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.min.properties").build();
		settings.setStrict(true);
		String samlResponseEncoded = Util.getFileAsString("data/logout_responses/logout_response_deflated.xml.base64");
		final String requestURL = "/";
		HttpRequest httpRequest = newHttpRequest(requestURL, samlResponseEncoded);
		LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
		assertNull(logoutResponse.getError());
		assertNull(logoutResponse.getValidationException());
		logoutResponse.isValid();
		assertThat(logoutResponse.getError(), containsString("The LogoutResponse was received at"));
		assertTrue(logoutResponse.getValidationException() instanceof ValidationError);

		settings.setStrict(false);
		logoutResponse = new LogoutResponse(settings, httpRequest);
		assertNull(logoutResponse.getError());
		assertNull(logoutResponse.getValidationException());
		logoutResponse.isValid();
		assertNull(logoutResponse.getError());
		assertNull(logoutResponse.getValidationException());
	}

	private static HttpRequest newHttpRequest(String requestURL, String samlResponseEncoded) {
		return new HttpRequest(requestURL, (String)null).addParameter("SAMLResponse", samlResponseEncoded);
	}
}
