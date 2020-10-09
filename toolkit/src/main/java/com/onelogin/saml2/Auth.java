package com.onelogin.saml2;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.logout.LogoutRequest;
import com.onelogin.saml2.logout.LogoutResponse;
import com.onelogin.saml2.model.SamlResponseStatus;
import com.onelogin.saml2.model.KeyStoreSettings;
import com.onelogin.saml2.servlet.ServletUtils;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

/**
 * Main class of OneLogin's Java Toolkit.
 *
 * This class implements the SP SAML instance.
 * Defines the methods that you can invoke in your application in
 * order to add SAML support (initiates sso, initiates slo, processes a
 * SAML Response, a Logout Request or a Logout Response).
 *
 * This is stateful and not thread-safe, you should create a new instance for each request/response.
 */
public class Auth {
	/**
	 * Private property to construct a logger for this class.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(Auth.class);

	/**
	 * Settings data.
	 */
	private Saml2Settings settings;

	/**
	 * HttpServletRequest object to be processed (Contains GET and POST parameters, session, ...).
	 */
	private HttpServletRequest request;

	/**
	 * HttpServletResponse object to be used (For example to execute the redirections).
	 */
	private HttpServletResponse response;

	/**
	 * NameID.
	 */
	private String nameid;

	/**
	 * NameIDFormat.
	 */
	private String nameidFormat;

	/**
	 * nameId NameQualifier
	 */
	private String nameidNameQualifier;

	/**
	 * nameId SP NameQualifier
	 */
	private String nameidSPNameQualifier;

	/**
	 * SessionIndex. When the user is logged, this stored it from the AuthnStatement of the SAML Response
	 */
	private String sessionIndex;

	/**
	 * SessionNotOnOrAfter. When the user is logged, this stored it from the AuthnStatement of the SAML Response
	 */
	private DateTime sessionExpiration;

	/**
	 * The ID of the last message processed
	 */
	private String lastMessageId;

	/**
	 * The ID of the last assertion processed
	 */
	private String lastAssertionId;

	/**
	 * The NotOnOrAfter values of the last assertion processed
	 */
	private List<Instant> lastAssertionNotOnOrAfter;

	/**
	 * User attributes data.
	 */
	private Map<String, List<String>> attributes = new HashMap<String, List<String>>();

	/**
	 * If user is authenticated.
	 */
	private boolean authenticated = false;

	/**
	 * Stores any error.
	 */
	private List<String> errors = new ArrayList<String>();

	/**
	 * Reason of the last error.
	 */
	private String errorReason;

	/**
	 * Exception of the last error.
	 */
	private Exception validationException;

	/**
	 * The id of the last request (Authn or Logout) generated
	 */
	private String lastRequestId;

	/**
	 * The most recently-constructed/processed XML SAML request
	 * (AuthNRequest, LogoutRequest)
	 */
	private String lastRequest;

	/**
	 * The most recently-constructed/processed XML SAML response
	 * (SAMLResponse, LogoutResponse). If the SAMLResponse was
	 * encrypted, by default tries to return the decrypted XML
	 */
	private String lastResponse;

	/**
	 * Initializes the SP SAML instance.
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws Error
	 */
	public Auth() throws IOException, SettingsException, Error {
		this(new SettingsBuilder().fromFile("onelogin.saml.properties").build(), null, null);
	}

	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param keyStoreSetting KeyStoreSettings is a KeyStore which have the Private/Public keys
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws Error
	 */
	public Auth(KeyStoreSettings keyStoreSetting) throws IOException, SettingsException, Error {
		this("onelogin.saml.properties", keyStoreSetting);
	}
	
	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param filename String Filename with the settings
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws Error
	 */
	public Auth(String filename) throws IOException, SettingsException, Error {
		this(filename, null, null, null);
	}

	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param filename String Filename with the settings
	 * @param keyStoreSetting KeyStoreSettings is a KeyStore which have the Private/Public keys
     *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws Error
	 */
	public Auth(String filename, KeyStoreSettings keyStoreSetting)
			throws IOException, SettingsException, Error {
		this(new SettingsBuilder().fromFile(filename, keyStoreSetting).build(), null, null);
	}

	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param request  HttpServletRequest object to be processed
	 * @param response HttpServletResponse object to be used
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws Error
	 */
	public Auth(HttpServletRequest request, HttpServletResponse response) throws IOException, SettingsException, Error {
		this(new SettingsBuilder().fromFile("onelogin.saml.properties").build(), request, response);
	}

	/**
	 * Initializes the SP SAML instance.
	 * 
	 * @param keyStoreSetting KeyStoreSettings is a KeyStore which have the Private/Public keys
	 * @param request  HttpServletRequest object to be processed
	 * @param response HttpServletResponse object to be used
	 *
	 * @throws IOException
	 * @throws SettingsException
	 * @throws Error
	 */
	public Auth(KeyStoreSettings keyStoreSetting, HttpServletRequest request, HttpServletResponse response)
			throws IOException, SettingsException, Error {
		this(new SettingsBuilder().fromFile("onelogin.saml.properties", keyStoreSetting).build(), request,
				response);
	}

	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param filename String Filename with the settings
	 * @param request  HttpServletRequest object to be processed
	 * @param response HttpServletResponse object to be used
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws Error
	 */
	public Auth(String filename, HttpServletRequest request, HttpServletResponse response)
			throws SettingsException, IOException, Error {
		this(filename, null, request, response);
	}

	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param filename 			String Filename with the settings
	 * @param keyStoreSetting 	KeyStoreSettings is a KeyStore which have the Private/Public keys
	 * @param request  			HttpServletRequest object to be processed
	 * @param response 			HttpServletResponse object to be used
	 *
	 * @throws SettingsException
	 * @throws IOException
	 * @throws Error
	 */
	public Auth(String filename, KeyStoreSettings keyStoreSetting, HttpServletRequest request,
			HttpServletResponse response) throws SettingsException, IOException, Error {
		this(new SettingsBuilder().fromFile(filename, keyStoreSetting).build(), request, response);
	}

	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param settings Saml2Settings object. Setting data
	 * @param request  HttpServletRequest object to be processed
	 * @param response HttpServletResponse object to be used
	 *
	 * @throws SettingsException
	 */
	public Auth(Saml2Settings settings, HttpServletRequest request, HttpServletResponse response)
			throws SettingsException {
		this.settings = settings;
		this.request = request;
		this.response = response;

		// Check settings
		List<String> settingsErrors = settings.checkSettings();
		if (!settingsErrors.isEmpty()) {
			String errorMsg = "Invalid settings: ";
			errorMsg += StringUtils.join(settingsErrors, ", ");
			LOGGER.error(errorMsg);
			throw new SettingsException(errorMsg, SettingsException.SETTINGS_INVALID);
		}
		LOGGER.debug("Settings validated");
	}

	/**
	 * Set the strict mode active/disable
	 *
	 * @param value Strict value
	 */
	public void setStrict(Boolean value) {
		settings.setStrict(value);
	}

	/**
	 * Initiates the SSO process.
	 *
	 * @param returnTo        The target URL the user should be returned to after
	 *                        login (relayState). Will be a self-routed URL when
	 *                        null, or not be appended at all when an empty string
	 *                        is provided
	 * @param forceAuthn      When true the AuthNRequest will set the
	 *                        ForceAuthn='true'
	 * @param isPassive       When true the AuthNRequest will set the
	 *                        IsPassive='true'
	 * @param setNameIdPolicy When true the AuthNRequest will set a nameIdPolicy
	 * @param stay            True if we want to stay (returns the url string) False
	 *                        to execute redirection
	 * @param nameIdValueReq  Indicates to the IdP the subject that should be
	 *                        authenticated
	 *
	 * @return the SSO URL with the AuthNRequest if stay = True
	 *
	 * @throws IOException
	 * @throws SettingsException
	 */
	public String login(String returnTo, Boolean forceAuthn, Boolean isPassive, Boolean setNameIdPolicy, Boolean stay,
			String nameIdValueReq) throws IOException, SettingsException {
		Map<String, String> parameters = new HashMap<String, String>();

		AuthnRequest authnRequest = new AuthnRequest(settings, forceAuthn, isPassive, setNameIdPolicy, nameIdValueReq);

		String samlRequest = authnRequest.getEncodedAuthnRequest();

		parameters.put("SAMLRequest", samlRequest);

		String relayState;
		if (returnTo == null) {
			relayState = ServletUtils.getSelfRoutedURLNoQuery(request);
		} else {
			relayState = returnTo;
		}

		if (!relayState.isEmpty()) {
			parameters.put("RelayState", relayState);
		}

		if (settings.getAuthnRequestsSigned()) {
			String sigAlg = settings.getSignatureAlgorithm();
			String signature = this.buildRequestSignature(samlRequest, relayState, sigAlg);

			parameters.put("SigAlg", sigAlg);
			parameters.put("Signature", signature);
		}

		String ssoUrl = getSSOurl();
		lastRequestId = authnRequest.getId();
		lastRequest = authnRequest.getAuthnRequestXml();

		if (!stay) {
			LOGGER.debug("AuthNRequest sent to " + ssoUrl + " --> " + samlRequest);
		}
		return ServletUtils.sendRedirect(response, ssoUrl, parameters, stay);
	}

	/**
	 * Initiates the SSO process.
	 *
	 * @param returnTo        The target URL the user should be returned to after
	 *                        login (relayState). Will be a self-routed URL when
	 *                        null, or not be appended at all when an empty string
	 *                        is provided
	 * @param forceAuthn      When true the AuthNRequest will set the
	 *                        ForceAuthn='true'
	 * @param isPassive       When true the AuthNRequest will set the
	 *                        IsPassive='true'
	 * @param setNameIdPolicy When true the AuthNRequest will set a nameIdPolicy
	 * @param stay            True if we want to stay (returns the url string) False
	 *                        to execute redirection
	 *
	 * @return the SSO URL with the AuthNRequest if stay = True
	 *
	 * @throws IOException
	 * @throws SettingsException
	 */
	public String login(String returnTo, Boolean forceAuthn, Boolean isPassive, Boolean setNameIdPolicy, Boolean stay)
			throws IOException, SettingsException {
		return login(returnTo, forceAuthn, isPassive, setNameIdPolicy, stay, null);
	}

	/**
	 * Initiates the SSO process.
	 *
	 * @param returnTo        The target URL the user should be returned to after
	 *                        login (relayState). Will be a self-routed URL when
	 *                        null, or not be appended at all when an empty string
	 *                        is provided
	 * @param forceAuthn      When true the AuthNRequest will set the
	 *                        ForceAuthn='true'
	 * @param isPassive       When true the AuthNRequest will set the
	 *                        IsPassive='true'
	 * @param setNameIdPolicy When true the AuthNRequest will set a nameIdPolicy
	 *
	 * @throws IOException
	 * @throws SettingsException
	 */
	public void login(String returnTo, Boolean forceAuthn, Boolean isPassive, Boolean setNameIdPolicy)
			throws IOException, SettingsException {
		login(returnTo, forceAuthn, isPassive, setNameIdPolicy, false);
	}

	/**
	 * Initiates the SSO process.
	 *
	 * @throws IOException
	 * @throws SettingsException
	 */
	public void login() throws IOException, SettingsException {
		login(null, false, false, true);
	}

	/**
	 * Initiates the SSO process.
	 *
	 * @param returnTo The target URL the user should be returned to after login
	 *                 (relayState). Will be a self-routed URL when null, or not be
	 *                 appended at all when an empty string is provided.
	 *
	 * @throws IOException
	 * @throws SettingsException
	 */
	public void login(String returnTo) throws IOException, SettingsException {
		login(returnTo, false, false, true);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo              The target URL the user should be returned to
	 *                              after logout (relayState). Will be a self-routed
	 *                              URL when null, or not be appended at all when an
	 *                              empty string is provided
	 * @param nameId                The NameID that will be set in the
	 *                              LogoutRequest.
	 * @param sessionIndex          The SessionIndex (taken from the SAML Response
	 *                              in the SSO process).
	 * @param stay                  True if we want to stay (returns the url string)
	 *                              False to execute redirection
	 * @param nameidFormat          The NameID Format that will be set in the
	 *                              LogoutRequest.
	 * @param nameIdNameQualifier   The NameID NameQualifier that will be set in the
	 *                              LogoutRequest.
	 * @param nameIdSPNameQualifier The NameID SP Name Qualifier that will be set in
	 *                              the LogoutRequest.
	 *
	 * @return the SLO URL with the LogoutRequest if stay = True
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws SettingsException
	 */
	public String logout(String returnTo, String nameId, String sessionIndex, Boolean stay, String nameidFormat,
			String nameIdNameQualifier, String nameIdSPNameQualifier)
			throws IOException, XMLEntityException, SettingsException {
		Map<String, String> parameters = new HashMap<String, String>();

		LogoutRequest logoutRequest = new LogoutRequest(settings, null, nameId, sessionIndex, nameidFormat,
				nameIdNameQualifier, nameIdSPNameQualifier);
		String samlLogoutRequest = logoutRequest.getEncodedLogoutRequest();
		parameters.put("SAMLRequest", samlLogoutRequest);

		String relayState;
		if (returnTo == null) {
			relayState = ServletUtils.getSelfRoutedURLNoQuery(request);
		} else {
			relayState = returnTo;
		}

		if (!relayState.isEmpty()) {
			parameters.put("RelayState", relayState);
		}

		if (settings.getLogoutRequestSigned()) {
			String sigAlg = settings.getSignatureAlgorithm();
			String signature = this.buildRequestSignature(samlLogoutRequest, relayState, sigAlg);

			parameters.put("SigAlg", sigAlg);
			parameters.put("Signature", signature);
		}

		String sloUrl = getSLOurl();
		lastRequestId = logoutRequest.getId();
		lastRequest = logoutRequest.getLogoutRequestXml();

		if (!stay) {
			LOGGER.debug("Logout request sent to " + sloUrl + " --> " + samlLogoutRequest);
		}
		return ServletUtils.sendRedirect(response, sloUrl, parameters, stay);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo            The target URL the user should be returned to
	 *                            after logout (relayState). Will be a self-routed
	 *                            URL when null, or not be appended at all when an
	 *                            empty string is provided
	 * @param nameId              The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex        The SessionIndex (taken from the SAML Response in
	 *                            the SSO process).
	 * @param stay                True if we want to stay (returns the url string)
	 *                            False to execute redirection
	 * @param nameidFormat        The NameID Format will be set in the
	 *                            LogoutRequest.
	 * @param nameIdNameQualifier The NameID NameQualifier will be set in the
	 *                            LogoutRequest.
	 *
	 * @return the SLO URL with the LogoutRequest if stay = True
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws SettingsException
	 */
	public String logout(String returnTo, String nameId, String sessionIndex, Boolean stay, String nameidFormat,
			String nameIdNameQualifier) throws IOException, XMLEntityException, SettingsException {
		return logout(returnTo, nameId, sessionIndex, stay, nameidFormat, nameIdNameQualifier, null);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo     The target URL the user should be returned to after
	 *                     logout (relayState). Will be a self-routed URL when null,
	 *                     or not be appended at all when an empty string is
	 *                     provided
	 * @param nameId       The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex The SessionIndex (taken from the SAML Response in the SSO
	 *                     process).
	 * @param stay         True if we want to stay (returns the url string) False to
	 *                     execute redirection
	 * @param nameidFormat The NameID Format will be set in the LogoutRequest.
	 *
	 * @return the SLO URL with the LogoutRequest if stay = True
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws SettingsException
	 */
	public String logout(String returnTo, String nameId, String sessionIndex, Boolean stay, String nameidFormat)
			throws IOException, XMLEntityException, SettingsException {
		return logout(returnTo, nameId, sessionIndex, stay, nameidFormat, null);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo     The target URL the user should be returned to after
	 *                     logout (relayState). Will be a self-routed URL when null,
	 *                     or not be appended at all when an empty string is
	 *                     provided
	 * @param nameId       The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex The SessionIndex (taken from the SAML Response in the SSO
	 *                     process).
	 * @param stay         True if we want to stay (returns the url string) False to
	 *                     execute redirection
	 *
	 * @return the SLO URL with the LogoutRequest if stay = True
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws SettingsException
	 */
	public String logout(String returnTo, String nameId, String sessionIndex, Boolean stay)
			throws IOException, XMLEntityException, SettingsException {
		return logout(returnTo, nameId, sessionIndex, stay, null);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo              The target URL the user should be returned to
	 *                              after logout (relayState). Will be a self-routed
	 *                              URL when null, or not be appended at all when an
	 *                              empty string is provided
	 * @param nameId                The NameID that will be set in the
	 *                              LogoutRequest.
	 * @param sessionIndex          The SessionIndex (taken from the SAML Response
	 *                              in the SSO process).
	 * @param nameidFormat          The NameID Format will be set in the
	 *                              LogoutRequest.
	 * @param nameIdNameQualifier   The NameID NameQualifier that will be set in the
	 *                              LogoutRequest.
	 * @param nameIdSPNameQualifier The NameID SP Name Qualifier that will be set in
	 *                              the LogoutRequest.
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws SettingsException
	 */
	public void logout(String returnTo, String nameId, String sessionIndex, String nameidFormat,
			String nameIdNameQualifier, String nameIdSPNameQualifier)
			throws IOException, XMLEntityException, SettingsException {
		logout(returnTo, nameId, sessionIndex, false, nameidFormat, nameIdNameQualifier, nameIdSPNameQualifier);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo            The target URL the user should be returned to
	 *                            after logout (relayState). Will be a self-routed
	 *                            URL when null, or not be appended at all when an
	 *                            empty string is provided
	 * @param nameId              The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex        The SessionIndex (taken from the SAML Response in
	 *                            the SSO process).
	 * @param nameidFormat        The NameID Format will be set in the
	 *                            LogoutRequest.
	 * @param nameIdNameQualifier The NameID NameQualifier will be set in the
	 *                            LogoutRequest.
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws SettingsException
	 */
	public void logout(String returnTo, String nameId, String sessionIndex, String nameidFormat,
			String nameIdNameQualifier) throws IOException, XMLEntityException, SettingsException {
		logout(returnTo, nameId, sessionIndex, false, nameidFormat, nameIdNameQualifier);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo     The target URL the user should be returned to after
	 *                     logout (relayState). Will be a self-routed URL when null,
	 *                     or not be appended at all when an empty string is
	 *                     provided
	 * @param nameId       The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex The SessionIndex (taken from the SAML Response in the SSO
	 *                     process).
	 * @param nameidFormat The NameID Format will be set in the LogoutRequest.
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws SettingsException
	 */
	public void logout(String returnTo, String nameId, String sessionIndex, String nameidFormat)
			throws IOException, XMLEntityException, SettingsException {
		logout(returnTo, nameId, sessionIndex, false, nameidFormat);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo     The target URL the user should be returned to after
	 *                     logout (relayState). Will be a self-routed URL when null,
	 *                     or not be appended at all when an empty string is
	 *                     provided
	 * @param nameId       The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex The SessionIndex (taken from the SAML Response in the SSO
	 *                     process).
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws SettingsException
	 */
	public void logout(String returnTo, String nameId, String sessionIndex)
			throws IOException, XMLEntityException, SettingsException {
		logout(returnTo, nameId, sessionIndex, false, null);
	}

	/**
	 * Initiates the SLO process.
	 * 
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws SettingsException
	 */
	public void logout() throws IOException, XMLEntityException, SettingsException {
		logout(null, null, null, false);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo The target URL the user should be returned to after logout
	 *                 (relayState). Will be a self-routed URL when null, or not be
	 *                 appended at all when an empty string is provided
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 * @throws SettingsException
	 */
	public void logout(String returnTo) throws IOException, XMLEntityException, SettingsException {
		logout(returnTo, null, null);
	}

	/**
	 * @return The url of the Single Sign On Service
	 */
	public String getSSOurl() {
		return settings.getIdpSingleSignOnServiceUrl().toString();
	}

	/**
	 * @return The url of the Single Logout Service
	 */
	public String getSLOurl() {
		return settings.getIdpSingleLogoutServiceUrl().toString();
	}

	/**
	 * @return The url of the Single Logout Service Response.
	 */
	public String getSLOResponseUrl() {
		return settings.getIdpSingleLogoutServiceResponseUrl().toString();
	}

	/**
	 * Process the SAML Response sent by the IdP.
	 *
	 * @param requestId The ID of the AuthNRequest sent by this SP to the IdP
	 *
	 * @throws Exception
	 */
	public void processResponse(String requestId) throws Exception {
		authenticated = false;
		final HttpRequest httpRequest = ServletUtils.makeHttpRequest(this.request);
		final String samlResponseParameter = httpRequest.getParameter("SAMLResponse");

		if (samlResponseParameter != null) {
			SamlResponse samlResponse = new SamlResponse(settings, httpRequest);
			lastResponse = samlResponse.getSAMLResponseXml();

			if (samlResponse.isValid(requestId)) {
				nameid = samlResponse.getNameId();
				nameidFormat = samlResponse.getNameIdFormat();
				nameidNameQualifier = samlResponse.getNameIdNameQualifier();
				nameidSPNameQualifier = samlResponse.getNameIdSPNameQualifier();
				authenticated = true;
				attributes = samlResponse.getAttributes();
				sessionIndex = samlResponse.getSessionIndex();
				sessionExpiration = samlResponse.getSessionNotOnOrAfter();
				lastMessageId = samlResponse.getId();
				lastAssertionId = samlResponse.getAssertionId();
				lastAssertionNotOnOrAfter = samlResponse.getAssertionNotOnOrAfter();
				LOGGER.debug("processResponse success --> " + samlResponseParameter);
			} else {
				errorReason = samlResponse.getError();
				validationException = samlResponse.getValidationException();
				SamlResponseStatus samlResponseStatus = samlResponse.getResponseStatus();
				if (samlResponseStatus.getStatusCode() == null || !samlResponseStatus.getStatusCode().equals(Constants.STATUS_SUCCESS)) {
					errors.add("response_not_success");
					LOGGER.error("processResponse error. sso_not_success");
					LOGGER.debug(" --> " + samlResponseParameter);
					errors.add(samlResponseStatus.getStatusCode());
					if (samlResponseStatus.getSubStatusCode() != null) {
						errors.add(samlResponseStatus.getSubStatusCode());
					}
				} else {
					errors.add("invalid_response");
					LOGGER.error("processResponse error. invalid_response");
					LOGGER.debug(" --> " + samlResponseParameter);
        }
			}
		} else {
			errors.add("invalid_binding");
			String errorMsg = "SAML Response not found, Only supported HTTP_POST Binding";
			LOGGER.error("processResponse error." + errorMsg);
			throw new Error(errorMsg, Error.SAML_RESPONSE_NOT_FOUND);
		}
	}

	/**
	 * Process the SAML Response sent by the IdP.
	 *
	 * @throws Exception
	 */
	public void processResponse() throws Exception {
		processResponse(null);
	}

	/**
	 * Process the SAML Logout Response / Logout Request sent by the IdP.
	 *
	 * @param keepLocalSession When true will keep the local session, otherwise will
	 *                         destroy it
	 * @param requestId        The ID of the LogoutRequest sent by this SP to the
	 *                         IdP
	 * @param stay             True if we want to stay (returns the url string) False
	 *                         to execute redirection
	 *
	 * @return the URL with the Logout Message if stay = True
	 *
	 * @throws Exception
	 */
	public String processSLO(Boolean keepLocalSession, String requestId, Boolean stay) throws Exception {
		final HttpRequest httpRequest = ServletUtils.makeHttpRequest(this.request);

		final String samlRequestParameter = httpRequest.getParameter("SAMLRequest");
		final String samlResponseParameter = httpRequest.getParameter("SAMLResponse");

		if (samlResponseParameter != null) {
			LogoutResponse logoutResponse = new LogoutResponse(settings, httpRequest);
			lastResponse = logoutResponse.getLogoutResponseXml();
			if (!logoutResponse.isValid(requestId)) {
				errors.add("invalid_logout_response");
				LOGGER.error("processSLO error. invalid_logout_response");
				LOGGER.debug(" --> " + samlResponseParameter);
				errorReason = logoutResponse.getError();
				validationException = logoutResponse.getValidationException();
			} else {
				SamlResponseStatus samlResponseStatus = logoutResponse.getSamlResponseStatus();
				String status = samlResponseStatus.getStatusCode();
				if (status == null || !status.equals(Constants.STATUS_SUCCESS)) {
					errors.add("logout_not_success");
					LOGGER.error("processSLO error. logout_not_success");
					LOGGER.debug(" --> " + samlResponseParameter);
					errors.add(samlResponseStatus.getStatusCode());
					if (samlResponseStatus.getSubStatusCode() != null) {
						errors.add(samlResponseStatus.getSubStatusCode());
					}
				} else {
					lastMessageId = logoutResponse.getId();
					LOGGER.debug("processSLO success --> " + samlResponseParameter);
					if (!keepLocalSession) {
						request.getSession().invalidate();
					}
				}
			}
			return null;
		} else if (samlRequestParameter != null) {
			LogoutRequest logoutRequest = new LogoutRequest(settings, httpRequest);
			lastRequest = logoutRequest.getLogoutRequestXml();
			if (!logoutRequest.isValid()) {
				errors.add("invalid_logout_request");
				LOGGER.error("processSLO error. invalid_logout_request");
				LOGGER.debug(" --> " + samlRequestParameter);
				errorReason = logoutRequest.getError();
				validationException = logoutRequest.getValidationException();
				return null;
			} else {
				lastMessageId = logoutRequest.getId();
				LOGGER.debug("processSLO success --> " + samlRequestParameter);
				if (!keepLocalSession) {
					request.getSession().invalidate();
				}

				String inResponseTo = logoutRequest.id;
				LogoutResponse logoutResponseBuilder = new LogoutResponse(settings, httpRequest);
				logoutResponseBuilder.build(inResponseTo, Constants.STATUS_SUCCESS);
				lastResponse = logoutResponseBuilder.getLogoutResponseXml();

				String samlLogoutResponse = logoutResponseBuilder.getEncodedLogoutResponse();

				Map<String, String> parameters = new LinkedHashMap<String, String>();

				parameters.put("SAMLResponse", samlLogoutResponse);

				String relayState = request.getParameter("RelayState");
				if (relayState != null) {
					parameters.put("RelayState", relayState);
				}

				if (settings.getLogoutResponseSigned()) {
					String sigAlg = settings.getSignatureAlgorithm();
					String signature = this.buildResponseSignature(samlLogoutResponse, relayState, sigAlg);

					parameters.put("SigAlg", sigAlg);
					parameters.put("Signature", signature);
				}

				String sloUrl = getSLOResponseUrl();

				if (!stay) {
					LOGGER.debug("Logout response sent to " + sloUrl + " --> " + samlLogoutResponse);
				}
				return ServletUtils.sendRedirect(response, sloUrl, parameters, stay);
			}
		} else {
			errors.add("invalid_binding");
			String errorMsg = "SAML LogoutRequest/LogoutResponse not found. Only supported HTTP_REDIRECT Binding";
			LOGGER.error("processSLO error." + errorMsg);
			throw new Error(errorMsg, Error.SAML_LOGOUTMESSAGE_NOT_FOUND);
		}
	}

	/**
	 * Process the SAML Logout Response / Logout Request sent by the IdP.
	 *
	 * @param keepLocalSession When true will keep the local session, otherwise will
	 *                         destroy it
	 * @param requestId        The ID of the LogoutRequest sent by this SP to the
	 *                         IdP
	 *
	 *
	 * @throws Exception
	 */
	public void processSLO(Boolean keepLocalSession, String requestId) throws Exception {
		processSLO(keepLocalSession, requestId, false);
	}

	/**
	 * Process the SAML Logout Response / Logout Request sent by the IdP.
	 *
	 * @throws Exception
	 */
	public void processSLO() throws Exception {
		processSLO(false, null);
	}

	/**
	 * @return the authenticated
	 */
	public final boolean isAuthenticated() {
		return authenticated;
	}

	/**
	 * @return the list of the names of the SAML attributes.
	 */
	public final List<String> getAttributesName() {
		return new ArrayList<String>(attributes.keySet());
	}

	/**
	 * @return the set of SAML attributes.
	 */
	public final Map<String, List<String>> getAttributes() {
		return attributes;
	}

	/**
	 * @param name Name of the attribute
	 *
	 * @return the attribute value
	 */
	public final Collection<String> getAttribute(String name) {
		return attributes.get(name);
	}

	/**
	 * @return the nameID of the assertion
	 */
	public final String getNameId() {
		return nameid;
	}

	/**
	 * @return the nameID Format of the assertion
	 */
	public final String getNameIdFormat() {
		return nameidFormat;
	}

	/**
	 * @return the NameQualifier of the assertion
	 */
	public final String getNameIdNameQualifier() {
		return nameidNameQualifier;
	}

	/**
	 * @return the SPNameQualifier of the assertion
	 */
	public final String getNameIdSPNameQualifier() {
		return nameidSPNameQualifier;
	}

	/**
	 * @return the SessionIndex of the assertion
	 */
	public final String getSessionIndex() {
		return sessionIndex;
	}

	/**
	 * @return the SessionNotOnOrAfter of the assertion
	 */
	public final DateTime getSessionExpiration() {
		return sessionExpiration;
	}

	/**
	 * @return The ID of the last message processed
	 */
	public String getLastMessageId() {
		return lastMessageId;
	}

	/**
	 * @return The ID of the last assertion processed
	 */
	public String getLastAssertionId() {
		return lastAssertionId;
	}

	/**
	 * @return The NotOnOrAfter values of the last assertion processed
	 */
	public List<Instant> getLastAssertionNotOnOrAfter() {
		return lastAssertionNotOnOrAfter;
	}

	/**
	 * @return an array with the errors, the array is empty when the validation was
	 *         successful
	 */
	public List<String> getErrors() {
		return errors;
	}

	/**
	 * @return the reason for the last error
	 */
	public String getLastErrorReason() {
		return errorReason;
	}

	/**
	 * @return the exception for the last error
	 */
	public Exception getLastValidationException() {
		return validationException;
	}

	/**
	 * @return the id of the last request generated (AuthnRequest or LogoutRequest),
	 *         null if none
	 */
	public String getLastRequestId() {
		return lastRequestId;
	}

	/**
	 * @return the Saml2Settings object. The Settings data.
	 */
	public Saml2Settings getSettings() {
		return settings;
	}

	/**
	 * @return if debug mode is active
	 */
	public Boolean isDebugActive() {
		return settings.isDebugActive();
	}

	/**
	 * Generates the Signature for a SAML Request
	 *
	 * @param samlRequest   The SAML Request
	 * @param relayState    The RelayState
	 * @param signAlgorithm Signature algorithm method
	 *
	 * @return a base64 encoded signature
	 *
	 * @throws SettingsException
	 */
	public String buildRequestSignature(String samlRequest, String relayState, String signAlgorithm)
			throws SettingsException {
		return buildSignature(samlRequest, relayState, signAlgorithm, "SAMLRequest");
	}

	/**
	 * Generates the Signature for a SAML Response
	 *
	 * @param samlResponse  The SAML Response
	 * @param relayState    The RelayState
	 * @param signAlgorithm Signature algorithm method
	 *
	 * @return the base64 encoded signature
	 *
	 * @throws SettingsException
	 */
	public String buildResponseSignature(String samlResponse, String relayState, String signAlgorithm)
			throws SettingsException {
		return buildSignature(samlResponse, relayState, signAlgorithm, "SAMLResponse");
	}

	/**
	 * Generates the Signature for a SAML Message
	 *
	 * @param samlMessage
	 *				The SAML Message
	 * @param relayState
	 *				The RelayState
	 * @param signAlgorithm
	 *				Signature algorithm method
	 * @param type
	 *              The type of the message
	 *
	 * @return the base64 encoded signature
	 *
	 * @throws SettingsException
	 * @throws IllegalArgumentException
	 */
	private String buildSignature(String samlMessage, String relayState, String signAlgorithm, String type) throws SettingsException, IllegalArgumentException
	{
		 String signature = "";
		 
		 if (!settings.checkSPCerts()) {
			 String errorMsg = "Trying to sign the " + type + " but can't load the SP private key";
			 LOGGER.error("buildSignature error. " + errorMsg);
			 throw new SettingsException(errorMsg, SettingsException.PRIVATE_KEY_NOT_FOUND);
		 }

		 PrivateKey key = settings.getSPkey();
		 
		 String msg = type + "=" + Util.urlEncoder(samlMessage);
		 if (StringUtils.isNotEmpty(relayState)) {
			 msg += "&RelayState=" + Util.urlEncoder(relayState);
		 }
		 
		 if (StringUtils.isEmpty(signAlgorithm)) {
			 signAlgorithm = Constants.RSA_SHA1;
		 }
		 
		 msg += "&SigAlg=" + Util.urlEncoder(signAlgorithm);

		 try {
			signature = Util.base64encoder(Util.sign(msg, key, signAlgorithm));
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			String errorMsg = "buildSignature error." + e.getMessage();
			LOGGER.error(errorMsg);
		}

		 if (signature.isEmpty()) {
			 String errorMsg = "There was a problem when calculating the Signature of the " + type;
			 LOGGER.error("buildSignature error. " + errorMsg);
			 throw new IllegalArgumentException(errorMsg);
		 }

		 LOGGER.debug("buildResponseSignature success. --> " + signature);
		 return signature;
	}

	/**
	 * Returns the most recently-constructed/processed XML SAML request
	 * (AuthNRequest, LogoutRequest)
	 *
	 * @return the last Request XML
	 */
	public String getLastRequestXML() {
		return lastRequest;
	}

	/**
	 * Returns the most recently-constructed/processed XML SAML response
	 * (SAMLResponse, LogoutResponse). If the SAMLResponse was encrypted, by default
	 * tries to return the decrypted XML.
	 *
	 * @return the last Response XML
	 */
	public String getLastResponseXML() {
		return lastResponse;
	}
}
