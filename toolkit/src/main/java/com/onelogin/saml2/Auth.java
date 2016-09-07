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
import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.logout.LogoutRequest;
import com.onelogin.saml2.logout.LogoutResponse;
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
     * SessionIndex. When the user is logged, this stored it from the AuthnStatement of the SAML Response
     */
	private String sessionIndex;

	/**
     * SessionNotOnOrAfter. When the user is logged, this stored it from the AuthnStatement of the SAML Response
	 */
	private DateTime sessionExpiration;

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
	 * The id of the last request (Authn or Logout) generated
	 */
	private String lastRequestId;

	/**
	 * Initializes the SP SAML instance.
	 *
	 * @throws IOException
	 * @throws SettingsException 
	 */
	public Auth() throws IOException, SettingsException {
		this(new SettingsBuilder().fromFile("onelogin.saml.properties").build(), null, null);
	}

	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param filename
	 * 				String Filename with the settings
	 *
	 * @throws IOException
	 * @throws SettingsException 
	 */
	public Auth(String filename) throws IOException, SettingsException {
		this(new SettingsBuilder().fromFile(filename).build(), null, null);
	}
	
	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param request
	 * 				HttpServletRequest object to be processed
	 * @param response
	 * 				HttpServletResponse object to be used
	 *
	 * @throws IOException
	 * @throws SettingsException 
	 */
	public Auth(HttpServletRequest request, HttpServletResponse response) throws IOException, SettingsException {
		this(new SettingsBuilder().fromFile("onelogin.saml.properties").build(), request, response);
	}

	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param filename
	 *				String Filename with the settings
	 * @param request
	 * 				HttpServletRequest object to be processed
	 * @param response
	 * 				HttpServletResponse object to be used
	 *
	 * @throws SettingsException 
	 * @throws IOException
	 */
	public Auth(String filename, HttpServletRequest request, HttpServletResponse response) throws SettingsException, IOException {
		this(new SettingsBuilder().fromFile(filename).build(), request, response);
	}
	
	/**
	 * Initializes the SP SAML instance.
	 *
	 * @param settings
	 *				Saml2Settings object. Setting data
	 * @param request
	 * 				HttpServletRequest object to be processed
	 * @param response
	 * 				HttpServletResponse object to be used
	 *
	 * @throws SettingsException 
	 */
	public Auth(Saml2Settings settings, HttpServletRequest request, HttpServletResponse response) throws SettingsException {
		this.settings = settings;
		this.request = request;
		this.response = response;
		
		// Check settings
		List<String> settingsErrors = settings.checkSettings();
		if (!settingsErrors.isEmpty()) {
			String errorMsg = "Invalid settings: ";
			errorMsg += StringUtils.join(settingsErrors, ", ");
			LOGGER.debug(errorMsg);
			throw new SettingsException(errorMsg);
		}
		LOGGER.debug("Settings validated");
	}

	/**
     * Set the strict mode active/disable
     *
     * @param value 
     *				Strict value
     */
    public void setStrict(Boolean value)
    {
        settings.setStrict(value);
    }

	/**
	 * Initiates the SSO process.
	 *
	 * @param returnTo
	 *				The target URL the user should be returned to after login.
	 * @param forceAuthn
	 *				When true the AuthNRequest will set the ForceAuthn='true'
	 * @param isPassive
	 *				When true the AuthNRequest will set the IsPassive='true'
	 * @param setNameIdPolicy
	 *            When true the AuthNRequest will set a nameIdPolicy
	 * @return the representation of the AuthNRequest generated
	 * @throws IOException
	 */
	public void login(String returnTo, Boolean forceAuthn, Boolean isPassive, Boolean setNameIdPolicy) throws IOException {
		Map<String, String> parameters = new HashMap<String, String>();

		AuthnRequest authnRequest = new AuthnRequest(settings, forceAuthn, isPassive, setNameIdPolicy);

		String samlRequest = authnRequest.getEncodedAuthnRequest();
		parameters.put("SAMLRequest", samlRequest);

		String relayState;
		if (returnTo == null) {
			relayState = ServletUtils.getSelfRoutedURLNoQuery(request);
		} else {
			relayState = returnTo;
		}
		parameters.put("RelayState", relayState);

		if (settings.getAuthnRequestsSigned()) {
			String sigAlg = settings.getSignatureAlgorithm();
			String signature = this.buildRequestSignature(samlRequest, relayState, sigAlg);

			parameters.put("SigAlg", sigAlg);
			parameters.put("Signature", signature);
		}

		String ssoUrl = getSSOurl();

		LOGGER.debug("AuthNRequest sent to " + ssoUrl + " --> " + samlRequest);
		ServletUtils.sendRedirect(response, ssoUrl, parameters);
		lastRequestId = authnRequest.getId();
	}

	/**
	 * Initiates the SSO process.
	 *
	 * @throws IOException
	 */
	public void login() throws IOException {
		login(null ,false, false, true);
	}

	/**
	 * Initiates the SSO process.
	 *
	 * @param returnTo 
     *				The target URL the user should be returned to after login.
     *
	 * @throws IOException
	 */
	public void login(String returnTo) throws IOException {
		login(returnTo ,false, false, true);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo 
     *				The target URL the user should be returned to after logout.
	 * @param nameId 
     *				The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex 
     *				The SessionIndex (taken from the SAML Response in the SSO process).
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 */
	public void logout(String returnTo, String nameId, String sessionIndex) throws IOException, XMLEntityException {
		Map<String, String> parameters = new HashMap<String, String>();

		LogoutRequest logoutRequest = new LogoutRequest(settings, null, nameId, sessionIndex);
		String samlLogoutRequest = logoutRequest.getEncodedLogoutRequest();
		parameters.put("SAMLRequest", samlLogoutRequest);

		String relayState;
		if (returnTo == null || returnTo.isEmpty()) {
			relayState = ServletUtils.getSelfRoutedURLNoQuery(request);
		} else {
			relayState = returnTo;
		}

		parameters.put("RelayState", relayState);

		if (settings.getLogoutRequestSigned()) {
			String sigAlg = settings.getSignatureAlgorithm();
			String signature = this.buildRequestSignature(samlLogoutRequest, relayState, sigAlg);

			parameters.put("SigAlg", sigAlg);
			parameters.put("Signature", signature);
		}

		String sloUrl = getSLOurl();
		LOGGER.debug("Logout request sent to " + sloUrl + " --> " + samlLogoutRequest);
		ServletUtils.sendRedirect(response, sloUrl, parameters);
		lastRequestId = logoutRequest.getId();
	}

	/**
	 * Initiates the SLO process.
	 * 
	 * @throws IOException
	 * @throws XMLEntityException
	 */
	public void logout() throws IOException, XMLEntityException {		
		logout(null, null, null);
	}

	/**
	 * Initiates the SLO process.
	 *
	 * @param returnTo 
     *				The target URL the user should be returned to after logout. 
	 *
	 * @throws IOException
	 * @throws XMLEntityException
	 */
	public void logout(String returnTo) throws IOException, XMLEntityException {		
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
     * Process the SAML Response sent by the IdP.
     *
     * @param requestId
     *				The ID of the AuthNRequest sent by this SP to the IdP
     *
	 * @throws Exception 
     */
	public void processResponse(String requestId) throws Exception {
		authenticated = false;
		final HttpRequest httpRequest = ServletUtils.makeHttpRequest(this.request);
		final String samlResponseParameter = httpRequest.getParameter("SAMLResponse");

		if (samlResponseParameter != null) {
			SamlResponse samlResponse = new SamlResponse(settings, httpRequest);

			if (samlResponse.isValid(requestId)) {
				nameid = samlResponse.getNameId();
				authenticated = true;
				attributes = samlResponse.getAttributes();
				sessionIndex = samlResponse.getSessionIndex();
				sessionExpiration = samlResponse.getSessionNotOnOrAfter();
				lastAssertionId = samlResponse.getAssertionId();
				lastAssertionNotOnOrAfter = samlResponse.getAssertionNotOnOrAfter();
				LOGGER.debug("processResponse success --> " + samlResponseParameter);
			} else {
				errors.add("invalid_response");
				LOGGER.error("processResponse error. invalid_response");
				LOGGER.debug(" --> " + samlResponseParameter);
				errorReason = samlResponse.getError();
			}
		} else {
			errors.add("invalid_binding");
			String errorMsg = "SAML Response not found, Only supported HTTP_POST Binding";
			LOGGER.error("processResponse error." + errorMsg);
			throw new IllegalArgumentException(errorMsg);
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
     * @param keepLocalSession
     *				When false will destroy the local session, otherwise will destroy it
     * @param requestId
     *				The ID of the LogoutRequest sent by this SP to the IdP
     *
     * @throws Exception 
     */
	public void processSLO(Boolean keepLocalSession, String requestId) throws Exception {
		String samlRequestParameter = request.getParameter("SAMLRequest"); 
		String samlResponseParameter = request.getParameter("SAMLResponse");

		if (samlResponseParameter != null) {
			LogoutResponse logoutResponse = new LogoutResponse(settings, request);
			if (!logoutResponse.isValid(requestId)) {
				errors.add("invalid_logout_response");
				LOGGER.error("processSLO error. invalid_logout_response");
				LOGGER.debug(" --> " + samlResponseParameter);
				errorReason = logoutResponse.getError();				
			} else {
				String status = logoutResponse.getStatus();				
				if (status == null || !status.equals(Constants.STATUS_SUCCESS)) {
					errors.add("logout_not_success");
					LOGGER.error("processSLO error. logout_not_success");
					LOGGER.debug(" --> " + samlResponseParameter);
				} else {
					LOGGER.debug("processSLO success --> " + samlResponseParameter);
					if (!keepLocalSession) {
						request.getSession().invalidate();
					}
				}
			}
		} else if (samlRequestParameter != null) {
			LogoutRequest logoutRequest = new LogoutRequest(settings, request);

			if (!logoutRequest.isValid()) {
				errors.add("invalid_logout_request");
				LOGGER.error("processSLO error. invalid_logout_request");
				LOGGER.debug(" --> " + samlRequestParameter);
				errorReason = logoutRequest.getError();
			} else {
				LOGGER.debug("processSLO success --> " + samlRequestParameter);
				if (!keepLocalSession) {
					request.getSession().invalidate();
				}

				String inResponseTo = logoutRequest.id;
				LogoutResponse logoutResponseBuilder = new LogoutResponse(settings, request);
				logoutResponseBuilder.build(inResponseTo);
				String samlLogoutResponse = logoutResponseBuilder.getEncodedLogoutResponse();

				Map<String, String> parameters = new LinkedHashMap<String, String>();

				parameters.put("SAMLResponse", samlLogoutResponse);

				String relayState = request.getParameter("RelayState");
				if (relayState != null) {
					parameters.put("RelayState", relayState);
				}

				if (settings.getLogoutRequestSigned()) {
					String sigAlg = settings.getSignatureAlgorithm();
					String signature = this.buildResponseSignature(samlLogoutResponse, relayState, sigAlg);

					parameters.put("SigAlg", sigAlg);
					parameters.put("Signature", signature);
				}

				String sloUrl = getSLOurl();
				LOGGER.debug("Logout response sent to " + sloUrl + " --> " + samlLogoutResponse);
				ServletUtils.sendRedirect(response, sloUrl, parameters);
			}
		} else {
			errors.add("invalid_binding");
			String errorMsg = "SAML LogoutRequest/LogoutResponse not found. Only supported HTTP_REDIRECT Binding";
			LOGGER.error("processSLO error." + errorMsg);
			throw new IllegalArgumentException(errorMsg);
		}
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
	 * @param name
	 *				Name of the attribute
	 *
	 * @return the attribute value
	 */
	public final Collection<String> getAttribute(String name) {
		return attributes.get(name);
	}

    /**
     * @return the nameID of the assertion
     */
    public final String getNameId()
    {
        return nameid;
    }

    /**
     * @return the SessionIndex of the assertion
     */
    public final String getSessionIndex()    
    {
        return sessionIndex;
    }

    /**
     * @return the SessionNotOnOrAfter of the assertion
     */
	public final DateTime getSessionExpiration()
	{
	    return sessionExpiration;
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
	 * @return an array with the errors, the array is empty when the validation was successful
	 */
    public List<String> getErrors()
    {
        return errors;
    }

    /**
	 * @return the reason for the last error
	 */
    public String getLastErrorReason()
    {
    	return errorReason;
    }

	/**
	 * @return the id of the last request generated (AuthnRequest or LogoutRequest), null if none
	 */
	public String getLastRequestId()
	{
		return lastRequestId;
	}

    /**
     * @return the Saml2Settings object. The Settings data.
     */
    public Saml2Settings getSettings()
    {
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
	 * @param samlRequest
	 *				The SAML Request
	 * @param relayState
	 *				The RelayState
	 * @param signAlgorithm
	 *				Signature algorithm method
	 *
	 * @return a base64 encoded signature
	 */
    public String buildRequestSignature(String samlRequest, String relayState, String signAlgorithm)
    {
    	return buildSignature(samlRequest, relayState, signAlgorithm, "SAMLRequest");
    }

	/**
	 * Generates the Signature for a SAML Response
	 *
	 * @param samlResponse
	 *				The SAML Response
	 * @param relayState
	 *				The RelayState
	 * @param signAlgorithm
	 *				Signature algorithm method
	 *
	 * @return the base64 encoded signature 
	 */
	public String buildResponseSignature(String samlResponse, String relayState, String signAlgorithm)
	{
		return buildSignature(samlResponse, relayState, signAlgorithm, "SAMLResponse");
	}
	
	private String buildSignature(String samlMessage, String relayState, String signAlgorithm, String type)
	{
		 String signature = "";
		 
		 if (!settings.checkSPCerts()) {
			 String errorMsg = "Trying to sign the " + type + " but can't load the SP certs";
			 LOGGER.error("buildSignature error. " + errorMsg);
			 throw new IllegalArgumentException(errorMsg);
		 }

		 PrivateKey key = settings.getSPkey();
		 
		 String msg = type + "=" + Util.urlEncoder(samlMessage);
		 if (relayState != null) {
			 msg += "&RelayState=" + Util.urlEncoder(relayState);
		 }
		 
		 if (signAlgorithm == null || signAlgorithm.isEmpty()) {
			 signAlgorithm = Constants.RSA_SHA1;
		 }
		 
		 msg += "&SigAlg=" + Util.urlEncoder(signAlgorithm);

		 try {
			signature = Util.base64encoder(Util.sign(msg, key, signAlgorithm));
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			LOGGER.error("buildSignature error." + e.getMessage());
		}

		 if (signature.isEmpty()) {
			 String errorMsg = "There was a problem when calculating the Signature of the " + type;
			 LOGGER.error("buildSignature error. " + errorMsg);
			 throw new IllegalArgumentException(errorMsg);
		 }

		 LOGGER.debug("buildResponseSignature success. --> " + signature);
		 return signature;
	}
}
