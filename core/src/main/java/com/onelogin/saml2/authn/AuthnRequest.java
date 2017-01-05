package com.onelogin.saml2.authn;

import java.io.IOException;
import java.net.URL;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.text.StrSubstitutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

/**
 * AuthNRequest class of OneLogin's Java Toolkit.
 *
 * A class that implements SAML 2 Authentication Request
 */
public class AuthnRequest {
	/**
     * Private property to construct a logger for this class.
     */
	private static final Logger LOGGER = LoggerFactory.getLogger(AuthnRequest.class);

	/**
	 * SAML AuthNRequest string
	 */
	private final String authnRequestString;

	/**
	 * SAML AuthNRequest ID.
	 */
	private final String id;

	/**
     * Settings data.
     */
	private final Saml2Settings settings;

	/**
	 * When true the AuthNRequest will set the ForceAuthn='true'
	 */
	private final boolean forceAuthn;

	/**
	 * When true the AuthNRequest will set the IsPassive='true'
	 */
	private final boolean isPassive;

	/**
	 * When true the AuthNReuqest will set a nameIdPolicy
	 */
	private final boolean setNameIdPolicy;

	
	/**
	 * Time stamp that indicates when the AuthNRequest was created
	 */
	private final Calendar issueInstant;

	/**
	 * Constructs the AuthnRequest object.
	 *
	 * @param settings
	 *            OneLogin_Saml2_Settings
	 */
	public AuthnRequest(Saml2Settings settings) {
		this(settings, false, false, true);
	}

	/**
	 * Constructs the AuthnRequest object.
	 *
	 * @param settings
	 *            OneLogin_Saml2_Settings
	 * @param forceAuthn
	 *            When true the AuthNReuqest will set the ForceAuthn='true'
	 * @param isPassive
	 *            When true the AuthNReuqest will set the IsPassive='true'
	 * @param setNameIdPolicy
	 *            When true the AuthNReuqest will set a nameIdPolicy
	 */
	public AuthnRequest(Saml2Settings settings, boolean forceAuthn, boolean isPassive, boolean setNameIdPolicy) {
		this.id = Util.generateUniqueID();
		issueInstant = Calendar.getInstance();
		this.isPassive = isPassive;
		this.settings = settings;
		this.forceAuthn = forceAuthn;
		this.setNameIdPolicy = setNameIdPolicy;

		StrSubstitutor substitutor = generateSubstitutor(settings);
		authnRequestString = substitutor.replace(getAuthnRequestTemplate());
		LOGGER.debug("AuthNRequest --> " + authnRequestString);
	}

	/**
	 * @return the base64 encoded unsigned AuthnRequest (deflated or not)
	 *
	 * @param deflated 
     *				If deflated or not the encoded AuthnRequest
     *
	 * @throws IOException 
	 */
	public String getEncodedAuthnRequest(Boolean deflated) throws IOException {
		String encodedAuthnRequest;
		if (deflated == null) {
			deflated = settings.isCompressRequestEnabled();
		}
		if (deflated) {
			encodedAuthnRequest = Util.deflatedBase64encoded(getAuthnRequestXml());
		} else {
			encodedAuthnRequest = Util.base64encoder(getAuthnRequestXml());
		}
		return encodedAuthnRequest;
	}
	
	/**
	 * @return base64 encoded, unsigned AuthnRequest (deflated or not)
	 * 
	 * @throws IOException 
	 */
	public String getEncodedAuthnRequest() throws IOException {
		return getEncodedAuthnRequest(null);
	}

	/**
	 * @return unsigned plain-text AuthnRequest. 
	 */
	public String getAuthnRequestXml() {
		return authnRequestString;
	}

	/**
	 * Substitutes AuthnRequest variables within a string by values.
	 *
	 * @param settings
	 * 				Saml2Settings object. Setting data
	 * 
	 * @return the StrSubstitutor object of the AuthnRequest 
	 */ 
	private StrSubstitutor generateSubstitutor(Saml2Settings settings) {

		Map<String, String> valueMap = new HashMap<String, String>();

		String forceAuthnStr = "";
		if (forceAuthn) {
			forceAuthnStr = " ForceAuthn=\"true\"";
		}

		String isPassiveStr = "";
		if (isPassive) {
			isPassiveStr = " IsPassive=\"true\"";
		}

		valueMap.put("forceAuthnStr", forceAuthnStr);
		valueMap.put("isPassiveStr", isPassiveStr);

		String destinationStr = "";
		URL sso =  settings.getIdpSingleSignOnServiceUrl();
		if (sso != null) {
			destinationStr = " Destination=\"" + sso.toString() + "\"";
		}
		valueMap.put("destinationStr", destinationStr);

		String nameIDPolicyStr = "";
		if (setNameIdPolicy) {
			String nameIDPolicyFormat = settings.getSpNameIDFormat();
			if (settings.getWantNameIdEncrypted()) {
				nameIDPolicyFormat = Constants.NAMEID_ENCRYPTED;
			}
			nameIDPolicyStr = "<samlp:NameIDPolicy Format=\"" + nameIDPolicyFormat + "\" AllowCreate=\"true\" />";
		}
		valueMap.put("nameIDPolicyStr", nameIDPolicyStr);

		String providerStr = "";
		Organization organization = settings.getOrganization();
		if (organization != null) {
			String displayName = organization.getOrgDisplayName();
			if (!displayName.isEmpty()) {
				providerStr = " ProviderName=\""+ displayName + "\""; 
			}
		}
		valueMap.put("providerStr", providerStr);

		String issueInstantString = Util.formatDateTime(issueInstant.getTimeInMillis());
		valueMap.put("issueInstant", issueInstantString);
		valueMap.put("id", String.valueOf(id));
		valueMap.put("assertionConsumerServiceURL", String.valueOf(settings.getSpAssertionConsumerServiceUrl()));
		valueMap.put("spEntityid", settings.getSpEntityId());

		String requestedAuthnContextStr = "";
		List<String> requestedAuthnContexts = settings.getRequestedAuthnContext();
		if (requestedAuthnContexts != null && !requestedAuthnContexts.isEmpty()) {
			String requestedAuthnContextCmp = settings.getRequestedAuthnContextComparison();
			requestedAuthnContextStr = "<samlp:RequestedAuthnContext Comparison=\"" + requestedAuthnContextCmp + "\">";
			for (String requestedAuthnContext : requestedAuthnContexts) {
				requestedAuthnContextStr += "<saml:AuthnContextClassRef>" + requestedAuthnContext + "</saml:AuthnContextClassRef>";
			}
			requestedAuthnContextStr += "</samlp:RequestedAuthnContext>";
		}

		valueMap.put("requestedAuthnContextStr", requestedAuthnContextStr);

		return new StrSubstitutor(valueMap);
	}

	/**
	 * @return the AuthnRequest's template
	 */
	private static StringBuilder getAuthnRequestTemplate() {
		StringBuilder template = new StringBuilder();
		template.append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"${id}\" Version=\"2.0\" IssueInstant=\"${issueInstant}\"${providerStr}${forceAuthnStr}${isPassiveStr}${destinationStr} ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"${assertionConsumerServiceURL}\">");
		template.append("<saml:Issuer>${spEntityid}</saml:Issuer>");
		template.append("${nameIDPolicyStr}${requestedAuthnContextStr}</samlp:AuthnRequest>");
		return template;
	}

	/**
	 * @return the generated id of the AuthnRequest message
	 */
	public String getId()
	{
		return id;
	}
}
