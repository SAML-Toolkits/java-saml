package com.onelogin.saml2.authn;

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
	 * When true the AuthNRequest will set the ForceAuthn='true'
	 */
	private final boolean forceAuthn;

	/**
	 * When true the AuthNRequest will set the IsPassive='true'
	 */
	private final boolean isPassive;

	/**
	 * Time stamp that indicates when the AuthNRequest was created
	 */
	private final Calendar issueInstant;

	public AuthnRequest(Saml2Settings settings) {
		this(settings, false, false);
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
	 */
	public AuthnRequest(Saml2Settings settings, boolean forceAuthn, boolean isPassive) {
		this.id = Util.generateUniqueID();
		issueInstant = Calendar.getInstance();
		this.isPassive = isPassive;
		this.forceAuthn = forceAuthn;

		StrSubstitutor substitutor = generateSubstitutor(settings);
		authnRequestString = substitutor.replace(getAuthnRequestTemplate());
		LOGGER.debug("AuthNRequest --> " + authnRequestString);
	}

	/**
	 * @return deflated, base64 encoded, unsigned AuthnRequest. 
	 */
	public String getEncodedAuthnRequest() {
		return Util.deflatedBase64encoded(getAuthnRequestXml());
	}

	/**
	 * @return unsigned plain-text AuthnRequest. 
	 */
	private String getAuthnRequestXml() {
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
		valueMap.put("forceAuthn", String.valueOf(forceAuthn));
		valueMap.put("isPassive", String.valueOf(isPassive));

		String destinationStr = "";
		URL slo =  settings.getIdpSingleSignOnServiceUrl();
		if (slo != null) {
			destinationStr = " Destination=\"" + slo.toString() + "\"";
		}
		valueMap.put("destinationStr", destinationStr);

		String nameIDPolicyFormat = settings.getSpNameIDFormat();
		if (settings.getWantNameIdEncrypted()) {
			nameIDPolicyFormat = Constants.NAMEID_ENCRYPTED;
		}
		valueMap.put("nameIDPolicyFormat", nameIDPolicyFormat);

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
		valueMap.put("assertionConsumerServiceURL", settings.getSpAssertionConsumerServiceUrl().toString());
		valueMap.put("spEntityid", settings.getSpEntityId());

		String requestedAuthnContextStr = "";
		List<String> requestedAuthnContexts = settings.getRequestedAuthnContext();
		if (requestedAuthnContexts != null && !requestedAuthnContexts.isEmpty()) {
			String requestedAuthnContextCmp = settings.getRequestedAuthnContextComparison();
			requestedAuthnContextStr = "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"" + requestedAuthnContextCmp + "\">";
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
		template.append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"${id}\" Version=\"2.0\" IssueInstant=\"${issueInstant}\"${providerStr} ForceAuthn=\"${forceAuthn}\" IsPassive=\"${isPassive}\"${destinationStr} ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"${assertionConsumerServiceURL}\">");
		template.append("<saml:Issuer>${spEntityid}</saml:Issuer>");
		template.append("<samlp:NameIDPolicy Format=\"${nameIDPolicyFormat}\" AllowCreate=\"true\" />");		
		template.append("${requestedAuthnContextStr}</samlp:AuthnRequest>");
		return template;
	}
}
