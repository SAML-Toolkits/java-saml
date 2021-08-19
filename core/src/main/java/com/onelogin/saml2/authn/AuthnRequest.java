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

import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.settings.Saml2Settings;
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
	 * Time stamp that indicates when the AuthNRequest was created
	 */
	private final Calendar issueInstant;

	/**
	 * Constructs the AuthnRequest object.
	 *
	 * @param settings
	 *            OneLogin_Saml2_Settings
	 * @see #AuthnRequest(Saml2Settings, AuthnRequestParams)
	 */
	public AuthnRequest(Saml2Settings settings) {
		this(settings, new AuthnRequestParams(false, false, true));
	}

	/**
	 * Constructs the AuthnRequest object.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param forceAuthn
	 *              When true the AuthNReuqest will set the ForceAuthn='true'
	 * @param isPassive
	 *              When true the AuthNReuqest will set the IsPassive='true'
	 * @param setNameIdPolicy
	 *              When true the AuthNReuqest will set a nameIdPolicy
	 * @param nameIdValueReq
	 *              Indicates to the IdP the subject that should be authenticated
	 * @deprecated use {@link #AuthnRequest(Saml2Settings, AuthnRequestParams)} with
	 *             {@link AuthnRequestParams#AuthnRequestParams(boolean, boolean, boolean, String)}
	 *             instead
	 */
	@Deprecated
	public AuthnRequest(Saml2Settings settings, boolean forceAuthn, boolean isPassive, boolean setNameIdPolicy, String nameIdValueReq) {
		this(settings, new AuthnRequestParams(forceAuthn, isPassive, setNameIdPolicy, nameIdValueReq));
	}
	
	/**
	 * Constructs the AuthnRequest object.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param forceAuthn
	 *              When true the AuthNReuqest will set the ForceAuthn='true'
	 * @param isPassive
	 *              When true the AuthNReuqest will set the IsPassive='true'
	 * @param setNameIdPolicy
	 *              When true the AuthNReuqest will set a nameIdPolicy
	 * @deprecated use {@link #AuthnRequest(Saml2Settings, AuthnRequestParams)} with
	 *             {@link AuthnRequestParams#AuthnRequestParams(boolean, boolean, boolean)}
	 *             instead
	 */
	@Deprecated
	public AuthnRequest(Saml2Settings settings, boolean forceAuthn, boolean isPassive, boolean setNameIdPolicy) {
		this(settings, forceAuthn, isPassive, setNameIdPolicy, null);
	}

	/**
	 * Constructs the AuthnRequest object.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param params
	 *              a set of authentication request input parameters that shape the
	 *              request to create
	 */
	public AuthnRequest(Saml2Settings settings, AuthnRequestParams params) {
		this.id = Util.generateUniqueID(settings.getUniqueIDPrefix());
		issueInstant = Calendar.getInstance();
		this.settings = settings;

		StrSubstitutor substitutor = generateSubstitutor(params, settings);
		authnRequestString = postProcessXml(substitutor.replace(getAuthnRequestTemplate()), params, settings);
		LOGGER.debug("AuthNRequest --> " + authnRequestString);
	}

	/**
	 * Allows for an extension class to post-process the AuthnRequest XML generated
	 * for this request, in order to customize the result.
	 * <p>
	 * This method is invoked at construction time, after all the other fields of
	 * this class have already been initialised. Its default implementation simply
	 * returns the input XML as-is, with no change.
	 * 
	 * @param authnRequestXml
	 *              the XML produced for this AuthnRequest by the standard
	 *              implementation provided by {@link AuthnRequest}
	 * @param params
	 *              the authentication request input parameters
	 * @param settings
	 *              the settings
	 * @return the post-processed XML for this AuthnRequest, which will then be
	 *         returned by any call to {@link #getAuthnRequestXml()}
	 */
	protected String postProcessXml(final String authnRequestXml, final AuthnRequestParams params, final Saml2Settings settings) {
		return authnRequestXml;
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
	 * @param params
	 *              the authentication request input parameters
	 * @param settings
	 * 				Saml2Settings object. Setting data
	 * 
	 * @return the StrSubstitutor object of the AuthnRequest 
	 */ 
	private StrSubstitutor generateSubstitutor(AuthnRequestParams params, Saml2Settings settings) {

		Map<String, String> valueMap = new HashMap<String, String>();

		String forceAuthnStr = "";
		if (params.isForceAuthn()) {
			forceAuthnStr = " ForceAuthn=\"true\"";
		}

		String isPassiveStr = "";
		if (params.isPassive()) {
			isPassiveStr = " IsPassive=\"true\"";
		}

		valueMap.put("forceAuthnStr", forceAuthnStr);
		valueMap.put("isPassiveStr", isPassiveStr);

		String destinationStr = "";
		URL sso =  settings.getIdpSingleSignOnServiceUrl();
		if (sso != null) {
			destinationStr = " Destination=\"" + Util.toXml(sso.toString()) + "\"";
		}
		valueMap.put("destinationStr", destinationStr);

		String subjectStr = "";
		String nameIdValueReq = params.getNameIdValueReq();
		if (nameIdValueReq != null && !nameIdValueReq.isEmpty()) {
			String nameIDFormat = settings.getSpNameIDFormat();
			subjectStr = "<saml:Subject>";
			subjectStr += "<saml:NameID Format=\"" + Util.toXml(nameIDFormat) + "\">" + Util.toXml(nameIdValueReq) + "</saml:NameID>";
			subjectStr += "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"></saml:SubjectConfirmation>";
			subjectStr += "</saml:Subject>";
        }
        valueMap.put("subjectStr", subjectStr);

		String nameIDPolicyStr = "";
		if (params.isSetNameIdPolicy()) {
			String nameIDPolicyFormat = settings.getSpNameIDFormat();
			if (settings.getWantNameIdEncrypted()) {
				nameIDPolicyFormat = Constants.NAMEID_ENCRYPTED;
			}
			String allowCreateStr = "";
			if (params.isAllowCreate()) {
				allowCreateStr = " AllowCreate=\"true\"";
			}
			nameIDPolicyStr = "<samlp:NameIDPolicy Format=\"" + Util.toXml(nameIDPolicyFormat) + "\"" + allowCreateStr + " />";
		}
		valueMap.put("nameIDPolicyStr", nameIDPolicyStr);

		String providerStr = "";
		Organization organization = settings.getOrganization();
		if (organization != null) {
			String displayName = organization.getOrgDisplayName();
			if (!displayName.isEmpty()) {
				providerStr = " ProviderName=\""+ Util.toXml(displayName) + "\""; 
			}
		}
		valueMap.put("providerStr", providerStr);

		String issueInstantString = Util.formatDateTime(issueInstant.getTimeInMillis());
		valueMap.put("issueInstant", issueInstantString);
		valueMap.put("id", Util.toXml(String.valueOf(id)));
		valueMap.put("assertionConsumerServiceURL", Util.toXml(String.valueOf(settings.getSpAssertionConsumerServiceUrl())));
		valueMap.put("protocolBinding", Util.toXml(settings.getSpAssertionConsumerServiceBinding()));
		valueMap.put("spEntityid", Util.toXml(settings.getSpEntityId()));

		String requestedAuthnContextStr = "";
		List<String> requestedAuthnContexts = settings.getRequestedAuthnContext();
		if (requestedAuthnContexts != null && !requestedAuthnContexts.isEmpty()) {
			String requestedAuthnContextCmp = settings.getRequestedAuthnContextComparison();
			requestedAuthnContextStr = "<samlp:RequestedAuthnContext Comparison=\"" + Util.toXml(requestedAuthnContextCmp) + "\">";
			for (String requestedAuthnContext : requestedAuthnContexts) {
				requestedAuthnContextStr += "<saml:AuthnContextClassRef>" + Util.toXml(requestedAuthnContext) + "</saml:AuthnContextClassRef>";
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
		template.append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"${id}\" Version=\"2.0\" IssueInstant=\"${issueInstant}\"${providerStr}${forceAuthnStr}${isPassiveStr}${destinationStr} ProtocolBinding=\"${protocolBinding}\" AssertionConsumerServiceURL=\"${assertionConsumerServiceURL}\">");
		template.append("<saml:Issuer>${spEntityid}</saml:Issuer>");
		template.append("${subjectStr}${nameIDPolicyStr}${requestedAuthnContextStr}</samlp:AuthnRequest>");
		return template;
	}

	/**
	 * @return the generated id of the AuthnRequest message
	 */
	public String getId()
	{
		return id;
	}
	
	/**
	 * Returns the issue instant of this message.
	 * 
	 * @return a new {@link Calendar} instance carrying the issue instant of this message
	 */
	public Calendar getIssueInstant() {
		return issueInstant == null? null: (Calendar) issueInstant.clone();
	}
}
