package com.onelogin.saml2.logout;

import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.lang3.text.StrSubstitutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.SchemaFactory;
import com.onelogin.saml2.util.Util;

/**
 * LogoutResponse class of OneLogin's Java Toolkit.
 *
 * A class that implements SAML 2 Logout Response builder/parser/validator
 */ 
public class LogoutResponse {
	/**
     * Private property to construct a logger for this class.
     */
	private static final Logger LOGGER = LoggerFactory.getLogger(LogoutResponse.class);

	/**
	 * SAML LogoutResponse string
	 */
	private String logoutResponseString;	

	/**
	 * A DOMDocument object loaded from the SAML Response.
	 */
	private Document logoutResponseDocument;

	/**
	 * SAML LogoutResponse ID.
	 */
	private String id;

	/**
     * Settings data.
     */
	private final Saml2Settings settings;

	/**
     * HttpServletRequest object to be processed (Contains GET and POST parameters, session, ...).
     */
	private final HttpServletRequest request;

	/**
	 * URL of the current host + current view
	 */
	private String currentUrl;

	/**
	 * The inResponseTo attribute of the Logout Request
	 */
	private String inResponseTo;

	/**
	 * Time when the Logout Request was created
	 */
	private Calendar issueInstant;

	/**
	 * After validation, if it fails this property has the cause of the problem
	 */ 
	private String error;

	/**
	 * Constructs the LogoutResponse object.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param request
     *              HttpServletRequest object to be processed (Contains GET and POST parameters, session, ...).
     *
	 * @throws XMLEntityException 
	 */
	public LogoutResponse(Saml2Settings settings, HttpServletRequest request) throws XMLEntityException {
		this.settings = settings;
		this.request = request;
		
		String samlLogoutResponse = null;
		if (request != null) {
			currentUrl = request.getRequestURL().toString();
			samlLogoutResponse = request.getParameter("SAMLResponse");
		}

		if (samlLogoutResponse != null && !samlLogoutResponse.isEmpty()) {	
			logoutResponseString = Util.base64decodedInflated(samlLogoutResponse);
			logoutResponseDocument = Util.loadXML(logoutResponseString);
		}
	}

	/**
	 * @return the deflated, base64 encoded, unsigned Logout Response.
	 *
	 * @throws IOException 
	 */
	public String getEncodedLogoutResponse() throws IOException {
		return Util.deflatedBase64encoded(getLogoutResponseXml());
	}

	/**
	 * @return the plain XML Logout Response
	 */
	protected String getLogoutResponseXml() {
		return logoutResponseString;
	}

	 /**
     * Determines if the SAML LogoutResponse is valid
     *
     * @param requestId
     *              The ID of the LogoutRequest sent by this SP to the IdP
     *
     * @throws Exception
     * 
     * @return if the SAML LogoutResponse is or not valid
     */
	public Boolean isValid(String requestId) {
		error = null;

		try {
			if (this.logoutResponseDocument == null) {
				throw new Exception("SAML Logout Response is not loaded");
			}

			/* No possible right now
			if (request == null) {
				throw new Exception("The HttpServletRequest of the current host was not established");
			}
			*/

			if (this.currentUrl == null || this.currentUrl.isEmpty()) {
				throw new Exception("The URL of the current host was not established");
			}

			String signature = request.getParameter("Signature");

			if (settings.isStrict()) {
				Element rootElement = logoutResponseDocument.getDocumentElement();
				rootElement.normalize();				

				if (settings.getWantXMLValidation()) {
					if (!Util.validateXML(this.logoutResponseDocument, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
						throw new Exception("Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd");
					}
				}

				// Check if the InResponseTo of the Logout Response matches the ID of the Logout Request (requestId) if provided
				if (requestId != null && rootElement.hasAttribute("InResponseTo")) {
					String responseInResponseTo = rootElement.getAttribute("InResponseTo");
					if (!responseInResponseTo.equals(requestId)) {
						throw new Exception("The InResponseTo of the Logout Response: " + responseInResponseTo
								+ ", does not match the ID of the Logout request sent by the SP:: " + requestId);
					}
				}

				// Check issuer
                String issuer = getIssuer();
                if (issuer != null && !issuer.isEmpty() && !issuer.equals(settings.getIdpEntityId())) {
                    throw new Exception("Invalid issuer in the Logout Response");
                }

				// Check destination
				if (rootElement.hasAttribute("Destination")) {
					String destinationUrl = rootElement.getAttribute("Destination");
					if (destinationUrl != null) {
						if (!destinationUrl.isEmpty() && !destinationUrl.equals(currentUrl)) {
							throw new Exception("The LogoutResponse was received at " + currentUrl + " instead of "
									+ destinationUrl);
						}
					}
				}

                if (settings.getWantMessagesSigned() && (signature == null || signature.isEmpty())) {
                    throw new Exception("The Message of the Logout Response is not signed and the SP requires it");
                }
			}

			if (signature != null && !signature.isEmpty()) {
				X509Certificate cert = settings.getIdpx509cert();
				if (cert == null) {
					throw new Exception("In order to validate the sign on the Logout Response, the x509cert of the IdP is required");
				}

				String signAlg = request.getParameter("SigAlg");
				if (signAlg == null || signAlg.isEmpty()) {
					signAlg = Constants.RSA_SHA1;
				}

				String signedQuery = "SAMLResponse=" + Util.urlEncoder(request.getParameter("SAMLResponse"));

				String relayState = request.getParameter("RelayState");
				if (relayState != null && !relayState.isEmpty()) {
					signedQuery += "&RelayState=" + Util.urlEncoder(relayState);
				}

				signedQuery += "&SigAlg=" + Util.urlEncoder(signAlg);

				if (!Util.validateBinarySignature(signedQuery, Util.base64decoder(signature), cert, signAlg)) {
					throw new Exception("Signature validation failed. Logout Response rejected");
				}
			}

			LOGGER.debug("LogoutRequest validated --> " + logoutResponseString);
			return true;
		} catch (Exception e) {
			error = e.getMessage();
			LOGGER.debug("LogoutResponse invalid --> " + logoutResponseString);
			LOGGER.error(error);
			return false;
		}
	}

	public Boolean isValid() {		
		return isValid(null);
	}

	/**
	 * Gets the Issuer from Logout Response.
	 * 
	 * @return the issuer of the logout response
	 *
	 * @throws XPathExpressionException
	 */
    public String getIssuer() throws XPathExpressionException {
    	String issuer = null;
		NodeList issuers = this.query("/samlp:LogoutResponse/saml:Issuer");
		if (issuers.getLength() == 1) {
			issuer = issuers.item(0).getTextContent();
		}    	
        return issuer;
    }

    /**
     * Gets the Status of the Logout Response.
     * 
     * @return the Status
     *
     * @throws XPathExpressionException 
     */
    public String getStatus() throws XPathExpressionException
    {
    	String statusCode = null;
		NodeList entries = this.query("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode");
		if (entries.getLength() == 1) {
			statusCode = entries.item(0).getAttributes().getNamedItem("Value").getNodeValue();
		}    	
        return statusCode;
    }    

	/**
     * Extracts nodes that match the query from the DOMDocument (Logout Response Menssage)
     *
     * @param query
     *				Xpath Expression
     *
     * @return DOMNodeList The queried nodes
     */
	private NodeList query (String query) throws XPathExpressionException {
		return Util.query(this.logoutResponseDocument, query, null);
	}

    /**
     * Generates a Logout Response XML string.
     *
     * @param inResponseTo
     *				InResponseTo attribute value to bet set at the Logout Response. 
     */
	public void build(String inResponseTo) {
		id = Util.generateUniqueID();
		issueInstant = Calendar.getInstance();
		this.inResponseTo = inResponseTo;

		StrSubstitutor substitutor = generateSubstitutor(settings);
		this.logoutResponseString = substitutor.replace(getLogoutResponseTemplate());
	}

    /**
     * Generates a Logout Response XML string.
     *
     */
	public void build() {
		build(null);
	}	

	/**
	 * Substitutes LogoutResponse variables within a string by values.
	 *
	 * @param settings
	 * 				Saml2Settings object. Setting data
	 * 
	 * @return the StrSubstitutor object of the LogoutResponse 
	 */
	private StrSubstitutor generateSubstitutor(Saml2Settings settings) {
		Map<String, String> valueMap = new HashMap<String, String>();

		valueMap.put("id", id);		

		String issueInstantString = Util.formatDateTime(issueInstant.getTimeInMillis());
		valueMap.put("issueInstant", issueInstantString);

		String destinationStr = "";
		URL slo =  settings.getIdpSingleLogoutServiceUrl();
		if (slo != null) {
			destinationStr = " Destination=\"" + slo.toString() + "\"";
		}
		valueMap.put("destinationStr", destinationStr);

		String inResponseStr = "";
		if (inResponseTo != null) {
			inResponseStr = " InResponseTo=\"" + inResponseTo + "\"";
		}
		valueMap.put("inResponseStr", inResponseStr);		

		valueMap.put("issuer", settings.getSpEntityId());

		return new StrSubstitutor(valueMap);
	}

	/**
	 * @return the LogoutResponse's template
	 */
	private static StringBuilder getLogoutResponseTemplate() {
		StringBuilder template = new StringBuilder();
		template.append("<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ");
		template.append("ID=\"${id}\" ");
		template.append("Version=\"2.0\" ");
		template.append("IssueInstant=\"${issueInstant}\"${destinationStr}${inResponseStr} >");
		template.append("<saml:Issuer>${issuer}</saml:Issuer>");
		template.append("<samlp:Status>");
		template.append("<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" />");
		template.append("</samlp:Status>");
		template.append("</samlp:LogoutResponse>");
		return template;
	}

	/**
     * After execute a validation process, if fails this method returns the cause
     *
     * @return the cause of the validation error 
     */
	public String getError() {
		return error;
	}
}