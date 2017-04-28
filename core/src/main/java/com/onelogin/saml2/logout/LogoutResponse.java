package com.onelogin.saml2.logout;

import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.lang3.text.StrSubstitutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.http.HttpRequest;
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
     * HttpRequest object to be processed (Contains GET and POST parameters, request URL, ...).
     */
	private final HttpRequest request;

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
     *              the HttpRequest object to be processed (Contains GET and POST parameters, request URL, ...).
     *
	 */
	public LogoutResponse(Saml2Settings settings, HttpRequest request) {
		this.settings = settings;
		this.request = request;
		
		String samlLogoutResponse = null;
		if (request != null) {
			currentUrl = request.getRequestURL();
			samlLogoutResponse = request.getParameter("SAMLResponse");
		}

		if (samlLogoutResponse != null && !samlLogoutResponse.isEmpty()) {	
			logoutResponseString = Util.base64decodedInflated(samlLogoutResponse);
			logoutResponseDocument = Util.loadXML(logoutResponseString);
		}
	}

	/**
	 * @return the base64 encoded unsigned Logout Response (deflated or not)
	 *
	 * @param deflated 
     *				If deflated or not the encoded Logout Response
     *
	 * @throws IOException 
	 */
	public String getEncodedLogoutResponse(Boolean deflated) throws IOException {
		String encodedLogoutResponse;
		if (deflated == null) {
			deflated = settings.isCompressResponseEnabled();
		}
		if (deflated) {
			encodedLogoutResponse = Util.deflatedBase64encoded(getLogoutResponseXml());
		} else {
			encodedLogoutResponse = Util.base64encoder(getLogoutResponseXml());
		}
		return encodedLogoutResponse;
	}
	
	/**
	 * @return the base64 encoded, unsigned Logout Response (deflated or not)
	 *
	 * @throws IOException 
	 */
	public String getEncodedLogoutResponse() throws IOException {
		return getEncodedLogoutResponse(null);
	}

	/**
	 * @return the plain XML Logout Response
	 */
	public String getLogoutResponseXml() {
		return logoutResponseString;
	}

	/**
	 * @return the ID of the Response
	 */
	public String getId() {
		String idvalue = null;
		if (id != null) {
			idvalue = id;
		} else if (logoutResponseDocument != null) {
			idvalue = logoutResponseDocument.getDocumentElement().getAttributes().getNamedItem("ID").getNodeValue();
		}
		return idvalue;
	}

	 /**
     * Determines if the SAML LogoutResponse is valid
     *
     * @param requestId
     *              The ID of the LogoutRequest sent by this SP to the IdP
     *
     * @return if the SAML LogoutResponse is or not valid
     */
	public Boolean isValid(String requestId) {
		error = null;

		try {
			if (this.logoutResponseDocument == null) {
				throw new ValidationError("SAML Logout Response is not loaded", ValidationError.INVALID_XML_FORMAT);
			}

			if (this.currentUrl == null || this.currentUrl.isEmpty()) {
				throw new Exception("The URL of the current host was not established");
			}

			String signature = request.getParameter("Signature");

			if (settings.isStrict()) {
				Element rootElement = logoutResponseDocument.getDocumentElement();
				rootElement.normalize();				

				if (settings.getWantXMLValidation()) {
					if (!Util.validateXML(this.logoutResponseDocument, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
						throw new ValidationError("Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd", ValidationError.INVALID_XML_FORMAT);
					}
				}

				String responseInResponseTo = rootElement.hasAttribute("InResponseTo") ? rootElement.getAttribute("InResponseTo") : null;
				if (requestId == null && responseInResponseTo != null && settings.isRejectUnsolicitedResponsesWithInResponseTo()) {
					throw new ValidationError("The Response has an InResponseTo attribute: " + responseInResponseTo +
							" while no InResponseTo was expected", ValidationError.WRONG_INRESPONSETO);
				}

				// Check if the InResponseTo of the Response matches the ID of the AuthNRequest (requestId) if provided
				if (requestId != null && !Objects.equals(responseInResponseTo, requestId)) {
						throw new ValidationError("The InResponseTo of the Logout Response: " + responseInResponseTo
								+ ", does not match the ID of the Logout request sent by the SP: " + requestId, ValidationError.WRONG_INRESPONSETO);
				}

				// Check issuer
                String issuer = getIssuer();
                if (issuer != null && !issuer.isEmpty() && !issuer.equals(settings.getIdpEntityId())) {
					throw new ValidationError(
							String.format("Invalid issuer in the Logout Response. Was '%s', but expected '%s'" , issuer, settings.getIdpEntityId()),
							ValidationError.WRONG_ISSUER
					);
                }

				// Check destination
				if (rootElement.hasAttribute("Destination")) {
					String destinationUrl = rootElement.getAttribute("Destination");
					if (destinationUrl != null) {
						if (!destinationUrl.isEmpty() && !destinationUrl.equals(currentUrl)) {
							throw new ValidationError("The LogoutResponse was received at " + currentUrl + " instead of "
									+ destinationUrl, ValidationError.WRONG_DESTINATION);
						}
					}
				}

                if (settings.getWantMessagesSigned() && (signature == null || signature.isEmpty())) {
                    throw new ValidationError("The Message of the Logout Response is not signed and the SP requires it", ValidationError.NO_SIGNED_MESSAGE);
                }
			}

			if (signature != null && !signature.isEmpty()) {
				X509Certificate cert = settings.getIdpx509cert();
				if (cert == null) {
					throw new SettingsException("In order to validate the sign on the Logout Response, the x509cert of the IdP is required", SettingsException.CERT_NOT_FOUND);
				}

				String signAlg = request.getParameter("SigAlg");
				if (signAlg == null || signAlg.isEmpty()) {
					signAlg = Constants.RSA_SHA1;
				}

				String signedQuery = "SAMLResponse=" + request.getEncodedParameter("SAMLResponse");

				String relayState = request.getEncodedParameter("RelayState");
				if (relayState != null && !relayState.isEmpty()) {
					signedQuery += "&RelayState=" + relayState;
				}

				signedQuery += "&SigAlg=" + request.getEncodedParameter("SigAlg", signAlg);

				if (!Util.validateBinarySignature(signedQuery, Util.base64decoder(signature), cert, signAlg)) {
					throw new ValidationError("Signature validation failed. Logout Response rejected", ValidationError.INVALID_SIGNATURE);
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
		URL slo =  settings.getIdpSingleLogoutServiceResponseUrl();
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