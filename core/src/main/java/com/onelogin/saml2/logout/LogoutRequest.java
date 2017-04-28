package com.onelogin.saml2.logout;

import java.io.IOException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.lang3.text.StrSubstitutor;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.util.Util;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.SchemaFactory;

/**
 * LogoutRequest class of OneLogin's Java Toolkit.
 *
 * A class that implements SAML 2 Logout Request builder/parser/validator
 */
public class LogoutRequest {
	/**
     * Private property to construct a logger for this class.
     */
	private static final Logger LOGGER = LoggerFactory.getLogger(LogoutRequest.class);

	/**
	 * SAML LogoutRequest string
	 */
	private final String logoutRequestString;

	/**
	 * SAML LogoutRequest ID.
	 */
	public String id;

	/**
     * Settings data.
     */
	private final Saml2Settings settings;

	/**
     * HttpRequest object to be processed (Contains GET and POST parameters, request URL, ...).
     */
	private final HttpRequest request;

	/**
     * NameID.
     */	
	private String nameId;

	/**
     * NameID Format.
     */
	private String nameIdFormat;

	/**
     * SessionIndex. When the user is logged, this stored it from the AuthnStatement of the SAML Response
     */
	private String sessionIndex;

	/**
	 * URL of the current host + current view
	 */
	private String currentUrl;

	/**
	 * Time when the Logout Request was created
	 */
	private Calendar issueInstant;

	/**
	 * After validation, if it fails this property has the cause of the problem
	 */ 
	private String error;

	/**
	 * Constructs the LogoutRequest object.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param request
     *              the HttpRequest object to be processed (Contains GET and POST parameters, request URL, ...).
	 * @param nameId
	 *              The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex
	 *              The SessionIndex (taken from the SAML Response in the SSO process).
	 * @param nameIdFormat
	 *              The nameIdFormat that will be set in the LogoutRequest.
	 * @throws XMLEntityException 
	 *
	 */
	public LogoutRequest(Saml2Settings settings, HttpRequest request, String nameId, String sessionIndex, String nameIdFormat) throws XMLEntityException {
		this.settings = settings;
		this.request = request;

		String samlLogoutRequest = null;

		if (request != null) {
			samlLogoutRequest = request.getParameter("SAMLRequest");
			currentUrl = request.getRequestURL();
		}

		if (samlLogoutRequest == null) {
			id = Util.generateUniqueID();
			issueInstant = Calendar.getInstance();
			this.nameId = nameId;
			this.nameIdFormat = nameIdFormat;
			this.sessionIndex = sessionIndex;

			StrSubstitutor substitutor = generateSubstitutor(settings);
			logoutRequestString = substitutor.replace(getLogoutRequestTemplate());
		} else {
			logoutRequestString = Util.base64decodedInflated(samlLogoutRequest);
			id = getId(logoutRequestString);
		}
	}

	/**
	 * Constructs the LogoutRequest object.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param request
     *              the HttpRequest object to be processed (Contains GET and POST parameters, request URL, ...).
	 * @param nameId
	 *              The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex
	 *              The SessionIndex (taken from the SAML Response in the SSO process).
	 *
	 * @throws XMLEntityException
	 */
	public LogoutRequest(Saml2Settings settings, HttpRequest request, String nameId, String sessionIndex) throws XMLEntityException {
		this(settings, request, nameId, sessionIndex, null);
	}

	/**
	 * Constructs the LogoutRequest object.
	 *
	 * @param settings
	 *            OneLogin_Saml2_Settings
	 *
	 * @throws XMLEntityException 
	 */
	public LogoutRequest(Saml2Settings settings) throws XMLEntityException {
		this(settings, null, null, null);
	}

	/**
	 * Constructs the LogoutRequest object.
	 *
	 * @param settings
	 *            OneLogin_Saml2_Settings
	 * @param request
     *              the HttpRequest object to be processed (Contains GET and POST parameters, request URL, ...).
     *
	 * @throws XMLEntityException 
	 */
	public LogoutRequest(Saml2Settings settings, HttpRequest request) throws XMLEntityException {
		this(settings, request, null, null);
	}

	/**
	 * @return the base64 encoded unsigned Logout Request (deflated or not)
	 *
	 * @param deflated 
     *				If deflated or not the encoded Logout Request
     *
	 * @throws IOException 
	 */
	public String getEncodedLogoutRequest(Boolean deflated) throws IOException {
		String encodedLogoutRequest;
		if (deflated == null) {
			deflated = settings.isCompressRequestEnabled();
		}
		if (deflated) {
			encodedLogoutRequest = Util.deflatedBase64encoded(getLogoutRequestXml());
		} else {
			encodedLogoutRequest = Util.base64encoder(getLogoutRequestXml());
		}
		return encodedLogoutRequest;
	}
	
	/**
	 * @return the base64 encoded unsigned Logout Request (deflated or not)
	 *
	 * @throws IOException 
	 */
	public String getEncodedLogoutRequest() throws IOException {
		return getEncodedLogoutRequest(null);
	}

	/**
	 * @return the plain XML Logout Request
	 */
	public String getLogoutRequestXml() {
		return logoutRequestString;
	}

	/**
	 * Substitutes LogoutRequest variables within a string by values.
	 *
	 * @param settings
	 * 				Saml2Settings object. Setting data
	 * 
	 * @return the StrSubstitutor object of the LogoutRequest 
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

		valueMap.put("issuer", settings.getSpEntityId());

		String nameIdFormat = null;
		String spNameQualifier = null;
		if (nameId != null) {
			if (this.nameIdFormat == null) {
				nameIdFormat = settings.getSpNameIDFormat();
			} else {
				nameIdFormat = this.nameIdFormat;
			}
		} else {
			nameId = settings.getIdpEntityId();
			nameIdFormat = Constants.NAMEID_ENTITY;
			spNameQualifier = settings.getSpEntityId();
		}

		X509Certificate cert = null;
		if (settings.getNameIdEncrypted()) {
			cert = settings.getIdpx509cert();
		}

		String nameIdStr = Util.generateNameId(nameId, spNameQualifier, nameIdFormat, cert);
		valueMap.put("nameIdStr", nameIdStr);

		String sessionIndexStr = "";
		if (sessionIndex != null) {
			sessionIndexStr = " <samlp:SessionIndex>" + sessionIndex + "</samlp:SessionIndex>";
		}
		valueMap.put("sessionIndexStr", sessionIndexStr);

		return new StrSubstitutor(valueMap);
	}

	/**
	 * @return the LogoutRequest's template
	 */
	private static StringBuilder getLogoutRequestTemplate() {
		StringBuilder template = new StringBuilder();
		template.append("<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ");
		template.append("ID=\"${id}\" ");
		template.append("Version=\"2.0\" ");
		template.append("IssueInstant=\"${issueInstant}\"${destinationStr} >");
		template.append("<saml:Issuer>${issuer}</saml:Issuer>");
		template.append("${nameIdStr}${sessionIndexStr}</samlp:LogoutRequest>");
		return template;
	}

	 /**
     * Determines if the SAML LogoutRequest is valid or not
     *
     * @return true if the SAML LogoutRequest is valid
     *
	 * @throws Exception
     */
	public Boolean isValid() throws Exception {
		error = null;

		try {
			if (this.logoutRequestString == null || logoutRequestString.isEmpty()) {
				throw new ValidationError("SAML Logout Request is not loaded", ValidationError.INVALID_XML_FORMAT);
			}

			if (this.request == null) {
				throw new Exception("The HttpRequest of the current host was not established");
			}
			
			if (this.currentUrl == null || this.currentUrl.isEmpty()) {
				throw new Exception("The URL of the current host was not established");
			}

			String signature = request.getParameter("Signature");

			Document logoutRequestDocument = Util.loadXML(logoutRequestString);

			if (settings.isStrict()) {
				Element rootElement = logoutRequestDocument.getDocumentElement();
				rootElement.normalize();				

				if (settings.getWantXMLValidation()) {
					if (!Util.validateXML(logoutRequestDocument, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
						throw new ValidationError("Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd", ValidationError.INVALID_XML_FORMAT);
					}
				}

				// Check NotOnOrAfter
				if (rootElement.hasAttribute("NotOnOrAfter")) {
					String notOnOrAfter = rootElement.getAttribute("NotOnOrAfter");
					DateTime notOnOrAfterDate = Util.parseDateTime(notOnOrAfter);
					if (notOnOrAfterDate.isEqualNow() || notOnOrAfterDate.isBeforeNow()) {
						throw new ValidationError("Could not validate timestamp: expired. Check system clock.", ValidationError.RESPONSE_EXPIRED);
					}
				}

				// Check destination
				if (rootElement.hasAttribute("Destination")) {
					String destinationUrl = rootElement.getAttribute("Destination");
					if (destinationUrl != null) {
						if (!destinationUrl.isEmpty() && !destinationUrl.equals(currentUrl)) {
							throw new ValidationError("The LogoutRequest was received at " + currentUrl + " instead of "
									+ destinationUrl, ValidationError.WRONG_DESTINATION);
						}
					}
				}

				// Try get the nameID
				String nameID = getNameId(logoutRequestDocument, settings.getSPkey());

				// Check the issuer
				String issuer = getIssuer(logoutRequestDocument);
				if (issuer != null && (issuer.isEmpty() || !issuer.equals(settings.getIdpEntityId()))) {
					throw new ValidationError(
							String.format("Invalid issuer in the Logout Request. Was '%s', but expected '%s'", issuer, settings.getIdpEntityId()),
							ValidationError.WRONG_ISSUER
					);
				}

                if (settings.getWantMessagesSigned() && (signature == null || signature.isEmpty())) {
                    throw new ValidationError("The Message of the Logout Request is not signed and the SP requires it", ValidationError.NO_SIGNED_MESSAGE);
                }
			}
                
			if (signature != null && !signature.isEmpty()) {
				X509Certificate cert = settings.getIdpx509cert();
				if (cert == null) {
					throw new SettingsException("In order to validate the sign on the Logout Request, the x509cert of the IdP is required", SettingsException.CERT_NOT_FOUND);
				}

				String signAlg = request.getParameter("SigAlg");
				if (signAlg == null || signAlg.isEmpty()) {
					signAlg = Constants.RSA_SHA1;
				}
				String relayState = request.getEncodedParameter("RelayState");

				String signedQuery = "SAMLRequest=" + request.getEncodedParameter("SAMLRequest");

				if (relayState != null && !relayState.isEmpty()) {
					signedQuery += "&RelayState=" + relayState;
				}

				signedQuery += "&SigAlg=" + request.getEncodedParameter("SigAlg", signAlg);

				if (!Util.validateBinarySignature(signedQuery, Util.base64decoder(signature), cert, signAlg)) {
					throw new ValidationError("Signature validation failed. Logout Request rejected", ValidationError.INVALID_SIGNATURE);
				}
			}
			
			LOGGER.debug("LogoutRequest validated --> " + logoutRequestString);
		    return true;	
		} catch (Exception e) {
			error = e.getMessage();
			LOGGER.debug("LogoutRequest invalid --> " + logoutRequestString);
			LOGGER.error(error);
			return false;
		}
	}

    /**
     * Returns the ID of the Logout Request Document.
     *
	 * @param samlLogoutRequestDocument
	 * 				A DOMDocument object loaded from the SAML Logout Request.
	 *
     * @return the ID of the Logout Request.
     */
	public static String getId(Document samlLogoutRequestDocument) {
		String id = null;
		try {
			Element rootElement = samlLogoutRequestDocument.getDocumentElement();
			rootElement.normalize();
			id = rootElement.getAttribute("ID");
		} catch (Exception e) {}
		return id;
	}

    /**
     * Returns the ID of the Logout Request String.
     *
	 * @param samlLogoutRequestString
	 * 				A Logout Request string.
	 *
     * @return the ID of the Logout Request.
     *
     */
	public static String getId(String samlLogoutRequestString) {
		Document doc = Util.loadXML(samlLogoutRequestString);
		return getId(doc);
	}

	/**
     * Gets the NameID Data from the the Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     * 				A DOMDocument object loaded from the SAML Logout Request.
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     *
     * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
	 * @throws Exception
     */
	public static Map<String, String> getNameIdData(Document samlLogoutRequestDocument, PrivateKey key) throws Exception {
		NodeList encryptedIDNodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:EncryptedID");
		NodeList nameIdNodes;
		Element nameIdElem;
		
		if (encryptedIDNodes.getLength() == 1) {
			if (key == null) {
				throw new SettingsException("Key is required in order to decrypt the NameID", SettingsException.PRIVATE_KEY_NOT_FOUND);
			}

			Element encryptedData = (Element) encryptedIDNodes.item(0);
			Util.decryptElement(encryptedData, key);
			nameIdNodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:NameID");

			if (nameIdNodes == null || nameIdNodes.getLength() != 1) {
				throw new Exception("Not able to decrypt the EncryptedID and get a NameID");
			}
		} 
		else {
			nameIdNodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:NameID");
		}

		if (nameIdNodes != null && nameIdNodes.getLength() == 1) {
			nameIdElem = (Element) nameIdNodes.item(0);
		} else {
			throw new ValidationError("No name id found in Logout Request.", ValidationError.NO_NAMEID);
		}
		
		Map<String, String> nameIdData = new HashMap<String, String>();
		
		if (nameIdElem != null) {
			nameIdData.put("Value", nameIdElem.getTextContent());

			if (nameIdElem.hasAttribute("Format")) {
				nameIdData.put("Format", nameIdElem.getAttribute("Format"));
			}
			if (nameIdElem.hasAttribute("SPNameQualifier")) {
				nameIdData.put("SPNameQualifier", nameIdElem.getAttribute("SPNameQualifier"));
			}
			if (nameIdElem.hasAttribute("NameQualifier")) {
				nameIdData.put("NameQualifier", nameIdElem.getAttribute("NameQualifier"));
			}
		}
		return nameIdData;
	}

	/**
     * Gets the NameID Data from the the Logout Request String.
     *
     * @param samlLogoutRequestString
     * 				A DOMDocument object loaded from the SAML Logout Request.
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     *
     * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
	 * @throws Exception
     */
	public static Map<String, String> getNameIdData(String samlLogoutRequestString, PrivateKey key) throws Exception {
		Document doc = Util.loadXML(samlLogoutRequestString);
		return getNameIdData(doc, key);
	}

	/**
     * Gets the NameID value provided from the SAML Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     * 				A DOMDocument object loaded from the SAML Logout Request.
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     *
     * @return the Name ID value
     *
	 * @throws Exception 
     */
    public static String getNameId(Document samlLogoutRequestDocument, PrivateKey key) throws Exception
    {
    	Map<String, String> nameIdData = getNameIdData(samlLogoutRequestDocument, key);
		LOGGER.debug("LogoutRequest has NameID --> " + nameIdData.get("Value"));
        return nameIdData.get("Value");
    }

	/**
     * Gets the NameID value provided from the SAML Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     * 				A DOMDocument object loaded from the SAML Logout Request.
     *
     * @return the Name ID value
     *
	 * @throws Exception 
     */
    public static String getNameId(Document samlLogoutRequestDocument) throws Exception
    {
    	return  getNameId(samlLogoutRequestDocument, null);
    }
    
	/**
     * Gets the NameID value provided from the SAML Logout Request String.
     *
     * @param samlLogoutRequestString
     * 				A Logout Request string.
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     *
     * @return the Name ID value
     *
	 * @throws Exception
     */
    public static String getNameId(String samlLogoutRequestString, PrivateKey key) throws Exception
    {
    	Map<String, String> nameId =  getNameIdData(samlLogoutRequestString, key);
        return nameId.get("Value");
    }

	/**
     * Gets the NameID value provided from the SAML Logout Request String.
     *
     * @param samlLogoutRequestString
     * 				A Logout Request string.
     *
     * @return the Name ID value
     *
	 * @throws Exception
     */
    public static String getNameId(String samlLogoutRequestString) throws Exception
    {
    	return getNameId(samlLogoutRequestString, null);
    }
    
	/**
	 * Gets the Issuer from Logout Request Document.
	 * 
	 * @param samlLogoutRequestDocument 
	 * 				A DOMDocument object loaded from the SAML Logout Request.
	 *
	 * @return the issuer of the logout request
	 *
	 * @throws XPathExpressionException
	 */
    public static String getIssuer(Document samlLogoutRequestDocument) throws XPathExpressionException
    {
        String issuer = null;

        NodeList nodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:Issuer");

        if (nodes.getLength() == 1) {
			issuer = nodes.item(0).getTextContent();
		}

        return issuer;
    }

	/**
	 * Gets the Issuer from Logout Request String.
	 * 
	 * @param samlLogoutRequestString 
	 * 				A Logout Request string.
	 *
	 * @return the issuer of the logout request
	 * 
	 * @throws XPathExpressionException
	 */
    public static String getIssuer(String samlLogoutRequestString) throws XPathExpressionException
    {
		Document doc = Util.loadXML(samlLogoutRequestString);
		return getIssuer(doc);
    }

    /**
     * Gets the SessionIndexes from the LogoutRequest.
	 * 
	 * @param samlLogoutRequestDocument 
	 * 				A DOMDocument object loaded from the SAML Logout Request.
     * @return the SessionIndexes
     *
     * @throws XPathExpressionException 
     */
    public static List<String> getSessionIndexes(Document samlLogoutRequestDocument) throws XPathExpressionException
    {
        List<String> sessionIndexes = new ArrayList<String>(); 

        NodeList nodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/samlp:SessionIndex");

        for (int i = 0; i < nodes.getLength(); i++) {
        	sessionIndexes.add(nodes.item(i).getTextContent());
        }

        return sessionIndexes;
    }

    /**
     * Gets the SessionIndexes from the LogoutRequest.
	 * 
	 * @param samlLogoutRequestString 
	 * 				A Logout Request string.
     * @return the SessionIndexes
     *
     * @throws XPathExpressionException 
     */
    public static List<String> getSessionIndexes(String samlLogoutRequestString) throws XPathExpressionException
    {
		Document doc = Util.loadXML(samlLogoutRequestString);
		return getSessionIndexes(doc);
    }

	/**
     * After execute a validation process, if fails this method returns the cause
     *
     * @return the cause of the validation error 
     */
	public String getError() {
		return error;
	}

	/**
	 * @return the ID of the Logout Request
	 */
	public String getId()
	{
		return id;
	}
}
