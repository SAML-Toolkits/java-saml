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

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.lang3.text.StrSubstitutor;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.onelogin.saml2.exception.XMLEntityException;
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
     * HttpServletRequest object to be processed (Contains GET and POST parameters, session, ...).
     */
	private HttpServletRequest request;

	/**
     * NameID.
     */	
	private String nameId;
	
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
     *              HttpServletRequest object to be processed (Contains GET and POST parameters, session, ...).
	 * @param nameId
	 *              The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex
	 *              The SessionIndex (taken from the SAML Response in the SSO process).
	 *
	 * @throws XMLEntityException 
	 */
	public LogoutRequest(Saml2Settings settings, HttpServletRequest request, String nameId, String sessionIndex) throws XMLEntityException {
		this.settings = settings;
		this.request = request;

		String samlLogoutRequest = null;

		if (request != null) {
			samlLogoutRequest = request.getParameter("SAMLRequest");
			currentUrl = request.getRequestURL().toString();
		}

		if (samlLogoutRequest == null) {
			id = Util.generateUniqueID();
			issueInstant = Calendar.getInstance();
			this.nameId = nameId;
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
     *              HttpServletRequest object to be processed (Contains GET and POST parameters, session, ...).
     *
	 * @throws XMLEntityException 
	 */
	public LogoutRequest(Saml2Settings settings, HttpServletRequest request) throws XMLEntityException {
		this(settings, request, null, null);
	}

	/**
	 * @return the deflated base64 encoded unsigned Logout Request
	 *
	 * @throws IOException 
	 */
	public String getEncodedLogoutRequest() throws IOException {
		return Util.deflatedBase64encoded(getLogoutRequestXml());
	}

	/**
	 * @return the plain XML Logout Request
	 */
	protected String getLogoutRequestXml() {
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
			nameIdFormat = settings.getSpNameIDFormat();
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
	 * @throws XMLEntityException 
     */
	public Boolean isValid() throws XMLEntityException {
		error = null;

		try {
			if (this.logoutRequestString == null || logoutRequestString.isEmpty()) {
				throw new Exception("SAML Logout Request is not loaded");
			}

			if (this.request == null) {
				throw new Exception("The HttpServletRequest of the current host was not established");
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
						throw new Exception("Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd");
					}
				}

				// Check NotOnOrAfter
				if (rootElement.hasAttribute("NotOnOrAfter")) {
					String notOnOrAfter = rootElement.getAttribute("NotOnOrAfter");
					DateTime notOnOrAfterDate = Util.parseDateTime(notOnOrAfter);
					if (notOnOrAfterDate.isEqualNow() || notOnOrAfterDate.isBeforeNow()) {
						throw new Exception("Timing issues (please check your clock settings)");
					}
				}

				// Check destination
				if (rootElement.hasAttribute("Destination")) {
					String destinationUrl = rootElement.getAttribute("Destination");
					if (destinationUrl != null) {
						if (!destinationUrl.isEmpty() && !destinationUrl.equals(currentUrl)) {
							throw new Exception("The LogoutRequest was received at " + currentUrl + " instead of "
									+ destinationUrl);
						}
					}
				}

				// Try get the nameID
				String nameID = getNameId(logoutRequestDocument, settings.getSPkey());

				// Check the issuer
				String issuer = getIssuer(logoutRequestDocument);
				if (issuer != null && (issuer.isEmpty() || !issuer.equals(settings.getIdpEntityId()))) {
					throw new Exception("Invalid issuer in the Logout Request");
				}

                if (settings.getWantMessagesSigned() && (signature == null || signature.isEmpty())) {
                    throw new Exception("The Message of the Logout Request is not signed and the SP requires it");
                }
			}
                
			if (signature != null && !signature.isEmpty()) {
				X509Certificate cert = settings.getIdpx509cert();
				if (cert == null) {
					throw new Exception("In order to validate the sign on the Logout Request, the x509cert of the IdP is required");
				}

				String signAlg = request.getParameter("SigAlg");
				if (signAlg == null || signAlg.isEmpty()) {
					signAlg = Constants.RSA_SHA1;
				}
				String relayState = request.getParameter("RelayState");

				String signedQuery = "SAMLRequest=" + Util.urlEncoder(request.getParameter("SAMLRequest"));

				if (relayState != null && !relayState.isEmpty()) {
					signedQuery += "&RelayState=" + Util.urlEncoder(relayState);
				}

				signedQuery += "&SigAlg=" + Util.urlEncoder(signAlg);

				if (!Util.validateBinarySignature(signedQuery, Util.base64decoder(signature), cert, signAlg)) {
					throw new Exception("Signature validation failed. Logout Request rejected");
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
     * @throws XMLEntityException 
     */
	public static String getId(String samlLogoutRequestString) throws XMLEntityException {
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
     * @throws IllegalArgumentException
	 * @throws Exception
     */
	public static Map<String, String> getNameIdData(Document samlLogoutRequestDocument, PrivateKey key) throws IllegalArgumentException, Exception {
		NodeList encryptedIDNodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:EncryptedID");
		NodeList nameIdNodes;
		Element nameIdElem;
		
		if (encryptedIDNodes.getLength() > 0) {
			if (key == null) {
				throw new IllegalArgumentException("Key is required in order to decrypt the NameID");
			}

			Element encryptedData = (Element) encryptedIDNodes.item(0);
			Util.decryptElement(encryptedData, key);
			nameIdNodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:NameID");

			if (nameIdNodes == null || nameIdNodes.getLength() == 0) {
				throw new Exception("Not able to decrypt the EncryptedID and get a NameID");
			}
		} 
		else {
			nameIdNodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:NameID");
		}

		if (nameIdNodes != null && nameIdNodes.getLength() > 0) {
			nameIdElem = (Element) nameIdNodes.item(0);
		} else {
			throw new Exception("No name id found in Logout Request.");
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
	 * @throws IllegalArgumentException if PrivateKey is not provided and the NameId is encrypted
	 * @throws Exception
     */
	public static Map<String, String> getNameIdData(String samlLogoutRequestString, PrivateKey key) throws IllegalArgumentException, Exception {
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
	 * @throws XMLEntityException
	 * @throws XPathExpressionException
	 */
    public static String getIssuer(String samlLogoutRequestString) throws XMLEntityException, XPathExpressionException
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
     * @throws XMLEntityException
     * @throws XPathExpressionException 
     */
    public static List<String> getSessionIndexes(String samlLogoutRequestString) throws XMLEntityException, XPathExpressionException
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
	 * @return the generated id of the LogoutRequest message
	 */
	public String getId()
	{
		return id;
	}
}
