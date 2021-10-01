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
	private Exception validationException;

	/**
	 * Constructs the LogoutRequest object.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param request
	 *              the HttpRequest object to be processed (Contains GET and POST
	 *              parameters, request URL, ...).
	 * @param nameId
	 *              The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex
	 *              The SessionIndex (taken from the SAML Response in the SSO
	 *              process).
	 * @param nameIdFormat
	 *              The nameIdFormat that will be set in the LogoutRequest.
	 * @param nameIdNameQualifier
	 *              The NameID NameQualifier that will be set in the LogoutRequest.
	 * @param nameIdSPNameQualifier
	 *              The SP Name Qualifier that will be set in the LogoutRequest.
	 *
	 * @deprecated use {@link #LogoutRequest(Saml2Settings, HttpRequest)} to build a
	 *             received request from the HTTP request, or
	 *             {@link #LogoutRequest(Saml2Settings, LogoutRequestParams)} with
	 *             {@link LogoutRequestParams#LogoutRequestParams(String, String, String, String, String)}
	 *             to build a new request to be sent
	 */
	@Deprecated
	public LogoutRequest(Saml2Settings settings, HttpRequest request, String nameId, String sessionIndex, String nameIdFormat, String nameIdNameQualifier, String nameIdSPNameQualifier) {
		this.settings = settings;
		this.request = request;
	
		String samlLogoutRequest = null;
	
		if (request != null) {
			samlLogoutRequest = request.getParameter("SAMLRequest");
			currentUrl = request.getRequestURL();
		}
	
		if (samlLogoutRequest == null) {
			LogoutRequestParams params = new LogoutRequestParams(sessionIndex, nameId, nameIdFormat, nameIdNameQualifier, nameIdSPNameQualifier);
			id = Util.generateUniqueID(settings.getUniqueIDPrefix());
			issueInstant = Calendar.getInstance();
	
			StrSubstitutor substitutor = generateSubstitutor(params, settings);
			logoutRequestString = postProcessXml(substitutor.replace(getLogoutRequestTemplate()), params, settings);
		} else {
			logoutRequestString = Util.base64decodedInflated(samlLogoutRequest);
			Document doc = Util.loadXML(logoutRequestString);
			id = getId(doc);
			issueInstant = getIssueInstant(doc);
		}
	}

	/**
	 * Constructs the LogoutRequest object.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param request
	 *              the HttpRequest object to be processed (Contains GET and POST
	 *              parameters, request URL, ...).
	 * @param nameId
	 *              The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex
	 *              The SessionIndex (taken from the SAML Response in the SSO
	 *              process).
	 * @param nameIdFormat
	 *              The nameIdFormat that will be set in the LogoutRequest.
	 * @param nameIdNameQualifier
	 *              The NameID NameQualifier will be set in the LogoutRequest.
	 *
	 * @deprecated use {@link #LogoutRequest(Saml2Settings, HttpRequest)} to build a
	 *             received request from the HTTP request, or
	 *             {@link #LogoutRequest(Saml2Settings, LogoutRequestParams)} with
	 *             {@link LogoutRequestParams#LogoutRequestParams(String, String, String, String)}
	 *             to build a new request to be sent
	 */
	@Deprecated
	public LogoutRequest(Saml2Settings settings, HttpRequest request, String nameId, String sessionIndex, String nameIdFormat, String nameIdNameQualifier) {
		this(settings, request, nameId, sessionIndex, nameIdFormat, nameIdNameQualifier, null);
	}

	/**
	 * Constructs the LogoutRequest object.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param request
	 *              the HttpRequest object to be processed (Contains GET and POST
	 *              parameters, request URL, ...).
	 * @param nameId
	 *              The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex
	 *              The SessionIndex (taken from the SAML Response in the SSO
	 *              process).
	 * @param nameIdFormat
	 *              The nameIdFormat that will be set in the LogoutRequest.
	 *
	 * @deprecated use {@link #LogoutRequest(Saml2Settings, HttpRequest)} to build a
	 *             received request from the HTTP request, or
	 *             {@link #LogoutRequest(Saml2Settings, LogoutRequestParams)} with
	 *             {@link LogoutRequestParams#LogoutRequestParams(String, String, String)}
	 *             to build a new request to be sent
	 */
	@Deprecated
	public LogoutRequest(Saml2Settings settings, HttpRequest request, String nameId, String sessionIndex, String nameIdFormat) {
		this(settings, request, nameId, sessionIndex, nameIdFormat, null);
	}

	/**
	 * Constructs the LogoutRequest object.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param request
	 *              the HttpRequest object to be processed (Contains GET and POST
	 *              parameters, request URL, ...).
	 * @param nameId
	 *              The NameID that will be set in the LogoutRequest.
	 * @param sessionIndex
	 *              The SessionIndex (taken from the SAML Response in the SSO
	 *              process).
	 *
	 * @deprecated use {@link #LogoutRequest(Saml2Settings, HttpRequest)} to build a
	 *             received request from the HTTP request, or
	 *             {@link #LogoutRequest(Saml2Settings, LogoutRequestParams)} with
	 *             {@link LogoutRequestParams#LogoutRequestParams(String, String)}
	 *             to build a new request to be sent
	 */
	@Deprecated
	public LogoutRequest(Saml2Settings settings, HttpRequest request, String nameId, String sessionIndex) {
		this(settings, request, nameId, sessionIndex, null);
	}

	/**
	 * Constructs a LogoutRequest object when a new request should be generated and
	 * sent.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 *
	 * @see #LogoutRequest(Saml2Settings, LogoutRequestParams)
	 */
	public LogoutRequest(Saml2Settings settings) {
		this(settings, new LogoutRequestParams());
	}

	/**
	 * Constructs the LogoutRequest object when a received request should be
	 * extracted from the HTTP request and parsed.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param request
	 *              the HttpRequest object to be processed (Contains GET and POST
	 *              parameters, request URL, ...).
	 */
	public LogoutRequest(Saml2Settings settings, HttpRequest request) {
		this(settings, request, null, null);
	}

	/**
	 * Constructs the LogoutRequest object when a new request should be generated
	 * and sent.
	 *
	 * @param settings
	 *              OneLogin_Saml2_Settings
	 * @param params
	 *              a set of logout request input parameters that shape the
	 *              request to create
	 */
	public LogoutRequest(Saml2Settings settings, LogoutRequestParams params) {
		this.settings = settings;
		this.request = null;
		id = Util.generateUniqueID(settings.getUniqueIDPrefix());
		issueInstant = Calendar.getInstance();

		StrSubstitutor substitutor = generateSubstitutor(params, settings);
		logoutRequestString = postProcessXml(substitutor.replace(getLogoutRequestTemplate()), params, settings);
	}

	/**
	 * Allows for an extension class to post-process the LogoutRequest XML generated
	 * for this request, in order to customize the result.
	 * <p>
	 * This method is invoked at construction time when no existing LogoutRequest
	 * message is found in the HTTP request (and hence in the logout request sending
	 * scenario only), after all the other fields of this class have already been
	 * initialised. Its default implementation simply returns the input XML as-is,
	 * with no change.
	 * 
	 * @param logoutRequestXml
	 *              the XML produced for this LogoutRequest by the standard
	 *              implementation provided by {@link LogoutRequest}
	 * @param params
	 *              the logout request input parameters
	 * @param settings
	 *              the settings
	 * @return the post-processed XML for this LogoutRequest, which will then be
	 *         returned by any call to {@link #getLogoutRequestXml()}
	 */
	protected String postProcessXml(final String logoutRequestXml, final LogoutRequestParams params, final Saml2Settings settings) {
		return logoutRequestXml;
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
	 * @param params
	 *              the logout request input parameters
	 * @param settings
	 *              Saml2Settings object. Setting data
	 * 
	 * @return the StrSubstitutor object of the LogoutRequest
	 */
	private StrSubstitutor generateSubstitutor(LogoutRequestParams params, Saml2Settings settings) {
		Map<String, String> valueMap = new HashMap<String, String>();

		valueMap.put("id", Util.toXml(id));		

		String issueInstantString = Util.formatDateTime(issueInstant.getTimeInMillis());
		valueMap.put("issueInstant", issueInstantString);

		String destinationStr = "";
		URL slo =  settings.getIdpSingleLogoutServiceUrl();
		if (slo != null) {
			destinationStr = " Destination=\"" + Util.toXml(slo.toString()) + "\"";
		}
		valueMap.put("destinationStr", destinationStr);

		valueMap.put("issuer", Util.toXml(settings.getSpEntityId()));

		String nameId = params.getNameId();
		String requestedNameIdFormat = params.getNameIdFormat();
		String nameIdFormat = null;
		String spNameQualifier = params.getNameIdSPNameQualifier();
		String nameQualifier = params.getNameIdNameQualifier();
		if (nameId != null) {
			if (requestedNameIdFormat == null && !settings.getSpNameIDFormat().equals(Constants.NAMEID_UNSPECIFIED)) {
				nameIdFormat = settings.getSpNameIDFormat();
			} else {
				nameIdFormat = requestedNameIdFormat;
			}
		} else {
			nameId = settings.getIdpEntityId();
			nameIdFormat = Constants.NAMEID_ENTITY;			
		}

		// From saml-core-2.0-os 8.3.6, when the entity Format is used: "The NameQualifier, SPNameQualifier, and
        // SPProvidedID attributes MUST be omitted.		
		if (nameIdFormat != null && nameIdFormat.equals(Constants.NAMEID_ENTITY)) {
			nameQualifier = null;
			spNameQualifier = null;
		}

		// NameID Format UNSPECIFIED omitted
		if (nameIdFormat != null && nameIdFormat.equals(Constants.NAMEID_UNSPECIFIED)) {
			nameIdFormat = null;
		}

		X509Certificate cert = null;
		if (settings.getNameIdEncrypted()) {
			cert = settings.getIdpx509cert();
			if (cert == null) {
				List<X509Certificate> multipleCertList = settings.getIdpx509certMulti();
				if (multipleCertList != null && !multipleCertList.isEmpty())
				cert = multipleCertList.get(0);
			}
		}

		String nameIdStr = Util.generateNameId(nameId, spNameQualifier, nameIdFormat, nameQualifier, cert);
		valueMap.put("nameIdStr", nameIdStr);

		String sessionIndexStr = "";
		String sessionIndex = params.getSessionIndex();
		if (sessionIndex != null) {
			sessionIndexStr = " <samlp:SessionIndex>" + Util.toXml(sessionIndex) + "</samlp:SessionIndex>";
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
       */
	public Boolean isValid() {
		validationException = null;

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
				String nameID = getNameId(logoutRequestDocument, settings.getSPkey(), settings.isTrimNameIds());

				// Check the issuer
				String issuer = getIssuer(logoutRequestDocument, settings.isTrimNameIds());
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
				
				List<X509Certificate> certList = new ArrayList<X509Certificate>();
				List<X509Certificate> multipleCertList = settings.getIdpx509certMulti();

				if (multipleCertList != null && multipleCertList.size() != 0) {
					certList.addAll(multipleCertList);
				}

				if (cert != null) {
					if (certList.isEmpty() || !certList.contains(cert)) {
						certList.add(0, cert);
					}
				}

				if (certList.isEmpty()) {
					throw new SettingsException("In order to validate the sign on the Logout Request, the x509cert of the IdP is required", SettingsException.CERT_NOT_FOUND);
				}

				String signAlg = request.getParameter("SigAlg");
				if (signAlg == null || signAlg.isEmpty()) {
					signAlg = Constants.RSA_SHA1;
				}

				Boolean rejectDeprecatedAlg = settings.getRejectDeprecatedAlg();
				if (Util.mustRejectDeprecatedSignatureAlgo(signAlg, rejectDeprecatedAlg)) {
					return false;
				}

				String relayState = request.getEncodedParameter("RelayState");

				String signedQuery = "SAMLRequest=" + request.getEncodedParameter("SAMLRequest");

				if (relayState != null && !relayState.isEmpty()) {
					signedQuery += "&RelayState=" + relayState;
				}

				signedQuery += "&SigAlg=" + request.getEncodedParameter("SigAlg", signAlg);

				if (!Util.validateBinarySignature(signedQuery, Util.base64decoder(signature), certList, signAlg)) {
					throw new ValidationError("Signature validation failed. Logout Request rejected", ValidationError.INVALID_SIGNATURE);
				}
			}
			
			LOGGER.debug("LogoutRequest validated --> " + logoutRequestString);
		    return true;	
		} catch (Exception e) {
			validationException = e;
			LOGGER.debug("LogoutRequest invalid --> " + logoutRequestString);
			LOGGER.error(validationException.getMessage());
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
       * Returns the issue instant of the Logout Request Document.
       *
       * @param samlLogoutRequestDocument
       * 				A DOMDocument object loaded from the SAML Logout Request.
       *
       * @return the issue instant of the Logout Request.
       */
	public static Calendar getIssueInstant(Document samlLogoutRequestDocument) {
		Calendar issueInstant = null;
		try {
			Element rootElement = samlLogoutRequestDocument.getDocumentElement();
			rootElement.normalize();
			String issueInstantString = rootElement.hasAttribute(
					"IssueInstant")? rootElement.getAttribute("IssueInstant"): null;
			if(issueInstantString == null)
				return null;
			issueInstant = Calendar.getInstance();
			issueInstant.setTimeInMillis(Util.parseDateTime(issueInstantString).getMillis());
		} catch (Exception e) {}
		return issueInstant;
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
       * Returns the issue instant of the Logout Request Document.
       *
       * @param samlLogoutRequestDocument
       * 				A DOMDocument object loaded from the SAML Logout Request.
       *
       * @return the issue instant of the Logout Request.
       */
	public static Calendar getIssueInstant(String samlLogoutRequestString) {
		Document doc = Util.loadXML(samlLogoutRequestString);
		return getIssueInstant(doc);
	}

	/**
	 * Gets the NameID Data from the the Logout Request Document.
	 *
	 * @param samlLogoutRequestDocument
	 *              A DOMDocument object loaded from the SAML Logout Request.
	 * @param key
	 *              The SP key to decrypt the NameID if encrypted
	 *
	 * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
	 *
	 * @throws Exception
	 */
	public static Map<String, String> getNameIdData(Document samlLogoutRequestDocument, PrivateKey key) throws Exception {
		return getNameIdData(samlLogoutRequestDocument, key, false);
	}
	
	/**
	 * Gets the NameID Data from the the Logout Request Document.
	 *
	 * @param samlLogoutRequestDocument
	 *              A DOMDocument object loaded from the SAML Logout Request.
	 * @param key
	 *              The SP key to decrypt the NameID if encrypted
	 * @param trimValue
	 *              whether the extracted Name ID value should be trimmed
	 *
	 * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
	 *
	 * @throws Exception
	 */
	public static Map<String, String> getNameIdData(Document samlLogoutRequestDocument, PrivateKey key, boolean trimValue) throws Exception {
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
			String value = nameIdElem.getTextContent();
			if(value != null && trimValue) {
				value = value.trim();
			}
			nameIdData.put("Value", value);

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
	 *              A DOMDocument object loaded from the SAML Logout Request.
	 * @param key
	 *              The SP key to decrypt the NameID if encrypted
	 *
	 * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
	 *
	 * @throws Exception
	 */
	public static Map<String, String> getNameIdData(String samlLogoutRequestString, PrivateKey key) throws Exception {
		return getNameIdData(samlLogoutRequestString, key, false);
	}

	/**
	 * Gets the NameID Data from the the Logout Request String.
	 *
	 * @param samlLogoutRequestString
	 *              A DOMDocument object loaded from the SAML Logout Request.
	 * @param key
	 *              The SP key to decrypt the NameID if encrypted
	 * @param trimValue
	 *              whether the extracted Name ID value should be trimmed
	 *
	 * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
	 *
	 * @throws Exception
	 */
	public static Map<String, String> getNameIdData(String samlLogoutRequestString, PrivateKey key, boolean trimValue) throws Exception {
		Document doc = Util.loadXML(samlLogoutRequestString);
		return getNameIdData(doc, key, trimValue);
	}

	/**
	 * Gets the NameID value provided from the SAML Logout Request Document.
	 *
	 * @param samlLogoutRequestDocument
	 *              A DOMDocument object loaded from the SAML Logout Request.
	 * 
	 * @param key
	 *              The SP key to decrypt the NameID if encrypted
	 * 
	 * @return the Name ID value
	 *
	 * @throws Exception
	 */
	public static String getNameId(Document samlLogoutRequestDocument, PrivateKey key) throws Exception {
		return getNameId(samlLogoutRequestDocument, key, false);
	}

	/**
	 * Gets the NameID value provided from the SAML Logout Request Document.
	 *
	 * @param samlLogoutRequestDocument
	 *              A DOMDocument object loaded from the SAML Logout Request.
	 * 
	 * @param key
	 *              The SP key to decrypt the NameID if encrypted
	 * 
	 * @param trimValue
	 *              whether the extracted Name ID value should be trimmed
	 *
	 * @return the Name ID value
	 *
	 * @throws Exception
	 */
	public static String getNameId(Document samlLogoutRequestDocument, PrivateKey key, boolean trimValue)
	            throws Exception {
		Map<String, String> nameIdData = getNameIdData(samlLogoutRequestDocument, key, trimValue);
		LOGGER.debug("LogoutRequest has NameID --> " + nameIdData.get("Value"));
		return nameIdData.get("Value");
	}

	/**
	 * Gets the NameID value provided from the SAML Logout Request Document.
	 *
	 * @param samlLogoutRequestDocument
	 *              A DOMDocument object loaded from the SAML Logout Request.
	 *
	 * @return the Name ID value
	 *
	 * @throws Exception
	 */
	public static String getNameId(Document samlLogoutRequestDocument) throws Exception {
		return getNameId(samlLogoutRequestDocument, null);
	}
    
	/**
	 * Gets the NameID value provided from the SAML Logout Request String.
	 *
	 * @param samlLogoutRequestString
	 *              A Logout Request string.
	 * @param key
	 *              The SP key to decrypt the NameID if encrypted
	 *
	 * @return the Name ID value
	 *
	 * @throws Exception
	 */
	public static String getNameId(String samlLogoutRequestString, PrivateKey key) throws Exception {
		return getNameId(samlLogoutRequestString, key, false);
	}

	/**
	 * Gets the NameID value provided from the SAML Logout Request String.
	 *
	 * @param samlLogoutRequestString
	 *              A Logout Request string.
	 * @param key
	 *              The SP key to decrypt the NameID if encrypted
	 * @param trimValue
	 *              whether the extracted Name ID value should be trimmed
	 *
	 * @return the Name ID value
	 *
	 * @throws Exception
	 */
	public static String getNameId(String samlLogoutRequestString, PrivateKey key, boolean trimValue)
	            throws Exception {
		Map<String, String> nameId = getNameIdData(samlLogoutRequestString, key, trimValue);
		return nameId.get("Value");
	}

	/**
	 * Gets the NameID value provided from the SAML Logout Request String.
	 *
	 * @param samlLogoutRequestString
	 *              A Logout Request string.
	 *
	 * @return the Name ID value
	 *
	 * @throws Exception
	 */
	public static String getNameId(String samlLogoutRequestString) throws Exception {
		return getNameId(samlLogoutRequestString, null);
	}
    
    /**
     * Gets the Issuer from Logout Request Document.
     * 
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     *
     * @return the issuer of the logout request
     *
     * @throws XPathExpressionException
     */
    public static String getIssuer(Document samlLogoutRequestDocument) throws XPathExpressionException {
	    return getIssuer(samlLogoutRequestDocument, false);
    }

    /**
     * Gets the Issuer from Logout Request Document.
     * 
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     * @param trim
     *              whether the extracted issuer value should be trimmed
     *
     * @return the issuer of the logout request
     *
     * @throws XPathExpressionException
     */
    public static String getIssuer(Document samlLogoutRequestDocument, boolean trim) throws XPathExpressionException {
	    String issuer = null;

	    NodeList nodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:Issuer");

	    if (nodes.getLength() == 1) {
		    issuer = nodes.item(0).getTextContent();
	    }
	    if (issuer != null && trim) {
		    issuer = issuer.trim();
	    }
	    return issuer;
    }

    /**
     * Gets the Issuer from Logout Request String.
     * 
     * @param samlLogoutRequestString
     *              A Logout Request string.
     *
     * @return the issuer of the logout request
     * 
     * @throws XPathExpressionException
     */
    public static String getIssuer(String samlLogoutRequestString) throws XPathExpressionException {
	    return getIssuer(samlLogoutRequestString, false);
    }

    /**
     * Gets the Issuer from Logout Request String.
     * 
     * @param samlLogoutRequestString
     *              A Logout Request string.
     * @param trim
     *              whether the extracted issuer value should be trimmed
     *
     * @return the issuer of the logout request
     * 
     * @throws XPathExpressionException
     */
    public static String getIssuer(String samlLogoutRequestString, boolean trim) throws XPathExpressionException {
	    Document doc = Util.loadXML(samlLogoutRequestString);
	    return getIssuer(doc, trim);
    }


    /**
     * Gets the SessionIndexes from the LogoutRequest.
     * 
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     * @return the SessionIndexes
     *
     * @throws XPathExpressionException
     */
    public static List<String> getSessionIndexes(Document samlLogoutRequestDocument) throws XPathExpressionException {
	    return getSessionIndexes(samlLogoutRequestDocument, false);
    }

    /**
     * Gets the SessionIndexes from the LogoutRequest.
     * 
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     * @param trim
     *              whether the extracted session indexes should be trimmed
     * @return the SessionIndexes
     *
     * @throws XPathExpressionException
     */
    public static List<String> getSessionIndexes(Document samlLogoutRequestDocument, boolean trim)
                throws XPathExpressionException {
	    List<String> sessionIndexes = new ArrayList<String>();

	    NodeList nodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/samlp:SessionIndex");

	    for (int i = 0; i < nodes.getLength(); i++) {
		    String sessionIndex = nodes.item(i).getTextContent();
		    if (sessionIndex != null) {
			    if (trim) {
				    sessionIndex = sessionIndex.trim();
			    }
			    sessionIndexes.add(sessionIndex);
		    }
	    }

	    return sessionIndexes;
    }

    /**
     * Gets the SessionIndexes from the LogoutRequest.
     * 
     * @param samlLogoutRequestString
     *              A Logout Request string.
     * @return the SessionIndexes
     *
     * @throws XPathExpressionException
     */
    public static List<String> getSessionIndexes(String samlLogoutRequestString) throws XPathExpressionException {
	    return getSessionIndexes(samlLogoutRequestString, false);
    }

    /**
     * Gets the SessionIndexes from the LogoutRequest.
     * 
     * @param samlLogoutRequestString
     *              A Logout Request string.
     * @param trim
     *              whether the extracted session indexes should be trimmed
     * @return the SessionIndexes
     *
     * @throws XPathExpressionException
     */
    public static List<String> getSessionIndexes(String samlLogoutRequestString, boolean trim)
                throws XPathExpressionException {
	    Document doc = Util.loadXML(samlLogoutRequestString);
	    return getSessionIndexes(doc, trim);
    }

	/**
     * After execute a validation process, if fails this method returns the cause
     *
     * @return the cause of the validation error 
     */
	public String getError() {
		if (validationException != null) {
			return validationException.getMessage();
		}
		return null;
	}

	/**
	 * After execute a validation process, if fails this method returns the Exception object
	 *
	 * @return the cause of the validation error
	 */
	public Exception getValidationException() {
		return validationException;
	}

	/**
	 * Sets the validation exception that this {@link LogoutRequest} should return
	 * when a validation error occurs.
	 * 
	 * @param validationException
	 *              the validation exception to set
	 */
	protected void setValidationException(Exception validationException) {
		this.validationException = validationException;
	}

	/**
	 * @return the ID of the Logout Request
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
