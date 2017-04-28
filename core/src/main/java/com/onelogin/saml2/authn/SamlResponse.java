package com.onelogin.saml2.authn;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.model.SamlResponseStatus;
import com.onelogin.saml2.model.SubjectConfirmationIssue;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.SchemaFactory;
import com.onelogin.saml2.util.Util;

import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.ValidationError;

/**
 * SamlResponse class of OneLogin's Java Toolkit.
 *
 * A class that implements SAML 2 Authentication Response parser/validator
 */
public class SamlResponse {
	/**
     * Private property to construct a logger for this class.
     */
	private static final Logger LOGGER = LoggerFactory.getLogger(SamlResponse.class);

	/**
     * Settings data.
     */
	private final Saml2Settings settings;

	/**
     * The decoded, unprocessed XML response provided to the constructor.
     */
	private String samlResponseString;

	/**
	 * A DOMDocument object loaded from the SAML Response.
	 */
	private Document samlResponseDocument;

	/**
	 * A DOMDocument object loaded from the SAML Response (Decrypted).
	 */
	private Document decryptedDocument;

	/**
	 * URL of the current host + current view
	 */
	private String currentUrl;

	/**
	 * Mark if the response contains an encrypted assertion.
	 */
	private Boolean encrypted = false;

	/**
	 * After validation, if it fails this property has the cause of the problem
	 */ 
	private String error;

	/**
	 * Constructor to have a Response object full builded and ready to validate
	 * the saml response
	 *
	 * @param settings
	 *              Saml2Settings object. Setting data
	 * @param request
	 *				the HttpRequest object to be processed (Contains GET and POST parameters, request URL, ...).
	 *
	 * @throws ValidationError
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws XPathExpressionException
     *
	 */
	public SamlResponse(Saml2Settings settings, HttpRequest request) throws XPathExpressionException, ParserConfigurationException, SAXException, IOException, SettingsException, ValidationError {
		this.settings = settings;

		if (request != null) {
			currentUrl = request.getRequestURL();
			loadXmlFromBase64(request.getParameter("SAMLResponse"));
		}
	}

	/**
	 * Load a XML base64encoded SAMLResponse
	 *
	 * @param responseStr
	 *              Saml2Settings object. Setting data
	 *
	 * @throws ParserConfigurationException
	 * @throws SettingsException
	 * @throws IOException
	 * @throws SAXException
	 * @throws XPathExpressionException
	 * @throws ValidationError
	 */
	public void loadXmlFromBase64(String responseStr) throws ParserConfigurationException, XPathExpressionException, SAXException, IOException, SettingsException, ValidationError {
		samlResponseString = new String(Util.base64decoder(responseStr), "UTF-8");
		samlResponseDocument = Util.loadXML(samlResponseString);

		if (samlResponseDocument == null) {
			throw new ValidationError("SAML Response could not be processed", ValidationError.INVALID_XML_FORMAT);
		}

		NodeList encryptedAssertionNodes = samlResponseDocument.getElementsByTagNameNS(Constants.NS_SAML,"EncryptedAssertion");

		if (encryptedAssertionNodes.getLength() != 0) {			
			decryptedDocument = Util.copyDocument(samlResponseDocument);
			encrypted = true;
			decryptedDocument = this.decryptAssertion(decryptedDocument);
		}
	}

	/**
	 * Determines if the SAML Response is valid using the certificate.
	 *
	 * @param requestId The ID of the AuthNRequest sent by this SP to the IdP
	 * 
	 * @return if the response is valid or not
	 */
	public boolean isValid(String requestId) {
		error = null;

		try {
			if (samlResponseDocument == null) {
				throw new Exception("SAML Response is not loaded");
			}

			if (this.currentUrl == null || this.currentUrl.isEmpty()) {
				throw new Exception("The URL of the current host was not established");
			}

			Element rootElement = samlResponseDocument.getDocumentElement();
			rootElement.normalize();

			// Check SAML version
			if (!rootElement.getAttribute("Version").equals("2.0")) {
				throw new ValidationError("Unsupported SAML Version.", ValidationError.UNSUPPORTED_SAML_VERSION);
			}

			// Check ID in the response
			if (!rootElement.hasAttribute("ID")) {
				throw new ValidationError("Missing ID attribute on SAML Response.", ValidationError.MISSING_ID);
			}

			this.checkStatus();

			if (!this.validateNumAssertions()) {
				throw new ValidationError("SAML Response must contain 1 Assertion.", ValidationError.WRONG_NUMBER_OF_ASSERTIONS);
			}

			ArrayList<String> signedElements = processSignedElements();

			String responseTag = "{" + Constants.NS_SAMLP  + "}Response";
			String assertionTag = "{" + Constants.NS_SAML + "}Assertion";

			final boolean hasSignedResponse = signedElements.contains(responseTag);
			final boolean hasSignedAssertion = signedElements.contains(assertionTag);

			if (settings.isStrict()) {
				if (settings.getWantXMLValidation()) {
					if (!Util.validateXML(samlResponseDocument, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
						throw new ValidationError("Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd", ValidationError.INVALID_XML_FORMAT);
					}

					// If encrypted, check also the decrypted document
					if (encrypted) {
						if (!Util.validateXML(decryptedDocument, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
							throw new ValidationError("Invalid decrypted SAML Response. Not match the saml-schema-protocol-2.0.xsd", ValidationError.INVALID_XML_FORMAT);
						}
					}
				}

				String responseInResponseTo = rootElement.hasAttribute("InResponseTo") ? rootElement.getAttribute("InResponseTo") : null;
				if (requestId == null && responseInResponseTo != null && settings.isRejectUnsolicitedResponsesWithInResponseTo()) {
					throw new ValidationError("The Response has an InResponseTo attribute: " + responseInResponseTo +
							" while no InResponseTo was expected", ValidationError.WRONG_INRESPONSETO);
				}

				// Check if the InResponseTo of the Response matches the ID of the AuthNRequest (requestId) if provided
				if (requestId != null && !Objects.equals(responseInResponseTo, requestId)) {
						throw new ValidationError("The InResponseTo of the Response: " + responseInResponseTo
								+ ", does not match the ID of the AuthNRequest sent by the SP: " + requestId, ValidationError.WRONG_INRESPONSETO);
				}

				if (!this.encrypted && settings.getWantAssertionsEncrypted()) {
					throw new ValidationError("The assertion of the Response is not encrypted and the SP requires it", ValidationError.NO_ENCRYPTED_ASSERTION);
				}

				if (settings.getWantNameIdEncrypted()) {
					NodeList encryptedNameIdNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID/xenc:EncryptedData");
					if (encryptedNameIdNodes.getLength() == 0) {
						throw new ValidationError("The NameID of the Response is not encrypted and the SP requires it", ValidationError.NO_ENCRYPTED_NAMEID);
					}
				}

				// Validate Conditions element exists
				if (!this.checkOneCondition()) {
					throw new ValidationError("The Assertion must include a Conditions element", ValidationError.MISSING_CONDITIONS);
				}
				
				// Validate Assertion timestamps
				if (!this.validateTimestamps()) {
					throw new Exception("Timing issues (please check your clock settings)");
				}

				// Validate AuthnStatement element exists and is unique
				if (!this.checkOneAuthnStatement()) {
					throw new ValidationError("The Assertion must include an AuthnStatement element", ValidationError.WRONG_NUMBER_OF_AUTHSTATEMENTS);
				}
				
				// EncryptedAttributes are not supported
				NodeList encryptedAttributeNodes = this.queryAssertion("/saml:AttributeStatement/saml:EncryptedAttribute");
				if (encryptedAttributeNodes.getLength() > 0) {
					throw new ValidationError("There is an EncryptedAttribute in the Response and this SP not support them", ValidationError.ENCRYPTED_ATTRIBUTES);
				}
				
				// Check destination
				if (rootElement.hasAttribute("Destination")) {
					String destinationUrl = rootElement.getAttribute("Destination");
					if (destinationUrl != null) {
						if (destinationUrl.isEmpty()) {
							throw new ValidationError("The response has an empty Destination value", ValidationError.EMPTY_DESTINATION);
						} else if (!destinationUrl.equals(currentUrl)) {
							throw new ValidationError("The response was received at " + currentUrl + " instead of "
									+ destinationUrl, ValidationError.WRONG_DESTINATION);
						}
					}
				}

				// Check Audience
				List<String> validAudiences = this.getAudiences();				
				if (!validAudiences.isEmpty() && !validAudiences.contains(settings.getSpEntityId())) {
					throw new ValidationError(settings.getSpEntityId() + " is not a valid audience for this Response", ValidationError.WRONG_AUDIENCE);
				}
				
				// Check the issuers
				List<String> issuers = this.getIssuers();
				for (int i = 0; i < issuers.size(); i++) {
					String issuer = issuers.get(i);
					if (issuer.isEmpty() || !issuer.equals(settings.getIdpEntityId())) {
						throw new ValidationError(
								String.format("Invalid issuer in the Assertion/Response. Was '%s', but expected '%s'", issuer, settings.getIdpEntityId()),
								ValidationError.WRONG_ISSUER);
					}
				}

				// Check the session Expiration
				DateTime sessionExpiration = this.getSessionNotOnOrAfter();
				if (sessionExpiration != null) {
					sessionExpiration = sessionExpiration.plus(Constants.ALOWED_CLOCK_DRIFT * 1000);
					if (sessionExpiration.isEqualNow() || sessionExpiration.isBeforeNow()) {
						throw new ValidationError("The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response", ValidationError.SESSION_EXPIRED);
					}
				}

				validateSubjectConfirmation(responseInResponseTo);

                if (settings.getWantAssertionsSigned() && !hasSignedAssertion) {
                	throw new ValidationError("The Assertion of the Response is not signed and the SP requires it", ValidationError.NO_SIGNED_ASSERTION);
                }

                if (settings.getWantMessagesSigned() && !hasSignedResponse) {
                	throw new ValidationError("The Message of the Response is not signed and the SP requires it", ValidationError.NO_SIGNED_MESSAGE);
                }
			}

			if (signedElements.isEmpty() || (!hasSignedAssertion && !hasSignedResponse)) {
				throw new ValidationError("No Signature found. SAML Response rejected", ValidationError.NO_SIGNATURE_FOUND);
			} else {				 
				X509Certificate cert = settings.getIdpx509cert();
				String fingerprint = settings.getIdpCertFingerprint();
				String alg = settings.getIdpCertFingerprintAlgorithm();

				if (hasSignedResponse && !Util.validateSign(samlResponseDocument, cert, fingerprint, alg, Util.RESPONSE_SIGNATURE_XPATH)) {
					throw new ValidationError("Signature validation failed. SAML Response rejected", ValidationError.INVALID_SIGNATURE);
				}

				final Document documentToCheckAssertion = encrypted ? decryptedDocument : samlResponseDocument;
				if (hasSignedAssertion && !Util.validateSign(documentToCheckAssertion, cert, fingerprint, alg, Util.ASSERTION_SIGNATURE_XPATH)) {
					throw new ValidationError("Signature validation failed. SAML Response rejected", ValidationError.INVALID_SIGNATURE);
				}
			}

			LOGGER.debug("SAMLResponse validated --> " + samlResponseString);
			return true;
		} catch (Exception e) {
			error = e.getMessage();
			LOGGER.debug("SAMLResponse invalid --> " + samlResponseString);
			LOGGER.error(error);
			return false;
		}
	}

	/**
	 * Check SubjectConfirmation, at least one SubjectConfirmation must be valid
	 *
	 * @param responseInResponseTo
	 *     The InResponseTo value of the SAML Response
	 *
	 * @throws XPathExpressionException
	 * @throws ValidationError
	 */
	private void validateSubjectConfirmation(String responseInResponseTo) throws XPathExpressionException, ValidationError {
		final List<SubjectConfirmationIssue> validationIssues = new ArrayList<>();
		boolean validSubjectConfirmation = false;
		NodeList subjectConfirmationNodes = this.queryAssertion("/saml:Subject/saml:SubjectConfirmation");
		for (int i = 0; i < subjectConfirmationNodes.getLength(); i++) {
			Node scn = subjectConfirmationNodes.item(i);

			Node method = scn.getAttributes().getNamedItem("Method");
			if (method != null && !method.getNodeValue().equals(Constants.CM_BEARER)) {
				continue;
			}

			NodeList subjectConfirmationDataNodes = scn.getChildNodes();
			for (int c = 0; c < subjectConfirmationDataNodes.getLength(); c++) {
				if (subjectConfirmationDataNodes.item(c).getLocalName() != null && subjectConfirmationDataNodes.item(c).getLocalName().equals("SubjectConfirmationData")) {

					Node recipient = subjectConfirmationDataNodes.item(c).getAttributes().getNamedItem("Recipient");
					if (recipient == null) {
						validationIssues.add(new SubjectConfirmationIssue(i, "SubjectConfirmationData doesn't contain a Recipient"));
						continue;
					}

					if (!recipient.getNodeValue().equals(currentUrl)) {
						validationIssues.add(new SubjectConfirmationIssue(i, "SubjectConfirmationData doesn't match a valid Recipient"));
						continue;
					}

					Node inResponseTo = subjectConfirmationDataNodes.item(c).getAttributes().getNamedItem("InResponseTo");
					if (inResponseTo == null && responseInResponseTo != null ||
							inResponseTo != null && !inResponseTo.getNodeValue().equals(responseInResponseTo)) {
						validationIssues.add(new SubjectConfirmationIssue(i, "SubjectConfirmationData has an invalid InResponseTo value"));;
						continue;
					}

					Node notOnOrAfter = subjectConfirmationDataNodes.item(c).getAttributes().getNamedItem("NotOnOrAfter");
					if (notOnOrAfter == null) {
						validationIssues.add(new SubjectConfirmationIssue(i, "SubjectConfirmationData doesn't contain a NotOnOrAfter attribute"));
						continue;
					}

					DateTime noa = Util.parseDateTime(notOnOrAfter.getNodeValue());
					noa = noa.plus(Constants.ALOWED_CLOCK_DRIFT * 1000);
					if (noa.isEqualNow() || noa.isBeforeNow()) {
						validationIssues.add(new SubjectConfirmationIssue(i, "SubjectConfirmationData is no longer valid"));
						continue;
					}

					Node notBefore = subjectConfirmationDataNodes.item(c).getAttributes().getNamedItem("NotBefore");
					if (notBefore != null) {
						DateTime nb = Util.parseDateTime(notBefore.getNodeValue());
						nb = nb.minus(Constants.ALOWED_CLOCK_DRIFT * 1000);
						if (nb.isAfterNow()) {
							validationIssues.add(new SubjectConfirmationIssue(i, "SubjectConfirmationData is not yet valid"));
							continue;
						}
					}
					validSubjectConfirmation = true;
				}
			}
		}

		if (!validSubjectConfirmation) {
			throw new ValidationError(SubjectConfirmationIssue.prettyPrintIssues(validationIssues), ValidationError.WRONG_SUBJECTCONFIRMATION);
		}
	}

	/**
	 * Determines if the SAML Response is valid using the certificate.
	 *
	 * @return if the response is valid or not
	 */
	public boolean isValid() {
		return isValid(null);
	}

	/**
     * Gets the NameID provided from the SAML Response Document.
     *
     * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
	 * @throws Exception 
     *
     */
	public HashMap<String,String> getNameIdData() throws Exception {
		HashMap<String,String> nameIdData = new HashMap<String, String>();

		NodeList encryptedIDNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID");
		NodeList nameIdNodes;
		Element nameIdElem;
		if (encryptedIDNodes.getLength() == 1) {
			NodeList encryptedDataNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID/xenc:EncryptedData");
			if (encryptedDataNodes.getLength() == 1) {
				Element encryptedData = (Element) encryptedDataNodes.item(0);
				PrivateKey key = settings.getSPkey();
				if (key == null) {
					throw new SettingsException("Key is required in order to decrypt the NameID", SettingsException.PRIVATE_KEY_NOT_FOUND);
				}

				Util.decryptElement(encryptedData, key);
			}
			nameIdNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID/saml:NameID|/saml:Subject/saml:NameID");

			if (nameIdNodes == null || nameIdNodes.getLength() == 0) {
				throw new Exception("Not able to decrypt the EncryptedID and get a NameID");
			}
		} else {
			nameIdNodes = this.queryAssertion("/saml:Subject/saml:NameID");
		}

		if (nameIdNodes != null && nameIdNodes.getLength() == 1) {
			nameIdElem = (Element) nameIdNodes.item(0);
			
			if (nameIdElem != null) {
				String value = nameIdElem.getTextContent();
				if (settings.isStrict() && value.isEmpty()) {
					throw new ValidationError("An empty NameID value found", ValidationError.EMPTY_NAMEID);
				}

				nameIdData.put("Value", value);

				if (nameIdElem.hasAttribute("Format")) {
					nameIdData.put("Format", nameIdElem.getAttribute("Format"));
				}
				if (nameIdElem.hasAttribute("SPNameQualifier")) {
					String spNameQualifier = nameIdElem.getAttribute("SPNameQualifier");
					if (settings.isStrict() && !spNameQualifier.equals(settings.getSpEntityId())) {
						throw new ValidationError("The SPNameQualifier value mistmatch the SP entityID value.", ValidationError.SP_NAME_QUALIFIER_NAME_MISMATCH);
					} else {
						nameIdData.put("SPNameQualifier", spNameQualifier);
					}
				}
				if (nameIdElem.hasAttribute("NameQualifier")) {
					nameIdData.put("NameQualifier", nameIdElem.getAttribute("NameQualifier"));
				}
			}
		} else {
			if (settings.getWantNameId()) {
				throw new ValidationError("No name id found in Document.", ValidationError.NO_NAMEID);
			}
		}
		return nameIdData;
	}

    /**
     * Gets the NameID value provided from the SAML Response String.
     *
     * @return string Name ID Value
     *
     * @throws Exception 
     */
	public String getNameId() throws Exception {
		HashMap<String,String> nameIdData = getNameIdData();
		String nameID = null;
		if (!nameIdData.isEmpty()) {
			LOGGER.debug("SAMLResponse has NameID --> " + nameIdData.get("Value"));
			nameID = nameIdData.get("Value");
		}
		return nameID;
	}

    /**
     * Gets the NameID Format provided from the SAML Response String.
     *
     * @return string NameID Format
     *
     * @throws Exception
     */
	public String getNameIdFormat() throws Exception {
		HashMap<String,String> nameIdData = getNameIdData();
		String nameidFormat = null;
		if (!nameIdData.isEmpty() && nameIdData.containsKey("Format")) {
			LOGGER.debug("SAMLResponse has NameID Format --> " + nameIdData.get("Format"));
			nameidFormat = nameIdData.get("Format");
		}
		return nameidFormat;
	}

	/**
     * Gets the Attributes from the AttributeStatement element.
     *
     * @return the attributes of the SAML Assertion
     *
	 * @throws XPathExpressionException
	 * @throws ValidationError
     *
     */	
	public HashMap<String, List<String>> getAttributes() throws XPathExpressionException, ValidationError {
		HashMap<String, List<String>> attributes = new HashMap<String, List<String>>();

		NodeList nodes = this.queryAssertion("/saml:AttributeStatement/saml:Attribute");
		
		if (nodes.getLength() != 0) {
			for (int i = 0; i < nodes.getLength(); i++) {
				NamedNodeMap attrName = nodes.item(i).getAttributes();
				String attName = attrName.getNamedItem("Name").getNodeValue();
				if (attributes.containsKey(attName)) {
					throw new ValidationError("Found an Attribute element with duplicated Name", ValidationError.DUPLICATED_ATTRIBUTE_NAME_FOUND);
				}
				
				NodeList childrens = nodes.item(i).getChildNodes();

				List<String> attrValues = new ArrayList<String>();
				for (int j = 0; j < childrens.getLength(); j++) {
					if ("AttributeValue".equals(childrens.item(j).getLocalName())) {
						attrValues.add(childrens.item(j).getTextContent());
					}
				}
				attributes.put(attName, attrValues);
			}
			LOGGER.debug("SAMLResponse has attributes: " + attributes.toString());
		} else {
			LOGGER.debug("SAMLResponse has no attributes");
		}
		return attributes;
	}

	/**
	 * Checks the Status
	 *
	 * @throws ValidationError
	 *             If status is not success
	 */
	public void checkStatus() throws ValidationError {
		SamlResponseStatus responseStatus = getStatus(samlResponseDocument);
		if (!responseStatus.is(Constants.STATUS_SUCCESS)) {
			String statusExceptionMsg = "The status code of the Response was not Success, was "
					+ responseStatus.getStatusCode();
			if (responseStatus.getStatusMessage() != null) {
				statusExceptionMsg += " -> " + responseStatus.getStatusMessage();
			}
			throw new ValidationError(statusExceptionMsg, ValidationError.STATUS_CODE_IS_NOT_SUCCESS);
		}
	}

	/**
	 * Get Status from a Response
	 *
	 * @param dom
	 *            The Response as XML
	 *
	 * @return array with the code and a message
	 *
	 * @throws IllegalArgumentException
	 *             if the response not contain status or if Unexpected XPath error
	 * @throws ValidationError 
	 */
	public static SamlResponseStatus getStatus(Document dom) throws ValidationError {
		try {
			String statusExpr = "/samlp:Response/samlp:Status";

			NodeList statusEntry = Util.query(dom, statusExpr, null);
			if (statusEntry.getLength() != 1) {
				throw new ValidationError("Missing Status on response", ValidationError.MISSING_STATUS);
			}
			NodeList codeEntry;

			codeEntry = Util.query(dom, statusExpr + "/samlp:StatusCode", (Element) statusEntry.item(0));

			if (codeEntry.getLength() != 1) {
				throw new ValidationError("Missing Status Code on response", ValidationError.MISSING_STATUS_CODE);
			}

			String stausCode = codeEntry.item(0).getAttributes().getNamedItem("Value").getNodeValue();
			SamlResponseStatus status = new SamlResponseStatus(stausCode);

			NodeList messageEntry = Util.query(dom, statusExpr + "/samlp:StatusMessage",
					(Element) statusEntry.item(0));
			if (messageEntry.getLength() == 1) {
				status.setStatusMessage(messageEntry.item(0).getTextContent());
			}
			return status;
		} catch (XPathExpressionException e) {
			String error = "Unexpected error in getStatus." +  e.getMessage();
			LOGGER.error(error);
			throw new IllegalArgumentException(error);
		}
	}

	/**
	 * Checks that the samlp:Response/saml:Assertion/saml:Conditions element exists and is unique.
	 *
	 * @return true if the Conditions element exists and is unique
	 *
	 * @throws XPathExpressionException
	 */
	public Boolean checkOneCondition() throws XPathExpressionException {
		NodeList entries = this.queryAssertion("/saml:Conditions");
		if (entries.getLength() == 1) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Checks that the samlp:Response/saml:Assertion/saml:AuthnStatement element exists and is unique.
	 *
	 * @return true if the AuthnStatement element exists and is unique
	 *
	 * @throws XPathExpressionException
	 */
	public Boolean checkOneAuthnStatement() throws XPathExpressionException {
		NodeList entries = this.queryAssertion("/saml:AuthnStatement");
		if (entries.getLength() == 1) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Gets the audiences.
	 *
	 * @return the audiences of the response
	 * 
	 * @throws XPathExpressionException
	 */
	public List<String> getAudiences() throws XPathExpressionException {
		List<String> audiences = new ArrayList<String>();

		NodeList entries = this.queryAssertion("/saml:Conditions/saml:AudienceRestriction/saml:Audience");

		for (int i = 0; i < entries.getLength(); i++) {
			if (entries.item(i) != null) {
				String value = entries.item(i).getTextContent();
				if (value != null && !value.trim().isEmpty()) {
					audiences.add(value.trim());
				}
			}
		}
		return audiences;
	}

	/**
	 * Gets the Issuers (from Response and Assertion).
	 *
	 * @return the issuers of the assertion/response
	 *
	 * @throws XPathExpressionException 
	 * @throws ValidationError 
	 */
	public List<String> getIssuers() throws XPathExpressionException, ValidationError {
		List<String> issuers = new ArrayList<String>();
		String value;
		NodeList responseIssuer = Util.query(samlResponseDocument, "/samlp:Response/saml:Issuer");
		if (responseIssuer.getLength() > 1) {
			if (responseIssuer.getLength() == 1) {
				value = responseIssuer.item(0).getTextContent();
				if (!issuers.contains(value)) {
					issuers.add(value);
				}
			} else {
				throw new ValidationError("Issuer of the Response is multiple.", ValidationError.ISSUER_MULTIPLE_IN_RESPONSE);
			}
		}

		NodeList assertionIssuer = this.queryAssertion("/saml:Issuer");
		if (assertionIssuer.getLength() == 1) {
			value = assertionIssuer.item(0).getTextContent();
			if (!issuers.contains(value)) {
				issuers.add(value);
			}
		} else {
			throw new ValidationError("Issuer of the Assertion not found or multiple.", ValidationError.ISSUER_NOT_FOUND_IN_ASSERTION);
		}

		return issuers;
	}

	/**
	 * Gets the SessionNotOnOrAfter from the AuthnStatement. Could be used to
	 * set the local session expiration
	 *
	 * @return the SessionNotOnOrAfter value
	 *
	 * @throws XPathExpressionException
	 */
	public DateTime getSessionNotOnOrAfter() throws XPathExpressionException {
		String notOnOrAfter = null;
		NodeList entries = this.queryAssertion("/saml:AuthnStatement[@SessionNotOnOrAfter]");
		if (entries.getLength() > 0) {
			notOnOrAfter = entries.item(0).getAttributes().getNamedItem("SessionNotOnOrAfter").getNodeValue();
			return Util.parseDateTime(notOnOrAfter);
		}
		return null;
	}

    /**
     * Gets the SessionIndex from the AuthnStatement.
     * Could be used to be stored in the local session in order
     * to be used in a future Logout Request that the SP could
     * send to the SP, to set what specific session must be deleted
     *
     * @return the SessionIndex value
     *
     * @throws XPathExpressionException 
     */
    public String getSessionIndex() throws XPathExpressionException {
        String sessionIndex = null;
        NodeList entries = this.queryAssertion("/saml:AuthnStatement[@SessionIndex]");
        if (entries.getLength() > 0) {
            sessionIndex = entries.item(0).getAttributes().getNamedItem("SessionIndex").getNodeValue();
        }
        return sessionIndex;
    }

	/**
	 * @return the ID of the Response
	 */
	public String getId() {
		return samlResponseDocument.getDocumentElement().getAttributes().getNamedItem("ID").getNodeValue();
	}

	/**
	 * @return the ID of the assertion in the Response
	 * @throws XPathExpressionException
	 *
	 */
	public String getAssertionId() throws XPathExpressionException {
		if (!validateNumAssertions()) {
			throw new IllegalArgumentException("SAML Response must contain 1 Assertion.");
		}
		final NodeList assertionNode = queryAssertion("");
		return assertionNode.item(0).getAttributes().getNamedItem("ID").getNodeValue();
	}

	/**
	 * @return a list of NotOnOrAfter values from SubjectConfirmationData nodes in this Response
	 * @throws XPathExpressionException
	 *
	 */
	public List<Instant> getAssertionNotOnOrAfter() throws XPathExpressionException {
		final NodeList notOnOrAfterNodes = queryAssertion("/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData");
		final ArrayList<Instant> notOnOrAfters = new ArrayList<>();
		for (int i = 0; i < notOnOrAfterNodes.getLength(); i++) {
			final Node notOnOrAfterAttribute = notOnOrAfterNodes.item(i).getAttributes().getNamedItem("NotOnOrAfter");
			if (notOnOrAfterAttribute != null) {
				notOnOrAfters.add(new Instant(notOnOrAfterAttribute.getNodeValue()));
		}}
		return notOnOrAfters;
	}

	/**
	 * Verifies that the document only contains a single Assertion (encrypted or not).
	 *
	 * @return true if the document passes.
	 *
	 * @throws IllegalArgumentException
	 */
	public Boolean validateNumAssertions() throws IllegalArgumentException {
		NodeList encryptedAssertionNodes = samlResponseDocument.getElementsByTagNameNS(Constants.NS_SAML, "EncryptedAssertion");
		NodeList assertionNodes = samlResponseDocument.getElementsByTagNameNS(Constants.NS_SAML, "Assertion");

		Boolean valid = assertionNodes.getLength() + encryptedAssertionNodes.getLength() == 1;

		if (encrypted) {
			valid = valid && decryptedDocument.getElementsByTagNameNS(Constants.NS_SAML, "Assertion").getLength() == 1;
		}

		return valid;
	}

    /**
     * Verifies the signature nodes:
     * - Checks that are Response or Assertion
     * - Check that IDs and reference URI are unique and consistent.
     *
     * @return array Signed element tags
     *
     * @throws XPathExpressionException
     * @throws ValidationError
     */
	public ArrayList<String> processSignedElements() throws XPathExpressionException, ValidationError {
		ArrayList<String> signedElements = new ArrayList<String>();
		ArrayList<String> verifiedSeis = new ArrayList<String>();
		ArrayList<String> verifiedIds = new ArrayList<String>();

		NodeList signNodes = query("//ds:Signature", null);
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			String signedElement = "{" + signNode.getParentNode().getNamespaceURI() + "}" + signNode.getParentNode().getLocalName();

			String responseTag = "{" + Constants.NS_SAMLP  + "}Response";
			String assertionTag = "{" + Constants.NS_SAML + "}Assertion";
			
			if (!signedElement.equals(responseTag) && !signedElement.equals(assertionTag)) {
				throw new ValidationError("Invalid Signature Element " + signedElement + " SAML Response rejected", ValidationError.WRONG_SIGNED_ELEMENT);
			}

			// Check that reference URI matches the parent ID and no duplicate References or IDs
			Node idNode = signNode.getParentNode().getAttributes().getNamedItem("ID");
			if (idNode == null || idNode.getNodeValue() == null || idNode.getNodeValue().isEmpty()) {
				throw new ValidationError("Signed Element must contain an ID. SAML Response rejected", ValidationError.ID_NOT_FOUND_IN_SIGNED_ELEMENT);
			}
			
			String idValue = idNode.getNodeValue();			
			if (verifiedIds.contains(idValue)) {
				throw new ValidationError("Duplicated ID. SAML Response rejected", ValidationError.DUPLICATED_ID_IN_SIGNED_ELEMENTS);
			}
			verifiedIds.add(idValue);
			
			NodeList refNodes = Util.query(null, "ds:SignedInfo/ds:Reference", signNode);
			if (refNodes.getLength() == 1) {
				Node refNode = refNodes.item(0);
				Node seiNode = refNode.getAttributes().getNamedItem("URI");
				if (seiNode != null && seiNode.getNodeValue() != null && !seiNode.getNodeValue().isEmpty()) {
					String sei = seiNode.getNodeValue().substring(1);
					if (!sei.equals(idValue)) {
						throw new ValidationError("Found an invalid Signed Element. SAML Response rejected", ValidationError.INVALID_SIGNED_ELEMENT);
					}
					
					if (verifiedSeis.contains(sei)) {
						throw new ValidationError("Duplicated Reference URI. SAML Response rejected", ValidationError.DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS);
					}
					verifiedSeis.add(sei);
				}
			} else {
				// Signatures MUST contain a single <ds:Reference> containing a same-document reference to the ID
				// attribute value of the root element of the assertion or protocol message being signed
				throw new ValidationError("Unexpected number of Reference nodes found for signature. SAML Response rejected.", ValidationError.UNEXPECTED_REFERENCE);
			}

			signedElements.add(signedElement);
		}
		if (!signedElements.isEmpty()) {
			if (!validateSignedElements(signedElements)) {
				throw new ValidationError("Found an unexpected Signature Element. SAML Response rejected", ValidationError.UNEXPECTED_SIGNED_ELEMENTS);
			}
		}
		return signedElements;
	}

	/**
	 * Verifies that the document has the expected signed nodes.
	 *
	 * @param signedElements
	 *				the elements to be validated
	 * @return true if is valid
	 *
	 * @throws XPathExpressionException
	 * @throws ValidationError
	 *
	 */
	public boolean validateSignedElements(ArrayList<String> signedElements) throws XPathExpressionException, ValidationError {
		if (signedElements.size() > 2) {
			return false;
		}

		Map<String, Integer> occurrences = new HashMap<String, Integer>();
		for (String e : signedElements) {
			if (occurrences.containsKey(e)) {
				occurrences.put(e, occurrences.get(e).intValue() + 1);
			} else {
				occurrences.put(e, 1);
			}
		}

		String responseTag = "{" + Constants.NS_SAMLP  + "}Response";
		String assertionTag = "{" + Constants.NS_SAML + "}Assertion";

		if ((occurrences.containsKey(responseTag) && occurrences.get(responseTag) > 1)
				|| (occurrences.containsKey(assertionTag) && occurrences.get(assertionTag) > 1)
				|| !occurrences.containsKey(responseTag) && !occurrences.containsKey(assertionTag)) {
			return false;
		}

		// check that the signed elements found here, are the ones that will be verified
		// by com.onelogin.saml2.util.Util.validateSign()
		if (occurrences.containsKey(responseTag)) {
			final NodeList expectedSignatureNode = query(Util.RESPONSE_SIGNATURE_XPATH, null);
			if (expectedSignatureNode.getLength() != 1) {
				throw new ValidationError("Unexpected number of Response signatures found. SAML Response rejected.", ValidationError.WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE);
			}
		}

		if (occurrences.containsKey(assertionTag)) {
			final NodeList expectedSignatureNode = query(Util.ASSERTION_SIGNATURE_XPATH, null);
			if (expectedSignatureNode.getLength() != 1) {
				throw new ValidationError("Unexpected number of Assertion signatures found. SAML Response rejected.", ValidationError.WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION);
			}
		}

		return true;
	}

	/**
	 * Verifies that the document is still valid according Conditions Element.
	 *
	 * @return true if still valid
	 *
	 * @throws ValidationError 
	 */
	public boolean validateTimestamps() throws ValidationError {
		NodeList timestampNodes = samlResponseDocument.getElementsByTagNameNS("*", "Conditions");
		if (timestampNodes.getLength() != 0) {
			for (int i = 0; i < timestampNodes.getLength(); i++) {
				NamedNodeMap attrName = timestampNodes.item(i).getAttributes();
				Node nbAttribute = attrName.getNamedItem("NotBefore");
				Node naAttribute = attrName.getNamedItem("NotOnOrAfter");
				// validate NotOnOrAfter
				if (naAttribute != null) {
					DateTime notOnOrAfterDate = Util.parseDateTime(naAttribute.getNodeValue());
					notOnOrAfterDate = notOnOrAfterDate.plus(Constants.ALOWED_CLOCK_DRIFT * 1000);
					if (notOnOrAfterDate.isEqualNow() || notOnOrAfterDate.isBeforeNow()) {
						throw new ValidationError("Could not validate timestamp: expired. Check system clock.", ValidationError.ASSERTION_EXPIRED);
					}
				}
				// validate NotBefore
				if (nbAttribute != null) {
					DateTime notBeforeDate = Util.parseDateTime(nbAttribute.getNodeValue());
					notBeforeDate = notBeforeDate.minus(Constants.ALOWED_CLOCK_DRIFT * 1000);
					if (notBeforeDate.isAfterNow()) {
						throw new ValidationError("Could not validate timestamp: not yet valid. Check system clock.", ValidationError.ASSERTION_TOO_EARLY);
					}
				}
			}
		}
		return true;
	}

	/**
     * Aux method to set the destination url
     * 
	 * @param urld 
	 *				the url to set as currentUrl
     */
	public void setDestinationUrl(String urld) {
		currentUrl = urld;
	}

	/**
     * After execute a validation process, if fails this method returns the cause
     *
     * @return the cause of the validation error 
     */
	public String getError() {
		if (error != null) {
			return error;
		}
		return null;
	}

	/**
	 * Extracts a node from the DOMDocument (Assertion).
	 *
	 * @param assertionXpath
	 *				Xpath Expression
	 *
	 * @return the queried node
	 * @throws XPathExpressionException 
	 *
	 */
	private NodeList queryAssertion(String assertionXpath) throws XPathExpressionException {
        final String assertionExpr = "/saml:Assertion";
        final String signatureExpr = "ds:Signature/ds:SignedInfo/ds:Reference";

        String nameQuery;
        String signedAssertionQuery = "/samlp:Response" + assertionExpr + "/" + signatureExpr;
        NodeList nodeList = query(signedAssertionQuery, null);
        if (nodeList.getLength() == 0 ) {
        	// let see if the whole response signed?
            String signedMessageQuery = "/samlp:Response/" + signatureExpr;
            nodeList = query(signedMessageQuery, null);
            if (nodeList.getLength() == 1) {
                Node responseReferenceNode = nodeList.item(0);
                String responseId = responseReferenceNode.getAttributes().getNamedItem("URI").getNodeValue();
                if (responseId != null && !responseId.isEmpty()) {
                    responseId = responseId.substring(1);
                } else {
                    responseId = responseReferenceNode.getParentNode().getParentNode().getParentNode().getAttributes().getNamedItem("ID").getNodeValue();
                }
                nameQuery = "/samlp:Response[@ID='" + responseId + "']";
            } else {
                // On this case there is no element signed, the query will work but
                // the response validation will throw and error.
            	nameQuery = "/samlp:Response";
            }
            nameQuery += assertionExpr;
        } else {  // there is a signed assertion
        	Node assertionReferenceNode = nodeList.item(0);
            String assertionId = assertionReferenceNode.getAttributes().getNamedItem("URI").getNodeValue();
            if (assertionId != null && !assertionId.isEmpty()) {
                assertionId = assertionId.substring(1);
            } else {
                assertionId = assertionReferenceNode.getParentNode().getParentNode().getParentNode().getAttributes().getNamedItem("ID").getNodeValue();
            }
            nameQuery = "/samlp:Response/" + assertionExpr + "[@ID='" + assertionId + "']";
        }
        nameQuery += assertionXpath;

        return query(nameQuery, null);
	}

	/**
     * Extracts nodes that match the query from the DOMDocument (Response Menssage)
     *
     * @param nameQuery
     *				Xpath Expression
     * @param context 
     *              The context node
     *
     * @return DOMNodeList The queried nodes
     */
	private NodeList query(String nameQuery, Node context) throws XPathExpressionException {
		Document doc;
		if (encrypted) {
			doc = decryptedDocument;
		} else {
        	doc = samlResponseDocument;
		}

		// LOGGER.debug("Executing query " + nameQuery);
		return Util.query(doc, nameQuery, context);
	}

	/**
	 * Decrypt assertion.
	 * 
	 * @param dom
	 *            Encrypted assertion
	 *
	 * @return Decrypted Assertion.
	 *
	 * @throws XPathExpressionException 
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws SettingsException
	 */
	private Document decryptAssertion(Document dom) throws XPathExpressionException, ParserConfigurationException, SAXException, IOException, SettingsException {		
		PrivateKey key = settings.getSPkey();

		if (key == null) {
			throw new SettingsException("No private key available for decrypt, check settings", SettingsException.PRIVATE_KEY_NOT_FOUND);
		}

		NodeList encryptedDataNodes = Util.query(dom, "/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData");
		Element encryptedData = (Element) encryptedDataNodes.item(0);
		Util.decryptElement(encryptedData, key);

		// We need to Remove the saml:EncryptedAssertion Node
		NodeList AssertionDataNodes = Util.query(dom, "/samlp:Response/saml:EncryptedAssertion/saml:Assertion");
		Node assertionNode = AssertionDataNodes.item(0);
		assertionNode.getParentNode().getParentNode().replaceChild(assertionNode, assertionNode.getParentNode());

		// In order to avoid Signature Validation errors we need to rebuild the dom.
		// https://groups.google.com/forum/#!topic/opensaml-users/gpXvwaZ53NA
		String xmlStr = Util.convertDocumentToString(dom);
		Document doc = Util.convertStringToDocument(xmlStr);
		// LOGGER.debug("Decrypted SAMLResponse --> " + xmlStr);
		return doc;
	}

	/**
	 * @return the SAMLResponse XML, If the Assertion of the SAMLResponse was encrypted,  
	 *         returns the XML with the assertion decrypted
	 */
	public String getSAMLResponseXml() {
		String xml;
		if (encrypted) {
			xml = Util.convertDocumentToString(decryptedDocument);
		} else {
        	xml = samlResponseString;
		}
		return xml; 
	}

	/**
	 * @return the SAMLResponse Document, If the Assertion of the SAMLResponse was encrypted,  
	 *         returns the Document with the assertion decrypted
	 */
	protected Document getSAMLResponseDocument() {
		Document doc;
		if (encrypted) {
			doc = decryptedDocument;
		} else {
        	doc = samlResponseDocument;
		}
		return doc;
	}
}
