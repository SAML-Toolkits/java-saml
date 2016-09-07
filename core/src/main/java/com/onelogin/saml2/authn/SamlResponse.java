package com.onelogin.saml2.authn;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.lang3.ObjectUtils;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.model.SamlResponseStatus;
import com.onelogin.saml2.model.SubjectConfirmationIssue;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.SchemaFactory;
import com.onelogin.saml2.util.Util;


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
	 * @throws Exception
	 */
	public SamlResponse(Saml2Settings settings, HttpRequest request) throws Exception {
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
	 * @throws Exception 
	 */
	public void loadXmlFromBase64(String responseStr) throws Exception {
		samlResponseString = new String(Util.base64decoder(responseStr));
		samlResponseDocument = Util.loadXML(samlResponseString);

		if (samlResponseDocument == null) {
			throw new IllegalArgumentException("SAML Response could not be processed");
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
				throw new Exception("Unsupported SAML Version.");
			}

			// Check ID in the response
			if (!rootElement.hasAttribute("ID")) {
				throw new Exception("Missing ID attribute on SAML Response.");
			}

			this.checkStatus();

			if (!this.validateNumAssertions()) {
				throw new IllegalArgumentException("SAML Response must contain 1 Assertion.");
			}

			ArrayList<String> signedElements = processSignedElements();

			if (settings.isStrict()) {
				if (settings.getWantXMLValidation()) {
					if (!Util.validateXML(samlResponseDocument, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
						throw new Exception("Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd");
					}

					// If encrypted, check also the decrypted document
					if (encrypted) {
						if (!Util.validateXML(decryptedDocument, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
							throw new Exception("Invalid decrypted SAML Response. Not match the saml-schema-protocol-2.0.xsd");
						}
					}
				}

				String responseInResponseTo = rootElement.hasAttribute("InResponseTo") ? rootElement.getAttribute("InResponseTo") : null;
				if (requestId == null && responseInResponseTo != null && settings.isRejectUnsolicitedResponsesWithInResponseTo()) {
					throw new Exception("The Response has an InResponseTo attribute: " + responseInResponseTo +
							" while no InResponseTo was expected");
				}

				// Check if the InResponseTo of the Response matches the ID of the AuthNRequest (requestId) if provided
				if (requestId != null && !ObjectUtils.equals(responseInResponseTo, requestId)) {
						throw new Exception("The InResponseTo of the Response: " + responseInResponseTo
								+ ", does not match the ID of the AuthNRequest sent by the SP: " + requestId);
				}

				if (!this.encrypted && settings.getWantAssertionsEncrypted()) {
					throw new Exception("The assertion of the Response is not encrypted and the SP requires it");
				}

				if (settings.getWantNameIdEncrypted()) {
					NodeList encryptedNameIdNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID/xenc:EncryptedData");
					if (encryptedNameIdNodes.getLength() == 0) {
						throw new Exception("The NameID of the Response is not encrypted and the SP requires it");
					}
				}

				// Validate Assertion timestamps
				if (!this.validateTimestamps()) {
					throw new Exception("Timing issues (please check your clock settings)");
				}

				// EncryptedAttributes are not supported
				NodeList encryptedAttributeNodes = this.queryAssertion("/saml:AttributeStatement/saml:EncryptedAttribute");
				if (encryptedAttributeNodes.getLength() > 0) {
					throw new Exception("There is an EncryptedAttribute in the Response and this SP not support them");
				}

				// Check destination
				if (rootElement.hasAttribute("Destination")) {
					String destinationUrl = rootElement.getAttribute("Destination");
					if (destinationUrl != null) {
						if (!destinationUrl.isEmpty() && !destinationUrl.equals(currentUrl)) {
							throw new Exception("The response was received at " + currentUrl + " instead of "
									+ destinationUrl);
						}
					}
				}

				// Check Audience
				List<String> validAudiences = this.getAudiences();				
				if (!validAudiences.isEmpty() && !validAudiences.contains(settings.getSpEntityId())) {
				 throw new Exception( settings.getSpEntityId() + " is not a valid audience for this Response");
				}
				
				// Check the issuers
				List<String> issuers = this.getIssuers();
				for (int i = 0; i < issuers.size(); i++) {
					String issuer = issuers.get(i);
					if (issuer.isEmpty() || !issuer.equals(settings.getIdpEntityId())) {
						throw new Exception("Invalid issuer in the Assertion/Response");
					}
				}

				// Check the session Expiration
				DateTime sessionExpiration = this.getSessionNotOnOrAfter();
				if (sessionExpiration != null) {
					if (sessionExpiration.isEqualNow() || sessionExpiration.isBeforeNow()) {
						throw new Exception("The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response");
					}
				}

				validateSubjectConfirmation(responseInResponseTo);

                if (settings.getWantAssertionsSigned() && !signedElements.contains("Assertion")) {
                    throw new Exception("The Assertion of the Response is not signed and the SP requires it");
                }

                if (settings.getWantMessagesSigned() && !signedElements.contains("Response")) {
                    throw new Exception("The Message of the Response is not signed and the SP requires it");
                }
			}

			if (signedElements.isEmpty()) {
				throw new Exception("No Signature found. SAML Response rejected");
			} else {				 
				X509Certificate cert = settings.getIdpx509cert();
				String fingerprint = settings.getIdpCertFingerprint();
				String alg = settings.getIdpCertFingerprintAlgorithm();

				Document documentToValidate;
				if (signedElements.contains("Response")) {
					documentToValidate = samlResponseDocument;
				} else {
					if (encrypted) {
						documentToValidate = decryptedDocument;
					} else {
						documentToValidate = samlResponseDocument;
					}
				}

				if (!Util.validateSign(documentToValidate, cert, fingerprint, alg)) {
					throw new Exception("Signature validation failed. SAML Response rejected");
				}
			}

			LOGGER.debug("SAMLResponse validated --> " + samlResponseString);
			return true;
		} catch (Error | Exception e) {
			error = e.getMessage();
			LOGGER.debug("SAMLResponse invalid --> " + samlResponseString);
			LOGGER.error(error);
			return false;
		}
	}

	// Check SubjectConfirmation, at least one SubjectConfirmation must be valid
	private void validateSubjectConfirmation(String responseInResponseTo) throws Exception {
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
					if (noa.isEqualNow() || noa.isBeforeNow()) {
						validationIssues.add(new SubjectConfirmationIssue(i, "SubjectConfirmationData is no longer valid"));
						continue;
					}

					Node notBefore = subjectConfirmationDataNodes.item(c).getAttributes().getNamedItem("NotBefore");
					if (notBefore != null) {
						DateTime nb = Util.parseDateTime(notBefore.getNodeValue());
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
			throw new Exception(SubjectConfirmationIssue.prettyPrintIssues(validationIssues));
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
     */
	public HashMap<String,String> getNameIdData() throws Exception {
		HashMap<String,String> nameIdData = new HashMap<String, String>();

		NodeList encryptedIDNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID/xenc:EncryptedData");
		NodeList nameIdNodes;
		Element nameIdElem;
		if (encryptedIDNodes.getLength() > 0) {
			Element encryptedData = (Element) encryptedIDNodes.item(0);
			PrivateKey key = settings.getSPkey();
			if (key == null) {
				throw new IllegalArgumentException("Key is required in order to decrypt the NameID");
			}

			Util.decryptElement(encryptedData, key);
			nameIdNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID/saml:NameID|/saml:Subject/saml:NameID");

			if (nameIdNodes == null || nameIdNodes.getLength() == 0) {
				throw new Exception("Not able to decrypt the EncryptedID and get a NameID");
			}
		} else {
			nameIdNodes = this.queryAssertion("/saml:Subject/saml:NameID");
		}

		if (nameIdNodes != null && nameIdNodes.getLength() > 0) {
			nameIdElem = (Element) nameIdNodes.item(0);
			
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
		} else {
			if (settings.getWantNameId()) {
				throw new Exception("No name id found in Document.");
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
     * Gets the Attributes from the AttributeStatement element.
     *
     * @return the attributes of the SAML Assertion
     *
	 * @throws XPathExpressionException 
     */	
	public HashMap<String, List<String>> getAttributes() throws XPathExpressionException {
		HashMap<String, List<String>> attributes = new HashMap<String, List<String>>();

		NodeList nodes = this.queryAssertion("/saml:AttributeStatement/saml:Attribute");

		if (nodes.getLength() != 0) {
			for (int i = 0; i < nodes.getLength(); i++) {
				NamedNodeMap attrName = nodes.item(i).getAttributes();
				String attName = attrName.getNamedItem("Name").getNodeValue();
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
	 * @throws IllegalArgumentException
	 *             If status is not success
	 */
	public void checkStatus() {
		SamlResponseStatus responseStatus = getStatus(samlResponseDocument);
		if (!responseStatus.is(Constants.STATUS_SUCCESS)) {
			String statusExceptionMsg = "The status code of the Response was not Success, was "
					+ responseStatus.getStatusCode();
			if (responseStatus.getStatusMessage() != null) {
				statusExceptionMsg += " -> " + responseStatus.getStatusMessage();
			}
			throw new IllegalArgumentException(statusExceptionMsg);
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
	 */
	public static SamlResponseStatus getStatus(Document dom) throws IllegalArgumentException {
		try {
			String statusExpr = "/samlp:Response/samlp:Status";

			NodeList statusEntry = Util.query(dom, statusExpr, null);
			if (statusEntry.getLength() == 0) {
				throw new IllegalArgumentException("Missing Status on response");
			}
			NodeList codeEntry;

			codeEntry = Util.query(dom, statusExpr + "/samlp:StatusCode", (Element) statusEntry.item(0));

			if (codeEntry.getLength() == 0) {
				throw new IllegalArgumentException("Missing Status Code on response");
			}

			String stausCode = codeEntry.item(0).getAttributes().getNamedItem("Value").getNodeValue();
			SamlResponseStatus status = new SamlResponseStatus(stausCode);

			NodeList messageEntry = Util.query(dom, statusExpr + "/samlp:StatusMessage",
					(Element) statusEntry.item(0));
			if (messageEntry.getLength() > 0) {
				status.setStatusMessage(messageEntry.item(0).getTextContent());
			}
			return status;
		} catch (XPathExpressionException e) {
			LOGGER.error("Unexpected error in query parser." +  e.getMessage());
			throw new IllegalArgumentException();
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
	 */
	public List<String> getIssuers() throws XPathExpressionException {
		List<String> issuers = new ArrayList<String>();
		String value;
		NodeList responseIssuer = Util.query(samlResponseDocument, "/samlp:Response/saml:Issuer");
		if (responseIssuer.getLength() == 1) {
			value = responseIssuer.item(0).getTextContent();
			if (!issuers.contains(value)) {
				issuers.add(value);
			}
		}

		NodeList assertionIssuer = this.queryAssertion("/saml:Issuer");
		if (assertionIssuer.getLength() == 1) {
			value = assertionIssuer.item(0).getTextContent();
			if (!issuers.contains(value)) {
				issuers.add(value);
			}
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
	 * @return the ID of the assertion in the Response
	 */
	public String getAssertionId() throws XPathExpressionException {
		validateNumAssertions();
		final NodeList assertionNode = queryAssertion("");
		return assertionNode.item(0).getAttributes().getNamedItem("ID").getNodeValue();
	}

	/**
	 * @return a list of NotOnOrAfter values from SubjectConfirmationData nodes in this Response
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

		return (assertionNodes.getLength() + encryptedAssertionNodes.getLength() == 1);
	}

    /**
     * Verifies the signature nodes:
     * - Checks that are Response or Assertion
     * - Check that IDs and reference URI are unique and consistent.
     *
     * @return array Signed element tags
     * @throws Exception 
     */
	public ArrayList<String> processSignedElements() throws Exception {
		ArrayList<String> signedElements = new ArrayList<String>();
		ArrayList<String> verifiedSeis = new ArrayList<String>();
		ArrayList<String> verifiedIds = new ArrayList<String>();

		NodeList signNodes = query("//ds:Signature", null);
		for (int i = 0; i < signNodes.getLength(); i++) {
			Node signNode = signNodes.item(i);
			String signedElement = signNode.getParentNode().getLocalName();
			
			if (!signedElement.equals("Response") && !signedElement.equals("Assertion")) {
				throw new Exception("Invalid Signature Element " + signedElement + " SAML Response rejected");
			}
			
			// Check that reference URI matches the parent ID and no duplicate References or IDs
			Node idNode = signNode.getParentNode().getAttributes().getNamedItem("ID");
			if (idNode == null || idNode.getNodeValue() == null || idNode.getNodeValue().isEmpty()) {
				throw new Exception("Signed Element must contain an ID. SAML Response rejected");
			}
			
			String idValue = idNode.getNodeValue();			
			if (verifiedIds.contains(idValue)) {
				throw new Exception("Duplicated ID. SAML Response rejected");
			}
			verifiedIds.add(idValue);
			
			NodeList refNodes = Util.query(null, ".//ds:Reference", signNode);
			if (refNodes.getLength() > 0) {
				Node refNode = refNodes.item(0);
				Node seiNode = refNode.getAttributes().getNamedItem("URI");
				if (seiNode != null && seiNode.getNodeValue() != null && !seiNode.getNodeValue().isEmpty()) {
					String sei = seiNode.getNodeValue().substring(1);
					if (!sei.equals(idValue)) {
						throw new Exception("Found an invalid Signed Element. SAML Response rejected");
					}
					
					if (verifiedSeis.contains(sei)) {
						throw new Exception("Duplicated Reference URI. SAML Response rejected");
					}
					verifiedSeis.add(sei);
				}
			}

			signedElements.add(signedElement);
		}
		if (!signedElements.isEmpty()) {
			if (!validateSignedElements(signedElements)) {
				throw new Exception("Found an unexpected Signature Element. SAML Response rejected");
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
	 */
	public static boolean validateSignedElements(ArrayList<String> signedElements) {
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

		if ((occurrences.containsKey("Response") && occurrences.get("Response") > 1)
				|| (occurrences.containsKey("Assertion") && occurrences.get("Assertion") > 1)
				|| !occurrences.containsKey("Response") && !occurrences.containsKey("Assertion")) {
			return false;
		}
		return true;
	}

	/**
	 * Verifies that the document is still valid according Conditions Element.
	 *
	 * @return true if still valid
	 */
	public boolean validateTimestamps() {
		NodeList timestampNodes = samlResponseDocument.getElementsByTagNameNS("*", "Conditions");
		if (timestampNodes.getLength() != 0) {
			for (int i = 0; i < timestampNodes.getLength(); i++) {
				NamedNodeMap attrName = timestampNodes.item(i).getAttributes();
				Node nbAttribute = attrName.getNamedItem("NotBefore");
				Node naAttribute = attrName.getNamedItem("NotOnOrAfter");
				// validate NotOnOrAfter
				if (naAttribute != null) {
					final DateTime notOnOrAfterDate = Util.parseDateTime(naAttribute.getNodeValue());
					if (notOnOrAfterDate.isEqualNow() || notOnOrAfterDate.isBeforeNow()) {
						return false;
					}
				}
				// validate NotBefore
				if (nbAttribute != null) {
					final DateTime notBeforeDate = Util.parseDateTime(nbAttribute.getNodeValue());
					if (notBeforeDate.isAfterNow()) {
						return false;
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
			return error.toString();
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
        String assertionExpr;

        assertionExpr = "/saml:Assertion";

        String signatureExpr = "ds:Signature/ds:SignedInfo/ds:Reference";

        String nameQuery = "";
        String signedAssertionQuery = "/samlp:Response" + assertionExpr + "/" + signatureExpr;
        NodeList nodeList = query(signedAssertionQuery, null);
        if (nodeList.getLength() == 0 ) {
        	// let see if the whole response signed?
            String signedMessageQuery = "/samlp:Response/" + signatureExpr;
            nodeList = query(signedMessageQuery, null);
            if (nodeList.getLength() > 0) {
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
            	
            	// If we want to change this behaviour, uncomment this block.
            	// but test should be updated then.
            	
            	// Trick in order to return empty NodeList (not instanciable)
            	/*
            	XPath xpath = XPathFactory.newInstance().newXPath();
            	NodeList noresult = null;
				try {
					noresult = (NodeList) xpath.evaluate("/noresult", Util.convertStringToDocument("<null></null>"), XPathConstants.NODESET);
				} catch (ParserConfigurationException | SAXException | IOException e) {}
            	return noresult;
            	*/
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
	 * @throws Exception
	 */
	private Document decryptAssertion(Document dom) throws Exception {		
		PrivateKey key = settings.getSPkey();

		if (key == null) {
			throw new Exception ("No private key available for decrypt, check settings");
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
}
