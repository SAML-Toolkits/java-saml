package com.onelogin.saml2.settings;

import java.io.InputStream;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathExpressionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

/**
 * IdPMetadataParser class of OneLogin's Java Toolkit.
 *
 * A class that implements the settings parser from IdP Metadata
 *
 */
public class IdPMetadataParser {

	/**
	 * Private property to construct a logger for this class.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(IdPMetadataParser.class);

	/**
	 * Get IdP Metadata Info from XML Document
	 * 
	 * @param xmlDocument
	 *            XML document hat contains IdP metadata
	 * @param entityId
	 *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
	 * @param desiredNameIdFormat
	 *            If available on IdP metadata, use that nameIdFormat
	 * @param desiredSSOBinding
	 *            Parse specific binding SSO endpoint.
	 * @param desiredSLOBinding
	 *            Parse specific binding SLO endpoint.
	 * 
	 * @return Mapped values with metadata info in Saml2Settings format
	 * @throws XPathExpressionException
	 */
	public static Map<String, Object> parseXML(Document xmlDocument, String entityId, String desiredNameIdFormat, String desiredSSOBinding, String desiredSLOBinding) throws XPathException {
		Map<String, Object> metadataInfo = new LinkedHashMap<>();

		try {
			String customIdPStr = "";
			if (entityId != null && !entityId.isEmpty()) {
				customIdPStr = "[@entityID=\"" + entityId + "\"]";
			}

			String idpDescryptorXPath = "//md:EntityDescriptor" + customIdPStr + "/md:IDPSSODescriptor";

			NodeList idpDescriptorNodes = Util.query(xmlDocument, idpDescryptorXPath);

			if (idpDescriptorNodes.getLength() > 0) {

				Node idpDescriptorNode = idpDescriptorNodes.item(0);
				if (entityId == null || entityId.isEmpty()) {
					Node entityIDNode = idpDescriptorNode.getParentNode().getAttributes().getNamedItem("entityID");
					if (entityIDNode != null) {
						entityId = entityIDNode.getNodeValue();
					}
				}

				if (entityId != null && !entityId.isEmpty()) {
					metadataInfo.put(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY, entityId);
				}

				NodeList ssoNodes = Util.query(xmlDocument, "./md:SingleSignOnService[@Binding=\"" + desiredSSOBinding + "\"]", idpDescriptorNode);
				if (ssoNodes.getLength() < 1) {
					ssoNodes = Util.query(xmlDocument, "./md:SingleSignOnService", idpDescriptorNode);
				}
				if (ssoNodes.getLength() > 0) {
					metadataInfo.put(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY, ssoNodes.item(0).getAttributes().getNamedItem("Location").getNodeValue());
					metadataInfo.put(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY, ssoNodes.item(0).getAttributes().getNamedItem("Binding").getNodeValue());
				}

				NodeList sloNodes = Util.query(xmlDocument, "./md:SingleLogoutService[@Binding=\"" + desiredSLOBinding + "\"]", idpDescriptorNode);
				if (sloNodes.getLength() < 1) {
					sloNodes = Util.query(xmlDocument, "./md:SingleLogoutService", idpDescriptorNode);
				}
				if (sloNodes.getLength() > 0) {
					metadataInfo.put(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, sloNodes.item(0).getAttributes().getNamedItem("Location").getNodeValue());
					metadataInfo.put(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY, sloNodes.item(0).getAttributes().getNamedItem("Binding").getNodeValue());
				}

				NodeList keyDescriptorCertSigningNodes = Util.query(xmlDocument, "./md:KeyDescriptor[not(contains(@use, \"encryption\"))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
						idpDescriptorNode);

				NodeList keyDescriptorCertEncryptionNodes = Util.query(xmlDocument, "./md:KeyDescriptor[not(contains(@use, \"signing\"))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
						idpDescriptorNode);

				if (keyDescriptorCertSigningNodes.getLength() > 0 || keyDescriptorCertEncryptionNodes.getLength() > 0) {

					boolean hasEncryptionCert = keyDescriptorCertEncryptionNodes.getLength() > 0;
					String encryptionCert = null;

					if (hasEncryptionCert) {
						encryptionCert = keyDescriptorCertEncryptionNodes.item(0).getTextContent();
						metadataInfo.put(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY, encryptionCert);
					}

					if (keyDescriptorCertSigningNodes.getLength() > 0) {
						int index = 0;
						for (int i = 0; i < keyDescriptorCertSigningNodes.getLength(); i++) {
							String signingCert = keyDescriptorCertSigningNodes.item(i).getTextContent();
							if (i == 0 && !hasEncryptionCert) {
								metadataInfo.put(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY, signingCert);
							} else if (!hasEncryptionCert || !encryptionCert.equals(signingCert)) {
								metadataInfo.put(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + (index++), signingCert);
							}
						}
					}
				}

				NodeList nameIdFormatNodes = Util.query(xmlDocument, "./md:NameIDFormat", idpDescriptorNode);
				for (int i = 0; i < nameIdFormatNodes.getLength(); i++) {
					String nameIdFormat = nameIdFormatNodes.item(i).getTextContent();
					if (nameIdFormat != null && (desiredNameIdFormat == null || desiredNameIdFormat.equals(nameIdFormat))) {
						metadataInfo.put(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY, nameIdFormat);
						break;
					}
				}
			}
		} catch (XPathException e) {
			String errorMsg = "Error parsing metadata. " + e.getMessage();
			LOGGER.error(errorMsg, e);
			throw e;
		}

		return metadataInfo;
	}

	/**
	 * Get IdP Metadata Info from XML Document
	 * 
	 * @param xmlDocument
	 *            XML document that contains IdP metadata
	 * @param entityId
	 *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
	 * 
	 * @return Mapped values with metadata info in Saml2Settings format
	 * @throws XPathException
	 */
	public static Map<String, Object> parseXML(Document xmlDocument, String entityId) throws XPathException {
		return parseXML(xmlDocument, entityId, null, Constants.BINDING_HTTP_REDIRECT, Constants.BINDING_HTTP_REDIRECT);
	}

	/**
	 * Get IdP Metadata Info from XML Document
	 * 
	 * @param xmlDocument
	 *            XML document that contains IdP metadata
	 * 
	 * @return Mapped values with metadata info in Saml2Settings format
	 * @throws XPathException
	 */
	public static Map<String, Object> parseXML(Document xmlDocument) throws XPathException {
		return parseXML(xmlDocument, null);
	}

	/**
	 * Get IdP Metadata Info from XML file
	 * 
	 * @param xmlFileName
	 *            Filename of the XML filename that contains IdP metadata
	 * @param entityId
	 *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
	 * @param desiredNameIdFormat
	 *            If available on IdP metadata, use that nameIdFormat
	 * @param desiredSSOBinding
	 *            Parse specific binding SSO endpoint.
	 * @param desiredSLOBinding
	 *            Parse specific binding SLO endpoint.
	 * 
	 * @return Mapped values with metadata info in Saml2Settings format
	 * @throws Exception
	 */
	public static Map<String, Object> parseFileXML(String xmlFileName, String entityId, String desiredNameIdFormat, String desiredSSOBinding, String desiredSLOBinding) throws Exception {
		ClassLoader classLoader = IdPMetadataParser.class.getClassLoader();
		try (InputStream inputStream = classLoader.getResourceAsStream(xmlFileName)) {
			if (inputStream != null) {
				Document xmlDocument = Util.parseXML(new InputSource(inputStream));
				return parseXML(xmlDocument, entityId, desiredNameIdFormat, desiredSSOBinding, desiredSLOBinding);
			} else {
				throw new Exception("XML file '" + xmlFileName + "' not found in the classpath");
			}
		} catch (Exception e) {
			String errorMsg = "XML file'" + xmlFileName + "' cannot be loaded." + e.getMessage();
			LOGGER.error(errorMsg, e);
			throw new Error(errorMsg, Error.SETTINGS_FILE_NOT_FOUND);
		}
	}

	/**
	 * Get IdP Metadata Info from XML file
	 * 
	 * @param xmlFileName
	 *            Filename of the XML filename that contains IdP metadata
	 * @param entityId
	 *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
	 * 
	 * @return Mapped values with metadata info in Saml2Settings format
	 * @throws Exception
	 */
	public static Map<String, Object> parseFileXML(String xmlFileName, String entityId) throws Exception {
		return parseFileXML(xmlFileName, entityId, null, Constants.BINDING_HTTP_REDIRECT, Constants.BINDING_HTTP_REDIRECT);
	}

	/**
	 * Get IdP Metadata Info from XML file
	 * 
	 * @param xmlFileName
	 *            Filename of the XML filename that contains IdP metadata
	 * 
	 * @return Mapped values with metadata info in Saml2Settings format
	 * @throws Exception
	 */
	public static Map<String, Object> parseFileXML(String xmlFileName) throws Exception {
		return parseFileXML(xmlFileName, null);
	}

	/**
	 * Get IdP Metadata Info from XML file
	 * 
	 * @param xmlURL
	 *            URL to the XML document that contains IdP metadata
	 * @param entityId
	 *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
	 * @param desiredNameIdFormat
	 *            If available on IdP metadata, use that nameIdFormat
	 * @param desiredSSOBinding
	 *            Parse specific binding SSO endpoint.
	 * @param desiredSLOBinding
	 *            Parse specific binding SLO endpoint.
	 * 
	 * @return Mapped values with metadata info in Saml2Settings format
	 * @throws Exception
	 */
	public static Map<String, Object> parseRemoteXML(URL xmlURL, String entityId, String desiredNameIdFormat, String desiredSSOBinding, String desiredSLOBinding) throws Exception {
		Document xmlDocument = Util.parseXML(new InputSource(xmlURL.openStream()));
		return parseXML(xmlDocument, entityId, desiredNameIdFormat, desiredSSOBinding, desiredSLOBinding);
	}

	/**
	 * Get IdP Metadata Info from XML file
	 * 
	 * @param xmlURL
	 *            URL to the XML document that contains IdP metadata
	 * @param entityId
	 *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
	 * 
	 * @return Mapped values with metadata info in Saml2Settings format
	 * @throws Exception
	 */
	public static Map<String, Object> parseRemoteXML(URL xmlURL, String entityId) throws Exception {
		return parseRemoteXML(xmlURL, entityId, null, Constants.BINDING_HTTP_REDIRECT, Constants.BINDING_HTTP_REDIRECT);
	}

	/**
	 * Get IdP Metadata Info from XML file
	 * 
	 * @param xmlURL
	 *            URL to the XML document that contains IdP metadata
	 * 
	 * @return Mapped values with metadata info in Saml2Settings format
	 * @throws Exception
	 */
	public static Map<String, Object> parseRemoteXML(URL xmlURL) throws Exception {
		return parseRemoteXML(xmlURL, null);
	}

	/**
	 * Inject metadata info into Saml2Settings
	 *
	 * @param settings
	 *            the Saml2Settings object
	 * @param metadataInfo
	 *            mapped values with metadata info in Saml2Settings format
	 * 
	 * @return the Saml2Settings object with metadata info settings loaded
	 */
	public static Saml2Settings injectIntoSettings(Saml2Settings settings, Map<String, Object> metadataInfo) {

		SettingsBuilder settingsBuilder = new SettingsBuilder().fromValues(metadataInfo);
		settingsBuilder.build(settings);
		return settings;
	}

}
