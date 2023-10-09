package com.onelogin.saml2.settings;

import java.net.URL;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.xpath.XPathExpressionException;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import com.onelogin.saml2.model.Contact;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.model.AttributeConsumingService;
import com.onelogin.saml2.model.RequestedAttribute;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

/**
 * Metadata class of Java Toolkit.
 *
 * A class that contains methods related to the metadata of the SP
 */
public class Metadata {
	/**
	 * Private property to construct a logger for this class.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(Metadata.class);

	// Constants
	private static final int N_DAYS_VALID_UNTIL = 2;
	private static final int SECONDS_CACHED = 604800; // 1 week

	/**
     * AttributeConsumingService
     */
	private AttributeConsumingService attributeConsumingService = null;

	/**
	 * Generated metadata in string format
	 */
	private final String metadataString;

	/**
	 * validUntilTime of the metadata. How long the metadata is valid
	 */
	private final Calendar validUntilTime;

	/**
	 * cacheDuration of the metadata. Duration of the cache in seconds
	 */
	private final Integer cacheDuration;

	/**
	 * Constructs the Metadata object.
	 *
	 * @param settings                  Saml2Settings object. Setting data
	 * @param validUntilTime            Metadata's valid time
	 * @param cacheDuration             Duration of the cache in seconds
	 * @param attributeConsumingService AttributeConsumingService of service provider
	 * @throws CertificateEncodingException
	 */
	public Metadata(Saml2Settings settings, Calendar validUntilTime, Integer cacheDuration, AttributeConsumingService attributeConsumingService) throws CertificateEncodingException {
		this.validUntilTime = validUntilTime;
		this.attributeConsumingService = attributeConsumingService;
		this.cacheDuration = cacheDuration;

		StrSubstitutor substitutor = generateSubstitutor(settings);
		String unsignedMetadataString = postProcessXml(substitutor.replace(getMetadataTemplate()), settings);

		LOGGER.debug("metadata --> " + unsignedMetadataString);
		metadataString = unsignedMetadataString;
	}

	/**
	 * Constructs the Metadata object.
	 *
	 * @param settings       Saml2Settings object. Setting data
	 * @param validUntilTime Metadata's valid time
	 * @param cacheDuration  Duration of the cache in seconds
	 * @throws CertificateEncodingException
	 */
	public Metadata(Saml2Settings settings, Calendar validUntilTime, Integer cacheDuration) throws CertificateEncodingException {
		this(settings, validUntilTime, cacheDuration, null);
	}

	/**
	 * Constructs the Metadata object.
	 *
	 * @param settings Saml2Settings object. Setting data
	 * @throws CertificateEncodingException
	 */
	public Metadata(Saml2Settings settings) throws CertificateEncodingException {

		this.validUntilTime = Calendar.getInstance();
		this.validUntilTime.add(Calendar.DAY_OF_YEAR, N_DAYS_VALID_UNTIL);

		this.cacheDuration = SECONDS_CACHED;

		StrSubstitutor substitutor = generateSubstitutor(settings);
		String unsignedMetadataString = postProcessXml(substitutor.replace(getMetadataTemplate()), settings);

		LOGGER.debug("metadata --> " + unsignedMetadataString);
		metadataString = unsignedMetadataString;
	}

	/**
	 * Allows for an extension class to post-process the SAML metadata XML generated
	 * for this metadata instance, in order to customize the result.
	 * <p>
	 * This method is invoked at construction time, after all the other fields of
	 * this class have already been initialised. Its default implementation simply
	 * returns the input XML as-is, with no change.
	 *
	 * @param metadataXml
	 *              the XML produced for this metadata instance by the standard
	 *              implementation provided by {@link Metadata}
	 * @param settings
	 *              the settings
	 * @return the post-processed XML for this metadata instance, which will then be
	 *         returned by any call to {@link #getMetadataString()}
	 */
	protected String postProcessXml(final String metadataXml, final Saml2Settings settings) {
		return metadataXml;
	}

	/**
	 * Substitutes metadata variables within a string by values.
	 *
	 * @param settings Saml2Settings object. Setting data
	 * @return the StrSubstitutor object of the metadata
	 */
	private StrSubstitutor generateSubstitutor(Saml2Settings settings) throws CertificateEncodingException {

		Map<String, String> valueMap = new HashMap<String, String>();
		Boolean wantsEncrypted = settings.getWantAssertionsEncrypted() || settings.getWantNameIdEncrypted();

		valueMap.put("id", Util.toXml(Util.generateUniqueID(settings.getUniqueIDPrefix())));
		String validUntilTimeStr = "";
		if (validUntilTime != null) {
			String validUntilTimeValue = Util.formatDateTime(validUntilTime.getTimeInMillis());
			validUntilTimeStr = " validUntil=\"" + validUntilTimeValue + "\"";
		}
		valueMap.put("validUntilTimeStr", validUntilTimeStr);

		String cacheDurationStr = "";
		if (cacheDuration != null) {
			String cacheDurationValue = String.valueOf(cacheDuration);
			cacheDurationStr = " cacheDuration=\"PT" + cacheDurationValue + "S\"";
		}
		valueMap.put("cacheDurationStr", cacheDurationStr);

		valueMap.put("spEntityId", Util.toXml(settings.getSpEntityId()));
		valueMap.put("strAuthnsign", String.valueOf(settings.getAuthnRequestsSigned()));
		valueMap.put("strWsign", String.valueOf(settings.getWantAssertionsSigned()));
		valueMap.put("spNameIDFormat", Util.toXml(settings.getSpNameIDFormat()));
		valueMap.put("spAssertionConsumerServiceBinding", Util.toXml(settings.getSpAssertionConsumerServiceBinding()));
		valueMap.put("spAssertionConsumerServiceUrl", Util.toXml(settings.getSpAssertionConsumerServiceUrl().toString()));
		valueMap.put("sls", toSLSXml(settings.getSpSingleLogoutServiceUrl(), settings.getSpSingleLogoutServiceBinding()));

		valueMap.put("strAttributeConsumingService", getAttributeConsumingServiceXml());

		valueMap.put("strKeyDescriptor", toX509KeyDescriptorsXML(settings.getSPcert(), settings.getSPcertNew(), wantsEncrypted));

		valueMap.put("strContacts", toContactsXml(settings.getContacts()));
		valueMap.put("strOrganization", toOrganizationXml(settings.getOrganization()));

		return new StrSubstitutor(valueMap);
	}

	/**
	 * @return the metadata's template
	 */
	private static StringBuilder getMetadataTemplate() {

		StringBuilder template = new StringBuilder();
		template.append("<?xml version=\"1.0\"?>");
		template.append("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"");
		template.append("${validUntilTimeStr}");
		template.append("${cacheDurationStr}");
		template.append(" entityID=\"${spEntityId}\"");
		template.append(" ID=\"${id}\">");
		template.append("<md:SPSSODescriptor AuthnRequestsSigned=\"${strAuthnsign}\" WantAssertionsSigned=\"${strWsign}\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">");
		template.append("${strKeyDescriptor}");
		template.append("${sls}<md:NameIDFormat>${spNameIDFormat}</md:NameIDFormat>");
		template.append("<md:AssertionConsumerService Binding=\"${spAssertionConsumerServiceBinding}\"");
		template.append(" Location=\"${spAssertionConsumerServiceUrl}\"");
		template.append(" index=\"1\"/>");
		template.append("${strAttributeConsumingService}");
		template.append("</md:SPSSODescriptor>${strOrganization}${strContacts}");
		template.append("</md:EntityDescriptor>");

		return template;
	}

	/**
	 * Generates the AttributeConsumingService section of the metadata's template
	 *
	 * @return the AttributeConsumingService section of the metadata's template
	 */
	private String getAttributeConsumingServiceXml() {
		StringBuilder attributeConsumingServiceXML = new StringBuilder();
		if (attributeConsumingService != null) {
			String serviceName = attributeConsumingService.getServiceName();
			String serviceDescription = attributeConsumingService.getServiceDescription();
			List<RequestedAttribute> requestedAttributes = attributeConsumingService.getRequestedAttributes();

			attributeConsumingServiceXML.append("<md:AttributeConsumingService index=\"1\">");
			if (serviceName != null && !serviceName.isEmpty()) {
				attributeConsumingServiceXML.append("<md:ServiceName xml:lang=\"en\">" + Util.toXml(serviceName) + "</md:ServiceName>");
			}
			if (serviceDescription != null && !serviceDescription.isEmpty()) {
				attributeConsumingServiceXML.append("<md:ServiceDescription xml:lang=\"en\">" + Util.toXml(serviceDescription) + "</md:ServiceDescription>");
			}
			if (requestedAttributes != null && !requestedAttributes.isEmpty()) {
				for (RequestedAttribute requestedAttribute : requestedAttributes) {
					String name = requestedAttribute.getName();
					String friendlyName = requestedAttribute.getFriendlyName();
					String nameFormat = requestedAttribute.getNameFormat();
					Boolean isRequired = requestedAttribute.isRequired();
					List<String> attrValues = requestedAttribute.getAttributeValues();

					String contentStr = "<md:RequestedAttribute";

					if (name != null && !name.isEmpty()) {
						contentStr += " Name=\"" + Util.toXml(name) + "\"";
					}

					if (nameFormat != null && !nameFormat.isEmpty()) {
						contentStr += " NameFormat=\"" + Util.toXml(nameFormat) + "\"";
					}

					if (friendlyName != null && !friendlyName.isEmpty()) {
						contentStr += " FriendlyName=\"" + Util.toXml(friendlyName) + "\"";
					}

					if (isRequired != null) {
						contentStr += " isRequired=\"" + isRequired.toString() + "\"";
					}

					if (attrValues != null && !attrValues.isEmpty()) {
						contentStr += ">";
						for (String attrValue : attrValues) {
							contentStr += "<saml:AttributeValue xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + Util.toXml(attrValue) + "</saml:AttributeValue>";
						}
						attributeConsumingServiceXML.append(contentStr + "</md:RequestedAttribute>");
					} else {
						attributeConsumingServiceXML.append(contentStr + " />");
					}
				}
			}
			attributeConsumingServiceXML.append("</md:AttributeConsumingService>");
		}

		return attributeConsumingServiceXML.toString();
	}

	/**
	 * Generates the contact section of the metadata's template
	 *
	 * @param contacts List of contact objects
	 * @return the contact section of the metadata's template
	 */
	private String toContactsXml(List<Contact> contacts) {
		StringBuilder contactsXml = new StringBuilder();

		for (Contact contact : contacts) {
			contactsXml.append("<md:ContactPerson contactType=\"" + Util.toXml(contact.getContactType()) + "\">");
			final String company = contact.getCompany();
			if(company != null)
				contactsXml.append("<md:Company>" + Util.toXml(company) + "</md:Company>");
			final String givenName = contact.getGivenName();
			if(givenName != null)
				contactsXml.append("<md:GivenName>" + Util.toXml(givenName) + "</md:GivenName>");
			final String surName = contact.getSurName();
			if(surName != null)
				contactsXml.append("<md:SurName>" + Util.toXml(surName) + "</md:SurName>");
			final List<String> emailAddresses = contact.getEmailAddresses();
			emailAddresses.forEach(emailAddress -> contactsXml
			            .append("<md:EmailAddress>" + Util.toXml(emailAddress) + "</md:EmailAddress>"));
			final List<String> telephoneNumbers = contact.getTelephoneNumbers();
			telephoneNumbers.forEach(telephoneNumber -> contactsXml
			            .append("<md:TelephoneNumber>" + Util.toXml(telephoneNumber) + "</md:TelephoneNumber>"));
			contactsXml.append("</md:ContactPerson>");
		}

		return contactsXml.toString();
	}

	/**
	 * Generates the organization section of the metadata's template
	 *
	 * @param organization organization object
	 * @return the organization section of the metadata's template
	 */
	private String toOrganizationXml(Organization organization) {
		String orgXml = "";

		if (organization != null) {
			String lang = organization.getOrgLangAttribute();
			orgXml = "<md:Organization><md:OrganizationName xml:lang=\"" + Util.toXml(lang) + "\">" + Util.toXml(organization.getOrgName())
					+ "</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"" + Util.toXml(lang) + "\">"
					+ Util.toXml(organization.getOrgDisplayName()) + "</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\""
					+ Util.toXml(lang) + "\">" + Util.toXml(organization.getOrgUrl()) + "</md:OrganizationURL></md:Organization>";
		}
		return orgXml;
	}

	/**
	 * Generates the KeyDescriptor section of the metadata's template
	 * @param cert the public cert that will be used by the SP to sign and encrypt
	 * @param wantsEncrypted Whether to include the KeyDescriptor for encryption
	 * @return the KeyDescriptor section of the metadata's template
	 */
	private String toX509KeyDescriptorsXML(X509Certificate cert, Boolean wantsEncrypted) throws CertificateEncodingException {
		return this.toX509KeyDescriptorsXML(cert, null, wantsEncrypted);
	}

	/**
	 * Generates the KeyDescriptor section of the metadata's template
	 *
	 * @param certCurrent the public cert that will be used by the SP to sign and encrypt
	 * @param certNew the public cert that will be used by the SP to sign and encrypt in future
	 * @param wantsEncrypted Whether to include the KeyDescriptor for encryption
	 *
	 * @return the KeyDescriptor section of the metadata's template
	 */
	private String toX509KeyDescriptorsXML(X509Certificate certCurrent, X509Certificate certNew, Boolean wantsEncrypted) throws CertificateEncodingException {
		StringBuilder keyDescriptorXml = new StringBuilder();

		List<X509Certificate> certs = Arrays.asList(certCurrent, certNew);
		for(X509Certificate cert : certs) {
		    if (cert != null) {
	            Base64 encoder = new Base64(64);
	            byte[] encodedCert = cert.getEncoded();
	            String certString = new String(encoder.encode(encodedCert));

	            keyDescriptorXml.append("<md:KeyDescriptor use=\"signing\">");
	            keyDescriptorXml.append("<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
	            keyDescriptorXml.append("<ds:X509Data>");
	            keyDescriptorXml.append("<ds:X509Certificate>"+certString+"</ds:X509Certificate>");
	            keyDescriptorXml.append("</ds:X509Data>");
	            keyDescriptorXml.append("</ds:KeyInfo>");
	            keyDescriptorXml.append("</md:KeyDescriptor>");

	            if (wantsEncrypted) {
	                keyDescriptorXml.append("<md:KeyDescriptor use=\"encryption\">");
	                keyDescriptorXml.append("<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
	                keyDescriptorXml.append("<ds:X509Data>");
	                keyDescriptorXml.append("<ds:X509Certificate>"+certString+"</ds:X509Certificate>");
	                keyDescriptorXml.append("</ds:X509Data>");
	                keyDescriptorXml.append("</ds:KeyInfo>");
	                keyDescriptorXml.append("</md:KeyDescriptor>");
	            }
	        }
		}

		return keyDescriptorXml.toString();
	}

	/**
	 * @return the md:SingleLogoutService section of the metadata's template
	 */
	private String toSLSXml(URL spSingleLogoutServiceUrl, String spSingleLogoutServiceBinding) {
		StringBuilder slsXml = new StringBuilder();

		if (spSingleLogoutServiceUrl != null) {
			slsXml.append("<md:SingleLogoutService Binding=\"" + Util.toXml(spSingleLogoutServiceBinding) + "\"");
			slsXml.append(" Location=\"" + Util.toXml(spSingleLogoutServiceUrl.toString()) + "\"/>");
		}
		return slsXml.toString();
	}

	/**
	 * @return the metadata
	 */
	public final String getMetadataString() {
		return metadataString;
	}

	/**
	 * Signs the metadata with the key/cert provided
	 *
	 * @param metadata      SAML Metadata XML
	 * @param key           Private Key
	 * @param cert          x509 Public certificate
	 * @param signAlgorithm Signature Algorithm
	 * @return string Signed Metadata
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 */
	public static String signMetadata(String metadata, PrivateKey key, X509Certificate cert, String signAlgorithm) throws XPathExpressionException, XMLSecurityException {
		return signMetadata(metadata, key, cert, signAlgorithm, Constants.SHA1);
	}

	/**
	 * Signs the metadata with the key/cert provided
	 *
	 * @param metadata        SAML Metadata XML
	 * @param key             Private Key
	 * @param cert            x509 Public certificate
	 * @param signAlgorithm   Signature Algorithm
	 * @param digestAlgorithm Digest Algorithm
	 * @return string Signed Metadata
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 */
	public static String signMetadata(String metadata, PrivateKey key, X509Certificate cert, String signAlgorithm, String digestAlgorithm) throws XPathExpressionException, XMLSecurityException {
		Document metadataDoc = Util.loadXML(metadata);
		String signedMetadata = Util.addSign(metadataDoc, key, cert, signAlgorithm, digestAlgorithm);
		LOGGER.debug("Signed metadata --> " + signedMetadata);
		return signedMetadata;
	}
}
