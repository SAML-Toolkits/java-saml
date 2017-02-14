package com.onelogin.saml2.settings;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.model.Contact;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.util.Util;

/**
 * SettingsBuilder class of OneLogin's Java Toolkit.
 *
 * A class that implements the settings builder
 */ 
public class SettingsBuilder {
	/**
     * Private property to construct a logger for this class.
     */
	private static final Logger LOGGER = LoggerFactory.getLogger(SettingsBuilder.class);

	/**
     * Private property that contains the SAML settings
     */
	private Properties prop = new Properties();

	/**
     * Saml2Settings object
     */
	private Saml2Settings saml2Setting;

	public final static String STRICT_PROPERTY_KEY = "onelogin.saml2.strict";
	public final static String DEBUG_PROPERTY_KEY = "onelogin.saml2.debug";

	// SP
	public final static String SP_ENTITYID_PROPERTY_KEY = "onelogin.saml2.sp.entityid";
	public final static String SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY = "onelogin.saml2.sp.assertion_consumer_service.url";
	public final static String SP_ASSERTION_CONSUMER_SERVICE_BINDING_PROPERTY_KEY = "onelogin.saml2.sp.assertion_consumer_service.binding";
	public final static String SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY = "onelogin.saml2.sp.single_logout_service.url";
	public final static String SP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY = "onelogin.saml2.sp.single_logout_service.binding";
	public final static String SP_NAMEIDFORMAT_PROPERTY_KEY = "onelogin.saml2.sp.nameidformat";

	public final static String SP_X509CERT_PROPERTY_KEY = "onelogin.saml2.sp.x509cert";
	public final static String SP_PRIVATEKEY_PROPERTY_KEY = "onelogin.saml2.sp.privatekey";

	// IDP
	public final static String IDP_ENTITYID_PROPERTY_KEY = "onelogin.saml2.idp.entityid";
	public final static String IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY = "onelogin.saml2.idp.single_sign_on_service.url";
	public final static String IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY = "onelogin.saml2.idp.single_sign_on_service.binding";
	public final static String IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY = "onelogin.saml2.idp.single_logout_service.url";
	public final static String IDP_SINGLE_LOGOUT_SERVICE_RESPONSE_URL_PROPERTY_KEY = "onelogin.saml2.idp.single_logout_service.response.url";
	public final static String IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY = "onelogin.saml2.idp.single_logout_service.binding";

	public final static String IDP_X509CERT_PROPERTY_KEY = "onelogin.saml2.idp.x509cert";
	public final static String CERTFINGERPRINT_PROPERTY_KEY = "onelogin.saml2.idp.certfingerprint";
	public final static String CERTFINGERPRINT_ALGORITHM_PROPERTY_KEY = "onelogin.saml2.idp.certfingerprint_algorithm";

	// Security
	public final static String SECURITY_NAMEID_ENCRYPTED = "onelogin.saml2.security.nameid_encrypted";
	public final static String SECURITY_AUTHREQUEST_SIGNED = "onelogin.saml2.security.authnrequest_signed";
	public final static String SECURITY_LOGOUTREQUEST_SIGNED = "onelogin.saml2.security.logoutrequest_signed";
	public final static String SECURITY_LOGOUTRESPONSE_SIGNED = "onelogin.saml2.security.logoutresponse_signed";
	public final static String SECURITY_WANT_MESSAGES_SIGNED = "onelogin.saml2.security.want_messages_signed";
	public final static String SECURITY_WANT_ASSERTIONS_SIGNED = "onelogin.saml2.security.want_assertions_signed";
	public final static String SECURITY_WANT_ASSERTIONS_ENCRYPTED = "onelogin.saml2.security.want_assertions_encrypted";
	public final static String SECURITY_WANT_NAMEID = "onelogin.saml2.security.want_nameid";
	public final static String SECURITY_WANT_NAMEID_ENCRYPTED = "onelogin.saml2.security.want_nameid_encrypted";
	public final static String SECURITY_SIGN_METADATA = "onelogin.saml2.security.sign_metadata";
	public final static String SECURITY_REQUESTED_AUTHNCONTEXT = "onelogin.saml2.security.requested_authncontext";
	public final static String SECURITY_REQUESTED_AUTHNCONTEXTCOMPARISON = "onelogin.saml2.security.requested_authncontextcomparison";
	public final static String SECURITY_WANT_XML_VALIDATION = "onelogin.saml2.security.want_xml_validation";
	public final static String SECURITY_SIGNATURE_ALGORITHM = "onelogin.saml2.security.signature_algorithm";
	public final static String SECURITY_REJECT_UNSOLICITED_RESPONSES_WITH_INRESPONSETO = "onelogin.saml2.security.reject_unsolicited_responses_with_inresponseto";

	// Compress
	public final static String COMPRESS_REQUEST = "onelogin.saml2.compress.request";
	public final static String COMPRESS_RESPONSE = "onelogin.saml2.compress.response";
	
	// Misc
	public final static String CONTACT_TECHNICAL_GIVEN_NAME = "onelogin.saml2.contacts.technical.given_name";
	public final static String CONTACT_TECHNICAL_EMAIL_ADDRESS = "onelogin.saml2.contacts.technical.email_address";
	public final static String CONTACT_SUPPORT_GIVEN_NAME = "onelogin.saml2.contacts.support.given_name";
	public final static String CONTACT_SUPPORT_EMAIL_ADDRESS = "onelogin.saml2.contacts.support.email_address";

	public final static String ORGANIZATION_NAME = "onelogin.saml2.organization.name";
	public final static String ORGANIZATION_DISPLAYNAME = "onelogin.saml2.organization.displayname";
	public final static String ORGANIZATION_URL = "onelogin.saml2.organization.url";

	/**
	 * Load settings from the file
	 *
	 * @param propFileName
	 *            OneLogin_Saml2_Settings
	 *
	 * @return the SettingsBuilder object with the settings loaded from the file
	 *
	 * @throws IOException
	 * @throws Error
	 */
	public SettingsBuilder fromFile(String propFileName) throws IOException, Error {
		this.loadPropFile(propFileName);
		return this;
	}

	/**
	 * Loads the settings from the properties file
	 *
	 * @param propFileName
	 *            the name of the file
	 *
	 * @throws IOException
	 * @throws Error
	 */
	private void loadPropFile(String propFileName) throws IOException, Error {

		InputStream inputStream = null;

		try {
			inputStream = getClass().getClassLoader().getResourceAsStream(propFileName);
			if (inputStream != null) {
				this.prop.load(inputStream);
				LOGGER.debug("properties file " + propFileName + "loaded succesfully");
			} else {
				String errorMsg = "properties file '" + propFileName + "' not found in the classpath";
				LOGGER.error(errorMsg);
				throw new Error(errorMsg, Error.SETTINGS_FILE_NOT_FOUND);
			}
		} finally {
			try {
				if (inputStream != null) {
					inputStream.close();
				}
			} catch (IOException e) {
				LOGGER.warn("properties file '"  + propFileName +  "' not closed properly.");
			}
		}
	}

	/**
	 * Loads the settings from a properties object
	 *
	 * @param prop
	 *            contains the properties
	 *
	 * @return the SettingsBuilder object with the settings loaded from the prop object
	 */
	public SettingsBuilder fromProperties(Properties prop) {
	    this.prop = prop;
	    return this;
	}

	/**
	 * Builds the Saml2Settings object. Read the Properties object and set all the SAML settings
	 * 
	 * @return the Saml2Settings object with all the SAML settings loaded
	 *
	 * @throws IOException
	 */
	public Saml2Settings build() throws IOException {

		saml2Setting = new Saml2Settings();
		
		Boolean strict = loadBooleanProperty(STRICT_PROPERTY_KEY);
		if (strict != null)
			saml2Setting.setStrict(strict);

		Boolean debug = loadBooleanProperty(DEBUG_PROPERTY_KEY);
		if (debug != null)
			saml2Setting.setDebug(debug);

		this.loadSpSetting();
		this.loadIdpSetting();
		this.loadSecuritySetting();
		this.loadCompressSetting();
		
		saml2Setting.setContacts(loadContacts());

		saml2Setting.setOrganization(loadOrganization());

		return saml2Setting;
	}
	
	/**
	 * Loads the IdP settings from the properties file
	 */
	private void loadIdpSetting() {
		String idpEntityID = loadStringProperty(IDP_ENTITYID_PROPERTY_KEY);
		if (idpEntityID != null)
			saml2Setting.setIdpEntityId(idpEntityID);

		URL idpSingleSignOnServiceUrl = loadURLProperty(IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY);
		if (idpSingleSignOnServiceUrl != null)
			saml2Setting.setIdpSingleSignOnServiceUrl(idpSingleSignOnServiceUrl);

		String idpSingleSignOnServiceBinding = loadStringProperty(IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY);
		if (idpSingleSignOnServiceBinding != null)
			saml2Setting.setIdpSingleSignOnServiceBinding(idpSingleSignOnServiceBinding);

		URL idpSingleLogoutServiceUrl = loadURLProperty(IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY);
		if (idpSingleLogoutServiceUrl != null)
			saml2Setting.setIdpSingleLogoutServiceUrl(idpSingleLogoutServiceUrl);

		URL idpSingleLogoutServiceResponseUrl = loadURLProperty(IDP_SINGLE_LOGOUT_SERVICE_RESPONSE_URL_PROPERTY_KEY);
		if (idpSingleLogoutServiceResponseUrl != null)
			saml2Setting.setIdpSingleLogoutServiceResponseUrl(idpSingleLogoutServiceResponseUrl);

		String idpSingleLogoutServiceBinding = loadStringProperty(IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY);
		if (idpSingleLogoutServiceBinding != null)
			saml2Setting.setIdpSingleLogoutServiceBinding(idpSingleLogoutServiceBinding);

		X509Certificate idpX509cert = loadCertificateFromProp(IDP_X509CERT_PROPERTY_KEY);
		if (idpX509cert != null)
			saml2Setting.setIdpx509cert(idpX509cert);

		String idpCertFingerprint = loadStringProperty(CERTFINGERPRINT_PROPERTY_KEY);
		if (idpCertFingerprint != null)
			saml2Setting.setIdpCertFingerprint(idpCertFingerprint);

		String idpCertFingerprintAlgorithm = loadStringProperty(CERTFINGERPRINT_ALGORITHM_PROPERTY_KEY);
		if (idpCertFingerprintAlgorithm != null && !idpCertFingerprintAlgorithm.isEmpty())
			saml2Setting.setIdpCertFingerprintAlgorithm(idpCertFingerprintAlgorithm);
	}

	/**
	 * Loads the security settings from the properties file
	 */
	private void loadSecuritySetting() {
		Boolean nameIdEncrypted = loadBooleanProperty(SECURITY_NAMEID_ENCRYPTED);
		if (nameIdEncrypted != null)
			saml2Setting.setNameIdEncrypted(nameIdEncrypted);

		Boolean authnRequestsSigned = loadBooleanProperty(SECURITY_AUTHREQUEST_SIGNED);
		if (authnRequestsSigned != null)
			saml2Setting.setAuthnRequestsSigned(authnRequestsSigned);

		Boolean logoutRequestSigned = loadBooleanProperty(SECURITY_LOGOUTREQUEST_SIGNED);
		if (logoutRequestSigned != null)
			saml2Setting.setLogoutRequestSigned(logoutRequestSigned);

		Boolean logoutResponseSigned = loadBooleanProperty(SECURITY_LOGOUTRESPONSE_SIGNED);
		if (logoutResponseSigned != null)
			saml2Setting.setLogoutResponseSigned(logoutResponseSigned);

		Boolean wantMessagesSigned = loadBooleanProperty(SECURITY_WANT_MESSAGES_SIGNED);
		if (wantMessagesSigned != null)
			saml2Setting.setWantMessagesSigned(wantMessagesSigned);

		Boolean wantAssertionsSigned = loadBooleanProperty(SECURITY_WANT_ASSERTIONS_SIGNED);
		if (wantAssertionsSigned != null)
			saml2Setting.setWantAssertionsSigned(wantAssertionsSigned);

		Boolean wantAssertionsEncrypted = loadBooleanProperty(SECURITY_WANT_ASSERTIONS_ENCRYPTED);
		if (wantAssertionsEncrypted != null)
			saml2Setting.setWantAssertionsEncrypted(wantAssertionsEncrypted);

		Boolean wantNameId = loadBooleanProperty(SECURITY_WANT_NAMEID);
		if (wantNameId != null)
			saml2Setting.setWantNameId(wantNameId);

		Boolean wantNameIdEncrypted = loadBooleanProperty(SECURITY_WANT_NAMEID_ENCRYPTED);
		if (wantNameIdEncrypted != null)
			saml2Setting.setWantNameIdEncrypted(wantNameIdEncrypted);

		Boolean wantXMLValidation = loadBooleanProperty(SECURITY_WANT_XML_VALIDATION);
		if (wantXMLValidation != null)
			saml2Setting.setWantXMLValidation(wantXMLValidation);

		Boolean signMetadata = loadBooleanProperty(SECURITY_SIGN_METADATA);
		if (signMetadata != null)
			saml2Setting.setSignMetadata(signMetadata);

		List<String> requestedAuthnContext = loadListProperty(SECURITY_REQUESTED_AUTHNCONTEXT);
		if (requestedAuthnContext != null)
			saml2Setting.setRequestedAuthnContext(requestedAuthnContext);

		String requestedAuthnContextComparison = loadStringProperty(SECURITY_REQUESTED_AUTHNCONTEXTCOMPARISON);
		if (requestedAuthnContextComparison != null && !requestedAuthnContextComparison.isEmpty())
			saml2Setting.setRequestedAuthnContextComparison(requestedAuthnContextComparison);

		String signatureAlgorithm = loadStringProperty(SECURITY_SIGNATURE_ALGORITHM);
		if (signatureAlgorithm != null && !signatureAlgorithm.isEmpty())
			saml2Setting.setSignatureAlgorithm(signatureAlgorithm);

		Boolean rejectUnsolicitedResponsesWithInResponseTo = loadBooleanProperty(SECURITY_REJECT_UNSOLICITED_RESPONSES_WITH_INRESPONSETO);
		if (rejectUnsolicitedResponsesWithInResponseTo != null) {
			saml2Setting.setRejectUnsolicitedResponsesWithInResponseTo(rejectUnsolicitedResponsesWithInResponseTo);
		}
	}

	/**
	 * Loads the compress settings from the properties file
	 */
	private void loadCompressSetting() {
		Boolean compressRequest = loadBooleanProperty(COMPRESS_REQUEST);
		if (compressRequest != null) {
			saml2Setting.setCompressRequest(compressRequest);
		}

		Boolean compressResponse = loadBooleanProperty(COMPRESS_RESPONSE);
		if (compressResponse != null) {
			saml2Setting.setCompressResponse(compressResponse);
		}		
	}
	
	/**
	 * Loads the organization settings from the properties file
	 */
	private Organization loadOrganization() {
		Organization orgResult = null;

		String orgName = loadStringProperty(ORGANIZATION_NAME);
		String orgDisplayName = loadStringProperty(ORGANIZATION_DISPLAYNAME);
		URL orgUrl = loadURLProperty(ORGANIZATION_URL);

		if ((orgName != null && !orgName.isEmpty()) || (orgDisplayName != null && !orgDisplayName.isEmpty()) || (orgUrl != null)) {
			orgResult = new Organization(orgName, orgDisplayName, orgUrl);
		}

		return orgResult;
	}

	/**
	 * Loads the contacts settings from the properties file
	 */
	private List<Contact> loadContacts() {
		List<Contact> contacts = new LinkedList<Contact>();

		String technicalGn = loadStringProperty(CONTACT_TECHNICAL_GIVEN_NAME);
		String technicalEmailAddress = loadStringProperty(CONTACT_TECHNICAL_EMAIL_ADDRESS);

		if ((technicalGn != null && !technicalGn.isEmpty()) || (technicalEmailAddress != null && !technicalEmailAddress.isEmpty())) {
			Contact technical = new Contact("technical", technicalGn, technicalEmailAddress);
			contacts.add(technical);
		}

		String supportGn = loadStringProperty(CONTACT_SUPPORT_GIVEN_NAME);
		String supportEmailAddress = loadStringProperty(CONTACT_SUPPORT_EMAIL_ADDRESS);

		if ((supportGn != null && !supportGn.isEmpty()) || (supportEmailAddress != null && !supportEmailAddress.isEmpty())) {
			Contact support = new Contact("support", supportGn, supportEmailAddress);
			contacts.add(support);
		}

		return contacts;
	}

	/**
	 * Loads the SP settings from the properties file
	 */
	private void loadSpSetting() {
		String spEntityID = loadStringProperty(SP_ENTITYID_PROPERTY_KEY);
		if (spEntityID != null)
			saml2Setting.setSpEntityId(spEntityID);

		URL assertionConsumerServiceUrl = loadURLProperty(SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY);
		if (assertionConsumerServiceUrl != null)
			saml2Setting.setSpAssertionConsumerServiceUrl(assertionConsumerServiceUrl);

		String spAssertionConsumerServiceBinding = loadStringProperty(SP_ASSERTION_CONSUMER_SERVICE_BINDING_PROPERTY_KEY);
		if (spAssertionConsumerServiceBinding != null)
			saml2Setting.setSpAssertionConsumerServiceBinding(spAssertionConsumerServiceBinding);

		URL spSingleLogoutServiceUrl = loadURLProperty(SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY);
		if (spSingleLogoutServiceUrl != null)
			saml2Setting.setSpSingleLogoutServiceUrl(spSingleLogoutServiceUrl);

		String spSingleLogoutServiceBinding = loadStringProperty(SP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY);
		if (spSingleLogoutServiceBinding != null)
			saml2Setting.setSpSingleLogoutServiceBinding(spSingleLogoutServiceBinding);

		String spNameIDFormat = loadStringProperty(SP_NAMEIDFORMAT_PROPERTY_KEY);
		if (spNameIDFormat != null && !spNameIDFormat.isEmpty())
			saml2Setting.setSpNameIDFormat(spNameIDFormat);

		X509Certificate spX509cert = loadCertificateFromProp(SP_X509CERT_PROPERTY_KEY);
		if (spX509cert != null)
			saml2Setting.setSpX509cert(spX509cert);

		PrivateKey spPrivateKey = loadPrivateKeyFromProp(SP_PRIVATEKEY_PROPERTY_KEY);
		if (spPrivateKey != null)
			saml2Setting.setSpPrivateKey(spPrivateKey);
	}

	/**
	 * Loads a property of the type String from the Properties object
	 *
	 * @param propertyKey
	 *            the property name
	 *
	 * @return the value
	 */
	private String loadStringProperty(String propertyKey) {
		String propValue = prop.getProperty(propertyKey);
		if (propValue != null) {
			propValue = propValue.trim();
		}
		return propValue;
	}

	/**
	 * Loads a property of the type Boolean from the Properties object
	 *
	 * @param propertyKey
	 *            the property name
	 *
	 * @return the value
	 */
	private Boolean loadBooleanProperty(String propertyKey) {
		String booleanPropValue = prop.getProperty(propertyKey);
		if (booleanPropValue != null) {
			return Boolean.parseBoolean(booleanPropValue.trim());
		} else {
			return null;
		}
	}

	/**
	 * Loads a property of the type List from the Properties object
	 *
	 * @param propertyKey
	 *            the property name
	 *
	 * @return the value
	 */
	private List<String> loadListProperty(String propertyKey) {
		String arrayPropValue = prop.getProperty(propertyKey);
		if (arrayPropValue != null && !arrayPropValue.isEmpty()) {
			String [] values = arrayPropValue.trim().split(",");
			for (int i = 0; i < values.length; i++) {
				values[i] = values[i].trim();
			}
			return Arrays.asList(values);
		} else {
			return null;
		}
	}

	/**
	 * Loads a property of the type URL from the Properties object
	 *
	 * @param propertyKey
	 *            the property name
	 *
	 * @return the value
	 */
	private URL loadURLProperty(String propertyKey) {

		String urlPropValue = prop.getProperty(propertyKey);

		if (urlPropValue == null || urlPropValue.isEmpty()) {
			return null;
		} else {
			try {
				return new URL(urlPropValue.trim());
			} catch (MalformedURLException e) {
				LOGGER.error("'" + propertyKey + "' contains malformed url.", e);
				return null;
			}
		}
	}
	
	/**
	 * Loads a property of the type X509Certificate from the Properties object
	 *
	 * @param propertyKey
	 *            the property name
	 *
	 * @return the X509Certificate object
	 */
	protected X509Certificate loadCertificateFromProp(String propertyKey) {
		String certString = prop.getProperty(propertyKey);

		if (certString == null || certString.isEmpty()) {
			return null;
		} else {
			try {
				return Util.loadCert(certString);
			} catch (CertificateException e) {
				LOGGER.error("Error loading certificate from properties.", e);
				return null;
			} catch (UnsupportedEncodingException e) {
				LOGGER.error("the certificate is not in correct format.", e);
				return null;
			}
		}
	}

	/**
	 * Loads a property of the type X509Certificate from file
	 *
	 * @param filename
	 *            the file name of the file that contains the X509Certificate
	 *
	 * @return the X509Certificate object
	 */
	/*
	protected X509Certificate loadCertificateFromFile(String filename) {
		String certString = null;

		try {
			certString = Util.getFileAsString(filename.trim());
		} catch (URISyntaxException e) {
			LOGGER.error("Error loading certificate from file.", e);
			return null;
		}
		catch (IOException e) {
			LOGGER.error("Error loading certificate from file.", e);
			return null;
		}
		
		try {
			return Util.loadCert(certString);
		} catch (CertificateException e) {
			LOGGER.error("Error loading certificate from file.", e);
			return null;
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("the certificate is not in correct format.", e);
			return null;
		}
	}
	*/

	/**
	 * Loads a property of the type PrivateKey from the Properties object
	 *
	 * @param propertyKey
	 *            the property name
	 *
	 * @return the PrivateKey object
	 */
	protected PrivateKey loadPrivateKeyFromProp(String propertyKey) {
		String keyString = prop.getProperty(propertyKey);

		if (keyString == null || keyString.isEmpty()) {
			return null;
		} else {
			try {
				return Util.loadPrivateKey(keyString);
			} catch (Exception e) {
				LOGGER.error("Error loading privatekey from properties.", e);
				return null;
			}
		}
	}

	/**
	 * Loads a property of the type PrivateKey from file
	 *
	 * @param filename
	 *            the file name of the file that contains the PrivateKey
	 *
	 * @return the PrivateKey object
	 */
	/*
	protected PrivateKey loadPrivateKeyFromFile(String filename) {
		String keyString = null;
		
		try {
			keyString = Util.getFileAsString(filename.trim());
		} catch (URISyntaxException e) {
			LOGGER.error("Error loading privatekey from file.", e);
			return null;
		} catch (IOException e) {
			LOGGER.error("Error loading privatekey from file.", e);
			return null;
		}
		
		try {
			return Util.loadPrivateKey(keyString);
		} catch (GeneralSecurityException e) {
			LOGGER.error("Error loading privatekey from file.", e);
			return null;
		} catch (IOException e) {
			LOGGER.debug("Error loading privatekey from file.", e);
			return null;
		}
	}
	*/
}
