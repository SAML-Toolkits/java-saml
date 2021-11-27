package com.onelogin.saml2.settings;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Properties;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.model.Contact;
import com.onelogin.saml2.model.KeyStoreSettings;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.util.Constants;
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
	private Map<String, Object> samlData = new LinkedHashMap<>();

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
	public final static String SP_X509CERTNEW_PROPERTY_KEY = "onelogin.saml2.sp.x509certNew";

	public final static String SP_CONTACT_PROPERTY_KEY_PREFIX = "onelogin.saml2.sp.contact";
	public final static String SP_CONTACT_CONTACT_TYPE_PROPERTY_KEY_SUFFIX = "contactType";
	public final static String SP_CONTACT_COMPANY_PROPERTY_KEY_SUFFIX = "company";
	public final static String SP_CONTACT_GIVEN_NAME_PROPERTY_KEY_SUFFIX = "given_name";
	public final static String SP_CONTACT_SUR_NAME_PROPERTY_KEY_SUFFIX = "sur_name";
	public final static String SP_CONTACT_EMAIL_ADDRESS_PROPERTY_KEY_PREFIX = "email_address";
	public final static String SP_CONTACT_TELEPHONE_NUMBER_PROPERTY_KEY_PREFIX = "telephone_number";
	
	// KeyStore
	public final static String KEYSTORE_KEY = "onelogin.saml2.keystore.store";
	public final static String KEYSTORE_ALIAS = "onelogin.saml2.keystore.alias";
	public final static String KEYSTORE_KEY_PASSWORD = "onelogin.saml2.keystore.key.password";

	// IDP
	public final static String IDP_ENTITYID_PROPERTY_KEY = "onelogin.saml2.idp.entityid";
	public final static String IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY = "onelogin.saml2.idp.single_sign_on_service.url";
	public final static String IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY = "onelogin.saml2.idp.single_sign_on_service.binding";
	public final static String IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY = "onelogin.saml2.idp.single_logout_service.url";
	public final static String IDP_SINGLE_LOGOUT_SERVICE_RESPONSE_URL_PROPERTY_KEY = "onelogin.saml2.idp.single_logout_service.response.url";
	public final static String IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY = "onelogin.saml2.idp.single_logout_service.binding";

	public final static String IDP_X509CERT_PROPERTY_KEY = "onelogin.saml2.idp.x509cert";
	public final static String IDP_X509CERTMULTI_PROPERTY_KEY = "onelogin.saml2.idp.x509certMulti";
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
	public final static String SECURITY_DIGEST_ALGORITHM = "onelogin.saml2.security.digest_algorithm";
	public final static String SECURITY_REJECT_UNSOLICITED_RESPONSES_WITH_INRESPONSETO = "onelogin.saml2.security.reject_unsolicited_responses_with_inresponseto";
	public final static String SECURITY_ALLOW_REPEAT_ATTRIBUTE_NAME_PROPERTY_KEY = "onelogin.saml2.security.allow_duplicated_attribute_name";
	public final static String SECURITY_REJECT_DEPRECATED_ALGORITHM = "onelogin.saml2.security.reject_deprecated_alg";

	// Compress
	public final static String COMPRESS_REQUEST = "onelogin.saml2.compress.request";
	public final static String COMPRESS_RESPONSE = "onelogin.saml2.compress.response";

	// Parsing
	public final static String PARSING_TRIM_NAME_IDS = "onelogin.saml2.parsing.trim_name_ids";
	public final static String PARSING_TRIM_ATTRIBUTE_VALUES = "onelogin.saml2.parsing.trim_attribute_values";
	
	// Misc
	@Deprecated
	public final static String CONTACT_TECHNICAL_GIVEN_NAME = "onelogin.saml2.contacts.technical.given_name";
	@Deprecated
	public final static String CONTACT_TECHNICAL_EMAIL_ADDRESS = "onelogin.saml2.contacts.technical.email_address";
	@Deprecated
	public final static String CONTACT_SUPPORT_GIVEN_NAME = "onelogin.saml2.contacts.support.given_name";
	@Deprecated
	public final static String CONTACT_SUPPORT_EMAIL_ADDRESS = "onelogin.saml2.contacts.support.email_address";

	public final static String ORGANIZATION_NAME = "onelogin.saml2.organization.name";
	public final static String ORGANIZATION_DISPLAYNAME = "onelogin.saml2.organization.displayname";
	public final static String ORGANIZATION_URL = "onelogin.saml2.organization.url";
	public final static String ORGANIZATION_LANG = "onelogin.saml2.organization.lang";
	public final static String UNIQUE_ID_PREFIX_PROPERTY_KEY = "onelogin.saml2.unique_id_prefix";

	/**
	 * Load settings from the file
	 *
	 * @param propFileName OneLogin_Saml2_Settings
	 *
	 * @return the SettingsBuilder object with the settings loaded from the file
	 *
	 * @throws IOException
	 * @throws Error
	 */
	public SettingsBuilder fromFile(String propFileName) throws Error, IOException {
		return fromFile(propFileName, null);
	}

	/**
	 * Load settings from the file
	 *
	 * @param propFileName OneLogin_Saml2_Settings
	 * @param keyStoreSetting KeyStore which have the Private/Public keys
	 * 
	 * @return the SettingsBuilder object with the settings loaded from the file
	 *
	 * @throws IOException
	 * @throws Error
	 */
	public SettingsBuilder fromFile(String propFileName, KeyStoreSettings keyStoreSetting) throws Error, IOException {

		ClassLoader classLoader = getClass().getClassLoader();
		try (InputStream inputStream = classLoader.getResourceAsStream(propFileName)) {
			if (inputStream != null) {
				Properties prop = new Properties();
				prop.load(inputStream);
				parseProperties(prop);
				LOGGER.debug("properties file '{}' loaded succesfully", propFileName);
			} else {
				String errorMsg = "properties file '" + propFileName + "' not found in the classpath";
				LOGGER.error(errorMsg);
				throw new Error(errorMsg, Error.SETTINGS_FILE_NOT_FOUND);
			}
		} catch (IOException e) {
			String errorMsg = "properties file'" + propFileName + "' cannot be loaded.";
			LOGGER.error(errorMsg, e);
			throw new Error(errorMsg, Error.SETTINGS_FILE_NOT_FOUND);
		}
		// Parse KeyStore and set the properties for SP Cert and Key
		if (keyStoreSetting != null) {
			parseKeyStore(keyStoreSetting);
		}

		return this;
	}

	/**
	 * Loads the settings from a properties object
	 *
	 * @param prop contains the properties
	 *
	 * @return the SettingsBuilder object with the settings loaded from the prop
	 *         object
	 */
	public SettingsBuilder fromProperties(Properties prop) {
		parseProperties(prop);
		return this;
	}

	/**
	 * Loads the settings from mapped values.
	 *
	 * @param samlData Mapped values.
	 *
	 * @return the SettingsBuilder object with the settings loaded from the prop
	 *         object
	 */
	public SettingsBuilder fromValues(Map<String, Object> samlData) {
	    return this.fromValues(samlData, null);
	}

	/**
	 * Loads the settings from mapped values and KeyStore settings.
	 *
	 * @param samlData Mapped values.
	 * @param keyStoreSetting KeyStore model
	 *
	 * @return the SettingsBuilder object with the settings loaded from the prop
	 *         object
	 */
	public SettingsBuilder fromValues(Map<String, Object> samlData, KeyStoreSettings keyStoreSetting) {
		if (samlData != null) {
		    this.samlData.putAll(samlData);
		}
		if (keyStoreSetting != null) {
		    parseKeyStore(keyStoreSetting);
		}
		return this;
	}

	/**
	 * Builds the Saml2Settings object. Read the Properties object and set all the
	 * SAML settings
	 *
	 * @return the Saml2Settings object with all the SAML settings loaded
	 *
	 */
	public Saml2Settings build() {
		return build(new Saml2Settings());
	}

	/**
	 * Builds the Saml2Settings object. Read the Properties object and set all the
	 * SAML settings
	 * 
	 * @param saml2Setting an existing Saml2Settings
	 * 
	 * @return the Saml2Settings object with all the SAML settings loaded
	 *
	 */
	public Saml2Settings build(Saml2Settings saml2Setting) {

		this.saml2Setting = saml2Setting;

		Boolean strict = loadBooleanProperty(STRICT_PROPERTY_KEY);
		if (strict != null) {
			saml2Setting.setStrict(strict);
		}

		Boolean debug = loadBooleanProperty(DEBUG_PROPERTY_KEY);
		if (debug != null) {
			saml2Setting.setDebug(debug);
		}

		this.loadSpSetting();
		this.loadIdpSetting();
		this.loadSecuritySetting();
		this.loadCompressSetting();
		this.loadParsingSetting();

		List<Contact> contacts = this.loadContacts();
		if (!contacts.isEmpty()) {
			saml2Setting.setContacts(contacts);
		}

		Organization org = this.loadOrganization();
		if (org != null) {
			saml2Setting.setOrganization(org);
		}

		String uniqueIdPrefix = loadUniqueIDPrefix();
		if (StringUtils.isNotEmpty(uniqueIdPrefix)) {
			saml2Setting.setUniqueIDPrefix(uniqueIdPrefix);
		} else if (saml2Setting.getUniqueIDPrefix() == null){
			saml2Setting.setUniqueIDPrefix(Util.UNIQUE_ID_PREFIX);
		}

		return saml2Setting;
	}

	/**
	 * Loads the IdP settings from the properties file
	 */
	private void loadIdpSetting() {
		String idpEntityID = loadStringProperty(IDP_ENTITYID_PROPERTY_KEY);
		if (idpEntityID != null) {
			saml2Setting.setIdpEntityId(idpEntityID);
		}

		URL idpSingleSignOnServiceUrl = loadURLProperty(IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY);
		if (idpSingleSignOnServiceUrl != null) {
			saml2Setting.setIdpSingleSignOnServiceUrl(idpSingleSignOnServiceUrl);
		}

		String idpSingleSignOnServiceBinding = loadStringProperty(IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY);
		if (idpSingleSignOnServiceBinding != null) {
			saml2Setting.setIdpSingleSignOnServiceBinding(idpSingleSignOnServiceBinding);
		}

		URL idpSingleLogoutServiceUrl = loadURLProperty(IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY);
		if (idpSingleLogoutServiceUrl != null) {
			saml2Setting.setIdpSingleLogoutServiceUrl(idpSingleLogoutServiceUrl);
		}

		URL idpSingleLogoutServiceResponseUrl = loadURLProperty(IDP_SINGLE_LOGOUT_SERVICE_RESPONSE_URL_PROPERTY_KEY);
		if (idpSingleLogoutServiceResponseUrl != null) {
			saml2Setting.setIdpSingleLogoutServiceResponseUrl(idpSingleLogoutServiceResponseUrl);
		}

		String idpSingleLogoutServiceBinding = loadStringProperty(IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY);
		if (idpSingleLogoutServiceBinding != null) {
			saml2Setting.setIdpSingleLogoutServiceBinding(idpSingleLogoutServiceBinding);
		}

		List<X509Certificate> idpX509certMulti = loadCertificateListFromProp(IDP_X509CERTMULTI_PROPERTY_KEY);
		if (idpX509certMulti != null) {
			saml2Setting.setIdpx509certMulti(idpX509certMulti);
		}

		X509Certificate idpX509cert = loadCertificateFromProp(IDP_X509CERT_PROPERTY_KEY);
		if (idpX509cert != null) {
			saml2Setting.setIdpx509cert(idpX509cert);
		}

		String idpCertFingerprint = loadStringProperty(CERTFINGERPRINT_PROPERTY_KEY);
		if (idpCertFingerprint != null) {
			saml2Setting.setIdpCertFingerprint(idpCertFingerprint);
		}

		String idpCertFingerprintAlgorithm = loadStringProperty(CERTFINGERPRINT_ALGORITHM_PROPERTY_KEY);
		if (idpCertFingerprintAlgorithm != null && !idpCertFingerprintAlgorithm.isEmpty()) {
			saml2Setting.setIdpCertFingerprintAlgorithm(idpCertFingerprintAlgorithm);
		}
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

		String digestAlgorithm = loadStringProperty(SECURITY_DIGEST_ALGORITHM);
		if (digestAlgorithm != null && !digestAlgorithm.isEmpty())
			saml2Setting.setDigestAlgorithm(digestAlgorithm);

		Boolean rejectUnsolicitedResponsesWithInResponseTo = loadBooleanProperty(SECURITY_REJECT_UNSOLICITED_RESPONSES_WITH_INRESPONSETO);
		if (rejectUnsolicitedResponsesWithInResponseTo != null) {
			saml2Setting.setRejectUnsolicitedResponsesWithInResponseTo(rejectUnsolicitedResponsesWithInResponseTo);
		}

		Boolean allowRepeatAttributeName = loadBooleanProperty(SECURITY_ALLOW_REPEAT_ATTRIBUTE_NAME_PROPERTY_KEY);
		if (allowRepeatAttributeName != null) {
			saml2Setting.setAllowRepeatAttributeName(allowRepeatAttributeName);
		}

		Boolean rejectDeprecatedAlg = loadBooleanProperty(SECURITY_REJECT_DEPRECATED_ALGORITHM);
		if (rejectDeprecatedAlg != null) {
			saml2Setting.setRejectDeprecatedAlg(rejectDeprecatedAlg);
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
	 * Loads the parsing settings from the properties file
	 */
	private void loadParsingSetting() {
		Boolean trimNameIds = loadBooleanProperty(PARSING_TRIM_NAME_IDS);
		if (trimNameIds != null) {
			saml2Setting.setTrimNameIds(trimNameIds);
		}

		Boolean trimAttributeValues = loadBooleanProperty(PARSING_TRIM_ATTRIBUTE_VALUES);
		if (trimAttributeValues != null) {
			saml2Setting.setTrimAttributeValues(trimAttributeValues);
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
		String orgLangAttribute = loadStringProperty(ORGANIZATION_LANG);

		if (StringUtils.isNotBlank(orgName) || StringUtils.isNotBlank(orgDisplayName) || orgUrl != null) {
			orgResult = new Organization(orgName, orgDisplayName, orgUrl, orgLangAttribute);
		}

		return orgResult;
	}

	/**
	 * Loads the contacts settings from the properties file
	 * 
	 * @return a list containing all the loaded contacts
	 */
	@SuppressWarnings("deprecation")
	private List<Contact> loadContacts() {
		// first split properties into a map of properties
		// key = contact index; value = contact properties
		final SortedMap<Integer, Map<String, Object>> contactProps = 
				extractIndexedProperties(SP_CONTACT_PROPERTY_KEY_PREFIX, samlData);
		// then build each contact
		// multiple indexed services specified
		final List<Contact> contacts = contactProps.entrySet().stream()
			            .map(entry -> loadContact(entry.getValue(), entry.getKey()))
			            .collect(Collectors.toList());
		// append legacy contacts if present
		String technicalGn = loadStringProperty(CONTACT_TECHNICAL_GIVEN_NAME);
		String technicalEmailAddress = loadStringProperty(CONTACT_TECHNICAL_EMAIL_ADDRESS);

		if ((technicalGn != null && !technicalGn.isEmpty()) || (technicalEmailAddress != null && !technicalEmailAddress.isEmpty())) {
			Contact technical = new Contact(Constants.CONTACT_TYPE_TECHNICAL, technicalGn, technicalEmailAddress);
			contacts.add(technical);
		}

		String supportGn = loadStringProperty(CONTACT_SUPPORT_GIVEN_NAME);
		String supportEmailAddress = loadStringProperty(CONTACT_SUPPORT_EMAIL_ADDRESS);

		if ((supportGn != null && !supportGn.isEmpty()) || (supportEmailAddress != null && !supportEmailAddress.isEmpty())) {
			Contact support = new Contact(Constants.CONTACT_TYPE_SUPPORT, supportGn, supportEmailAddress);
			contacts.add(support);
		}

		return contacts;
	}

	/**
	 * Loads a single contact from settings.
	 * 
	 * @param contactProps
	 *              a map containing the contact settings
	 * @param index
	 *              the contact index
	 * @return the loaded contact
	 */
	private Contact loadContact(Map<String, Object> contactProps, int index) {
		final String contactType =  loadStringProperty(SP_CONTACT_CONTACT_TYPE_PROPERTY_KEY_SUFFIX, contactProps);
		final String company = loadStringProperty(SP_CONTACT_COMPANY_PROPERTY_KEY_SUFFIX, contactProps);
		final String givenName = loadStringProperty(SP_CONTACT_GIVEN_NAME_PROPERTY_KEY_SUFFIX, contactProps);
		final String surName = loadStringProperty(SP_CONTACT_SUR_NAME_PROPERTY_KEY_SUFFIX, contactProps);
		// split properties into a map of properties
		// key = e-mail address index; value = e-mail address
		final SortedMap<Integer, Object> emailAddresses = extractIndexedValues(SP_CONTACT_EMAIL_ADDRESS_PROPERTY_KEY_PREFIX, contactProps);
		final List<String> emails = toStringList(emailAddresses);
		// split properties into a map of properties
		// key = phone number index; value = phone numbers
		final SortedMap<Integer, Object> phoneNumbers = extractIndexedValues(SP_CONTACT_TELEPHONE_NUMBER_PROPERTY_KEY_PREFIX, contactProps);
		final List<String> numbers = toStringList(phoneNumbers);
		return new Contact(contactType, company, givenName, surName, emails, numbers);
	}

	/**
	 * Given a map containing settings data, extracts all the indexed properties
	 * identified by a given prefix. The returned map has indexes as keys and a map
	 * describing the extracted indexed data as values. Keys are sorted by their
	 * natural order (i.e. iterating over the map will return entries in index order).
	 * <p>
	 * For instance, if the prefix is <code>foo</code>, all the following properties
	 * will be extracted:
	 * 
	 * <pre>
	 * foo[0].prop1=&lt;value1&gt;
	 * foo[0].prop2=&lt;value2&gt;
	 * foo[1].prop1=&lt;value3&gt;
	 * </pre>
	 * 
	 * and the returned map will be:
	 * 
	 * <pre>
	 * 0 => prop1=&lt;value1&gt;
	 *      prop2=&lt;value2&gt;
	 * 1 => prop1=&lt;value3&gt;
	 * </pre>
	 * 
	 * The index is optional: if missing, "-1" is returned. In other words, in the
	 * above example:
	 * 
	 * <pre>
	 * foo.prop1=&lt;value1&gt;
	 * foo.prop2=&lt;value2&gt;
	 * </pre>
	 * 
	 * will be mapped to:
	 * 
	 * <pre>
	 * -1 => prop1=&lt;value1&gt;
	 *       prop2=&lt;value2&gt;
	 * </pre>
	 * 
	 * Indices can be made of maximum 9 digits, to prevent overflows. Leading zeroes
	 * are discarded.
	 * 
	 * @param prefix
	 *              the prefix that identifies the indexed property to extract
	 * @param data
	 *              the input data
	 * @return a map with extracted data for each identified index
	 */
	private SortedMap<Integer, Map<String, Object>> extractIndexedProperties(String prefix, Map<String, Object> data) {
		final Pattern p = Pattern.compile(Pattern.quote(prefix) + 
				"(?:\\[(\\d{1,9})\\])?\\.(.+)");
		final SortedMap<Integer, Map<String, Object>> indexedProps = new TreeMap<>();
		for(final Entry<String, Object> prop: data.entrySet()) {
			final Matcher m = p.matcher(prop.getKey());
			if(m.matches()) {
				final String indexString = m.group(1);
				final int index = indexString == null? -1: Integer.parseInt(indexString);
				final String suffix = m.group(2);
				Map<String, Object> props = indexedProps.get(index);
				if(props == null) {
					props = new HashMap<>();
					indexedProps.put(index, props);
				}
				props.put(suffix, prop.getValue());
			}
		}
		return indexedProps;
	}
	
	/**
	 * Given a map containing settings data, extracts all the indexed values
	 * identified by a given prefix. The returned map has indexes as keys and the
	 * corresponding values as values. Keys are sorted by their natural order 
	 * (i.e. iterating over the map will return entries in index order).
	 * <p>
	 * For instance, if the prefix is <code>foo</code>, all the following values
	 * will be extracted:
	 * 
	 * <pre>
	 * foo[0]=&lt;value1&gt;
	 * foo[1]=&lt;value2&gt;
	 * foo[2]=&lt;value3&gt;
	 * </pre>
	 * 
	 * and the returned map will be:
	 * 
	 * <pre>
	 * 0 => &lt;value1&gt;
	 * 1 => &lt;value2&gt;
	 * 3 => &lt;value3&gt;
	 * </pre>
	 * 
	 * The index is optional: if missing, "-1" is returned. In other words, in the
	 * above example:
	 * 
	 * <pre>
	 * foo=&lt;value1&gt;
	 * </pre>
	 * 
	 * will be mapped to:
	 * 
	 * <pre>
	 * -1 => &lt;value1&gt;
	 * </pre>
	 * 
	 * Indices can be made of maximum 9 digits, to prevent overflows. Leading zeroes
	 * are discarded.
	 * 
	 * @param prefix
	 *              the prefix that identifies the indexed property to extract
	 * @param data
	 *              the input data
	 * @return a map with extracted values for each identified index
	 */
	private SortedMap<Integer, Object> extractIndexedValues(String prefix, Map<String, Object> data) {
		final Pattern p = Pattern.compile(Pattern.quote(prefix) + 
				"(?:\\[(\\d{1,9})\\])?");
		final SortedMap<Integer, Object> indexedValues = new TreeMap<>();
		for(final Entry<String, Object> prop: data.entrySet()) {
			final Matcher m = p.matcher(prop.getKey());
			if(m.matches()) {
				final String indexString = m.group(1);
				final int index = indexString == null? -1: Integer.parseInt(indexString);
				indexedValues.put(index, prop.getValue());
			}
		}
		return indexedValues;
	}
	
	/**
	 * Given a map of indexed property values (possibly extracted with
	 * {@link #extractIndexedValues(String, Map)}), returns a list containing all
	 * the {@link String} values contained in the map, sorted by their iteration
	 * order.
	 * 
	 * @param indexedValues
	 *              a map containing indexed values (key = index; value = actual
	 *              value)
	 * @return a list containing all the string values in the input map, sorted by
	 *         their iteration order; therefore, if the map is a {@link SortedMap},
	 *         the returned list has values sorted by their index
	 */
	private List<String> toStringList(final Map<Integer, Object> indexedValues) {
		return indexedValues.values().stream()
		            .map(value -> isString(value) ? StringUtils.trimToNull((String) value) : null)
		            .filter(Objects::nonNull).collect(Collectors.toList());
	}

	/**
	 * Loads the unique ID prefix. Uses default if property not set.
	 */
	private String loadUniqueIDPrefix() {
		String uniqueIDPrefix = loadStringProperty(UNIQUE_ID_PREFIX_PROPERTY_KEY);
		return uniqueIDPrefix;
	}

	/**
	 * Loads the SP settings from the properties file
	 */
	private void loadSpSetting() {
		String spEntityID = loadStringProperty(SP_ENTITYID_PROPERTY_KEY);
		if (spEntityID != null) {
			saml2Setting.setSpEntityId(spEntityID);
		}

		URL assertionConsumerServiceUrl = loadURLProperty(SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY);
		if (assertionConsumerServiceUrl != null) {
			saml2Setting.setSpAssertionConsumerServiceUrl(assertionConsumerServiceUrl);
		}

		String spAssertionConsumerServiceBinding = loadStringProperty(SP_ASSERTION_CONSUMER_SERVICE_BINDING_PROPERTY_KEY);
		if (spAssertionConsumerServiceBinding != null) {
			saml2Setting.setSpAssertionConsumerServiceBinding(spAssertionConsumerServiceBinding);
		}

		URL spSingleLogoutServiceUrl = loadURLProperty(SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY);
		if (spSingleLogoutServiceUrl != null) {
			saml2Setting.setSpSingleLogoutServiceUrl(spSingleLogoutServiceUrl);
		}

		String spSingleLogoutServiceBinding = loadStringProperty(SP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY);
		if (spSingleLogoutServiceBinding != null) {
			saml2Setting.setSpSingleLogoutServiceBinding(spSingleLogoutServiceBinding);
		}

		String spNameIDFormat = loadStringProperty(SP_NAMEIDFORMAT_PROPERTY_KEY);
		if (spNameIDFormat != null && !spNameIDFormat.isEmpty()) {
			saml2Setting.setSpNameIDFormat(spNameIDFormat);
		}

		boolean keyStoreEnabled = this.samlData.get(KEYSTORE_KEY) != null && this.samlData.get(KEYSTORE_ALIAS) != null
				&& this.samlData.get(KEYSTORE_KEY_PASSWORD) != null;

		X509Certificate spX509cert;
		PrivateKey spPrivateKey;

		if (keyStoreEnabled) {
			KeyStore ks = (KeyStore) this.samlData.get(KEYSTORE_KEY);
			String alias = (String) this.samlData.get(KEYSTORE_ALIAS);
			String password = (String) this.samlData.get(KEYSTORE_KEY_PASSWORD);

			spX509cert = getCertificateFromKeyStore(ks, alias, password);
			spPrivateKey = getPrivateKeyFromKeyStore(ks, alias, password);
		} else {
			spX509cert = loadCertificateFromProp(SP_X509CERT_PROPERTY_KEY);
			spPrivateKey = loadPrivateKeyFromProp(SP_PRIVATEKEY_PROPERTY_KEY);
		}

		if (spX509cert != null) {
			saml2Setting.setSpX509cert(spX509cert);
		}
		if (spPrivateKey != null) {
			saml2Setting.setSpPrivateKey(spPrivateKey);
		}

		X509Certificate spX509certNew = loadCertificateFromProp(SP_X509CERTNEW_PROPERTY_KEY);
		if (spX509certNew != null) {
			saml2Setting.setSpX509certNew(spX509certNew);
		}
	}

	/**
	 * Loads a property of the type String from the Properties object
	 *
	 * @param propertyKey the property name
	 *
	 * @return the value
	 */
	private String loadStringProperty(String propertyKey) {
		return loadStringProperty(propertyKey, samlData);
	}

	/**
	 * Loads a property of the type String from the specified data
	 *
	 * @param propertyKey the property name
	 * @param data the input data
	 *
	 * @return the value
	 */
	private String loadStringProperty(String propertyKey, Map<String, Object> data) {
		Object propValue = data.get(propertyKey);
		if (isString(propValue)) {
			return StringUtils.trimToNull((String) propValue);
		}
		return null;
	}
	
	/**
	 * Loads a property of the type Boolean from the Properties object
	 *
	 * @param propertyKey the property name
	 *
	 * @return the value
	 */
	private Boolean loadBooleanProperty(String propertyKey) {
		Object propValue = samlData.get(propertyKey);
		if (isString(propValue)) {
			return Boolean.parseBoolean(((String) propValue).trim());
		}

		if (propValue instanceof Boolean) {
			return (Boolean) propValue;
		}
		return null;
	}

	/**
	 * Loads a property of the type List from the Properties object
	 *
	 * @param propertyKey the property name
	 *
	 * @return the value
	 */
	private List<String> loadListProperty(String propertyKey) {
		Object propValue = samlData.get(propertyKey);
		if (isString(propValue)) {
			String[] values = ((String) propValue).trim().split(",");
			for (int i = 0; i < values.length; i++) {
				values[i] = values[i].trim();
			}
			return Arrays.asList(values);
		}

		if (propValue instanceof List) {
			return (List<String>) propValue;
		}
		return null;
	}

	/**
	 * Loads a property of the type URL from the Properties object
	 *
	 * @param propertyKey the property name
	 *
	 * @return the value
	 */
	private URL loadURLProperty(String propertyKey) {

		Object propValue = samlData.get(propertyKey);

		if (isString(propValue)) {
			try {
				return new URL(((String) propValue).trim());
			} catch (MalformedURLException e) {
				LOGGER.error("'{}' contains malformed url.", propertyKey, e);
				return null;
			}
		}

		if (propValue instanceof URL) {
			return (URL) propValue;
		}

		return null;
	}

	protected PrivateKey getPrivateKeyFromKeyStore(KeyStore keyStore, String alias, String password) {
		Key key;
		try {
			if (keyStore.containsAlias(alias)) {
				key = keyStore.getKey(alias, password.toCharArray());
				if (key instanceof PrivateKey) {
					return (PrivateKey) key;
				}
			} else {
				LOGGER.error("Entry for alias {} not found in keystore", alias);
			}
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			LOGGER.error("Error loading private key from keystore. {}", e);
		}
		return null;
	}

	protected X509Certificate getCertificateFromKeyStore(KeyStore keyStore, String alias, String password) {
		try {
			if (keyStore.containsAlias(alias)) {
				Key key = keyStore.getKey(alias, password.toCharArray());
				if (key instanceof PrivateKey) {
					Certificate cert = keyStore.getCertificate(alias);
					if (cert instanceof X509Certificate) {
						return (X509Certificate) cert;
					}
				}
			} else {
				LOGGER.error("Entry for alias {} not found in keystore", alias);
			}
		} catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
			LOGGER.error("Error loading certificate from keystore. {}", e);
		}
		return null;
	}

	/**
	 * Loads a property of the type X509Certificate from the property value
	 *
	 * @param propValue the property value
	 *
	 * @return the X509Certificate object
	 */
	protected X509Certificate loadCertificateFromProp(Object propValue) {

		if (isString(propValue)) {
			try {
				return Util.loadCert(((String) propValue).trim());
			} catch (CertificateException e) {
				LOGGER.error("Error loading certificate from properties.", e);
				return null;
			}
		}

		if (propValue instanceof X509Certificate) {
			return (X509Certificate) propValue;
		}

		return null;
	}

	/**
	 * Loads a property of the type X509Certificate from the Properties object
	 *
	 * @param propertyKey the property name
	 *
	 * @return the X509Certificate object
	 */
	protected X509Certificate loadCertificateFromProp(String propertyKey) {
		return loadCertificateFromProp(samlData.get(propertyKey));
	}

	/**
	 * Loads a property of the type List of X509Certificate from the Properties
	 * object
	 *
	 * @param propertyKey the property name
	 *
	 * @return the X509Certificate object list
	 */
	private List<X509Certificate> loadCertificateListFromProp(String propertyKey) {
		List<X509Certificate> list = new ArrayList<X509Certificate>();

		int i = 0;
		while (true) {
			Object propValue = samlData.get(propertyKey + "." + i++);

			if (propValue == null)
				break;

			list.add(loadCertificateFromProp(propValue));
		}

		return list;
	}

	/**
	 * Loads a property of the type X509Certificate from file
	 *
	 * @param filename the file name of the file that contains the X509Certificate
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
	 * @param propertyKey the property name
	 *
	 * @return the PrivateKey object
	 */
	protected PrivateKey loadPrivateKeyFromProp(String propertyKey) {
		Object propValue = samlData.get(propertyKey);

		if (isString(propValue)) {
			try {
				return Util.loadPrivateKey(((String) propValue).trim());
			} catch (Exception e) {
				LOGGER.error("Error loading privatekey from properties.", e);
				return null;
			}
		}

		if (propValue instanceof PrivateKey) {
			return (PrivateKey) propValue;
		}

		return null;
	}

	/**
	 * Parses properties
	 *
	 * @param properties the Properties object to be parsed
	 */
	private void parseProperties(Properties properties) {
		if (properties != null) {
			for (String propertyKey : properties.stringPropertyNames()) {
				this.samlData.put(propertyKey, properties.getProperty(propertyKey));
			}
		}
	}

	/**
	 * Parses the KeyStore data
	 *
	 * @param setting the KeyStoreSettings object to be parsed
	 */
    private void parseKeyStore(KeyStoreSettings setting) {
		this.samlData.put(KEYSTORE_KEY, setting.getKeyStore());
		this.samlData.put(KEYSTORE_ALIAS, setting.getSpAlias());
		this.samlData.put(KEYSTORE_KEY_PASSWORD, setting.getSpKeyPass());
    }

	/**
	 * Aux method that verifies if an Object is an string
	 *
	 * @param propValue the Object to be verified
	 */
	private boolean isString(Object propValue) {
		return propValue instanceof String && StringUtils.isNotBlank((String) propValue);
	}
}
