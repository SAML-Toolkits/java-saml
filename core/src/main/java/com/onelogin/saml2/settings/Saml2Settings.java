package com.onelogin.saml2.settings;

import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.onelogin.saml2.model.Contact;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.SchemaFactory;
import com.onelogin.saml2.util.Util;

/**
 * Saml2Settings class of OneLogin's Java Toolkit.
 *
 * A class that implements the settings handler
 */ 
public class Saml2Settings {
	/**
     * Private property to construct a logger for this class.
     */
	private static final Logger LOGGER = LoggerFactory.getLogger(Saml2Settings.class);

	// Toolkit settings
	private boolean strict = false;
	private boolean debug = false;
	
	// SP
	private String spEntityId = "";
	private URL spAssertionConsumerServiceUrl = null;
	private String spAssertionConsumerServiceBinding = Constants.BINDING_HTTP_POST;
	private URL spSingleLogoutServiceUrl = null;
	private String spSingleLogoutServiceBinding = Constants.BINDING_HTTP_REDIRECT;
	private String spNameIDFormat = Constants.NAMEID_UNSPECIFIED;
	private X509Certificate spX509cert = null;
	private PrivateKey spPrivateKey = null;

	// IdP
	private String idpEntityId = "";
	private URL idpSingleSignOnServiceUrl = null;
	private String idpSingleSignOnServiceBinding = Constants.BINDING_HTTP_REDIRECT;
	private URL idpSingleLogoutServiceUrl = null;
	private URL idpSingleLogoutServiceResponseUrl = null;
	private String idpSingleLogoutServiceBinding = Constants.BINDING_HTTP_REDIRECT;
	private X509Certificate idpx509cert = null;
	private String idpCertFingerprint = null;
	private String idpCertFingerprintAlgorithm = "sha1";

	// Security
	private boolean nameIdEncrypted = false;
	private boolean authnRequestsSigned = false;
	private boolean logoutRequestSigned = false;
	private boolean logoutResponseSigned = false;
	private boolean wantMessagesSigned = false;
	private boolean wantAssertionsSigned = false;
	private boolean wantAssertionsEncrypted = false;
	private boolean wantNameId = true;
	private boolean wantNameIdEncrypted = false;
	private boolean signMetadata = false;
	private List<String> requestedAuthnContext = new ArrayList<>();
	private String requestedAuthnContextComparison = "exact";
	private boolean wantXMLValidation = true;
	private String signatureAlgorithm = Constants.RSA_SHA1;
	private boolean rejectUnsolicitedResponsesWithInResponseTo = false;

	// Compress
	private boolean compressRequest = true;
	private boolean compressResponse = true;

	// Misc
	private List<Contact> contacts = new LinkedList<>();
	private Organization organization = null;

	private boolean spValidationOnly = false;
	
	/**
	 * @return the strict setting value
	 */
	public final boolean isStrict() {
		return strict;
	}

	/**
	 * @return the spEntityId setting value
	 */
	public final String getSpEntityId() {
		return spEntityId;
	}

	/**
	 * @return the spAssertionConsumerServiceUrl
	 */
	public final URL getSpAssertionConsumerServiceUrl() {
		return spAssertionConsumerServiceUrl;
	}

	/**
	 * @return the spAssertionConsumerServiceBinding setting value
	 */
	public final String getSpAssertionConsumerServiceBinding() {
		return spAssertionConsumerServiceBinding;
	}

	/**
	 * @return the spSingleLogoutServiceUrl setting value
	 */
	public final URL getSpSingleLogoutServiceUrl() {
		return spSingleLogoutServiceUrl;
	}

	/**
	 * @return the spSingleLogoutServiceBinding setting value
	 */
	public final String getSpSingleLogoutServiceBinding() {
		return spSingleLogoutServiceBinding;
	}

	/**
	 * @return the spNameIDFormat setting value
	 */
	public final String getSpNameIDFormat() {
		return spNameIDFormat;
	}

	/**
	 * @return the spX509cert setting value
	 */
	public final X509Certificate getSPcert() {
		return spX509cert;
	}

	/**
	 * @return the spPrivateKey setting value
	 */
	public final PrivateKey getSPkey() {
		return spPrivateKey;
	}

	/**
	 * @return the idpEntityId setting value
	 */
	public final String getIdpEntityId() {
		return idpEntityId;
	}

	/**
	 * @return the idpSingleSignOnServiceUrl setting value
	 */
	public final URL getIdpSingleSignOnServiceUrl() {
		return idpSingleSignOnServiceUrl;
	}

	/**
	 * @return the idpSingleSignOnServiceBinding setting value
	 */
	public final String getIdpSingleSignOnServiceBinding() {
		return idpSingleSignOnServiceBinding;
	}

	/**
	 * @return the idpSingleLogoutServiceUrl setting value
	 */
	public final URL getIdpSingleLogoutServiceUrl() {
		return idpSingleLogoutServiceUrl;
	}

	/**
	 * @return the idpSingleLogoutServiceResponseUrl setting value
	 */
	public final URL getIdpSingleLogoutServiceResponseUrl() {
		if (idpSingleLogoutServiceResponseUrl == null) {
			return getIdpSingleLogoutServiceUrl();
		}

		return idpSingleLogoutServiceResponseUrl;
	}

	/**
	 * @return the idpSingleLogoutServiceBinding setting value
	 */
	public final String getIdpSingleLogoutServiceBinding() {
		return idpSingleLogoutServiceBinding;
	}

	/**
	 * @return the idpx509cert setting value
	 */
	public final X509Certificate getIdpx509cert() {
		return idpx509cert;
	}

	/**
	 * @return the idpCertFingerprint setting value
	 */
	public final String getIdpCertFingerprint() {
		return idpCertFingerprint;
	}

	/**
	 * @return the idpCertFingerprintAlgorithm setting value
	 */
	public final String getIdpCertFingerprintAlgorithm() {
		return idpCertFingerprintAlgorithm;
	}

	/**
	 * @return the nameIdEncrypted setting value
	 */
	public boolean getNameIdEncrypted() {
		return nameIdEncrypted;
	}

	/**
	 * @return the authnRequestsSigned setting value
	 */
	public boolean getAuthnRequestsSigned() {
		return authnRequestsSigned;
	}

	/**
	 * @return the logoutRequestSigned setting value
	 */
	public boolean getLogoutRequestSigned() {
		return logoutRequestSigned;
	}

	/**
	 * @return the logoutResponseSigned setting value
	 */
	public boolean getLogoutResponseSigned() {
		return logoutResponseSigned;
	}

	/**
	 * @return the wantMessagesSigned setting value
	 */
	public boolean getWantMessagesSigned() {
		return wantMessagesSigned;
	}

	/**
	 * @return the wantAssertionsSigned setting value
	 */
	public boolean getWantAssertionsSigned() {
		return wantAssertionsSigned;
	}

	/**
	 * @return the wantAssertionsEncrypted setting value
	 */
	public boolean getWantAssertionsEncrypted() {
		return wantAssertionsEncrypted;
	}

	/**
	 * @return the wantNameId setting value
	 */
	public boolean getWantNameId() {
		return wantNameId;
	}
	
	/**
	 * @return the wantNameIdEncrypted setting value
	 */
	public boolean getWantNameIdEncrypted() {
		return wantNameIdEncrypted;
	}

	/**
	 * @return the signMetadata setting value
	 */
	public boolean getSignMetadata() {
		return signMetadata;
	}

	/**
	 * @return the requestedAuthnContext setting value
	 */
	public List<String> getRequestedAuthnContext() {
		return requestedAuthnContext;
	}

	/**
	 * @return the requestedAuthnContextComparison setting value
	 */
	public String getRequestedAuthnContextComparison() {
		return requestedAuthnContextComparison;
	}

	/**
	 * @return the wantXMLValidation setting value
	 */
	public boolean getWantXMLValidation() {
		return wantXMLValidation;
	}

	/**
	 * @return the signatureAlgorithm setting value
	 */
	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	/**
	 * @return SP Contact info
	 */
	public List<Contact> getContacts() {
		return this.contacts;
	}

	/**
	 * @return SP Organization info
	 */
	public Organization getOrganization() {
		return this.organization;
	}

	/**
	 * @return if the debug is active or not
	 */
	public boolean isDebugActive() {
		return this.debug;
	}
	
	/**
	 * Set the strict setting value
	 * 
	 * @param strict
	 *            the strict to be set
	 */
	public void setStrict(boolean strict) {
		this.strict = strict;
	}

	/**
	 * Set the debug setting value
	 *
	 * @param debug
	 *            the debug mode to be set
	 */
	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	/**
	 * Set the spEntityId setting value
	 *
	 * @param spEntityId
	 *            the spEntityId value to be set
	 */
	protected final void setSpEntityId(String spEntityId) {
		this.spEntityId = spEntityId;
	}

	/**
	 * Set the spAssertionConsumerServiceUrl setting value
	 *
	 * @param spAssertionConsumerServiceUrl
	 *            the spAssertionConsumerServiceUrl value to be set
	 */
	protected final void setSpAssertionConsumerServiceUrl(URL spAssertionConsumerServiceUrl) {
		this.spAssertionConsumerServiceUrl = spAssertionConsumerServiceUrl;
	}

	/**
	 * Set the spAssertionConsumerServiceBinding setting value
	 *
	 * @param spAssertionConsumerServiceBinding
	 *            the spAssertionConsumerServiceBinding value to be set
	 */
	protected final void setSpAssertionConsumerServiceBinding(String spAssertionConsumerServiceBinding) {
		this.spAssertionConsumerServiceBinding = spAssertionConsumerServiceBinding;
	}

	/**
	 * Set the spSingleLogoutServiceUrl setting value
	 *
	 * @param spSingleLogoutServiceUrl
	 *            the spSingleLogoutServiceUrl value to be set
	 */
	protected final void setSpSingleLogoutServiceUrl(URL spSingleLogoutServiceUrl) {
		this.spSingleLogoutServiceUrl = spSingleLogoutServiceUrl;
	}

	/**
	 * Set the spSingleLogoutServiceBinding setting value
	 *
	 * @param spSingleLogoutServiceBinding
	 *            the spSingleLogoutServiceBinding value to be set
	 */
	protected final void setSpSingleLogoutServiceBinding(String spSingleLogoutServiceBinding) {
		this.spSingleLogoutServiceBinding = spSingleLogoutServiceBinding;
	}

	/**
	 * Set the spNameIDFormat setting value
	 *
	 * @param spNameIDFormat
	 *            the spNameIDFormat value to be set
	 */
	protected final void setSpNameIDFormat(String spNameIDFormat) {
		this.spNameIDFormat = spNameIDFormat;
	}

	/**
	 * Set the spX509cert setting value provided as X509Certificate object
	 *
	 * @param spX509cert
	 *            the spX509cert value to be set in X509Certificate format
	 */
	protected final void setSpX509cert(X509Certificate spX509cert) {
		this.spX509cert = spX509cert;
	}

	/**
	 * Set the spPrivateKey setting value provided as a PrivateKey object
	 *
	 * @param spPrivateKey
	 *            the spprivateKey value to be set in PrivateKey format
	 */
	protected final void setSpPrivateKey(PrivateKey spPrivateKey) {
		this.spPrivateKey = spPrivateKey;
	}

	/**
	 * Set the idpEntityId setting value
	 *
	 * @param idpEntityId
	 *            the idpEntityId value to be set
	 */
	protected final void setIdpEntityId(String idpEntityId) {
		this.idpEntityId = idpEntityId;
	}

	/**
	 * Set the idpSingleSignOnServiceUrl setting value
	 *
	 * @param idpSingleSignOnServiceUrl
	 *            the idpSingleSignOnServiceUrl value to be set
	 */
	protected final void setIdpSingleSignOnServiceUrl(URL idpSingleSignOnServiceUrl) {
		this.idpSingleSignOnServiceUrl = idpSingleSignOnServiceUrl;
	}

	/**
	 * Set the idpSingleSignOnServiceBinding setting value
	 *
	 * @param idpSingleSignOnServiceBinding
	 *            the idpSingleSignOnServiceBinding value to be set
	 */
	protected final void setIdpSingleSignOnServiceBinding(String idpSingleSignOnServiceBinding) {
		this.idpSingleSignOnServiceBinding = idpSingleSignOnServiceBinding;
	}

	/**
	 * Set the idpSingleLogoutServiceUrl setting value
	 *
	 * @param idpSingleLogoutServiceUrl
	 *            the idpSingleLogoutServiceUrl value to be set
	 */
	protected final void setIdpSingleLogoutServiceUrl(URL idpSingleLogoutServiceUrl) {
		this.idpSingleLogoutServiceUrl = idpSingleLogoutServiceUrl;
	}

	/**
	 * Set the idpSingleLogoutServiceUrl setting value
	 *
	 * @param idpSingleLogoutServiceResponseUrl
	 *            the idpSingleLogoutServiceUrl value to be set
	 */
	protected final void setIdpSingleLogoutServiceResponseUrl(URL idpSingleLogoutServiceResponseUrl) {
			this.idpSingleLogoutServiceResponseUrl = idpSingleLogoutServiceResponseUrl;
	}


	/**
	 * Set the idpSingleLogoutServiceBinding setting value
	 *
	 * @param idpSingleLogoutServiceBinding
	 *            the idpSingleLogoutServiceBinding value to be set
	 */
	protected final void setIdpSingleLogoutServiceBinding(String idpSingleLogoutServiceBinding) {
		this.idpSingleLogoutServiceBinding = idpSingleLogoutServiceBinding;
	}

	/**
	 * Set the idpX509cert setting value provided as a X509Certificate object
	 *
	 * @param idpX509cert
	 *            the idpX509cert value to be set in X509Certificate format
	 */
	protected final void setIdpx509cert(X509Certificate idpX509cert) {
		this.idpx509cert = idpX509cert;
	}

	/**
	 * Set the idpCertFingerprint setting value
	 *
	 * @param idpCertFingerprint
	 *            the idpCertFingerprint value to be set
	 */
	protected final void setIdpCertFingerprint(String idpCertFingerprint) {
		this.idpCertFingerprint = idpCertFingerprint;
	}

	/**
	 * Set the idpCertFingerprintAlgorithm setting value
	 *
	 * @param idpCertFingerprintAlgorithm
	 *            the idpCertFingerprintAlgorithm value to be set.
	 */
	protected final void setIdpCertFingerprintAlgorithm(String idpCertFingerprintAlgorithm) {
		this.idpCertFingerprintAlgorithm = idpCertFingerprintAlgorithm;
	}

	/**
	 * Set the nameIdEncrypted setting value
	 *
	 * @param nameIdEncrypted
	 *            the nameIdEncrypted value to be set. Based on it the SP will encrypt the NameID or not
	 */
	public void setNameIdEncrypted(boolean nameIdEncrypted) {
		this.nameIdEncrypted = nameIdEncrypted;
	}

	/**
	 * Set the authnRequestsSigned setting value
	 *
	 * @param authnRequestsSigned
	 *            the authnRequestsSigned value to be set. Based on it the SP will sign Logout Request or not
	 */
	public void setAuthnRequestsSigned(boolean authnRequestsSigned) {
		this.authnRequestsSigned = authnRequestsSigned;
	}

	/**
	 * Set the logoutRequestSigned setting value
	 *
	 * @param logoutRequestSigned
	 *            the logoutRequestSigned value to be set. Based on it the SP will sign Logout Request or not
	 */
	public void setLogoutRequestSigned(boolean logoutRequestSigned) {
		this.logoutRequestSigned = logoutRequestSigned;
	}

	/**
	 * Set the logoutResponseSigned setting value
	 *
	 * @param logoutResponseSigned
	 *            the logoutResponseSigned value to be set. Based on it the SP will sign Logout Response or not
	 */
	public void setLogoutResponseSigned(boolean logoutResponseSigned) {
		this.logoutResponseSigned = logoutResponseSigned;
	}

	/**
	 * Set the wantMessagesSigned setting value
	 *
	 * @param wantMessagesSigned
	 *            the wantMessagesSigned value to be set. Based on it the SP expects the SAML Messages to be signed or not
	 */
	public void setWantMessagesSigned(boolean wantMessagesSigned) {
		this.wantMessagesSigned = wantMessagesSigned;
	}

	/**
	 * Set the wantAssertionsSigned setting value
	 *
	 * @param wantAssertionsSigned
	 *            the wantAssertionsSigned value to be set. Based on it the SP expects the SAML Assertions to be signed or not
	 */
	public void setWantAssertionsSigned(boolean wantAssertionsSigned) {
		this.wantAssertionsSigned = wantAssertionsSigned;
	}

	/**
	 * Set the wantAssertionsEncrypted setting value
	 *
	 * @param wantAssertionsEncrypted
	 *            the wantAssertionsEncrypted value to be set. Based on it the SP expects the SAML Assertions to be encrypted or not
	 */
	public void setWantAssertionsEncrypted(boolean wantAssertionsEncrypted) {
		this.wantAssertionsEncrypted = wantAssertionsEncrypted;
	}

	/**
	 * Set the wantNameId setting value
	 *
	 * @param wantNameId
	 *            the wantNameId value to be set. Based on it the SP expects a NameID
	 */
	public void setWantNameId(boolean wantNameId) {
		this.wantNameId = wantNameId;
	}

	/**
	 * Set the wantNameIdEncrypted setting value
	 *
	 * @param wantNameIdEncrypted
	 *            the wantNameIdEncrypted value to be set. Based on it the SP expects the NameID to be encrypted or not
	 */
	public void setWantNameIdEncrypted(boolean wantNameIdEncrypted) {
		this.wantNameIdEncrypted = wantNameIdEncrypted;
	}

	/**
	 * Set the signMetadata setting value
	 *
	 * @param signMetadata
	 *            the signMetadata value to be set. Based on it the SP will sign or not the metadata with the SP PrivateKey/Certificate
	 */
	public void setSignMetadata(boolean signMetadata) {
		this.signMetadata = signMetadata;
	}

	/**
	 * Set the requestedAuthnContext setting value
	 *
	 * @param requestedAuthnContext
	 *            the requestedAuthnContext value to be set on the AuthNRequest.
	 */
	public void setRequestedAuthnContext(List<String> requestedAuthnContext) {
		if (requestedAuthnContext != null) {
			this.requestedAuthnContext = requestedAuthnContext;
		}
	}

	/**
	 * Set the requestedAuthnContextComparison setting value
	 *
	 * @param requestedAuthnContextComparison
	 *            the requestedAuthnContextComparison value to be set.
	 */
	public void setRequestedAuthnContextComparison(String requestedAuthnContextComparison) {
		this.requestedAuthnContextComparison = requestedAuthnContextComparison;
	}

	/**
	 * Set the wantXMLValidation setting value
	 *
	 * @param wantXMLValidation
	 *            the wantXMLValidation value to be set. Based on it the SP will validate SAML messages against the XML scheme 
	 */
	public void setWantXMLValidation(boolean wantXMLValidation) {
		this.wantXMLValidation = wantXMLValidation;
	}

	/**
	 * Set the signatureAlgorithm setting value
	 *
	 * @param signatureAlgorithm
	 *            the signatureAlgorithm value to be set.
	 */
	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	/**
	 * Controls if unsolicited Responses are rejected if they contain an InResponseTo value.
	 *
	 * If false using a validate method {@link com.onelogin.saml2.authn.SamlResponse#isValid(String)} with a null argument will
	 * accept messages with any (or none) InResponseTo value.
	 *
	 * If true using these methods with a null argument will only accept messages with no InRespoonseTo value,
	 * and reject messages where the value is set.
	 *
	 * In all cases using validate with a specified request ID will only accept responses that have the same
	 * InResponseTo id set.
	 *
	 * @param rejectUnsolicitedResponsesWithInResponseTo whether to strictly check the InResponseTo attribute
	 */
	public void setRejectUnsolicitedResponsesWithInResponseTo(boolean rejectUnsolicitedResponsesWithInResponseTo) {
		this.rejectUnsolicitedResponsesWithInResponseTo = rejectUnsolicitedResponsesWithInResponseTo;
	}

	public boolean isRejectUnsolicitedResponsesWithInResponseTo() {
		return rejectUnsolicitedResponsesWithInResponseTo;
	}

	/**
	 * Set the compressRequest setting value
	 *
	 * @param compressRequest
	 *            the compressRequest value to be set.
	 */
	public void setCompressRequest(boolean compressRequest) {
		this.compressRequest = compressRequest;
	}

	/**
	 * @return the compressRequest setting value
	 */
	public boolean isCompressRequestEnabled() {
		return compressRequest;
	}

	/**
	 * Set the compressResponse setting value
	 *
	 * @param compressResponse
	 *            the compressResponse value to be set.
	 */
	public void setCompressResponse(boolean compressResponse) {
		this.compressResponse = compressResponse;
	}

	/**
	 * @return the compressResponse setting value
	 */
	public boolean isCompressResponseEnabled() {
		return compressResponse;
	}

	/**
	 * Set contacts info that will be listed on the Service Provider metadata
	 * 
	 * @param contacts
	 *            the contacts to set
	 */
	protected final void setContacts(List<Contact> contacts) {
		this.contacts = contacts;
	}

	/**
	 * Set the organization info that will be published on the Service Provider metadata
	 *
	 * @param organization
	 *            the organization to set
	 */
	protected final void setOrganization(Organization organization) {
		this.organization = organization;
	}

	/**
	 * Checks the settings .
	 * 
	 * @return errors found on the settings data
	 */
	public List<String> checkSettings() {
		List<String> errors = new ArrayList<>(this.checkSPSettings());
		if (!spValidationOnly) { 
			errors.addAll(this.checkIdPSettings());
		}

		return errors;
	}
	
	/**
	 * Checks the IdP settings .
	 * 
	 * @return errors found on the IdP settings data
	 */
	public List<String> checkIdPSettings() {
		List<String> errors = new ArrayList<>();
		String errorMsg;

		if (!checkRequired(getIdpEntityId())) {
			errorMsg = "idp_entityId_not_found";
			errors.add(errorMsg);
			LOGGER.error(errorMsg);
		}

		if (!checkRequired(this.getIdpSingleSignOnServiceUrl())) {
			errorMsg = "idp_sso_url_invalid";
			errors.add(errorMsg);
			LOGGER.error(errorMsg);
		}

		if (this.getIdpx509cert() == null && !checkRequired(this.getIdpCertFingerprint())) {
			errorMsg = "idp_cert_or_fingerprint_not_found_and_required";
			errors.add(errorMsg);
			LOGGER.error(errorMsg);			
		}

		if (this.getNameIdEncrypted() == true && this.getIdpx509cert() == null) {
			errorMsg = "idp_cert_not_found_and_required";
			errors.add(errorMsg);
			LOGGER.error(errorMsg);
		}

		return errors;
	}

	/**
	 * Checks the SP settings .
	 *
	 * @return errors found on the SP settings data
	 */
	public List<String> checkSPSettings() {
		List<String> errors = new ArrayList<>();
		String errorMsg;

		if (!checkRequired(getSpEntityId())) {
			errorMsg = "sp_entityId_not_found";
			errors.add(errorMsg);
			LOGGER.error(errorMsg);
		}

		if (!checkRequired(getSpAssertionConsumerServiceUrl())) {
			errorMsg = "sp_acs_not_found";
			errors.add(errorMsg);
			LOGGER.error(errorMsg);
		}

		if ((this.getAuthnRequestsSigned() == true ||
			  this.getLogoutRequestSigned() == true ||
			  this.getLogoutResponseSigned() == true ||
			  this.getWantAssertionsEncrypted() == true ||
			  this.getWantNameIdEncrypted() == true)
			  && this.checkSPCerts() == false) {
			errorMsg = "sp_cert_not_found_and_required";
			errors.add(errorMsg);
			LOGGER.error(errorMsg);
		}

		List<Contact> contacts = this.getContacts();
		if (!contacts.isEmpty()) {
/*			
			List<String> validTypes = new ArrayList<String>();
			validTypes.add("technical");
			validTypes.add("support");
			validTypes.add("administrative");
			validTypes.add("billing");
			validTypes.add("other");
*/
			for (Contact contact : contacts) {
/*
				if (!validTypes.contains(contact.getContactType())) {
					errorMsg = "contact_type_invalid";
					errors.add(errorMsg);
					LOGGER.error(errorMsg);
				}
*/

				if (contact.getEmailAddress().isEmpty() || contact.getGivenName().isEmpty()) {
					errorMsg = "contact_not_enought_data";
					errors.add(errorMsg);
					LOGGER.error(errorMsg);
				}
			}
		}

		Organization org = this.getOrganization();
		if (org != null && (org.getOrgDisplayName().isEmpty() || org.getOrgName().isEmpty() || org.getOrgUrl().isEmpty())) {
			errorMsg = "organization_not_enought_data";
			errors.add(errorMsg);
			LOGGER.error(errorMsg);
		}

		return errors;
	}

	/**
	 * Checks the x509 certficate/private key SP settings .
	 *
	 * @return true if the SP settings are valid
	 */
	public boolean checkSPCerts() {
		X509Certificate cert = getSPcert();
		PrivateKey key = getSPkey();

		return (cert != null && key != null);
	}
	
	/**
	 * Auxiliary method to check required properties.
	 *
	 * @param value
	 *            the current value of the property to be checked
	 *
	 *
	 * @return true if the SP settings are valid
	 */
	private boolean checkRequired(Object value) {
		if (value == null) {
			return false;
		}

		if (value instanceof String && ((String) value).isEmpty()) {
			return false;
		}

		if (value instanceof List && ((List<?>) value).isEmpty()) {
			return false;
		}
		return true;
	}

	/**
	 * Set the spValidationOnly value, used to check IdP data on checkSettings method
	 *
	 * @param spValidationOnly
	 *            the spValidationOnly value to be set
	 */
	public void setSPValidationOnly(boolean spValidationOnly)
	{
		this.spValidationOnly = spValidationOnly;
	}

	/**
	 * @return the spValidationOnly value
	 */
	public boolean getSPValidationOnly()
	{
		return this.spValidationOnly;
	}
	
	/**
	 * Gets the SP metadata. The XML representation.
	 *
	 * @return the SP metadata (xml)
	 *
	 * @throws CertificateEncodingException
	 */
	public String getSPMetadata() throws CertificateEncodingException {
		Metadata metadataObj = new Metadata(this);
		String metadataString = metadataObj.getMetadataString();

		// Check if must be signed
		boolean signMetadata = this.getSignMetadata();
		if (signMetadata) {
			// TODO Extend this in order to be able to read not only SP privateKey/certificate
			try {
				metadataString =  Metadata.signMetadata(
						metadataString,
						this.getSPkey(),
						this.getSPcert(),
						this.getSignatureAlgorithm()
				);
			} catch (Exception e) {				
				LOGGER.debug("Error executing signMetadata: " + e.getMessage(), e);
			}
		}

		return metadataString;
	}
	
	/**
	 * Validates an XML SP Metadata.
	 *
	 * @param metadataString Metadata's XML that will be validate
	 * 
	 * @return Array The list of found errors
	 *
	 * @throws Exception 
	 */
	public static List<String> validateMetadata(String metadataString) throws Exception {

		metadataString = metadataString.replace("<?xml version=\"1.0\"?>", "");

		Document metadataDocument = Util.loadXML(metadataString);

		List<String> errors = new ArrayList<>();

		if (!Util.validateXML(metadataDocument, SchemaFactory.SAML_SCHEMA_METADATA_2_0)) {
			errors.add("Invalid SAML Metadata. Not match the saml-schema-metadata-2.0.xsd");
		} else {
			Element rootElement = metadataDocument.getDocumentElement();
			if (!rootElement.getLocalName().equals("EntityDescriptor")) {
				errors.add("noEntityDescriptor_xml");
			} else {
				if (rootElement.getElementsByTagNameNS(Constants.NS_MD, "SPSSODescriptor").getLength() != 1) {
					errors.add("onlySPSSODescriptor_allowed_xml");
				} else {
					String validUntil = null;
					String cacheDuration = null;

					if (rootElement.hasAttribute("cacheDuration")) {
						cacheDuration = rootElement.getAttribute("cacheDuration");
					}

					if (rootElement.hasAttribute("validUntil")) {
						validUntil = rootElement.getAttribute("validUntil");
					}

					long expireTime = Util.getExpireTime(cacheDuration, validUntil);

					if (expireTime != 0 && Util.getCurrentTimeStamp() > expireTime) {
						errors.add("expired_xml");
					}
				}
			}
		}
		// TODO Validate Sign if required with Util.validateMetadataSign
		
		return errors;
	}
}
