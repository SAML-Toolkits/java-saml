package com.onelogin.saml2.settings;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.model.Contact;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.util.Util;

/**
 * A SettingsBuilder class of OneLogin's Java Toolkit.
 *
 * This class gives the possibility to load settings dynamically from other sources.
 */
public class DynamicSettingsBuilder {

    /**
     * Private property to construct a logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamicSettingsBuilder.class);

    /**
     * Saml2Settings object
     */
    private final Saml2Settings saml2Settings;

    /**
     * Settings builder constructor.
     * 
     * @param strict <code>true</code> if Requests and responses must fulfill strict validation.
     */
    public DynamicSettingsBuilder(boolean strict) {
        this.saml2Settings = new Saml2Settings();
        this.saml2Settings.setStrict(strict);
    }

    /**
     * Set the SP entity Id.
     * 
     * @param spEntityId the idpEntityId value to be set. Cannot be null.
     */
    public DynamicSettingsBuilder spEntityId(String spEntityId) {
        String value = StringUtils.trimToNull(spEntityId);
        if (value != null) {
            this.saml2Settings.setSpEntityId(value);
        }
        return this;
    }
    
    /**
     * Set the SP assertion Consumer service URL. Malformed URLs will result on setting null.
     * 
     * @param spAssertionConsumerServiceUrl the String URL to set. Cannot be null
     */
    public DynamicSettingsBuilder spAssertionConsumerServiceUrl(String spAssertionConsumerServiceUrl) {
        URL url = toURL(spAssertionConsumerServiceUrl);
        if (url != null) {
            this.saml2Settings.setSpAssertionConsumerServiceUrl(url);
        }
        return this;
    }
    
    /**
     * Set the spAssertionConsumerServiceBinding setting value
     *
     * @param spAssertionConsumerServiceBinding
     *            the spAssertionConsumerServiceBinding value to be set. Cannot be null.
     */
    public DynamicSettingsBuilder spAssertionConsumerServiceBinding(String spAssertionConsumerServiceBinding) {
        String value = StringUtils.trimToNull(spAssertionConsumerServiceBinding);
        if (value != null) {
            this.saml2Settings.setSpAssertionConsumerServiceBinding(spAssertionConsumerServiceBinding);
        }
        return this;
    }
    
    /**
     * Set the spSingleLogoutServiceUrl setting value
     *
     * @param spSingleLogoutServiceUrl the spSingleLogoutServiceUrl value to be set. Cannot be null.
     */
    public DynamicSettingsBuilder spSingleLogoutServiceUrl(String spSingleLogoutServiceUrl) {
        URL url = toURL(spSingleLogoutServiceUrl);
        if (url != null) {
            this.saml2Settings.setSpSingleLogoutServiceUrl(url);
        }
        return this;
    }
    
    /**
     * Set the spSingleLogoutServiceBinding setting value
     *
     * @param spSingleLogoutServiceBinding the spSingleLogoutServiceBinding value to be set. Cannot be null.
     */
    public DynamicSettingsBuilder spSingleLogoutServiceBinding(String spSingleLogoutServiceBinding) {
        String value = StringUtils.trimToNull(spSingleLogoutServiceBinding);
        if (value != null) {
            this.saml2Settings.setSpSingleLogoutServiceBinding(value);
        }
        return this;
    }
    
    /**
     * Set the spNameIDFormat setting value
     *
     * @param spNameIDFormat
     *            the spNameIDFormat value to be set
     */
    public DynamicSettingsBuilder spNameIDFormat(String spNameIDFormat) {
        String value = StringUtils.trimToNull(spNameIDFormat);
        if (value != null) {
            this.saml2Settings.setSpNameIDFormat(value);
        }
        return this;
    }
    
    /**
     * Set the SP X509certificate
     *
     * @param spX509cert A Base 64 encoded string of the X509cert
     */
    public DynamicSettingsBuilder spX509cert(String spX509cert) {
        this.saml2Settings.setSpX509cert(loadCertificate(spX509cert));
        return this;
    }

    /**
     * Set the SP PrivateKey. MUST related to the SP X509certificate.
     *
     * @param spPrivateKey A Base 64 encoded string of the private key
     * 
     */
    public DynamicSettingsBuilder spPrivateKey(String spPrivateKey) {
        this.saml2Settings.setSpPrivateKey(loadPrivateKey(spPrivateKey));
        return this;
    }
    
    /**
     * Set the idpEntityId setting value
     *
     * @param idpEntityId the idpEntityId value to be set
     */
    public DynamicSettingsBuilder idpEntityId(String idpEntityId) {
        String value = StringUtils.trimToNull(idpEntityId);
        if (value != null) {
            this.saml2Settings.setIdpEntityId(value);
        }
        return this;
    }

    /**
     * Set the idpSingleSignOnServiceUrl setting value
     *
     * @param idpSingleSignOnServiceUrl the idpSingleSignOnServiceUrl value to be set
     */
    public DynamicSettingsBuilder idpSingleSignOnServiceUrl(String idpSingleSignOnServiceUrl) {
        URL url = toURL(idpSingleSignOnServiceUrl);
        if (url != null) {
            this.saml2Settings.setIdpSingleSignOnServiceUrl(url);
        }
        return this;
    }

    /**
     * Set the idpSingleSignOnServiceBinding setting value
     *
     * @param idpSingleSignOnServiceBinding the idpSingleSignOnServiceBinding value to be set
     */
    public DynamicSettingsBuilder idpSingleSignOnServiceBinding(String idpSingleSignOnServiceBinding) {
        String value = StringUtils.trimToNull(idpSingleSignOnServiceBinding);
        if (value != null) {
            this.saml2Settings.setIdpSingleSignOnServiceBinding(value);
        }
        return this;
    }

    /**
     * Set the idpSingleLogoutServiceUrl setting value
     *
     * @param idpSingleLogoutServiceUrl
     *            the idpSingleLogoutServiceUrl value to be set
     */
    public DynamicSettingsBuilder idpSingleLogoutServiceUrl(String idpSingleLogoutServiceUrl) {
        URL url = toURL(idpSingleLogoutServiceUrl);
        if (url != null) {
            this.saml2Settings.setIdpSingleLogoutServiceUrl(url);
        }
        return this;
    }

    /**
     * Set the idpSingleLogoutServiceUrl setting value
     *
     * @param idpSingleLogoutServiceResponseUrl
     *            the idpSingleLogoutServiceUrl value to be set
     */
    public DynamicSettingsBuilder idpSingleLogoutServiceResponseUrl(String idpSingleLogoutServiceResponseUrl) {
        URL url = toURL(idpSingleLogoutServiceResponseUrl);
        if (url != null) {
            this.saml2Settings.setIdpSingleLogoutServiceResponseUrl(url);
        }
        return this;
    }

    /**
     * Set the idpSingleLogoutServiceBinding setting value
     *
     * @param idpSingleLogoutServiceBinding the idpSingleLogoutServiceBinding value to be set
     */
    public DynamicSettingsBuilder idpSingleLogoutServiceBinding(String idpSingleLogoutServiceBinding) {
        String value = StringUtils.trimToNull(idpSingleLogoutServiceBinding);
        if (value != null) {
            this.saml2Settings.setIdpSingleLogoutServiceBinding(value);
        }
        return this;
    }

    /**
     * Set the idpX509cert setting value provided as a X509Certificate object
     *
     * @param idpX509cert the idpX509cert value to be set in X509Certificate format
     */
    public DynamicSettingsBuilder idpX509cert(String idpX509cert) {
        this.saml2Settings.setIdpx509cert(loadCertificate(idpX509cert));
        return this;
    }

    /**
     * Set the idpCertFingerprint setting value
     *
     * @param idpCertFingerprint the idpCertFingerprint value to be set
     */
    public DynamicSettingsBuilder idpCertFingerprint(String idpCertFingerprint) {
        this.saml2Settings.setIdpCertFingerprint(StringUtils.trimToNull(idpCertFingerprint));
        return this;
    }

    /**
     * Set the idpCertFingerprintAlgorithm setting value
     *
     * @param idpCertFingerprintAlgorithm the idpCertFingerprintAlgorithm value to be set.
     */
    public DynamicSettingsBuilder idpCertFingerprintAlgorithm(String idpCertFingerprintAlgorithm) {
        this.saml2Settings.setIdpCertFingerprintAlgorithm(StringUtils.trimToNull(idpCertFingerprintAlgorithm));
        return this;
    }

    /**
     * Set the nameIdEncrypted setting value
     *
     * @param nameIdEncrypted the nameIdEncrypted value to be set. Based on it the SP will encrypt the NameID or not
     */
    public DynamicSettingsBuilder nameIdEncrypted(boolean nameIdEncrypted) {
        this.saml2Settings.setNameIdEncrypted(nameIdEncrypted);
        return this;
    }

    /**
     * Set the authnRequestsSigned setting value
     *
     * @param authnRequestsSigned the authnRequestsSigned value to be set. Based on it the SP will sign Logout Request
     *        or not
     */
    public DynamicSettingsBuilder authnRequestsSigned(boolean authnRequestsSigned) {
        this.saml2Settings.setAuthnRequestsSigned(authnRequestsSigned);
        return this;
    }

    /**
     * Set the logoutRequestSigned setting value
     *
     * @param logoutRequestSigned the logoutRequestSigned value to be set. Based on it the SP will sign Logout Request
     *        or not
     */
    public DynamicSettingsBuilder logoutRequestSigned(boolean logoutRequestSigned) {
        this.saml2Settings.setLogoutRequestSigned(logoutRequestSigned);
        return this;
    }

    /**
     * Set the logoutResponseSigned setting value
     *
     * @param logoutResponseSigned the logoutResponseSigned value to be set. Based on it the SP will sign Logout
     *        Response or not
     */
    public DynamicSettingsBuilder logoutResponseSigned(boolean logoutResponseSigned) {
        this.saml2Settings.setLogoutResponseSigned(logoutResponseSigned);
        return this;
    }

    /**
     * Set the wantMessagesSigned setting value
     *
     * @param wantMessagesSigned the wantMessagesSigned value to be set. Based on it the SP expects the SAML Messages to
     *        be signed or not
     */
    public DynamicSettingsBuilder wantMessagesSigned(boolean wantMessagesSigned) {
        this.saml2Settings.setWantMessagesSigned(wantMessagesSigned);
        return this;
    }

    /**
     * Set the wantAssertionsSigned setting value
     *
     * @param wantAssertionsSigned the wantAssertionsSigned value to be set. Based on it the SP expects the SAML
     *        Assertions to be signed or not
     */
    public DynamicSettingsBuilder wantAssertionsSigned(boolean wantAssertionsSigned) {
        this.saml2Settings.setWantAssertionsSigned(wantAssertionsSigned);
        return this;
    }

    /**
     * Set the wantAssertionsEncrypted setting value
     *
     * @param wantAssertionsEncrypted the wantAssertionsEncrypted value to be set. Based on it the SP expects the SAML
     *        Assertions to be encrypted or not
     */
    public DynamicSettingsBuilder wantAssertionsEncrypted(boolean wantAssertionsEncrypted) {
        this.saml2Settings.setWantAssertionsEncrypted(wantAssertionsEncrypted);
        return this;
    }

    /**
     * Set the wantNameId setting value
     *
     * @param wantNameId the wantNameId value to be set. Based on it the SP expects a NameID
     */
    public DynamicSettingsBuilder wantNameId(boolean wantNameId) {
        this.saml2Settings.setWantNameId(wantNameId);
        return this;
    }

    /**
     * Set the wantNameIdEncrypted setting value
     *
     * @param wantNameIdEncrypted the wantNameIdEncrypted value to be set. Based on it the SP expects the NameID to be
     *        encrypted or not
     */
    public DynamicSettingsBuilder wantNameIdEncrypted(boolean wantNameIdEncrypted) {
        this.saml2Settings.setWantNameIdEncrypted(wantNameIdEncrypted);
        return this;
    }

    /**
     * Set the signMetadata setting value
     *
     * @param signMetadata the signMetadata value to be set. Based on it the SP will sign or not the metadata with the
     *        SP PrivateKey/Certificate
     */
    public DynamicSettingsBuilder signMetadata(boolean signMetadata) {
        this.saml2Settings.setSignMetadata(signMetadata);
        return this;
    }

    /**
     * Set the requestedAuthnContext setting value
     *
     * @param requestedAuthnContext the requestedAuthnContext value to be set on the AuthNRequest.
     */
    public DynamicSettingsBuilder requestedAuthnContext(List<String> requestedAuthnContext) {
        if (requestedAuthnContext != null && !requestedAuthnContext.isEmpty()) {
            this.saml2Settings.setRequestedAuthnContext(requestedAuthnContext);
        }
        return this;
    }

    /**
     * Set the requestedAuthnContextComparison setting value
     *
     * @param requestedAuthnContextComparison the requestedAuthnContextComparison value to be set.
     */
    public DynamicSettingsBuilder requestedAuthnContextComparison(String requestedAuthnContextComparison) {
        String value = StringUtils.trimToNull(requestedAuthnContextComparison);
        if (value != null) {
            this.saml2Settings.setRequestedAuthnContextComparison(value);
        }
        return this;
    }

    /**
     * Set the wantXMLValidation setting value
     *
     * @param wantXMLValidation the wantXMLValidation value to be set. Based on it the SP will validate SAML messages
     *        against the XML scheme
     */
    public DynamicSettingsBuilder wantXMLValidation(boolean wantXMLValidation) {
        this.saml2Settings.setWantXMLValidation(wantXMLValidation);
        return this;
    }

    /**
     * Set the signatureAlgorithm setting value
     *
     * @param signatureAlgorithm the signatureAlgorithm value to be set.
     */
    public DynamicSettingsBuilder signatureAlgorithm(String signatureAlgorithm) {
        String value = StringUtils.trimToNull(signatureAlgorithm);
        if (value != null) {
            this.saml2Settings.setSignatureAlgorithm(signatureAlgorithm);
        }
        return this;
    }

    /**
     * Controls if unsolicited Responses are rejected if they contain an InResponseTo value.
     *
     * If false using a validate method {@link com.onelogin.saml2.authn.SamlResponse#isValid(String)} with a null
     * argument will accept messages with any (or none) InResponseTo value.
     *
     * If true using these methods with a null argument will only accept messages with no InRespoonseTo value, and
     * reject messages where the value is set.
     *
     * In all cases using validate with a specified request ID will only accept responses that have the same
     * InResponseTo id set.
     *
     * @param rejectUnsolicitedResponsesWithInResponseTo whether to strictly check the InResponseTo attribute
     */
    public DynamicSettingsBuilder rejectUnsolicitedResponsesWithInResponseTo(
            boolean rejectUnsolicitedResponsesWithInResponseTo) {
        this.saml2Settings.setRejectUnsolicitedResponsesWithInResponseTo(rejectUnsolicitedResponsesWithInResponseTo);
        return this;
    }

    /**
     * Set the compressRequest setting value
     *
     * @param compressRequest the compressRequest value to be set.
     */
    public DynamicSettingsBuilder compressRequest(boolean compressRequest) {
        this.saml2Settings.setCompressRequest(compressRequest);
        return this;
    }


    /**
     * Set the compressResponse setting value
     *
     * @param compressResponse
     *            the compressResponse value to be set.
     */
    public DynamicSettingsBuilder compressResponse(boolean compressResponse) {
        this.saml2Settings.setCompressResponse(compressResponse);
        return this;
    }

    /**
     * Set contacts info that will be listed on the Service Provider metadata
     * 
     * @param contacts the contacts to set
     */
    public DynamicSettingsBuilder contacts(String technicalName, String technicalEmail, String supportName,
            String supportEmail) {

        List<Contact> contacts = new ArrayList<>(2);
        if (StringUtils.isNotBlank(technicalName) || StringUtils.isNotBlank(technicalEmail)) {
            Contact technical = new Contact("technical", technicalName, technicalEmail);
            contacts.add(technical);
        }

        if (StringUtils.isNotBlank(supportName) || StringUtils.isNotBlank(supportEmail)) {
            Contact support = new Contact("support", supportName, supportEmail);
            contacts.add(support);
        }

        this.saml2Settings.setContacts(contacts);
        return this;
    }

    /**
     * Set the organization info that will be published on the Service Provider metadata
     *
     * @param organization the organization to set
     */
    public DynamicSettingsBuilder organization(String name, String displayName, String url, String lang) {

        Organization organization = null;

        URL orgURL = toURL(url);
        if (StringUtils.isNotBlank(name) || StringUtils.isNotBlank(displayName) || url != null) {
            organization = new Organization(name, displayName, orgURL, lang);
        }

        this.saml2Settings.setOrganization(organization);
        return this;
    }

    /**
     * Builds the saml2Setting object.
     * 
     * @return the Saml2Settings object with all the SAML settings set
     * @throws SettingsException
     */
    public Saml2Settings build() throws SettingsException {
        List<String> errors = new ArrayList<>();
        errors.addAll(this.saml2Settings.checkSettings());
        if (!errors.isEmpty()) {
            String errorMsg = "Invalid settings: ";
            errorMsg += StringUtils.join(errors, ", ");
            LOGGER.error(errorMsg);
            throw new SettingsException(errorMsg, SettingsException.SETTINGS_INVALID);
        }
        return this.saml2Settings;
    }

    /*
     * Loads a property of the type URL from the Properties object
     *
     * @param propertyKey the property name
     *
     * @return the value
     */
    private URL toURL(String value) {

        if (StringUtils.isBlank(value)) {
            return null;
        }

        try {
            return new URL(value.trim());
        } catch (MalformedURLException e) {
            LOGGER.error("'{}' is not a valid URL.", value, e);
            return null;
        }

    }

    /*
     * Loads a property of the type X509Certificate from the Properties object
     *
     * @param propertyKey the property name
     *
     * @return the X509Certificate object
     */
    private X509Certificate loadCertificate(String encodedCert) {

        if (StringUtils.isBlank(encodedCert)) {
            return null;
        }

        try {
            return Util.loadCert(encodedCert);
        } catch (CertificateException e) {
            LOGGER.error("Cannot read X509 certificate from string", e);
            return null;
        }
    }

    /*
     * Loads a property of the type PrivateKey from the Properties object
     *
     * @param propertyKey the property name
     *
     * @return the PrivateKey object
     */
    private PrivateKey loadPrivateKey(String encodedKey) {

        if (StringUtils.isBlank(encodedKey)) {
            return null;
        }

        try {
            return Util.loadPrivateKey(encodedKey);
        } catch (Exception e) {
            LOGGER.error("Cannot read private key from string.", e);
            return null;
        }
    }
}
