package com.onelogin.saml2.test.settings;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.model.Contact;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.settings.DynamicSettingsBuilder;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

public class DynamicSettingsBuilderTest {

    @Test
    public void testBuildMinimalSettings() throws Exception {

        DynamicSettingsBuilder builder = new DynamicSettingsBuilder(true);

        // Build SP
        builder.spEntityId("http://localhost:8080/java-saml-jspsample/metadata.jsp");
        builder.spAssertionConsumerServiceUrl("http://localhost:8080/java-saml-jspsample/acs.jsp");
        
        // Build IdP
        builder.idpEntityId("http://idp.example.com/");
        builder.idpSingleSignOnServiceUrl("http://idp.example.com/simplesaml/saml2/idp/SSOService.php");
        builder.idpX509cert("-----BEGIN CERTIFICATE-----\nMIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEwMTAxMTIxMTUxMloXDTE1MTAxMTIxMTUxMlowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAXBgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMPmjfjy7L35oDpeBXBoRVCgktPkLno9DOEWB7MgYMMVKs2B6ymWQLEWrDugMK1hkzWFhIb5fqWLGbWy0J0veGR9/gHOQG+rD/I36xAXnkdiXXhzoiAG/zQxM0edMOUf40n314FC8moErcUg6QabttzesO59HFz6shPuxcWaVAgxAgMBAAEwAwYBAAMBAA==\n-----END CERTIFICATE-----");
        
        Saml2Settings setting = builder.build();
        
        assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp", setting.getSpEntityId());
        assertEquals("http://localhost:8080/java-saml-jspsample/acs.jsp", setting.getSpAssertionConsumerServiceUrl().toString());
        assertEquals(setting.getSpAssertionConsumerServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        assertNull(setting.getSpSingleLogoutServiceUrl());
        assertEquals(setting.getSpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertEquals(setting.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

        assertEquals("http://idp.example.com/", setting.getIdpEntityId());
        assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting.getIdpSingleSignOnServiceUrl().toString());
        assertEquals(setting.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertNull(setting.getIdpSingleLogoutServiceUrl());
        assertNull(setting.getIdpSingleLogoutServiceResponseUrl());
        assertEquals(setting.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertNotNull(setting.getIdpx509cert());
        assertEquals(Util.loadCert(Util.getFileAsString("certs/certificate1")), setting.getIdpx509cert());
        assertNull(setting.getIdpCertFingerprint());
        assertEquals("sha1", setting.getIdpCertFingerprintAlgorithm());

        assertFalse(setting.getNameIdEncrypted());
        assertFalse(setting.getAuthnRequestsSigned());
        assertFalse(setting.getLogoutRequestSigned());
        assertFalse(setting.getLogoutResponseSigned());
        assertFalse(setting.getWantMessagesSigned());
        assertFalse(setting.getWantAssertionsSigned());
        assertFalse(setting.getWantAssertionsEncrypted());
        assertFalse(setting.getWantNameIdEncrypted());
        assertTrue(setting.getRequestedAuthnContext().isEmpty());
        assertEquals("exact", setting.getRequestedAuthnContextComparison());
        assertTrue(setting.getWantXMLValidation());
        assertEquals(Constants.RSA_SHA1, setting.getSignatureAlgorithm());
        assertFalse(setting.getSignMetadata());

        assertNull(setting.getOrganization());
        assertTrue(setting.getContacts().isEmpty());
    }

    @Test
    public void testBuildSettingsWithNulls() throws Exception {

        DynamicSettingsBuilder builder = new DynamicSettingsBuilder(true);

        // Build SP
        builder.spEntityId("http://localhost:8080/java-saml-jspsample/metadata.jsp");
        builder.spAssertionConsumerServiceUrl("http://localhost:8080/java-saml-jspsample/acs.jsp");
        builder.spAssertionConsumerServiceBinding(null);
        builder.spSingleLogoutServiceUrl(null);
        builder.spSingleLogoutServiceBinding(" ");
        builder.spNameIDFormat("\t");
        
        // Build IdP
        builder.idpEntityId("http://idp.example.com/");
        builder.idpSingleSignOnServiceUrl("http://idp.example.com/simplesaml/saml2/idp/SSOService.php");
        builder.idpSingleSignOnServiceBinding("");
        builder.idpSingleLogoutServiceUrl("this is an invalid URL");
        builder.idpSingleLogoutServiceResponseUrl(null);
        builder.idpSingleLogoutServiceBinding("\n");
        builder.idpX509cert("-----BEGIN CERTIFICATE-----\nMIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEwMTAxMTIxMTUxMloXDTE1MTAxMTIxMTUxMlowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAXBgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMPmjfjy7L35oDpeBXBoRVCgktPkLno9DOEWB7MgYMMVKs2B6ymWQLEWrDugMK1hkzWFhIb5fqWLGbWy0J0veGR9/gHOQG+rD/I36xAXnkdiXXhzoiAG/zQxM0edMOUf40n314FC8moErcUg6QabttzesO59HFz6shPuxcWaVAgxAgMBAAEwAwYBAAMBAA==\n-----END CERTIFICATE-----");
        Saml2Settings setting = builder.build();
        
        assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp", setting.getSpEntityId());
        assertEquals("http://localhost:8080/java-saml-jspsample/acs.jsp", setting.getSpAssertionConsumerServiceUrl().toString());
        assertEquals(setting.getSpAssertionConsumerServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        assertNull(setting.getSpSingleLogoutServiceUrl());
        assertEquals(setting.getSpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertEquals(setting.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

        assertEquals("http://idp.example.com/", setting.getIdpEntityId());
        assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting.getIdpSingleSignOnServiceUrl().toString());
        assertEquals(setting.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertNull(setting.getIdpSingleLogoutServiceUrl());
        assertNull(setting.getIdpSingleLogoutServiceResponseUrl());
        assertEquals(setting.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertNotNull(setting.getIdpx509cert());
        assertEquals(Util.loadCert(Util.getFileAsString("certs/certificate1")), setting.getIdpx509cert());
        assertNull(setting.getIdpCertFingerprint());
        assertEquals("sha1", setting.getIdpCertFingerprintAlgorithm());

        assertFalse(setting.getNameIdEncrypted());
        assertFalse(setting.getAuthnRequestsSigned());
        assertFalse(setting.getLogoutRequestSigned());
        assertFalse(setting.getLogoutResponseSigned());
        assertFalse(setting.getWantMessagesSigned());
        assertFalse(setting.getWantAssertionsSigned());
        assertFalse(setting.getWantAssertionsEncrypted());
        assertFalse(setting.getWantNameIdEncrypted());
        assertTrue(setting.getRequestedAuthnContext().isEmpty());
        assertEquals("exact", setting.getRequestedAuthnContextComparison());
        assertTrue(setting.getWantXMLValidation());
        assertEquals(Constants.RSA_SHA1, setting.getSignatureAlgorithm());
        assertFalse(setting.getSignMetadata());

        assertNull(setting.getOrganization());
        assertTrue(setting.getContacts().isEmpty());
    }
    
    @Test
    public void testBuildCompleteSettings() throws Exception {

        DynamicSettingsBuilder builder = new DynamicSettingsBuilder(true);

        // Build SP
        builder.spEntityId("http://localhost:8080/java-saml-jspsample/metadata.jsp");
        builder.spAssertionConsumerServiceUrl("http://localhost:8080/java-saml-jspsample/acs.jsp");
        builder.spAssertionConsumerServiceBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        builder.spSingleLogoutServiceUrl("http://localhost:8080/java-saml-jspsample/sls.jsp");
        builder.spSingleLogoutServiceBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        builder.spNameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        builder.spX509cert("-----BEGIN CERTIFICATE-----MIICeDCCAeGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBZMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lTG9naW4gSW5jMR4wHAYDVQQDDBVqYXZhLXNhbWwuZXhhbXBsZS5jb20wHhcNMTUxMDE4MjAxMjM1WhcNMTgwNzE0MjAxMjM1WjBZMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lTG9naW4gSW5jMR4wHAYDVQQDDBVqYXZhLXNhbWwuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALvwEktX1+4y2AhEqxVwOO6HO7Wtzi3hr5becRkfLYGjNSyhzZCjI1DsNL61JSWDO3nviZd9fSkFnRC4akFUm0CS6GJ7TZe4T5o+9aowQ6N8e8cts9XPXyP6Inz7q4sD8pO2EInlfwHYPQCqFmz/SDW7cDgIC8vb0ygOsiXdreANAgMBAAGjUDBOMB0GA1UdDgQWBBTifMwN3CQ5ZOPkV5tDJsutU8teFDAfBgNVHSMEGDAWgBTifMwN3CQ5ZOPkV5tDJsutU8teFDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAG3nAEUjJaA75SkzID5FKLolsxG5TE/0HU0+yEUAVkXiqvqN4mPWq/JjoK5+uP4LEZIb4pRrCqI3iHp+vazLLYSeyV3kaGN7q35Afw8nk8WM0f7vImbQ69j1S8GQ+6E0PEI26qBLykGkMn3GUVtBBWSdpP093NuNLJiOomnHqhqj-----END CERTIFICATE-----");
        builder.spPrivateKey("-----BEGIN PRIVATE KEY-----MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALvwEktX1+4y2AhEqxVwOO6HO7Wtzi3hr5becRkfLYGjNSyhzZCjI1DsNL61JSWDO3nviZd9fSkFnRC4akFUm0CS6GJ7TZe4T5o+9aowQ6N8e8cts9XPXyP6Inz7q4sD8pO2EInlfwHYPQCqFmz/SDW7cDgIC8vb0ygOsiXdreANAgMBAAECgYA7VPVRl+/xoVeWdKdWY1F17HerSa23ynI2vQ8TkUY6kR3ucz6ElRxHJesY8fNCPoX+XuMfUly7IKyPZMkWyvEgDPo7J5mYqP5VsTK0Li4AwR/BA93Aw6gaX7/EYi3HjBh8QdNSt4fi9yOea/hv04yfR9Lx/a5fvQIyhqaDtT2QeQJBAOnCgnxnj70/sv9UsFPa8t1OGdAfXtOgEoklh1F2NR9jid6FPw5E98eCpdZ00MfRrmUavgqg6Y4swZISyzJIjGMCQQDN0YNsC4S+eJJM6aOCpupKluWE/cCWB01UQYekyXH7OdUtl49NlKEUPBSAvtaLMuMKlTNOjlPrx4Q+/c5i0vTPAkEA5H7CR9J/OZETaewhc8ZYkaRvLPYNHjWhCLhLXoB6itUkhgOfUFZwEXAOpOOI1VmL675JN2B1DAmJqTx/rQYnWwJBAMx3ztsAmnBq8dTM6y65ydouDHhRawjg2jbRHwNbSQvuyVSQ08Gb3WZvxWKdtB/3fsydqqnpBYAf5sZ5eJZ+wssCQAOiIKnhdYe+RBbBwykzjUqtzEmt4fwCFE8tD4feEx77D05j5f7u7KYh1mL0G2zIbnUryi7jwc4ye98VirRpZ1w=-----END PRIVATE KEY-----");
        
        // Build IdP
        builder.idpEntityId("http://idp.example.com/");
        builder.idpSingleSignOnServiceUrl("http://idp.example.com/simplesaml/saml2/idp/SSOService.php");
        builder.idpSingleSignOnServiceBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        builder.idpSingleLogoutServiceUrl("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php");
        builder.idpSingleLogoutServiceResponseUrl("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutServiceResponse.php");
        builder.idpSingleLogoutServiceBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        builder.idpX509cert("-----BEGIN CERTIFICATE-----\nMIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEwMTAxMTIxMTUxMloXDTE1MTAxMTIxMTUxMlowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAXBgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMPmjfjy7L35oDpeBXBoRVCgktPkLno9DOEWB7MgYMMVKs2B6ymWQLEWrDugMK1hkzWFhIb5fqWLGbWy0J0veGR9/gHOQG+rD/I36xAXnkdiXXhzoiAG/zQxM0edMOUf40n314FC8moErcUg6QabttzesO59HFz6shPuxcWaVAgxAgMBAAEwAwYBAAMBAA==\n-----END CERTIFICATE-----");
        builder.idpCertFingerprint("4b6f70bb2cab82c86a8270f71a880b62e25bc2b3");
        builder.idpCertFingerprintAlgorithm("sha1");
        
        // Security
        builder.nameIdEncrypted(true);
        builder.authnRequestsSigned(true);
        builder.logoutRequestSigned(true);
        builder.logoutResponseSigned(true);
        builder.wantMessagesSigned(true);
        builder.wantAssertionsSigned(true);
        builder.signMetadata(true);
        builder.wantAssertionsEncrypted(true);
        builder.wantNameIdEncrypted(true);
        builder.requestedAuthnContext(Arrays.asList("urn:oasis:names:tc:SAML:2.0:ac:classes:urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
        builder.requestedAuthnContextComparison("exact");
        builder.wantXMLValidation(true);
        builder.signatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
        
        // Organization
        builder.organization("SP Java", "SP Java Example", "http://sp.example.com", "en");
        
        // Contacts
        builder.contacts("Technical Guy", "technical@example.org", "Support Guy", "support@example.org");
        
        Saml2Settings setting = builder.build();
        
        assertTrue(setting.isStrict());

        assertEquals("http://localhost:8080/java-saml-jspsample/metadata.jsp", setting.getSpEntityId());
        assertEquals("http://localhost:8080/java-saml-jspsample/acs.jsp", setting.getSpAssertionConsumerServiceUrl().toString());
        assertEquals(setting.getSpAssertionConsumerServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        assertEquals("http://localhost:8080/java-saml-jspsample/sls.jsp", setting.getSpSingleLogoutServiceUrl().toString());
        assertEquals(setting.getSpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertEquals(setting.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

        assertEquals("http://idp.example.com/", setting.getIdpEntityId());
        assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting.getIdpSingleSignOnServiceUrl().toString());
        assertEquals(setting.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceUrl().toString());
        assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutServiceResponse.php", setting.getIdpSingleLogoutServiceResponseUrl().toString());
        assertEquals(setting.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertNotNull(setting.getIdpx509cert());
        assertEquals(Util.loadCert(Util.getFileAsString("certs/certificate1")), setting.getIdpx509cert());
        assertEquals("4b6f70bb2cab82c86a8270f71a880b62e25bc2b3", setting.getIdpCertFingerprint());
        assertEquals("sha1", setting.getIdpCertFingerprintAlgorithm());

        assertTrue(setting.getNameIdEncrypted());
        assertTrue(setting.getAuthnRequestsSigned());
        assertTrue(setting.getLogoutRequestSigned());
        assertTrue(setting.getLogoutResponseSigned());
        assertTrue(setting.getWantMessagesSigned());
        assertTrue(setting.getWantAssertionsSigned());
        assertTrue(setting.getWantAssertionsEncrypted());
        assertTrue(setting.getWantNameIdEncrypted());

        List<String> reqAuthContext = new ArrayList<>();
        reqAuthContext.add("urn:oasis:names:tc:SAML:2.0:ac:classes:urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
        assertEquals(reqAuthContext, setting.getRequestedAuthnContext());
        assertEquals("exact", setting.getRequestedAuthnContextComparison());
        assertTrue(setting.getWantXMLValidation());
        assertEquals(Constants.RSA_SHA512, setting.getSignatureAlgorithm());
        assertTrue(setting.getSignMetadata());

        Organization org = new Organization("SP Java", "SP Java Example", "http://sp.example.com");
        assertTrue(org.equalsTo(setting.getOrganization()));

        List<Contact> contacts = setting.getContacts();
        assertEquals(2, contacts.size());
        Contact c1 = contacts.get(0);
        assertEquals("technical", c1.getContactType());
        assertEquals("technical@example.org", c1.getEmailAddress());
        assertEquals("Technical Guy", c1.getGivenName());
        Contact c2 = contacts.get(1);
        assertEquals("support", c2.getContactType());
        assertEquals("support@example.org", c2.getEmailAddress());
        assertEquals("Support Guy", c2.getGivenName());
    }

    @Test(expected = SettingsException.class)
    public void testInvalidSettings() throws Exception {
        DynamicSettingsBuilder builder = new DynamicSettingsBuilder(true);
        builder.build();
    }

    @Test(expected = SettingsException.class)
    public void testInvalidSPEntityId() throws Exception {
        DynamicSettingsBuilder builder = new DynamicSettingsBuilder(true);

        // Build SP
        builder.spEntityId(" ");
        builder.spAssertionConsumerServiceUrl("http://localhost:8080/java-saml-jspsample/acs.jsp");

        // Build IdP
        builder.idpEntityId("http://idp.example.com/");
        builder.idpSingleSignOnServiceUrl("http://idp.example.com/simplesaml/saml2/idp/SSOService.php");
        builder.idpX509cert(
                "-----BEGIN CERTIFICATE-----\nMIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEwMTAxMTIxMTUxMloXDTE1MTAxMTIxMTUxMlowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAXBgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMPmjfjy7L35oDpeBXBoRVCgktPkLno9DOEWB7MgYMMVKs2B6ymWQLEWrDugMK1hkzWFhIb5fqWLGbWy0J0veGR9/gHOQG+rD/I36xAXnkdiXXhzoiAG/zQxM0edMOUf40n314FC8moErcUg6QabttzesO59HFz6shPuxcWaVAgxAgMBAAEwAwYBAAMBAA==\n-----END CERTIFICATE-----");

        builder.build();
    }

    @Test(expected = SettingsException.class)
    public void testInvalidSPacsURL() throws Exception {
        DynamicSettingsBuilder builder = new DynamicSettingsBuilder(true);

        // Build SP
        builder.spEntityId("http://localhost:8080/java-saml-jspsample/metadata.jsp");
        builder.spAssertionConsumerServiceUrl("Invalid URL");

        // Build IdP
        builder.idpEntityId("http://idp.example.com/");
        builder.idpSingleSignOnServiceUrl("http://idp.example.com/simplesaml/saml2/idp/SSOService.php");
        builder.idpX509cert(
                "-----BEGIN CERTIFICATE-----\nMIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEwMTAxMTIxMTUxMloXDTE1MTAxMTIxMTUxMlowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAXBgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMPmjfjy7L35oDpeBXBoRVCgktPkLno9DOEWB7MgYMMVKs2B6ymWQLEWrDugMK1hkzWFhIb5fqWLGbWy0J0veGR9/gHOQG+rD/I36xAXnkdiXXhzoiAG/zQxM0edMOUf40n314FC8moErcUg6QabttzesO59HFz6shPuxcWaVAgxAgMBAAEwAwYBAAMBAA==\n-----END CERTIFICATE-----");

        builder.build();
    }

    @Test(expected = SettingsException.class)
    public void testInvalidIdPEntityId() throws Exception {
        DynamicSettingsBuilder builder = new DynamicSettingsBuilder(true);

        // Build SP
        builder.spEntityId("http://localhost:8080/java-saml-jspsample/metadata.jsp");
        builder.spAssertionConsumerServiceUrl("http://localhost:8080/java-saml-jspsample/acs.jsp");

        // Build IdP
        builder.idpEntityId(" ");
        builder.idpSingleSignOnServiceUrl("http://idp.example.com/simplesaml/saml2/idp/SSOService.php");
        builder.idpX509cert(
                "-----BEGIN CERTIFICATE-----\nMIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEwMTAxMTIxMTUxMloXDTE1MTAxMTIxMTUxMlowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAXBgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMPmjfjy7L35oDpeBXBoRVCgktPkLno9DOEWB7MgYMMVKs2B6ymWQLEWrDugMK1hkzWFhIb5fqWLGbWy0J0veGR9/gHOQG+rD/I36xAXnkdiXXhzoiAG/zQxM0edMOUf40n314FC8moErcUg6QabttzesO59HFz6shPuxcWaVAgxAgMBAAEwAwYBAAMBAA==\n-----END CERTIFICATE-----");

        builder.build();
    }

    @Test(expected = SettingsException.class)
    public void testInvalidSSOUrl() throws Exception {
        DynamicSettingsBuilder builder = new DynamicSettingsBuilder(true);

        // Build SP
        builder.spEntityId("http://localhost:8080/java-saml-jspsample/metadata.jsp");
        builder.spAssertionConsumerServiceUrl("http://localhost:8080/java-saml-jspsample/acs.jsp");

        // Build IdP
        builder.idpEntityId("http://idp.example.com/");
        builder.idpSingleSignOnServiceUrl(null);
        builder.idpX509cert(
                "-----BEGIN CERTIFICATE-----\nMIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEwMTAxMTIxMTUxMloXDTE1MTAxMTIxMTUxMlowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAXBgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMPmjfjy7L35oDpeBXBoRVCgktPkLno9DOEWB7MgYMMVKs2B6ymWQLEWrDugMK1hkzWFhIb5fqWLGbWy0J0veGR9/gHOQG+rD/I36xAXnkdiXXhzoiAG/zQxM0edMOUf40n314FC8moErcUg6QabttzesO59HFz6shPuxcWaVAgxAgMBAAEwAwYBAAMBAA==\n-----END CERTIFICATE-----");

        builder.build();
    }

    @Test(expected = SettingsException.class)
    public void testMissingIdPCert() throws Exception {
        DynamicSettingsBuilder builder = new DynamicSettingsBuilder(true);

        // Build SP
        builder.spEntityId("http://localhost:8080/java-saml-jspsample/metadata.jsp");
        builder.spAssertionConsumerServiceUrl("http://localhost:8080/java-saml-jspsample/acs.jsp");

        // Build IdP
        builder.idpEntityId("http://idp.example.com/");
        builder.idpSingleSignOnServiceUrl("http://idp.example.com/simplesaml/saml2/idp/SSOService.php");

        builder.build();
    }

    @Test(expected = SettingsException.class)
    public void testMissingSPCerts() throws Exception {
        DynamicSettingsBuilder builder = new DynamicSettingsBuilder(true);
        
        // Build SP
        builder.spEntityId("http://localhost:8080/java-saml-jspsample/metadata.jsp");
        builder.spAssertionConsumerServiceUrl("http://localhost:8080/java-saml-jspsample/acs.jsp");
        
        // Build IdP
        builder.idpEntityId("http://idp.example.com/");
        builder.idpSingleSignOnServiceUrl("http://idp.example.com/simplesaml/saml2/idp/SSOService.php");
        builder.idpX509cert("-----BEGIN CERTIFICATE-----\nMIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEwMTAxMTIxMTUxMloXDTE1MTAxMTIxMTUxMlowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAXBgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMPmjfjy7L35oDpeBXBoRVCgktPkLno9DOEWB7MgYMMVKs2B6ymWQLEWrDugMK1hkzWFhIb5fqWLGbWy0J0veGR9/gHOQG+rD/I36xAXnkdiXXhzoiAG/zQxM0edMOUf40n314FC8moErcUg6QabttzesO59HFz6shPuxcWaVAgxAgMBAAEwAwYBAAMBAA==\n-----END CERTIFICATE-----");
        
        builder.authnRequestsSigned(true);
        builder.build();
    }
}
