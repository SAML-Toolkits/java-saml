package com.onelogin.saml2.test.settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNull;

import java.net.URL;
import java.util.Map;

import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import com.onelogin.saml2.settings.IdPMetadataParser;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

public class IdPMetadataParserTest {

    @Test
    public void testParseFileXML() throws Exception {

        Map<String, Object> idpInfo = IdPMetadataParser.parseFileXML("data/metadata/onelogin_metadata.xml");
        assertEquals("https://app.onelogin.com/saml/metadata/645460", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://example.onelogin.com/trust/saml2/http-redirect/sso/645460", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals("https://example.onelogin.com/trust/saml2/http-redirect/slo/645460", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="));
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:transient", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));

        idpInfo = IdPMetadataParser.parseFileXML("data/metadata/idp_metadata.xml");
        assertEquals("https://app.onelogin.com/saml/metadata/383123", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://app.onelogin.com/trust/saml2/http-post/sso/383123", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sTgf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0mTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SFzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNVHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHuAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcVgG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClPTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWuQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh781sE="));
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));

        boolean throwedInvalidXPath = false;
        try {
            IdPMetadataParser.parseFileXML("data/metadata/idp_metadata.xml", null, null, "\"", "\"");
        } catch (Exception e) {
            throwedInvalidXPath = true;
        }
        assertTrue(throwedInvalidXPath);

        boolean throwedFileNotFound = false;
        try {
            IdPMetadataParser.parseFileXML("nonexistent.file", null, null, "\"", "\"");
        } catch (Exception e) {
            throwedFileNotFound = true;
        }
        assertTrue(throwedFileNotFound);

    }

    @Test
    public void testParseXML() throws Exception {
        Document xmlDocument = Util.parseXML(new InputSource(getClass().getClassLoader().getResourceAsStream("data/metadata/onelogin_metadata.xml")));

        Map<String, Object> idpInfo = IdPMetadataParser.parseXML(xmlDocument);
        assertEquals("https://app.onelogin.com/saml/metadata/645460", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://example.onelogin.com/trust/saml2/http-redirect/sso/645460", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals("https://example.onelogin.com/trust/saml2/http-redirect/slo/645460", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="));
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:transient", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));

    }

    @Test
    public void testParseFileXmlMultix509cert() throws Exception {

        Map<String, Object> idpInfo = IdPMetadataParser.parseFileXML("data/metadata/idp/metadata.xml");
        assertEquals("https://idp.examle.com/saml/metadata", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://idp.examle.com/saml/sso", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals("https://idp.examle.com/saml/slo", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + ".0")), Util.loadCert(
                "MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xNzA0MTUxNjMzMThaFw0xODA0MTUxNjMzMThaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6GLkl5lDUZdHNDAojp5i24OoPlqrt5TGXJIPqAZYT1hQvJW5nv17MFDHrjmtEnmW4ACKEy0fAX80QWIcHunZSkbEGHb+NG/6oTi5RipXMvmHnfFnPJJ0AdtiLiPE478CV856gXekV4Xx5u3KrylcOgkpYsp0GMIQBDzleMUXlYQIDAQABo1AwTjAdBgNVHQ4EFgQUnP8vlYPGPL2n6ZzDYij2kMDC8wMwHwYDVR0jBBgwFoAUnP8vlYPGPL2n6ZzDYij2kMDC8wMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQAlQGAl+b8Cpot1g+65lLLjVoY7APJPWLW0klKQNlMU0s4MU+71Y3ExUEOXDAZgKcFoavb1fEOGMwEf38NaJAy1e/l6VNuixXShffq20ymqHQxOG0q8ujeNkgZF9k6XDfn/QZ3AD0o/IrCT7UMc/0QsfgIjWYxwCvp2syApc5CYfQ=="));
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:transient", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));

    }

    @Test
    public void testParseFileXmlDesiredBindings() throws Exception {

        Map<String, Object> idpInfo = IdPMetadataParser.parseFileXML("data/metadata/idp/testshib-providers.xml");
        assertEquals("https://idp.testshib.org/idp/shibboleth", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzEVMBMGA1UECBMMUGVubnN5bHZhbmlhMRMwEQYDVQQHEwpQaXR0c2J1cmdoMREwDwYDVQQKEwhUZXN0U2hpYjEZMBcGA1UEAxMQaWRwLnRlc3RzaGliLm9yZzAeFw0wNjA4MzAyMTEyMjVaFw0xNjA4MjcyMTEyMjVaMGcxCzAJBgNVBAYTAlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExEzARBgNVBAcTClBpdHRzYnVyZ2gxETAPBgNVBAoTCFRlc3RTaGliMRkwFwYDVQQDExBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYkCGuTmJp9eAOSGHwRJo1SNatB5ZOKqDM9ysg7CyVTDClcpu93gSP10nH4gkCZOlnESNgttg0r+MqL8tfJC6ybddEFB3YBo8PZajKSe3OQ01Ow3yT4I+Wdg1tsTpSge9gEz7SrC07EkYmHuPtd71CHiUaCWDv+xVfUQX0aTNPFmDixzUjoYzbGDrtAyCqA8f9CN2txIfJnpHE6q6CmKcoLADS4UrNPlhHSzd614kR/JYiks0K4kbRqCQF0Dv0P5Di+rEfefC6glV8ysC8dB5/9nb0yh/ojRuJGmgMWHgWk6h0ihjihqiu4jACovUZ7vVOCgSE5Ipn7OIwqd93zp2wIDAQABo4HEMIHBMB0GA1UdDgQWBBSsBQ869nh83KqZr5jArr4/7b+QazCBkQYDVR0jBIGJMIGGgBSsBQ869nh83KqZr5jArr4/7b+Qa6FrpGkwZzELMAkGA1UEBhMCVVMxFTATBgNVBAgTDFBlbm5zeWx2YW5pYTETMBEGA1UEBxMKUGl0dHNidXJnaDERMA8GA1UEChMIVGVzdFNoaWIxGTAXBgNVBAMTEGlkcC50ZXN0c2hpYi5vcmeCAQAwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAjR29PhrCbk8qLN5MFfSVk98t3CT9jHZoYxd8QMRLI4j7iYQxXiGJTT1FXs1nd4Rha9un+LqTfeMMYqISdDDI6tv8iNpkOAvZZUosVkUo93pv1T0RPz35hcHHYq2yee59HJOco2bFlcsH8JBXRSRrJ3Q7Eut+z9uo80JdGNJ4/SJy5UorZ8KazGj16lfJhOBXldgrhppQBb0Nq6HKHguqmwRfJ+WkxemZXzhediAjGeka8nz8JjwxpUjAiSWYKLtJhGEaTqCYxCCX2Dw+dOTqUzHOZ7WKv4JXPK5G/Uhr8K/qhmFT2nIQi538n6rVYLeWj8Bbnl+ev0peYzxFyF5sQA=="));
        assertEquals("urn:mace:shibboleth:1.0:nameIdentifier", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));

        idpInfo = IdPMetadataParser.parseFileXML("data/metadata/idp/testshib-providers.xml", "https://idp.testshib.org/idp/shibboleth");
        assertEquals("https://idp.testshib.org/idp/shibboleth", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzEVMBMGA1UECBMMUGVubnN5bHZhbmlhMRMwEQYDVQQHEwpQaXR0c2J1cmdoMREwDwYDVQQKEwhUZXN0U2hpYjEZMBcGA1UEAxMQaWRwLnRlc3RzaGliLm9yZzAeFw0wNjA4MzAyMTEyMjVaFw0xNjA4MjcyMTEyMjVaMGcxCzAJBgNVBAYTAlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExEzARBgNVBAcTClBpdHRzYnVyZ2gxETAPBgNVBAoTCFRlc3RTaGliMRkwFwYDVQQDExBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYkCGuTmJp9eAOSGHwRJo1SNatB5ZOKqDM9ysg7CyVTDClcpu93gSP10nH4gkCZOlnESNgttg0r+MqL8tfJC6ybddEFB3YBo8PZajKSe3OQ01Ow3yT4I+Wdg1tsTpSge9gEz7SrC07EkYmHuPtd71CHiUaCWDv+xVfUQX0aTNPFmDixzUjoYzbGDrtAyCqA8f9CN2txIfJnpHE6q6CmKcoLADS4UrNPlhHSzd614kR/JYiks0K4kbRqCQF0Dv0P5Di+rEfefC6glV8ysC8dB5/9nb0yh/ojRuJGmgMWHgWk6h0ihjihqiu4jACovUZ7vVOCgSE5Ipn7OIwqd93zp2wIDAQABo4HEMIHBMB0GA1UdDgQWBBSsBQ869nh83KqZr5jArr4/7b+QazCBkQYDVR0jBIGJMIGGgBSsBQ869nh83KqZr5jArr4/7b+Qa6FrpGkwZzELMAkGA1UEBhMCVVMxFTATBgNVBAgTDFBlbm5zeWx2YW5pYTETMBEGA1UEBxMKUGl0dHNidXJnaDERMA8GA1UEChMIVGVzdFNoaWIxGTAXBgNVBAMTEGlkcC50ZXN0c2hpYi5vcmeCAQAwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAjR29PhrCbk8qLN5MFfSVk98t3CT9jHZoYxd8QMRLI4j7iYQxXiGJTT1FXs1nd4Rha9un+LqTfeMMYqISdDDI6tv8iNpkOAvZZUosVkUo93pv1T0RPz35hcHHYq2yee59HJOco2bFlcsH8JBXRSRrJ3Q7Eut+z9uo80JdGNJ4/SJy5UorZ8KazGj16lfJhOBXldgrhppQBb0Nq6HKHguqmwRfJ+WkxemZXzhediAjGeka8nz8JjwxpUjAiSWYKLtJhGEaTqCYxCCX2Dw+dOTqUzHOZ7WKv4JXPK5G/Uhr8K/qhmFT2nIQi538n6rVYLeWj8Bbnl+ev0peYzxFyF5sQA=="));
        assertEquals("urn:mace:shibboleth:1.0:nameIdentifier", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));

        idpInfo = IdPMetadataParser.parseFileXML("data/metadata/idp/testshib-providers.xml", null, null, Constants.BINDING_HTTP_REDIRECT, Constants.BINDING_HTTP_REDIRECT);
        assertEquals("https://idp.testshib.org/idp/shibboleth", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzEVMBMGA1UECBMMUGVubnN5bHZhbmlhMRMwEQYDVQQHEwpQaXR0c2J1cmdoMREwDwYDVQQKEwhUZXN0U2hpYjEZMBcGA1UEAxMQaWRwLnRlc3RzaGliLm9yZzAeFw0wNjA4MzAyMTEyMjVaFw0xNjA4MjcyMTEyMjVaMGcxCzAJBgNVBAYTAlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExEzARBgNVBAcTClBpdHRzYnVyZ2gxETAPBgNVBAoTCFRlc3RTaGliMRkwFwYDVQQDExBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYkCGuTmJp9eAOSGHwRJo1SNatB5ZOKqDM9ysg7CyVTDClcpu93gSP10nH4gkCZOlnESNgttg0r+MqL8tfJC6ybddEFB3YBo8PZajKSe3OQ01Ow3yT4I+Wdg1tsTpSge9gEz7SrC07EkYmHuPtd71CHiUaCWDv+xVfUQX0aTNPFmDixzUjoYzbGDrtAyCqA8f9CN2txIfJnpHE6q6CmKcoLADS4UrNPlhHSzd614kR/JYiks0K4kbRqCQF0Dv0P5Di+rEfefC6glV8ysC8dB5/9nb0yh/ojRuJGmgMWHgWk6h0ihjihqiu4jACovUZ7vVOCgSE5Ipn7OIwqd93zp2wIDAQABo4HEMIHBMB0GA1UdDgQWBBSsBQ869nh83KqZr5jArr4/7b+QazCBkQYDVR0jBIGJMIGGgBSsBQ869nh83KqZr5jArr4/7b+Qa6FrpGkwZzELMAkGA1UEBhMCVVMxFTATBgNVBAgTDFBlbm5zeWx2YW5pYTETMBEGA1UEBxMKUGl0dHNidXJnaDERMA8GA1UEChMIVGVzdFNoaWIxGTAXBgNVBAMTEGlkcC50ZXN0c2hpYi5vcmeCAQAwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAjR29PhrCbk8qLN5MFfSVk98t3CT9jHZoYxd8QMRLI4j7iYQxXiGJTT1FXs1nd4Rha9un+LqTfeMMYqISdDDI6tv8iNpkOAvZZUosVkUo93pv1T0RPz35hcHHYq2yee59HJOco2bFlcsH8JBXRSRrJ3Q7Eut+z9uo80JdGNJ4/SJy5UorZ8KazGj16lfJhOBXldgrhppQBb0Nq6HKHguqmwRfJ+WkxemZXzhediAjGeka8nz8JjwxpUjAiSWYKLtJhGEaTqCYxCCX2Dw+dOTqUzHOZ7WKv4JXPK5G/Uhr8K/qhmFT2nIQi538n6rVYLeWj8Bbnl+ev0peYzxFyF5sQA=="));
        assertEquals("urn:mace:shibboleth:1.0:nameIdentifier", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));

        idpInfo = IdPMetadataParser.parseFileXML("data/metadata/idp/testshib-providers.xml", null, null, Constants.BINDING_HTTP_ARTIFACT, Constants.BINDING_HTTP_ARTIFACT);
        assertEquals("https://idp.testshib.org/idp/shibboleth", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://idp.testshib.org/idp/profile/Shibboleth/SSO", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:mace:shibboleth:1.0:profiles:AuthnRequest", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzEVMBMGA1UECBMMUGVubnN5bHZhbmlhMRMwEQYDVQQHEwpQaXR0c2J1cmdoMREwDwYDVQQKEwhUZXN0U2hpYjEZMBcGA1UEAxMQaWRwLnRlc3RzaGliLm9yZzAeFw0wNjA4MzAyMTEyMjVaFw0xNjA4MjcyMTEyMjVaMGcxCzAJBgNVBAYTAlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExEzARBgNVBAcTClBpdHRzYnVyZ2gxETAPBgNVBAoTCFRlc3RTaGliMRkwFwYDVQQDExBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYkCGuTmJp9eAOSGHwRJo1SNatB5ZOKqDM9ysg7CyVTDClcpu93gSP10nH4gkCZOlnESNgttg0r+MqL8tfJC6ybddEFB3YBo8PZajKSe3OQ01Ow3yT4I+Wdg1tsTpSge9gEz7SrC07EkYmHuPtd71CHiUaCWDv+xVfUQX0aTNPFmDixzUjoYzbGDrtAyCqA8f9CN2txIfJnpHE6q6CmKcoLADS4UrNPlhHSzd614kR/JYiks0K4kbRqCQF0Dv0P5Di+rEfefC6glV8ysC8dB5/9nb0yh/ojRuJGmgMWHgWk6h0ihjihqiu4jACovUZ7vVOCgSE5Ipn7OIwqd93zp2wIDAQABo4HEMIHBMB0GA1UdDgQWBBSsBQ869nh83KqZr5jArr4/7b+QazCBkQYDVR0jBIGJMIGGgBSsBQ869nh83KqZr5jArr4/7b+Qa6FrpGkwZzELMAkGA1UEBhMCVVMxFTATBgNVBAgTDFBlbm5zeWx2YW5pYTETMBEGA1UEBxMKUGl0dHNidXJnaDERMA8GA1UEChMIVGVzdFNoaWIxGTAXBgNVBAMTEGlkcC50ZXN0c2hpYi5vcmeCAQAwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAjR29PhrCbk8qLN5MFfSVk98t3CT9jHZoYxd8QMRLI4j7iYQxXiGJTT1FXs1nd4Rha9un+LqTfeMMYqISdDDI6tv8iNpkOAvZZUosVkUo93pv1T0RPz35hcHHYq2yee59HJOco2bFlcsH8JBXRSRrJ3Q7Eut+z9uo80JdGNJ4/SJy5UorZ8KazGj16lfJhOBXldgrhppQBb0Nq6HKHguqmwRfJ+WkxemZXzhediAjGeka8nz8JjwxpUjAiSWYKLtJhGEaTqCYxCCX2Dw+dOTqUzHOZ7WKv4JXPK5G/Uhr8K/qhmFT2nIQi538n6rVYLeWj8Bbnl+ev0peYzxFyF5sQA=="));
        assertEquals("urn:mace:shibboleth:1.0:nameIdentifier", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));

    }

    @Test
    public void testParseRemoteXML() throws Exception {

        Map<String, Object> idpInfo = IdPMetadataParser.parseRemoteXML(new URL("https://app.onelogin.com/saml/metadata/645460"));
        assertEquals("https://app.onelogin.com/saml/metadata/645460", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://sgarcia-us-preprod.onelogin.com/trust/saml2/http-redirect/sso/645460", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals("https://sgarcia-us-preprod.onelogin.com/trust/saml2/http-redirect/slo/645460", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="));
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:transient", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));

        idpInfo = IdPMetadataParser.parseRemoteXML(new URL("https://app.onelogin.com/saml/metadata/383123"));
        assertEquals("https://app.onelogin.com/saml/metadata/383123", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://try-demo.onelogin.com/trust/saml2/http-redirect/sso/383123", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals("https://try-demo.onelogin.com/trust/saml2/http-redirect/slo/383123", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIDGTCCAoKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsalDL15zSKeEGy9c0Hao7+G02x6k/MlZuCwEvkPKUcl9QF/q0584lta735hmiZSuWOFQDNQ4VT53VevjAhOtzLJOsa8wcZ+SA1s3j4bNcpUIAHltb4Az6NC7U2/LatfnwscOazEJnVsfL4aaBdpIHBFQ6Ed0StD0AfB6Ci0hURwIDAQABo4HUMIHRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFHm3fLi+Q1zMc3guMyHy5AHdQvdgMIGRBgNVHSMEgYkwgYaAFHm3fLi+Q1zMc3guMyHy5AHdQvdgoWukaTBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADgYEANZvzlB1Aq84AdOvsn2XKxBB/PmNZLqnM1VWRPaNcvjafx7eHd5qayXFNQz+bOLujENmgAm5padbydG89SeefpOGcY2TMsVt0RUzxTnN3Zq5G6Ja2fAKOEX01ejdoPPMmStqqSw8k1wPUU8uLYJG5wmjf0rCb8RVaeAwMc+wcEIA="));
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));
    }

    @Test
    public void testParseMultiCerts() throws Exception {
        Map<String, Object> idpInfo = IdPMetadataParser.parseFileXML("data/metadata/idp/idp_metadata_multi_certs.xml");
        assertEquals("https://idp.examle.com/saml/metadata", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://idp.examle.com/saml/sso", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals("https://idp.examle.com/saml/slo", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + "0")), Util.loadCert(
                "MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xODAxMTcxNTMzNDNaFw0yMTEwMTMxNTMzNDNaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxejk/DNtB9TlB7PNek/Pds6txAhSbTSIEX6jjKgE170PXCncpkogIO9ae/r3psBll2nU+FbKpnml+Jv81I8nMazQceDg9R4CRnTUV5mwgZShW1DzpEuG3/8TzYcpA41HZQ7Wl7dT19h55speZ8egGptQEcOazMfWmLEI1QhHaowIDAQABo1AwTjAdBgNVHQ4EFgQUmTK9rvir0zDUxKg8iTSh3fMCirowHwYDVR0jBBgwFoAUmTK9rvir0zDUxKg8iTSh3fMCirowDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQBhFvvRdguCYT34NJl884UhcmyEBarSBEEajkn73YAvyqhh+yo4LhWIvam/yFLsNdaDzwo9R8wzAaj4XGMPqM4WwSA69RTIv+n5gSgsrgFSja7HhP7Epw8SxpDQiW0ijh/TUTBvWOuqEEhQQvYRwshyJW7n82+wtArH8pnpFUOFuA=="));
        assertNull(idpInfo.get(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + "1"));
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:transient", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));
    }

    @Test
    public void testParseMultiSigningCerts() throws Exception {
        Map<String, Object> idpInfo = IdPMetadataParser.parseFileXML("data/metadata/idp/idp_metadata_multi_signing_certs.xml");
        assertEquals("https://idp.examle.com/saml/metadata", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://idp.examle.com/saml/sso", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals("https://idp.examle.com/saml/slo", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + "0")), Util.loadCert(
                "MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xNzA0MTUxNjMzMThaFw0xODA0MTUxNjMzMThaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6GLkl5lDUZdHNDAojp5i24OoPlqrt5TGXJIPqAZYT1hQvJW5nv17MFDHrjmtEnmW4ACKEy0fAX80QWIcHunZSkbEGHb+NG/6oTi5RipXMvmHnfFnPJJ0AdtiLiPE478CV856gXekV4Xx5u3KrylcOgkpYsp0GMIQBDzleMUXlYQIDAQABo1AwTjAdBgNVHQ4EFgQUnP8vlYPGPL2n6ZzDYij2kMDC8wMwHwYDVR0jBBgwFoAUnP8vlYPGPL2n6ZzDYij2kMDC8wMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQAlQGAl+b8Cpot1g+65lLLjVoY7APJPWLW0klKQNlMU0s4MU+71Y3ExUEOXDAZgKcFoavb1fEOGMwEf38NaJAy1e/l6VNuixXShffq20ymqHQxOG0q8ujeNkgZF9k6XDfn/QZ3AD0o/IrCT7UMc/0QsfgIjWYxwCvp2syApc5CYfQ=="));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + "1")), Util.loadCert(
                "MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xODAxMTcxNTMzNDNaFw0yMTEwMTMxNTMzNDNaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxejk/DNtB9TlB7PNek/Pds6txAhSbTSIEX6jjKgE170PXCncpkogIO9ae/r3psBll2nU+FbKpnml+Jv81I8nMazQceDg9R4CRnTUV5mwgZShW1DzpEuG3/8TzYcpA41HZQ7Wl7dT19h55speZ8egGptQEcOazMfWmLEI1QhHaowIDAQABo1AwTjAdBgNVHQ4EFgQUmTK9rvir0zDUxKg8iTSh3fMCirowHwYDVR0jBBgwFoAUmTK9rvir0zDUxKg8iTSh3fMCirowDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQBhFvvRdguCYT34NJl884UhcmyEBarSBEEajkn73YAvyqhh+yo4LhWIvam/yFLsNdaDzwo9R8wzAaj4XGMPqM4WwSA69RTIv+n5gSgsrgFSja7HhP7Epw8SxpDQiW0ijh/TUTBvWOuqEEhQQvYRwshyJW7n82+wtArH8pnpFUOFuA=="));
        assertNull(idpInfo.get(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + "2"));
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:transient", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));
    }

    @Test
    public void testParseMultiSameSigningAndEncryptCert() throws Exception {
        Map<String, Object> idpInfo = IdPMetadataParser.parseFileXML("data/metadata/idp/idp_metadata_same_sign_and_encrypt_cert.xml");
        assertEquals("https://app.onelogin.com/saml/metadata/383123", idpInfo.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://app.onelogin.com/trust/saml2/http-post/sso/383123", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sTgf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0mTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SFzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNVHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHuAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcVgG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClPTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWuQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh781sE="));
        assertNull(idpInfo.get(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + "0"));
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", idpInfo.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));

        Map<String, Object> idpInfo2 = IdPMetadataParser.parseFileXML("data/metadata/idp/idp_metadata_different_sign_and_encrypt_cert.xml");
        assertEquals("https://app.onelogin.com/saml/metadata/383123", idpInfo2.get(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY));
        assertEquals("https://app.onelogin.com/trust/saml2/http-post/sso/383123", idpInfo2.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY));
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", idpInfo2.get(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY));
        assertEquals(Util.loadCert((String) idpInfo2.get(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY)), Util.loadCert(
                "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="));
        assertEquals(Util.loadCert((String) idpInfo2.get(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + "0")), Util.loadCert(
                "MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sTgf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0mTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SFzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNVHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHuAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcVgG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClPTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWuQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh781sE="));
        assertNull(idpInfo2.get(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + "2"));
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", idpInfo2.get(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY));
    }

    @Test
    public void testInjectIntoSettings() throws Exception {
        Saml2Settings setting = new SettingsBuilder().fromFile("config/config.min.properties").build();

        assertEquals("http://idp.example.com/", setting.getIdpEntityId());
        assertEquals("http://idp.example.com/simplesaml/saml2/idp/SSOService.php", setting.getIdpSingleSignOnServiceUrl().toString());
        assertEquals(setting.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertEquals("http://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", setting.getIdpSingleLogoutServiceUrl().toString());
        assertEquals(setting.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertEquals(Util.loadCert(Util.getFileAsString("certs/certificate1")), setting.getIdpx509cert());
        assertEquals(setting.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

        Map<String, Object> idpInfo = IdPMetadataParser.parseFileXML("data/metadata/idp/FederationMetadata.xml");
        setting = IdPMetadataParser.injectIntoSettings(setting, idpInfo);
        assertEquals("http://idp.adfs.example.com/adfs/services/trust", setting.getIdpEntityId());
        assertEquals("https://idp.adfs.example.com/adfs/ls/", setting.getIdpSingleSignOnServiceUrl().toString());
        assertEquals(setting.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertEquals("https://idp.adfs.example.com/adfs/ls/", setting.getIdpSingleLogoutServiceUrl().toString());
        assertEquals(setting.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertEquals(setting.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        assertEquals(setting.getIdpx509cert(), Util.loadCert(
                "MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xNzA0MTUxMjI3NTFaFw0yNzA0MTMxMjI3NTFaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYtEZ7hGZiNp+NecbcQXosYl8TzVOdL44b3Nl+BxL26Bvnt8YNnE63xiQzo7xDdO6+1MWWO26mMxwMpooTToOJgrot9YhlIX1VHIUPbOEGczSmXzCCmMhS26vR/leoLNah8QqCF1UdCoNQejb0fDCy+Q1yEdMXYkBWsFGfDSHSSQIDAQABo1AwTjAdBgNVHQ4EFgQUT1g33aGN0f6BJPgpYbr1pHrMZrYwHwYDVR0jBBgwFoAUT1g33aGN0f6BJPgpYbr1pHrMZrYwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQB6233Ic9bb6OCMT6hE1mRzhoP+AbixeojtUuM1IUG4JI5YUGsjsym96VBw+/ciwDLuxNYg6ZWu++WxWNwF3LwVRZGQ8bDdxYldm6VorvIbps2tzyT5N32xgMAgzy/3SZf6YOihdotXJd5AZNVp/razVO17WrjsFvldAlKtk0SM7w=="));
        assertEquals(setting.getIdpx509certMulti().get(0), Util.loadCert(
                "MIIC9jCCAd6gAwIBAgIQI/B8CLE676pCR2/QaKih9TANBgkqhkiG9w0BAQsFADA3MTUwMwYDVQQDEyxBREZTIFNpZ25pbmcgLSBsb2dpbnRlc3Qub3dlbnNib3JvaGVhbHRoLm9yZzAeFw0xNjEwMjUxNjI4MzhaFw0xNzEwMjUxNjI4MzhaMDcxNTAzBgNVBAMTLEFERlMgU2lnbmluZyAtIGxvZ2ludGVzdC5vd2Vuc2Jvcm9oZWFsdGgub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjikmKRRVD5oK3fxm0xNfDqvWCujZIhtv2zeIwmoRKUAjo6KeUhauII4BHh5DclmbOFD4ruli3sNWGKgqVCX1AFW/p3m3/FtzeumFeZSmyfqeJEeOqAK5jAom/MfXxaQ85QHlGa0BTtdWdCuxhJz5G797o4s1Me/8QOQdmbkkwOHOVXRDW0QxBXvsRB1jPpIO+JvNcWFpvJrELccD0Fws91LH42j2C4gDNR8JLu5LrUGL6zAIq8NM7wfbwoax9n/0tIZKa6lo6szpXGqiMrDBJPpAqC5MSePyp5/SEX6jxwodQUGRgI5bKILQwOWDrkgfsK1MIeHfovtyqnDZj8e9VwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBKbK4qu7WTLYeQW7OcFAeWcT5D7ujo61QtPf+6eY8hpNntN8yF71vGm+5zdOjmw18igxUrf3W7dLk2wAogXK196WX34x9muorwmFK/HqmKuy0kWWzGcNzZHb0o4Md2Ux7QQVoHqD6dUSqUisOBs34ZPgT5R42LepJTGDEZSkvOxUv9V6fY5dYk8UaWbZ7MQAFi1CnOyybq2nVNjpuxWyJ6SsHQYKRhXa7XGurXFB2mlgcjVj9jxW0gO7djkgRD68b6PNpQmJkbKnkCtJg9YsSeOmuUjwgh4DlcIo5jZocKd5bnLbQ9XKJ3YQHRxFoZbP3BXKrfhVV3vqqzRxMwjZmK"));
    }

}
