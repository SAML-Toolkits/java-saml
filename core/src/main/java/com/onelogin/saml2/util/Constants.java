package com.onelogin.saml2.util;

/**
 * Constants class of OneLogin's Java Toolkit.
 *
 * A class that contains several constants related to the SAML protocol
 */ 
public final class Constants {
	/**
     * Value added to the current time in time condition validations.
     */
	public static Integer ALOWED_CLOCK_DRIFT = 180; // 3 min in seconds

	// NameID Formats	
	public static String NAMEID_EMAIL_ADDRESS = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
	public static String NAMEID_X509_SUBJECT_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
	public static String NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
	public static String NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
	public static String NAMEID_KERBEROS = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
	public static String NAMEID_ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
	public static String NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
	public static String NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
	public static String NAMEID_ENCRYPTED = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";
	
	// Attribute Name Formats
	public static String ATTRNAME_FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
	public static String ATTRNAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
	public static String ATTRNAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

	// Namespaces
	public static String NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
	public static String NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
	public static String NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
	public static String NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
	public static String NS_XS = "http://www.w3.org/2001/XMLSchema";
	public static String NS_XSI = "http://www.w3.org/2001/XMLSchema-instance";
	public static String NS_XENC = "http://www.w3.org/2001/04/xmlenc#";
	public static String NS_DS = "http://www.w3.org/2000/09/xmldsig#";

	// Bindings
	public static String BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
	public static String BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
	public static String BINDING_HTTP_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
	public static String BINDING_SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
	public static String BINDING_DEFLATE = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";

	// Auth Context Class
	public static String AC_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
	public static String AC_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
	public static String AC_X509 = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";
	public static String AC_SMARTCARD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";
	public static String AC_KERBEROS = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos";

	// Subject Confirmation
	public static String CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
	public static String CM_HOLDER_KEY = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
	public static String CM_SENDER_VOUCHES = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

	// Status Codes
	public static String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
	public static String STATUS_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester";
	public static String STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";
	public static String STATUS_VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
	public static String STATUS_NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
	public static String STATUS_PARTIAL_LOGOUT = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
	public static String STATUS_PROXY_COUNT_EXCEEDED = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded";

	// Canonization
	public static String C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
	public static String C14N_WC = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
	public static String C14N11 = "http://www.w3.org/2006/12/xml-c14n11";
	public static String C14N11_WC = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
	public static String C14NEXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
	public static String C14NEXC_WC = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
	
    // Sign & Crypt   
	// https://www.w3.org/TR/xmlenc-core/#sec-Alg-MessageDigest
	// https://www.w3.org/TR/xmlsec-algorithms/#signature-method-uris
	// https://tools.ietf.org/html/rfc6931
	public static String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
	public static String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
	public static String SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
	public static String SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

	public static String DSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
	public static String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
	public static String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	public static String RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
	public static String RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    
	public static String TRIPLEDES_CBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
	public static String AES128_CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
	public static String AES192_CBC = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
	public static String AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
	public static String RSA_1_5 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
	public static String RSA_OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
	
	public static String ENVSIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
	
	private Constants() {
	      //not called
	}
	
}
