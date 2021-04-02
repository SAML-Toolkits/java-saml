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
	public final static Integer ALOWED_CLOCK_DRIFT = 180; // 3 min in seconds

	// NameID Formats	
	public final static String NAMEID_EMAIL_ADDRESS = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
	public final static String NAMEID_X509_SUBJECT_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
	public final static String NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
	public final static String NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
	public final static String NAMEID_KERBEROS = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
	public final static String NAMEID_ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
	public final static String NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
	public final static String NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
	public final static String NAMEID_ENCRYPTED = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";
	
	// Attribute Name Formats
	public final static String ATTRNAME_FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
	public final static String ATTRNAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
	public final static String ATTRNAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

	// Namespaces
	public final static String NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
	public final static String NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
	public final static String NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
	public final static String NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
	public final static String NS_XS = "http://www.w3.org/2001/XMLSchema";
	public final static String NS_XSI = "http://www.w3.org/2001/XMLSchema-instance";
	public final static String NS_XENC = "http://www.w3.org/2001/04/xmlenc#";
	public final static String NS_DS = "http://www.w3.org/2000/09/xmldsig#";

	// Bindings
	public final static String BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
	public final static String BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
	public final static String BINDING_HTTP_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
	public final static String BINDING_SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
	public final static String BINDING_DEFLATE = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";

	// Auth Context Class
	public final static String AC_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
	public final static String AC_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
	public final static String AC_X509 = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";
	public final static String AC_SMARTCARD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";
	public final static String AC_KERBEROS = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos";

	// Subject Confirmation
	public final static String CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
	public final static String CM_HOLDER_KEY = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
	public final static String CM_SENDER_VOUCHES = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

	// Status Codes
	public final static String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
	public final static String STATUS_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester";
	public final static String STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";
	public final static String STATUS_VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";

	// Status Second-level Codes
	public final static String STATUS_AUTHNFAILED = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
	public final static String STATUS_INVALID_ATTRNAME_OR_VALUE =  "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";
	public final static String STATUS_INVALID_NAMEIDPOLICY = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";
	public final static String STATUS_NO_AUTHNCONTEXT = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
	public final static String STATUS_NO_AVAILABLE_IDP = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP";
	public final static String STATUS_NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
	public final static String STATUS_NO_SUPPORTED_IDP = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP";
	public final static String STATUS_PARTIAL_LOGOUT = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
	public final static String STATUS_PROXY_COUNT_EXCEEDED = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded";
	public final static String STATUS_REQUEST_DENIED = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
	public final static String STATUS_REQUEST_UNSUPPORTED = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";
	public final static String STATUS_REQUEST_VERSION_DEPRECATED = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated";
	public final static String STATUS_REQUEST_VERSION_TOO_HIGH = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh";
	public final static String STATUS_REQUEST_VERSION_TOO_LOW = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow";
	public final static String STATUS_RESOURCE_NOT_RECOGNIZED = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized";
	public final static String STATUS_TOO_MANY_RESPONSES = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses";
	public final static String STATUS_UNKNOWN_ATTR_PROFILE = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile";
	public final static String STATUS_UNKNOWN_PRINCIPAL = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";
	public final static String STATUS_UNSUPPORTED_BINDING = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";

	// Canonization
	public final static String C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
	public final static String C14N_WC = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
	public final static String C14N11 = "http://www.w3.org/2006/12/xml-c14n11";
	public final static String C14N11_WC = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
	public final static String C14NEXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
	public final static String C14NEXC_WC = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
	
    // Sign & Crypt   
	// https://www.w3.org/TR/xmlenc-core/#sec-Alg-MessageDigest
	// https://www.w3.org/TR/xmlsec-algorithms/#signature-method-uris
	// https://tools.ietf.org/html/rfc6931
	public final static String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
	public final static String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
	public final static String SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
	public final static String SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

	public final static String DSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
	public final static String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
	public final static String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	public final static String RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
	public final static String RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    
	public final static String TRIPLEDES_CBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
	public final static String AES128_CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
	public final static String AES192_CBC = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
	public final static String AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
	public final static String A128KW = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
	public final static String A192KW = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
	public final static String A256KW = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
	public final static String RSA_1_5 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
	public final static String RSA_OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
	
	public final static String ENVSIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
	
	private Constants() {
	      //not called
	}
	
}
