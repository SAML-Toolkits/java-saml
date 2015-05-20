package com.onelogin;

public class Constants {
	// Value added to the current time in time condition validations
	public static Integer ALOWED_CLOCK_DRIFT = 180; // 3 min in seconds

	// NameID Formats
	public static String NAMEID_EMAIL_ADDRESS = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
	public static String NAMEID_X509_SUBJECT_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
	public static String NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
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

	// XMLSecurityKey
	public static String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
}
