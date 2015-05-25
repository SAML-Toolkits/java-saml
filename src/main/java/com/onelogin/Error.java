package com.onelogin;

/**
 * Error class of OneLogin Java Toolkit Defines the Error class
 */
@SuppressWarnings("serial")
public class Error extends Exception {
	// Errors
	public static Integer SETTINGS_FILE_NOT_FOUND = 0;
	public static Integer SETTINGS_INVALID_SYNTAX = 1;
	public static Integer SETTINGS_INVALID = 2;
	public static Integer METADATA_SP_INVALID = 3;
	public static Integer SP_CERTS_NOT_FOUND = 4;
	public static Integer REDIRECT_INVALID_URL = 5;
	public static Integer PUBLIC_CERT_FILE_NOT_FOUND = 6;
	public static Integer PRIVATE_KEY_FILE_NOT_FOUND = 7;
	public static Integer SAML_RESPONSE_NOT_FOUND = 8;
	public static Integer SAML_LOGOUTMESSAGE_NOT_FOUND = 9;
	public static Integer SAML_LOGOUTREQUEST_INVALID = 10;
	public static Integer SAML_LOGOUTRESPONSE_INVALID = 11;
	public static Integer SAML_SINGLE_LOGOUT_NOT_SUPPORTED = 12;

	public Error() {
	}

	/**
	 * Constructor that receives a message string.
	 * 
	 * @param message
	 *            Error message
	 */
	public Error(String message) {
		super(message);
	}

	/**
	 * Constructor that receives a message string and an inner exception.
	 * 
	 * @param message
	 *            Error Message
	 * @param inner
	 *            Inner exception
	 */
	public Error(String message, Exception inner) {
		super(message, inner);
	}
}
