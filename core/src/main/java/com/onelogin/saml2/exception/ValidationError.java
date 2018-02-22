package com.onelogin.saml2.exception;

public class ValidationError extends Exception {

	private static final long serialVersionUID = 1L;

	public static final int UNSUPPORTED_SAML_VERSION = 0;
	public static final int MISSING_ID = 1;
	public static final int WRONG_NUMBER_OF_ASSERTIONS = 2;
	public static final int MISSING_STATUS = 3;
	public static final int MISSING_STATUS_CODE = 4;
	public static final int STATUS_CODE_IS_NOT_SUCCESS = 5;
	public static final int WRONG_SIGNED_ELEMENT = 6;
	public static final int ID_NOT_FOUND_IN_SIGNED_ELEMENT = 7;
	public static final int DUPLICATED_ID_IN_SIGNED_ELEMENTS = 8;
	public static final int INVALID_SIGNED_ELEMENT = 9;
	public static final int DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS = 10;
	public static final int UNEXPECTED_SIGNED_ELEMENTS = 11;
	public static final int WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE = 12;
	public static final int WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION = 13;
	public static final int INVALID_XML_FORMAT = 14;
	public static final int WRONG_INRESPONSETO = 15;
	public static final int NO_ENCRYPTED_ASSERTION = 16;
	public static final int NO_ENCRYPTED_NAMEID = 17;
	public static final int MISSING_CONDITIONS = 18;
	public static final int ASSERTION_TOO_EARLY = 19;
	public static final int ASSERTION_EXPIRED = 20;
	public static final int WRONG_NUMBER_OF_AUTHSTATEMENTS = 21;
	public static final int NO_ATTRIBUTESTATEMENT = 22;
	public static final int ENCRYPTED_ATTRIBUTES = 23;
	public static final int WRONG_DESTINATION = 24;
	public static final int EMPTY_DESTINATION = 25;
	public static final int WRONG_AUDIENCE = 26;
	public static final int ISSUER_MULTIPLE_IN_RESPONSE = 27;
	public static final int ISSUER_NOT_FOUND_IN_ASSERTION = 28;
	public static final int WRONG_ISSUER = 29;
	public static final int SESSION_EXPIRED = 30;
	public static final int WRONG_SUBJECTCONFIRMATION = 31;
	public static final int NO_SIGNED_MESSAGE = 32;
	public static final int NO_SIGNED_ASSERTION = 33;
	public static final int NO_SIGNATURE_FOUND = 34;
	public static final int KEYINFO_NOT_FOUND_IN_ENCRYPTED_DATA = 35;
	public static final int CHILDREN_NODE_NOT_FOUND_IN_KEYINFO = 36;
	public static final int UNSUPPORTED_RETRIEVAL_METHOD = 37;
	public static final int NO_NAMEID = 38;
	public static final int EMPTY_NAMEID = 39;
	public static final int SP_NAME_QUALIFIER_NAME_MISMATCH = 40;
	public static final int DUPLICATED_ATTRIBUTE_NAME_FOUND = 41;
	public static final int INVALID_SIGNATURE = 42;
	public static final int WRONG_NUMBER_OF_SIGNATURES = 43;
	public static final int RESPONSE_EXPIRED = 44;
	public static final int UNEXPECTED_REFERENCE = 45;
	public static final int NOT_SUPPORTED = 46;
	public static final int KEY_ALGORITHM_ERROR = 47;
	public static final int MISSING_ENCRYPTED_ELEMENT = 48;
    
    private int errorCode;
	
	public ValidationError(String message, int errorCode) {
		super(message);
		this.errorCode = errorCode;
	}
	
    public int getErrorCode() {
        return errorCode;
    }

}
