package com.onelogin.saml2.exception;

public class Error extends Exception {

	private static final long serialVersionUID = 1L;

    public static final int SETTINGS_FILE_NOT_FOUND = 1;
    public static final int METADATA_SP_INVALID = 2;
    public static final int SAML_RESPONSE_NOT_FOUND = 3;
    public static final int SAML_LOGOUTMESSAGE_NOT_FOUND = 4;
    public static final int SAML_LOGOUTREQUEST_INVALID = 5;
    public static final int SAML_LOGOUTRESPONSE_INVALID = 6;
    public static final int SAML_SINGLE_LOGOUT_NOT_SUPPORTED = 7;
    
    private int errorCode;
	
	public Error(String message, int errorCode) {
		super(message);
		this.errorCode = errorCode;
	}
	
    public int getErrorCode() {
        return errorCode;
    }

}
