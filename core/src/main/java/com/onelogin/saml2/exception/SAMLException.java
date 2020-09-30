package com.onelogin.saml2.exception;

/**
 * Top-level exception class for the OneLogin SAML client.
 */
public class SAMLException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Construct a SAMLException with the provided error message.
     *
     * @param message 
     *     The human-readable error message associated with this exception.
     */
    public SAMLException(String message) {
        super(message);
    }

    /**
     * Construct a SAMLException with the provided cause for the exception.
     *
     * @param cause
     *     The upstream cause of this exception.
     */
    public SAMLException(Throwable cause) {
        super(cause);
    }

    /**
     * Construct a SAMLException with the provided human-readable error message
     * and upstream cause.
     *
     * @param message
     *     The human-readable error message associated with this exception.
     * 
     * @param cause 
     *     The upstream cause associated with this exception.
     */
    public SAMLException(String message, Throwable cause) {
        super(message, cause);
    }

}