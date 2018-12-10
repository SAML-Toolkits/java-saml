package com.onelogin.saml2.exception;

/**
 * Top-level exception class for the OneLogin SAML client.
 */
public class SamlException extends Exception {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * Construct a SamlException with the provided error message.
     * 
     * @param message 
     *     The human-readable error message associated with this exception.
     */
    public SamlException(String message) {
        super(message);
    }
    
    /**
     * Construct a SamlException with the provided cause for the exception.
     * 
     * @param cause
     *     The upstream cause of this exception.
     */
    public SamlException(Throwable cause) {
        super(cause);
    }
    
    /**
     * Construct a SamlException with the provided human-readable error message
     * and upstream cause.
     * 
     * @param message
     *     The human-readable error message associated with this exception.
     * 
     * @param cause 
     *     The upstream cause associated with this exception.
     */
    public SamlException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
