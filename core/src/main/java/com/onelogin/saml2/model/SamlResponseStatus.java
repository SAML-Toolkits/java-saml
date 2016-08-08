package com.onelogin.saml2.model;


/**
 * SamlResponseStatus class of OneLogin's Java Toolkit.
 *
 * A class that stores the SAML response status info
 */
public class SamlResponseStatus {
	/**
     * Status code
     */
	private String statusCode;

	/**
     * Status Message
     */
	private String statusMessage;

	/**
	 * Constructor
	 *
	 * @param statusCode
	 *              String. Status code
	 */
	public SamlResponseStatus(String statusCode) {
		this.statusCode = statusCode;
	}

	/**
	 * Constructor
	 *
	 * @param statusCode
	 *              String. Status code
	 * @param statusMessage
     *				String. Status message
	 */
	public SamlResponseStatus(String statusCode, String statusMessage) {
		this.statusCode = statusCode;
		this.statusMessage = statusMessage;
	}

	/**
	 * @return string the status code
	 */
	public String getStatusCode() {
		return statusCode;
	}

	/**
	 * Set the status code
	 * 
	 * @param stausCode 
	 *              String. Status code
	 */
	public void setStatusCode(String stausCode) {
		this.statusCode = stausCode;
	}

	/**
	 * @return string the status message
	 */
	public String getStatusMessage() {
		return statusMessage;
	}

	/**
	 * Set the status message
	 * 
	 * @param statusMessage 
	 *              String. Status message
	 */
	public void setStatusMessage(String statusMessage) {
		this.statusMessage = statusMessage;
	}

	/**
	 * Compare the status code
	 * 
	 * @param status 
	 *              String. Status code
	 *
	 * @return boolean checks the status code 
	 */
	public boolean is(String status) {
		return statusCode != null && !statusCode.isEmpty() && statusCode.equals(status);
	}

}
