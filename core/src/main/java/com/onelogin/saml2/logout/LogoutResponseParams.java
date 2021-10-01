package com.onelogin.saml2.logout;

import com.onelogin.saml2.model.SamlResponseStatus;
import com.onelogin.saml2.util.Constants;

/**
 * Input parameters for a SAML 2 logout response.
 */
public class LogoutResponseParams {

	/**
	 * Id of the logout request the response refers to.
	 */
	private final String inResponseTo;

	/**
	 * Response status.
	 */
	private final SamlResponseStatus responseStatus;

	/**
	 * Creates a logout response with no <code>inResponseTo</code> attribute and a
	 * response status with a top-level {@link Constants#STATUS_SUCCESS} status
	 * code.
	 */
	public LogoutResponseParams() {
		this((String) null);
	}

	/**
	 * Creates a logout response with a response status with a top-level
	 * {@link Constants#STATUS_SUCCESS} status code.
	 * 
	 * @param inResponseTo
	 *              the id of the logout request the response refers to; may be
	 *              <code>null</code> if such id cannot be determined (possibly
	 *              because the request is malformed)
	 */
	public LogoutResponseParams(String inResponseTo) {
		this(inResponseTo, Constants.STATUS_SUCCESS);
	}

	/**
	 * Creates a logout response.
	 *
	 * @param inResponseTo
	 *              the id of the logout request the response refers to; may be
	 *              <code>null</code> if such id cannot be determined (possibly
	 *              because the request is malformed)
	 * @param statusCode
	 *              the top-level status code code to set on the response
	 */
	public LogoutResponseParams(String inResponseTo, String statusCode) {
		this(inResponseTo, new SamlResponseStatus(statusCode));
	}

	/**
	 * Creates a logout response.
	 *
	 * @param inResponseTo
	 *              the id of the logout request the response refers to; may be
	 *              <code>null</code> if such id cannot be determined (possibly
	 *              because the request is malformed)
	 * @param responseStatus
	 *              the response status; should not be <code>null</code>
	 * @throws NullPointerException
	 *               if the specified response status is <code>null</code>
	 */
	public LogoutResponseParams(String inResponseTo, SamlResponseStatus responseStatus) throws NullPointerException {
		this.inResponseTo = inResponseTo;
		this.responseStatus = responseStatus;
		if (responseStatus == null)
			throw new NullPointerException("response status must not be null");
	}

	/**
	 * Create a set of logout request input parameters, by copying them from another
	 * set.
	 *
	 * @param source
	 *              the source set of logout request input parameters
	 */
	protected LogoutResponseParams(LogoutResponseParams source) {
		this.inResponseTo = source.getInResponseTo();
		this.responseStatus = source.getResponseStatus();
	}

	/**
	 * Returns the response status.
	 * 
	 * @return the response status
	 */
	public SamlResponseStatus getResponseStatus() {
		return responseStatus;
	}

	/**
	 * Returns the id of the logout request this response refers to.
	 * 
	 * @return the <code>inResponseTo</code>
	 */
	public String getInResponseTo() {
		return inResponseTo;
	}
}