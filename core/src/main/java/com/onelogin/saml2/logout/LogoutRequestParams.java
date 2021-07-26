package com.onelogin.saml2.logout;

/**
 * Input parameters for a SAML 2 logout request.
 */
public class LogoutRequestParams {

	/**
	 * SessionIndex. When the user is logged, this stored it from the AuthnStatement
	 * of the SAML Response
	 */
	private String sessionIndex;

	/**
	 * NameID.
	 */
	private String nameId;

	/**
	 * NameID Format.
	 */
	private String nameIdFormat;

	/**
	 * nameId NameQualifier
	 */
	private String nameIdNameQualifier;

	/**
	 * nameId SP NameQualifier
	 */
	private String nameIdSPNameQualifier;

	/** Create an empty set of logout request input parameters. */
	public LogoutRequestParams() {
	}

	/**
	 * Create a set of logout request input parameters.
	 *
	 * @param sessionIndex
	 *              the session index
	 * @param nameId
	 *              the name id of the user to log out
	 */
	public LogoutRequestParams(String sessionIndex, String nameId) {
		this(sessionIndex, nameId, null, null, null);
	}

	/**
	 * Create a set of logout request input parameters.
	 *
	 * @param sessionIndex
	 *              the session index
	 * @param nameId
	 *              the name id of the user to log out
	 * @param nameIdFormat
	 *              the name id format
	 */
	public LogoutRequestParams(String sessionIndex, String nameId, String nameIdFormat) {
		this(sessionIndex, nameId, nameIdFormat, null, null);
	}

	/**
	 * Create a set of logout request input parameters.
	 *
	 * @param sessionIndex
	 *              the session index
	 * @param nameId
	 *              the name id of the user to log out
	 * @param nameIdFormat
	 *              the name id format
	 * @param nameIdNameQualifier
	 *              the name id qualifier
	 */
	public LogoutRequestParams(String sessionIndex, String nameId, String nameIdFormat, String nameIdNameQualifier) {
		this(sessionIndex, nameId, nameIdFormat, nameIdNameQualifier, null);
	}

	/**
	 * Create a set of logout request input parameters.
	 *
	 * @param sessionIndex
	 *              the session index
	 * @param nameId
	 *              the name id of the user to log out
	 * @param nameIdFormat
	 *              the name id format
	 * @param nameIdNameQualifier
	 *              the name id qualifier
	 * @param nameIdSPNameQualifier
	 *              the name id SP qualifier
	 */
	public LogoutRequestParams(String sessionIndex, String nameId, String nameIdFormat, String nameIdNameQualifier,
	            String nameIdSPNameQualifier) {
		this.sessionIndex = sessionIndex;
		this.nameId = nameId;
		this.nameIdFormat = nameIdFormat;
		this.nameIdNameQualifier = nameIdNameQualifier;
		this.nameIdSPNameQualifier = nameIdSPNameQualifier;
	}

	/**
	 * Create a set of logout request input parameters, by copying them from another
	 * set.
	 *
	 * @param source
	 *              the source set of logout request input parameters
	 */
	protected LogoutRequestParams(LogoutRequestParams source) {
		this.sessionIndex = source.getSessionIndex();
		this.nameId = source.getNameId();
		this.nameIdFormat = source.getNameIdFormat();
		this.nameIdNameQualifier = source.getNameIdNameQualifier();
		this.nameIdSPNameQualifier = source.getNameIdSPNameQualifier();
	}

	/**
	 * @return the name ID
	 */
	protected String getNameId() {
		return nameId;
	}

	/**
	 * Sets the name ID
	 * 
	 * @param nameId
	 *              the name ID to set
	 */
	protected void setNameId(String nameId) {
		this.nameId = nameId;
	}

	/**
	 * @return the name ID format
	 */
	protected String getNameIdFormat() {
		return nameIdFormat;
	}

	/**
	 * @return the name ID name qualifier
	 */
	protected String getNameIdNameQualifier() {
		return nameIdNameQualifier;
	}

	/**
	 * @return the name ID SP name qualifier
	 */
	protected String getNameIdSPNameQualifier() {
		return nameIdSPNameQualifier;
	}

	/**
	 * @return the session index
	 */
	protected String getSessionIndex() {
		return sessionIndex;
	}
}