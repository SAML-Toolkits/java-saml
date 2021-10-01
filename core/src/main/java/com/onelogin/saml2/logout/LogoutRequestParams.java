package com.onelogin.saml2.logout;

/**
 * Input parameters for a SAML 2 logout request.
 */
public class LogoutRequestParams {

	/**
	 * SessionIndex. When the user is logged, this stored it from the AuthnStatement
	 * of the SAML Response
	 */
	private final String sessionIndex;

	/**
	 * NameID.
	 */
	private final String nameId;

	/**
	 * NameID Format.
	 */
	private final String nameIdFormat;

	/**
	 * nameId NameQualifier
	 */
	private final String nameIdNameQualifier;

	/**
	 * nameId SP NameQualifier
	 */
	private final String nameIdSPNameQualifier;

	/** Create an empty set of logout request input parameters. */
	public LogoutRequestParams() {
		this(null, null);
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
	public String getNameId() {
		return nameId;
	}

	/**
	 * @return the name ID format
	 */
	public String getNameIdFormat() {
		return nameIdFormat;
	}

	/**
	 * @return the name ID name qualifier
	 */
	public String getNameIdNameQualifier() {
		return nameIdNameQualifier;
	}

	/**
	 * @return the name ID SP name qualifier
	 */
	public String getNameIdSPNameQualifier() {
		return nameIdSPNameQualifier;
	}

	/**
	 * @return the session index
	 */
	public String getSessionIndex() {
		return sessionIndex;
	}
}