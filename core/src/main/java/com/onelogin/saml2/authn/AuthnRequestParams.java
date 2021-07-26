package com.onelogin.saml2.authn;

/**
 * Input parameters for a SAML 2 authentication request.
 */
public class AuthnRequestParams {

	/**
	 * When true the AuthNRequest will set the ForceAuthn='true'
	 */
	private final boolean forceAuthn;
	/**
	 * When true the AuthNRequest will set the IsPassive='true'
	 */
	private final boolean isPassive;
	/**
	 * When true the AuthNReuqest will set a nameIdPolicy
	 */
	private final boolean setNameIdPolicy;
	/**
	 * Indicates to the IdP the subject that should be authenticated
	 */
	private final String nameIdValueReq;

	/**
	 * Create a set of authentication request input parameters.
	 *
	 * @param forceAuthn
	 *              whether the <code>ForceAuthn</code> attribute should be set to
	 *              <code>true</code>
	 * @param isPassive
	 *              whether the <code>isPassive</code> attribute should be set to
	 *              <code>true</code>
	 * @param setNameIdPolicy
	 *              whether a <code>NameIDPolicy</code> should be set
	 */
	public AuthnRequestParams(boolean forceAuthn, boolean isPassive, boolean setNameIdPolicy) {
		this(forceAuthn, isPassive, setNameIdPolicy, null);
	}

	/**
	 * Create a set of authentication request input parameters.
	 *
	 * @param forceAuthn
	 *              whether the <code>ForceAuthn</code> attribute should be set to
	 *              <code>true</code>
	 * @param isPassive
	 *              whether the <code>isPassive</code> attribute should be set to
	 *              <code>true</code>
	 * @param setNameIdPolicy
	 *              whether a <code>NameIDPolicy</code> should be set
	 * @param nameIdValueReq
	 *              the subject that should be authenticated
	 */
	public AuthnRequestParams(boolean forceAuthn, boolean isPassive, boolean setNameIdPolicy, String nameIdValueReq) {
		this.forceAuthn = forceAuthn;
		this.isPassive = isPassive;
		this.setNameIdPolicy = setNameIdPolicy;
		this.nameIdValueReq = nameIdValueReq;
	}

	/**
	 * Create a set of authentication request input parameters, by copying them from
	 * another set.
	 *
	 * @param source
	 *              the source set of authentication request input parameters
	 */
	protected AuthnRequestParams(AuthnRequestParams source) {
		this.forceAuthn = source.isForceAuthn();
		this.isPassive = source.isPassive();
		this.setNameIdPolicy = source.isSetNameIdPolicy();
		this.nameIdValueReq = source.getNameIdValueReq();
	}

	/**
	 * @return whether the <code>ForceAuthn</code> attribute should be set to
	 *         <code>true</code>
	 */
	protected boolean isForceAuthn() {
		return forceAuthn;
	}

	/**
	 * @return whether the <code>isPassive</code> attribute should be set to
	 *         <code>true</code>
	 */
	protected boolean isPassive() {
		return isPassive;
	}

	/**
	 * @return whether a <code>NameIDPolicy</code> should be set
	 */
	protected boolean isSetNameIdPolicy() {
		return setNameIdPolicy;
	}

	/**
	 * @return the subject that should be authenticated
	 */
	protected String getNameIdValueReq() {
		return nameIdValueReq;
	}
}