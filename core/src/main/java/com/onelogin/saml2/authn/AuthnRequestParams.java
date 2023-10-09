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
	 * When true the AuthNRequest will set a nameIdPolicy
	 */
	private final boolean setNameIdPolicy;
	/**
	 * When true and {@link #setNameIdPolicy} is also <code>true</code>, then the
	 * AllowCreate='true' will be set on the NameIDPolicy element
	 */
	private final boolean allowCreate;
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
	 *              whether the <code>IsPassive</code> attribute should be set to
	 *              <code>true</code>
	 * @param setNameIdPolicy
	 *              whether a <code>NameIDPolicy</code> should be set
	 */
	public AuthnRequestParams(boolean forceAuthn, boolean isPassive, boolean setNameIdPolicy) {
		this(forceAuthn, isPassive, setNameIdPolicy, true);
	}

	/**
	 * Create a set of authentication request input parameters.
	 *
	 * @param forceAuthn
	 *              whether the <code>ForceAuthn</code> attribute should be set to
	 *              <code>true</code>
	 * @param isPassive
	 *              whether the <code>IsPassive</code> attribute should be set to
	 *              <code>true</code>
	 * @param setNameIdPolicy
	 *              whether a <code>NameIDPolicy</code> should be set
	 * @param allowCreate
	 *              whether the <code>AllowCreate</code> attribute should be set to
	 *              <code>true</code> on the <code>NameIDPolicy</code> element; only
	 *              meaningful if <code>setNameIdPolicy</code> is also
	 *              <code>true</code>
	 */
	public AuthnRequestParams(boolean forceAuthn, boolean isPassive, boolean setNameIdPolicy, boolean allowCreate) {
		this(forceAuthn, isPassive, setNameIdPolicy, allowCreate, null);
	}

	/**
	 * Create a set of authentication request input parameters.
	 *
	 * @param forceAuthn
	 *              whether the <code>ForceAuthn</code> attribute should be set to
	 *              <code>true</code>
	 * @param isPassive
	 *              whether the <code>IsPassive</code> attribute should be set to
	 *              <code>true</code>
	 * @param setNameIdPolicy
	 *              whether a <code>NameIDPolicy</code> should be set
	 * @param nameIdValueReq
	 *              the subject that should be authenticated
	 */
	public AuthnRequestParams(boolean forceAuthn, boolean isPassive, boolean setNameIdPolicy, String nameIdValueReq) {
		this(forceAuthn, isPassive, setNameIdPolicy, true, nameIdValueReq);
	}

	/**
	 * Create a set of authentication request input parameters.
	 *
	 * @param forceAuthn
	 *              whether the <code>ForceAuthn</code> attribute should be set to
	 *              <code>true</code>
	 * @param isPassive
	 *              whether the <code>IsPassive</code> attribute should be set to
	 *              <code>true</code>
	 * @param setNameIdPolicy
	 *              whether a <code>NameIDPolicy</code> should be set
	 * @param allowCreate
	 *              the value to set for the <code>allowCreate</code> attribute of
	 *              <code>NameIDPolicy</code> element; <code>null</code> means it's
	 *              not set at all; only meaningful when
	 *              <code>setNameIdPolicy</code> is <code>true</code>
	 * @param nameIdValueReq
	 *              the subject that should be authenticated
	 */
	public AuthnRequestParams(boolean forceAuthn, boolean isPassive, boolean setNameIdPolicy, boolean allowCreate,
	            String nameIdValueReq) {
		this.forceAuthn = forceAuthn;
		this.isPassive = isPassive;
		this.setNameIdPolicy = setNameIdPolicy;
		this.allowCreate = allowCreate;
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
		this.allowCreate = source.isAllowCreate();
		this.nameIdValueReq = source.getNameIdValueReq();
	}

	/**
	 * @return whether the <code>ForceAuthn</code> attribute should be set to
	 *         <code>true</code>
	 */
	public boolean isForceAuthn() {
		return forceAuthn;
	}

	/**
	 * @return whether the <code>IsPassive</code> attribute should be set to
	 *         <code>true</code>
	 */
	public boolean isPassive() {
		return isPassive;
	}

	/**
	 * @return whether a <code>NameIDPolicy</code> should be set
	 */
	public boolean isSetNameIdPolicy() {
		return setNameIdPolicy;
	}

	/**
	 * @return whether the <code>AllowCreate</code> attribute should be set to
	 *         <code>true</code> on the <code>NameIDPolicy</code> element (only
	 *         meaningful if {@link #isSetNameIdPolicy()} is also <code>true</code>)
	 */
	public boolean isAllowCreate() {
		return allowCreate;
	}

	/**
	 * @return the subject that should be authenticated
	 */
	public String getNameIdValueReq() {
		return nameIdValueReq;
	}
}