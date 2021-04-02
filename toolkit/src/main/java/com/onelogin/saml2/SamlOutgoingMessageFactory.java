package com.onelogin.saml2;

import com.onelogin.saml2.settings.Saml2Settings;

/**
 * Factory which can create an outgoing SAML message object from a
 * {@link Saml2Settings} instance and other input parameters.
 *
 * @param <U>
 *              the type of input parameters required
 * @param <R>
 *              the type of SAML outgoing message object created
 */
@FunctionalInterface
public interface SamlOutgoingMessageFactory<U, R> {

	/**
	 * Creates an outgoing SAML message object.
	 *
	 * @param settings
	 *              the settings
	 * @param params
	 *              the input parameters
	 * @return the created received SAML message object
	 */
	R create(Saml2Settings settings, U params);
}