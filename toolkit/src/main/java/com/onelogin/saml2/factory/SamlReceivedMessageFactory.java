package com.onelogin.saml2.factory;

import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.settings.Saml2Settings;

/**
 * Factory which can create a received SAML message object from a
 * {@link Saml2Settings} instance and other input parameters.
 *
 * @param <R>
 *              the type of received SAML message object created
 */
@FunctionalInterface
public interface SamlReceivedMessageFactory<R> {

	/**
	 * Creates a received SAML message object.
	 *
	 * @param settings
	 *              the settings
	 * @param httpRequest
	 *              the HTTP request
	 * @return the created received SAML message object
	 * @throws Exception
	 *               if the message creation fails
	 */
	R create(Saml2Settings settings, HttpRequest httpRequest) throws Exception;
}