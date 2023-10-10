package com.onelogin.saml2.model;

import java.net.URL;

import com.onelogin.saml2.util.Constants;

/**
 * AssertionConsumerService class of OneLogin's Java Toolkit.
 *
 * A class that stores an AssertionConsumerService (ACS)
 */
public class AssertionConsumerService {

	/**
	 * Service Index
	 */
	private final int index;

	/**
	 * Whether this service is the default one
	 */
	private final Boolean isDefault;

	/**
	 * Binding
	 */
	private final String binding;

	/**
	 * Location
	 */
	private final URL location;

	/**
	 * Constructor.
	 * <p>
	 * {@link Constants#BINDING_HTTP_POST} binding will be set.
	 * 
	 * @param location
	 *              ACS location URL
	 */
	public AssertionConsumerService(final URL location) {
		this(1, null, null, location);
	}

	/**
	 * Constructor
	 * 
	 * @param binding
	 *              ACS Binding; if <code>null</code>,
	 *              {@link Constants#BINDING_HTTP_POST} will be set
	 * @param location
	 *              ACS location URL
	 */
	public AssertionConsumerService(final String binding, final URL location) {
		this(1, null, binding, location);
	}

	/**
	 * Constructor
* 	 * <p>
	 * {@link Constants#BINDING_HTTP_POST} binding will be set.

	 * @param index
	 *              ACS index
	 * @param location
	 *              ACS location URL
	 */
	public AssertionConsumerService(final int index, final URL location) {
		this(index, null, null, location);
	}

	/**
	 * Constructor
	 * <p>
	 * {@link Constants#BINDING_HTTP_POST} binding will be set.
	 * 
	 * @param index
	 *              ACS index
	 * @param isDefault
	 *              Whether it's the default attribute consuming service
	 * @param location
	 *              ACS location URL
	 */
	public AssertionConsumerService(final int index, final Boolean isDefault, final URL location) {
		this(index, isDefault, null, location);
	}

	/**
	 * Constructor
	 * 
	 * @param index
	 *              ACS index
	 * @param isDefault
	 *              Whether it's the default attribute consuming service
	 * @param binding
	 *              ACS Binding; if <code>null</code>,
	 *              {@link Constants#BINDING_HTTP_POST} will be set
	 * @param location
	 *              ACS location URL
	 */
	public AssertionConsumerService(final int index, final Boolean isDefault, final String binding,
	            final URL location) {
		this.index = index;
		this.isDefault = isDefault;
		this.binding = binding != null ? binding : Constants.BINDING_HTTP_POST;
		this.location = location;
	}

	/**
	 * @return the ACS index
	 */
	public final int getIndex() {
		return index;
	}

	/**
	 * @return whether this is the default ACS
	 */
	public final Boolean isDefault() {
		return isDefault;
	}

	/**
	 * @return the binding
	 */
	public final String getBinding() {
		return binding;
	}

	/**
	 * @return the location
	 */
	public final URL getLocation() {
		return location;
	}
}