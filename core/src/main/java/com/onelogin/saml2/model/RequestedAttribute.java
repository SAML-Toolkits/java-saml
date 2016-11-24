package com.onelogin.saml2.model;

import java.util.List;


/**
 * RequestedAttribute class of OneLogin's Java Toolkit.
 *
 * A class that stores RequestedAttribute of the AttributeConsumingService 
 */
public class RequestedAttribute {
	/**
     * Name of the attribute
     */
	private final String name;

	/**
     * FriendlyName of the attribute
     */
	private final String friendlyName;

	/**
     * If the attribute is or not required
     */
	private final Boolean isRequired;
	
	/**
     * NameFormat of the attribute
     */
	private final String nameFormat;

	/**
     * Values of the attribute
     */
	private final List<String> attributeValues;
	
	/**
	 * Constructor
	 *
	 * @param name
	 *              String. RequestedAttribute Name
	 * @param friendlyName
	 *              String. RequestedAttribute FriendlyName
	 * @param isRequired
	 *              Boolean. RequestedAttribute isRequired value
	 * @param nameFormat
	 *              Boolean. RequestedAttribute NameFormat
	 * @param attributeValues
	 *              List<String>. RequestedAttribute values
	 */
	public RequestedAttribute(String name, String friendlyName, Boolean isRequired, String nameFormat, List<String> attributeValues) {
		this.name = name;
		this.friendlyName = friendlyName;
		this.isRequired = isRequired;
		this.nameFormat = nameFormat;
		this.attributeValues = attributeValues;
	}
	
	/**
	 * @return string the RequestedAttribute name
	 */
	public final String getName() {
		return name;
	}

	/**
	 * @return string the RequestedAttribute fiendlyname
	 */
	public final String getFriendlyName() {
		return friendlyName;
	}

	/**
	 * @return boolean the RequestedAttribute isRequired value
	 */
	public final Boolean isRequired() {
		return isRequired;
	}
	
	/**
	 * @return string the RequestedAttribute nameformat
	 */
	public final String getNameFormat() {
		return nameFormat;
	}
	
	/**
	 * @return string the RequestedAttribute nameformat
	 */
	public final List<String> getAttributeValues() {
		return attributeValues;
	}
}