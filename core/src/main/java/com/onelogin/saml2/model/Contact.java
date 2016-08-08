package com.onelogin.saml2.model;


/**
 * Contact class of OneLogin's Java Toolkit.
 *
 * A class that stores contact info 
 */
public class Contact {
	/**
     * Contact type
     */
	private final String contactType;

	/**
     * Contact given name
     */
	private final String givenName;

	/**
     * Contact email
     */
	private final String emailAddress;

	/**
	 * Constructor
	 *
	 * @param contactType
	 *              String. Contact type
	 * @param givenName
     *				String. Contact given name
	 * @param emailAddress
     *				String. Contact email
	 */
	public Contact(String contactType, String givenName, String emailAddress) {
		this.contactType = contactType != null? contactType : "";
		this.givenName = givenName != null? givenName : "";
		this.emailAddress = emailAddress != null? emailAddress : "";
	}

	/**
	 * @return string the contact type
	 */
	public final String getContactType() {
		return contactType;
	}

	/**
	 * @return string the contact email
	 */
	public final String getEmailAddress() {
		return emailAddress;
	}

	/**
	 * @return string the contact given name
	 */
	public final String getGivenName() {
		return givenName;
	}

}