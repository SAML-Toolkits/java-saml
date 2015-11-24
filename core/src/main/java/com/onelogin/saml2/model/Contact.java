package com.onelogin.saml2.model;


public class Contact {
	private final String contactType;
	private final String givenName;
	private final String emailAddress;

	public Contact(String contactType, String givenName, String emailAddress) {
		super();
		this.contactType = contactType;
		this.givenName = givenName;
		this.emailAddress = emailAddress;
	}

	/**
	 * @return the contactType
	 */
	public final String getContactType() {
		return contactType;
	}

	/**
	 * @return the emailAddress
	 */
	public final String getEmailAddress() {
		return emailAddress;
	}

	/**
	 * @return the givenName
	 */
	public final String getGivenName() {
		return givenName;
	}

}