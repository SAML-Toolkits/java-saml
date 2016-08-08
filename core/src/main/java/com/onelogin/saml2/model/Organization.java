package com.onelogin.saml2.model;

import java.net.URL;


/**
 * Organization class of OneLogin's Java Toolkit.
 *
 * A class that stores organization info 
 */
public class Organization {
	/**
     * Organization name
     */
	private final String orgName;

	/**
     * Organization display name
     */
	private final String orgDisplayName;

	/**
     * Organization URL
     */
	private final String orgUrl;

	/**
	 * Constructor
	 *
	 * @param orgName
	 *              String. Organization name
	 * @param orgDisplayName
     *				String. Organization display name
	 * @param orgUrl
     *				URL. Organization URL
	 */
	public Organization(String orgName, String orgDisplayName, URL orgUrl) {
		this.orgName = orgName != null ? orgName : "";
		this.orgDisplayName = orgDisplayName != null ? orgDisplayName : "";
		this.orgUrl = orgUrl != null ? orgUrl.toString() : "";
	}

	/**
	 * Constructor
	 *
	 * @param orgName
	 *              String. Organization name
	 * @param orgDisplayName
     *				String. Organization display name
	 * @param orgUrl
     *				String. Organization URL
	 */
	public Organization(String orgName, String orgDisplayName, String orgUrl) {
		this.orgName = orgName != null ? orgName : "";
		this.orgDisplayName = orgDisplayName != null ? orgDisplayName : "";
		this.orgUrl = orgUrl != null ? orgUrl : "";
	}

	/**
	 * @return string the organization name
	 */
	public final String getOrgName() {
		return orgName;
	}

	/**
	 * @return string the organization display name
	 */
	public final String getOrgDisplayName() {
		return orgDisplayName;
	}

	/**
	 * @return string the organization URL
	 */
	public final String getOrgUrl() {
		return orgUrl;
	}

	/**
	 * Compare with another organization
	 *
	 * @param org Organization to compare with
	 *
	 * @return boolean true if organizations are equals
	 */
	public final Boolean equalsTo(Organization org) {
		return orgName.equals(org.getOrgName()) && orgDisplayName.equals(org.getOrgDisplayName()) && orgUrl.equals(org.getOrgUrl());
	}	
}
