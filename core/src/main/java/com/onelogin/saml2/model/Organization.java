package com.onelogin.saml2.model;

import java.net.URL;

import org.apache.commons.lang3.StringUtils;


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
	 * Organization lang attribute
	 */
	private final String orgLangAttribute;

	/**
	 * Constructor
	 *
	 * @param orgName
	 *              String. Organization name
	 * @param orgDisplayName
     *				String. Organization display name
	 * @param orgUrl
     *				URL. Organization URL
     * @param orgLangAttribute
     * 				The xml lang attribute, describing name and display name
	 */
	public Organization(String orgName, String orgDisplayName, URL orgUrl, String orgLangAttribute) {
		this(orgName, orgDisplayName, orgUrl != null ? orgUrl.toString() : "", orgLangAttribute);
	}
	
	/**
	 * Constructor<br>
	 * Default the lang attribute to "en"
	 *
	 * @param orgName
	 *              String. Organization name
	 * @param orgDisplayName
     *				String. Organization display name
	 * @param orgUrl
     *				URL. Organization URL
	 */
	public Organization(String orgName, String orgDisplayName, URL orgUrl) {
		this(orgName, orgDisplayName, orgUrl, "en");
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
     * @param orgLangAttribute
     * 				The xml lang attribute, describing name and display name
	 */
	public Organization(String orgName, String orgDisplayName, String orgUrl, String orgLangAttribute) {
		this.orgName = orgName != null ? orgName : "";
		this.orgDisplayName = orgDisplayName != null ? orgDisplayName : "";
		this.orgUrl = orgUrl != null ? orgUrl : "";
		this.orgLangAttribute = StringUtils.defaultIfBlank(orgLangAttribute, "en");
	}
	
	/**
	 * Constructor<br>
	 * Default the lang attribute to "en"
	 *
	 * @param orgName
	 *              String. Organization name
	 * @param orgDisplayName
     *				String. Organization display name
	 * @param orgUrl
     *				String. Organization URL
	 */
	public Organization(String orgName, String orgDisplayName, String orgUrl) {
		this(orgName, orgDisplayName, orgUrl, "en");
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
	 * @return string the lang attribute
	 */
	public final String getOrgLangAttribute() {
		return orgLangAttribute;
	}	

	/**
	 * Compare with another organization
	 *
	 * @param org Organization to compare with
	 *
	 * @return boolean true if organizations are equals
	 */
	public final Boolean equalsTo(Organization org) {
		return orgName.equals(org.getOrgName()) && orgDisplayName.equals(org.getOrgDisplayName()) && orgUrl.equals(org.getOrgUrl()) && orgLangAttribute.equals(org.getOrgLangAttribute());
	}	
}
