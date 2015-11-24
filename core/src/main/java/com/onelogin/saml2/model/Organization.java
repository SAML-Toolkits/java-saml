package com.onelogin.saml2.model;

import java.net.URL;


public class Organization {
	private final String orgName;
	private final String orgDisplayName;
	private final String orgUrl;

	public Organization(String orgName, String orgDisplayName, URL orgUrl) {
		super();

		this.orgName = orgName != null ? orgName : "";
		this.orgDisplayName = orgDisplayName != null ? orgDisplayName : "";
		this.orgUrl = orgUrl != null ? orgUrl.toString() : "";
	}

	/**
	 * @return the orgName
	 */
	public final String getOrgName() {
		return orgName;
	}

	/**
	 * @return the orgDisplayName
	 */
	public final String getOrgDisplayName() {
		return orgDisplayName;
	}

	/**
	 * @return the orgUrl
	 */
	public final String getOrgUrl() {
		return orgUrl;
	}
}
