package com.onelogin.saml2.test.model;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.onelogin.saml2.model.Organization;

/**
 * Tests the com.onelogin.saml2.model.Organization class
 */
public class OrganizationTest {

	/**
	 * Tests the Organization constructor
	 *
	 * @throws MalformedURLException
	 *
	 * @see com.onelogin.saml2.model.Organization
	 */
	@Test
	public void testOrganization() throws MalformedURLException {
		URL url = null;
		Organization org = new Organization(null, null, url);
		assertEquals("", org.getOrgName());
		assertEquals("", org.getOrgDisplayName());
		assertEquals("", org.getOrgUrl());

		String urlStr = null;
		Organization org2 = new Organization(null, null, urlStr);
		assertEquals("", org2.getOrgName());
		assertEquals("", org2.getOrgDisplayName());
		assertEquals("", org2.getOrgUrl());

		URL urlExample = new URL("http://example.com");
		Organization org3 = new Organization("", "", urlExample);
		assertEquals("", org3.getOrgName());
		assertEquals("", org3.getOrgDisplayName());
		assertEquals("http://example.com", org3.getOrgUrl());

		String urlExampleStr = "http://example.com";
		Organization org4 = new Organization("", "", urlExampleStr);
		assertEquals("", org4.getOrgName());
		assertEquals("", org4.getOrgDisplayName());
		assertEquals("http://example.com", org4.getOrgUrl());

		Organization org5 = new Organization("OrgName", "DisplayName", urlExampleStr);
		assertEquals("OrgName", org5.getOrgName());
		assertEquals("DisplayName", org5.getOrgDisplayName());
		assertEquals("http://example.com", org5.getOrgUrl());
	}

	/**
	 * Tests Organization comparison
	 *
	 * @see com.onelogin.saml2.model.Organization#equalsTo
	 */
	@Test
	public void testEqualsTo() {
		Organization org = new Organization("SP Java", "SP Java Example", "http://sp.example.com");
		Organization org2 = new Organization("SP Java", "SP Java Example", "http://sp.example.com");
		Organization org3 = new Organization("SP Java 3", "SP Java Example", "http://sp.example.com");
		Organization org4 = new Organization("SP Java", "SP Java Example 4", "http://sp.example.com");
		Organization org5 = new Organization("SP Java", "SP Java Example", "http://sp.example.com/5");
		Organization org6 = new Organization("SP Java 6", "SP Java Example 6", "http://sp.example.com/6");

		assertTrue(org.equalsTo(org2));
		assertFalse(org.equalsTo(org3));
		assertFalse(org.equalsTo(org4));
		assertFalse(org.equalsTo(org5));
	}
}
