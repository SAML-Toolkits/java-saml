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
	 * Tests the Organization constructors
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
		assertEquals("en", org.getOrgLangAttribute());

		String urlStr = null;
		Organization org2 = new Organization(null, null, urlStr);
		assertEquals("", org2.getOrgName());
		assertEquals("", org2.getOrgDisplayName());
		assertEquals("", org2.getOrgUrl());
		assertEquals("en", org2.getOrgLangAttribute());

		URL urlExample = new URL("http://example.com");
		Organization org3 = new Organization("", "", urlExample);
		assertEquals("", org3.getOrgName());
		assertEquals("", org3.getOrgDisplayName());
		assertEquals("http://example.com", org3.getOrgUrl());
		assertEquals("en", org3.getOrgLangAttribute());

		String urlExampleStr = "http://example.com";
		Organization org4 = new Organization("", "", urlExampleStr);
		assertEquals("", org4.getOrgName());
		assertEquals("", org4.getOrgDisplayName());
		assertEquals("http://example.com", org4.getOrgUrl());
		assertEquals("en", org4.getOrgLangAttribute());

		Organization org5 = new Organization("OrgName", "DisplayName", urlExampleStr);
		assertEquals("OrgName", org5.getOrgName());
		assertEquals("DisplayName", org5.getOrgDisplayName());
		assertEquals("http://example.com", org5.getOrgUrl());
		assertEquals("en", org5.getOrgLangAttribute());
		
		Organization org6 = new Organization("NomOrg", "DisplayName", urlExampleStr, "fr");
		assertEquals("NomOrg", org6.getOrgName());
		assertEquals("DisplayName", org6.getOrgDisplayName());
		assertEquals("http://example.com", org6.getOrgUrl());
		assertEquals("fr", org6.getOrgLangAttribute());
		
		Organization org7 = new Organization("NomOrg", "DisplayName", urlExample, "fr");
		assertEquals("NomOrg", org7.getOrgName());
		assertEquals("DisplayName", org7.getOrgDisplayName());
		assertEquals("http://example.com", org7.getOrgUrl());
		assertEquals("fr", org7.getOrgLangAttribute());
		
		Organization org8 = new Organization("OrgName", "DisplayName", urlExampleStr, "");
		assertEquals("OrgName", org8.getOrgName());
		assertEquals("DisplayName", org8.getOrgDisplayName());
		assertEquals("http://example.com", org8.getOrgUrl());
		assertEquals("en", org8.getOrgLangAttribute());
		
		Organization org9 = new Organization("OrgName", "DisplayName", urlExampleStr, null);
		assertEquals("OrgName", org9.getOrgName());
		assertEquals("DisplayName", org9.getOrgDisplayName());
		assertEquals("http://example.com", org9.getOrgUrl());
		assertEquals("en", org9.getOrgLangAttribute());
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
		Organization org6 = new Organization("SP Java", "SP Java Example", "http://sp.example.com", "en");
		Organization org7 = new Organization("SP Java", "SP Java Example", "http://sp.example.com", "fr");

		assertTrue(org.equalsTo(org2));
		assertFalse(org.equalsTo(org3));
		assertFalse(org.equalsTo(org4));
		assertFalse(org.equalsTo(org5));
		assertTrue(org.equalsTo(org6));
		assertFalse(org.equalsTo(org7));
	}
}
