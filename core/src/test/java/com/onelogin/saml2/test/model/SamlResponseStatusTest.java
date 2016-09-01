package com.onelogin.saml2.test.model;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.onelogin.saml2.model.SamlResponseStatus;

/**
 * Tests the com.onelogin.saml2.model.SamlResponseStatus class
 */
public class SamlResponseStatusTest {

	/**
	 * Tests the SamlResponseStatus constructor
	 *
	 * @see com.onelogin.saml2.model.SamlResponseStatus
	 */
	@Test
	public void testSamlResponseStatus() {
		SamlResponseStatus srs1 = new SamlResponseStatus(null);
		assertNull(srs1.getStatusCode());
		assertNull(srs1.getStatusMessage());

		SamlResponseStatus srs2 = new SamlResponseStatus(null, null);
		assertNull(srs2.getStatusCode());
		assertNull(srs2.getStatusMessage());

		SamlResponseStatus srs3 = new SamlResponseStatus("");
		assertEquals("", srs3.getStatusCode());
		assertNull(srs3.getStatusMessage());

		SamlResponseStatus srs4 = new SamlResponseStatus("", "");
		assertEquals("", srs4.getStatusCode());
		assertEquals("", srs4.getStatusMessage());

		SamlResponseStatus srsSuccess = new SamlResponseStatus("urn:oasis:names:tc:SAML:2.0:status:Success");
		assertEquals("urn:oasis:names:tc:SAML:2.0:status:Success", srsSuccess.getStatusCode());
		assertNull(srsSuccess.getStatusMessage());
		
		SamlResponseStatus srsResponder = new SamlResponseStatus("urn:oasis:names:tc:SAML:2.0:status:Responder", "Invalid NameID");
		assertEquals("urn:oasis:names:tc:SAML:2.0:status:Responder", srsResponder.getStatusCode());
		assertEquals("Invalid NameID", srsResponder.getStatusMessage());
	}

	/**
	 * Tests the SamlResponseStatus setStatusCode method
	 *
	 * @see com.onelogin.saml2.model.SamlResponseStatus#setStatusCode
	 */
	@Test
	public void testSetStatusCode() {
		SamlResponseStatus srs1 = new SamlResponseStatus(null);
		assertNull(srs1.getStatusCode());
		assertNull(srs1.getStatusMessage());

		srs1.setStatusCode("");
		assertEquals("", srs1.getStatusCode());
		assertNull(srs1.getStatusMessage());
		
		srs1.setStatusCode("urn:oasis:names:tc:SAML:2.0:status:Success");
		assertEquals("urn:oasis:names:tc:SAML:2.0:status:Success", srs1.getStatusCode());
		assertNull(srs1.getStatusMessage());

		srs1.setStatusCode("urn:oasis:names:tc:SAML:2.0:status:Responder");
		assertEquals("urn:oasis:names:tc:SAML:2.0:status:Responder", srs1.getStatusCode());
		assertNull(srs1.getStatusMessage());
	}

	/**
	 * Tests the SamlResponseStatus setStatusMessage method
	 *
	 * @see com.onelogin.saml2.model.SamlResponseStatus#setStatusMessage
	 */
	@Test
	public void testSetStatusMessage() {
		SamlResponseStatus srs1 = new SamlResponseStatus(null, null);
		assertNull(srs1.getStatusCode());
		assertNull(srs1.getStatusMessage());

		srs1.setStatusMessage("");
		assertNull(srs1.getStatusCode());
		assertEquals("", srs1.getStatusMessage());

		srs1.setStatusMessage("Invalid NameID");
		assertNull(srs1.getStatusCode());
		assertEquals("Invalid NameID", srs1.getStatusMessage());
	}

	/**
	 * Tests the SamlResponseStatus is method
	 *
	 * @see com.onelogin.saml2.model.SamlResponseStatus#is
	 */
	@Test
	public void testIs() {
		SamlResponseStatus srs1 = new SamlResponseStatus(null, null);
		assertNull(srs1.getStatusCode());
		assertNull(srs1.getStatusMessage());
		assertFalse(srs1.is("urn:oasis:names:tc:SAML:2.0:status:Success"));
		
		srs1.setStatusCode("");
		assertFalse(srs1.is("urn:oasis:names:tc:SAML:2.0:status:Success"));
		
		srs1.setStatusCode("urn:oasis:names:tc:SAML:2.0:status:Responder");
		assertFalse(srs1.is("urn:oasis:names:tc:SAML:2.0:status:Success"));
		
		srs1.setStatusCode("urn:oasis:names:tc:SAML:2.0:status:Success");
		assertTrue(srs1.is("urn:oasis:names:tc:SAML:2.0:status:Success"));
		
		SamlResponseStatus srs2 = new SamlResponseStatus("urn:oasis:names:tc:SAML:2.0:status:Success");
		assertNull(srs2.getStatusMessage());
		assertTrue(srs2.is("urn:oasis:names:tc:SAML:2.0:status:Success"));
	}
}
