package com.onelogin.saml2.test.authn;

import static org.junit.Assert.assertEquals;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.support.membermodification.MemberMatcher.method;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Util;

@RunWith(PowerMockRunner.class)
@PrepareForTest(AuthnRequest.class)
public class AuthnRequestTest {

	@Test
	public void getRequestTest() throws Exception {
		Saml2Settings settings = new SettingsBuilder().fromFile("config/config.certstring.properties").build();

		String authnRequestString = Util.getFileAsString("data/requests/authn_request.xml");
		AuthnRequest authnRequest = PowerMockito.spy(new AuthnRequest(settings));

		when(authnRequest, method(AuthnRequest.class, "getAuthnRequestXml")).withNoArguments().thenReturn(
				authnRequestString);

		String expectedAuthnRequestStringBase64 = Util.getFileAsString("data/requests/authn_request.xml.base64");
		String authnRequestStringBase64 = authnRequest.getEncodedAuthnRequest();

		assertEquals(authnRequestStringBase64, expectedAuthnRequestStringBase64);

	}

}
