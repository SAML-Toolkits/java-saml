package com.onelogin.saml2.test.settings;

import static org.junit.Assert.assertEquals;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.junit.Test;

import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Util;

public class SettingBuilderTest {

	// TODO create file.properties with all properties

	@Test
	public void loadFromFileCertString() throws Exception {
		Saml2Settings setting = new SettingsBuilder().fromFile("config/config.certstring.properties").build();

		checkSettings(setting);
	}

	private void checkSettings(Saml2Settings setting) throws Exception {
		assertEquals(setting.isDebugActive(), false);
		assertEquals(setting.isStrict(), false);
		assertEquals(setting.getSpEntityId(), "http://localhost:8080/java-saml-jspsample/metadata.jsp");
		assertEquals(setting.getSpAssertionConsumerServiceUrl().toString(),
				"http://localhost:8080/java-saml-jspsample/acs.jsp");
		assertEquals(setting.getSpAssertionConsumerServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		assertEquals(setting.getSpSingleLogoutServiceUrl().toString(),
				"http://localhost:8080/java-saml-jspsample/sls.jsp");
		assertEquals(setting.getSpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

		assertEquals(setting.getSpNameIDFormat(), "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");

		assertEquals(setting.getIdpEntityId(), "http://idp.example.com/");
		assertEquals(setting.getIdpSingleSignOnServiceUrl().toString(),
				"http://idp.example.com/SSOService.php");
		assertEquals(setting.getIdpSingleSignOnServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals(setting.getIdpSingleLogoutServiceUrl().toString(),
				"http://idp.example.com/SingleLogoutService.php");
		assertEquals(setting.getIdpSingleLogoutServiceBinding(), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		assertEquals(setting.getIdpx509cert(), Util.loadCert(Util.getFileAsString("certs/certificate1")));

	}

	/*
	@Test
	public void loadFromFileCertFile() throws IOException {
		new SettingsBuilder().fromFile("config/config.certfile.properties").build();
	}
	*/

	@Test(expected = FileNotFoundException.class)
	public void loadFromFileNotExist() throws IOException {
		new SettingsBuilder().fromFile("config/config.notfound.properties").build();
	}

	@Test
	public void loadFromFileEmpty() throws IOException {
		new SettingsBuilder().fromFile("config/config.empty.properties").build();
	}
}
