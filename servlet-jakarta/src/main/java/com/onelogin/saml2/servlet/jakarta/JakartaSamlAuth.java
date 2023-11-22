package com.onelogin.saml2.servlet.jakarta;

import com.onelogin.saml2.BaseAuth;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.model.KeyStoreSettings;
import com.onelogin.saml2.settings.Saml2Settings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import static com.onelogin.saml2.servlet.jakarta.JakartaSamlHttpRequest.makeHttpRequest;
import static com.onelogin.saml2.servlet.jakarta.JakartaSamlHttpResponse.makeHttpResponse;

public class JakartaSamlAuth extends BaseAuth {

    public JakartaSamlAuth() throws IOException, SettingsException, Error {
        super();
    }

    public JakartaSamlAuth(KeyStoreSettings keyStoreSetting) throws IOException, SettingsException, Error {
        super(keyStoreSetting);
    }

    public JakartaSamlAuth(String filename) throws IOException, SettingsException, Error {
        super(filename);
    }

    public JakartaSamlAuth(String filename, KeyStoreSettings keyStoreSetting) throws IOException, SettingsException, Error {
        super(filename, keyStoreSetting);
    }

    public JakartaSamlAuth(HttpServletRequest request, HttpServletResponse response) throws IOException, SettingsException, Error {
        super(makeHttpRequest(request), makeHttpResponse(response));
    }

    public JakartaSamlAuth(KeyStoreSettings keyStoreSetting, HttpServletRequest request, HttpServletResponse response) throws IOException, SettingsException, Error {
        super(keyStoreSetting, makeHttpRequest(request), makeHttpResponse(response));
    }

    public JakartaSamlAuth(String filename, HttpServletRequest request, HttpServletResponse response) throws SettingsException, IOException, Error {
        super(filename, makeHttpRequest(request), makeHttpResponse(response));
    }

    public JakartaSamlAuth(String filename, KeyStoreSettings keyStoreSetting, HttpServletRequest request, HttpServletResponse response) throws SettingsException, IOException, Error {
        super(filename, keyStoreSetting, makeHttpRequest(request), makeHttpResponse(response));
    }

    public JakartaSamlAuth(Saml2Settings settings, HttpServletRequest request, HttpServletResponse response) throws SettingsException {
        super(settings, makeHttpRequest(request), makeHttpResponse(response));
    }

}
