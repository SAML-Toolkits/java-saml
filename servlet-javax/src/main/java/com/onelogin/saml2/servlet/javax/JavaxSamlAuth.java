package com.onelogin.saml2.servlet.javax;

import com.onelogin.saml2.BaseAuth;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.model.KeyStoreSettings;
import com.onelogin.saml2.settings.Saml2Settings;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.onelogin.saml2.servlet.javax.JavaxSamlHttpRequest.makeHttpRequest;
import static com.onelogin.saml2.servlet.javax.JavaxSamlHttpResponse.makeHttpResponse;

public class JavaxSamlAuth extends BaseAuth {

    public JavaxSamlAuth() throws IOException, SettingsException, Error {
        super();
    }

    public JavaxSamlAuth(KeyStoreSettings keyStoreSetting) throws IOException, SettingsException, Error {
        super(keyStoreSetting);
    }

    public JavaxSamlAuth(String filename) throws IOException, SettingsException, Error {
        super(filename);
    }

    public JavaxSamlAuth(String filename, KeyStoreSettings keyStoreSetting) throws IOException, SettingsException, Error {
        super(filename, keyStoreSetting);
    }

    public JavaxSamlAuth(HttpServletRequest request, HttpServletResponse response) throws IOException, SettingsException, Error {
        super(makeHttpRequest(request), makeHttpResponse(response));
    }

    public JavaxSamlAuth(KeyStoreSettings keyStoreSetting, HttpServletRequest request, HttpServletResponse response) throws IOException, SettingsException, Error {
        super(keyStoreSetting, makeHttpRequest(request), makeHttpResponse(response));
    }

    public JavaxSamlAuth(String filename, HttpServletRequest request, HttpServletResponse response) throws SettingsException, IOException, Error {
        super(filename, makeHttpRequest(request), makeHttpResponse(response));
    }

    public JavaxSamlAuth(String filename, KeyStoreSettings keyStoreSetting, HttpServletRequest request, HttpServletResponse response) throws SettingsException, IOException, Error {
        super(filename, keyStoreSetting, makeHttpRequest(request), makeHttpResponse(response));
    }

    public JavaxSamlAuth(Saml2Settings settings, HttpServletRequest request, HttpServletResponse response) throws SettingsException {
        super(settings, makeHttpRequest(request), makeHttpResponse(response));
    }

}
