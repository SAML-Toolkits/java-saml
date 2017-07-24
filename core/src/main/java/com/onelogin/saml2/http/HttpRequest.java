package com.onelogin.saml2.http;

import com.onelogin.saml2.util.Util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Framework-agnostic representation of an HTTP request.
 *
 * @since 2.0.0
 */
public abstract class HttpRequest {

    /**
     * @return true if the request is using a secure scheme (HTTPS)
     */
    public abstract boolean isSecure();

    /**
     * @return the name of the request protocol (HTTP / HTTPS)
     */
    public abstract String getScheme();

    /**
     * @return the server name in the request e.g. www.example.com
     */
    public abstract String getServerName();

    /**
     * @return the port over which the request is made e.g. 80 or 443
     */
    public abstract int getServerPort();

    /**
     * @return the query string part of the URL
     */
    public abstract String getQueryString();

    /**
     * @return the URI the client used to make the request - only includes
     * the server path, but not the query string parameters.
     */
    public abstract String getRequestURI();

    /**
     * The URL the client used to make the request. Includes a protocol, server name, port number, and server path, but
     * not the query string parameters.
     *
     * @return the request URL
     */
    public abstract String getRequestURL();

    /**
     * @param name the query parameter name
     * @return the first value for the parameter, or null
     */
    public abstract String getParameter(String name);

    /**
     * Return an url encoded get parameter value
     * Prefer to extract the original encoded value directly from queryString since url
     * encoding is not canonical.
     *
     * @param name
     * @return the first value for the parameter, or null
     */
    public final String getEncodedParameter(String name) {
        Matcher matcher = Pattern.compile(Pattern.quote(name) + "=([^&#]+)").matcher(getQueryString());
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            return Util.urlEncoder(getParameter(name));
        }
    }

    /**
     * Return an url encoded get parameter value
     * Prefer to extract the original encoded value directly from queryString since url
     * encoding is not canonical.
     *
     * @param name
     * @param defaultValue
     * @return the first value for the parameter, or url encoded default value
     */
    public final String getEncodedParameter(String name, String defaultValue) {
        String value = getEncodedParameter(name);
        return (value != null ? value : Util.urlEncoder(defaultValue));
    }

    /**
     * Invalidate the current session
     */
    public abstract void invalidateSession();
}
