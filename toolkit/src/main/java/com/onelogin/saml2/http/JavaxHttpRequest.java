package com.onelogin.saml2.http;

import javax.servlet.http.HttpServletRequest;

/**
 * {@link HttpRequest} implementation which wraps a standard
 * {@link HttpServletRequest} for a JavaEE-style container.
 *
 * @since 2.2.0
 */
public class JavaxHttpRequest extends HttpRequest {

    /**
     * The underlying request object
     */
    private final HttpServletRequest request;

    public JavaxHttpRequest(HttpServletRequest request) {
        this.request = request;
    }

    @Override
    public boolean isSecure() {
        return request.isSecure();
    }

    @Override
    public String getScheme() {
        return request.getScheme();
    }

    @Override
    public String getServerName() {
        return request.getServerName();
    }

    @Override
    public int getServerPort() {
        return request.getServerPort();
    }

    @Override
    public String getQueryString() {
        return request.getQueryString();
    }

    @Override
    public String getRequestURI() {
        return request.getRequestURI();
    }

    @Override
    public String getRequestURL() {
        return request.getRequestURL().toString();
    }

    @Override
    public String getParameter(String name) {
        return request.getParameter(name);
    }

    @Override
    public void invalidateSession() {
        request.getSession().invalidate();
    }
}
