package com.onelogin.saml2.servlet.jakarta;

import com.onelogin.saml2.http.HttpRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.util.Map;

import static com.onelogin.saml2.util.Preconditions.checkNotNull;

/**
 * An EE9 or later implementation of {@link HttpRequest} based the {@code jakarta} flavor
 * of {@link HttpServletRequest}.
 *
 * @see JakartaSamlHttpRequest#makeHttpRequest(HttpServletRequest)
 */
public class JakartaSamlHttpRequest implements HttpRequest {

    private final HttpServletRequest delegate;

    private JakartaSamlHttpRequest(HttpServletRequest delegate) {
        this.delegate = checkNotNull(delegate, "Servlet request cannot be null.");
    }

    @Override
    public int getServerPort() {
        return delegate.getServerPort();
    }

    @Override
    public String getScheme() {
        return delegate.getScheme();
    }

    @Override
    public String getServerName() {
        return delegate.getServerName();
    }

    @Override
    public String getRequestURL() {
        return delegate.getRequestURL().toString();
    }

    @Override
    public String getRequestURI() {
        return delegate.getRequestURI();
    }

    @Override
    public String getQueryString() {
        return delegate.getQueryString();
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return delegate.getParameterMap();
    }

    @Override
    public void invalidateSession() {
        HttpSession session = delegate.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }

    public static HttpRequest makeHttpRequest(HttpServletRequest delegate) {
        return new JakartaSamlHttpRequest(delegate);
    }

}
