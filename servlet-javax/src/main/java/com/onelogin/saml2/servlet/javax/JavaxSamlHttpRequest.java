package com.onelogin.saml2.servlet.javax;

import com.onelogin.saml2.http.HttpRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Map;

import static com.onelogin.saml2.util.Preconditions.checkNotNull;

/**
 * A pre EE9 implementation of {@link HttpRequest} based the {@code javax} flavor
 * of {@link HttpServletRequest}.
 *
 * @see JavaxSamlHttpRequest#makeHttpRequest(HttpServletRequest)
 */
public class JavaxSamlHttpRequest implements HttpRequest {

    private final HttpServletRequest delegate;

    private JavaxSamlHttpRequest(HttpServletRequest delegate) {
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
        return new JavaxSamlHttpRequest(delegate);
    }

}
