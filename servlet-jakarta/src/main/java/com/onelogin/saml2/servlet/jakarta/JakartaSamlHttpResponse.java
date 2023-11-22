package com.onelogin.saml2.servlet.jakarta;

import com.onelogin.saml2.http.HttpResponse;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import static com.onelogin.saml2.util.Preconditions.checkNotNull;

/**
 * An EE9 or later implementation of {@link HttpResponse} based the {@code jakarta} flavor
 * of {@link HttpServletResponse}.
 *
 * @see JakartaSamlHttpResponse#makeHttpResponse(HttpServletResponse)
 */
public class JakartaSamlHttpResponse implements HttpResponse {

    private final HttpServletResponse delegate;

    private JakartaSamlHttpResponse(HttpServletResponse delegate) {
        this.delegate = checkNotNull(delegate, "Servlet response cannot be null.");
    }

    @Override
    public void sendRedirect(String location) throws IOException {
        delegate.sendRedirect(location);
    }

    public static HttpResponse makeHttpResponse(HttpServletResponse delegate) {
        return new JakartaSamlHttpResponse(delegate);
    }

}
