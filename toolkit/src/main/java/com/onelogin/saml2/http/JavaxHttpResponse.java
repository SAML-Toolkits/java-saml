package com.onelogin.saml2.http;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * {@link HttpResponse} implementation which wraps a standard
 * {@link HttpServletResponse} for a JavaEE-style container.
 *
 * @since 2.2.0
 */
public class JavaxHttpResponse extends HttpResponse {

    /**
     * The underlying response object
     */
    private final HttpServletResponse response;

    public JavaxHttpResponse(HttpServletResponse response) {
        this.response = response;
    }

    @Override
    public void sendRedirect(String target) throws IOException {
        this.response.sendRedirect(target);
    }
}
