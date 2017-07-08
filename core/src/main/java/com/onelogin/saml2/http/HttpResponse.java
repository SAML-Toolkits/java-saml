package com.onelogin.saml2.http;

import java.io.IOException;

/**
 * Framework-agnostic representation of an HTTP response.
 *
 * @since 2.2.0
 */
public abstract class HttpResponse {

    /**
     * Sends an HTTP redirect to the target URL
     *
     * @param target
     *          the URL to redirect to
     * @throws IOException
     *          if the redirect could not be sent
     */
    public abstract void sendRedirect(String target) throws IOException;
}
