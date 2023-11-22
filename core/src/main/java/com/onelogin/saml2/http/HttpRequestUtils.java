package com.onelogin.saml2.http;

import org.apache.commons.lang3.StringUtils;

public class HttpRequestUtils {

    private HttpRequestUtils() {
    }

    /**
     * Returns the protocol + the current host + the port (if different than
     * common ports).
     *
     * @param request
     * 				HttpServletRequest object to be processed
     *
     * @return the HOST URL
     */
    public static String getSelfURLhost(HttpRequest request) {
        String hostUrl = StringUtils.EMPTY;
        final int serverPort = request.getServerPort();
        if ((serverPort == 80) || (serverPort == 443) || serverPort == 0) {
            hostUrl = String.format("%s://%s", request.getScheme(), request.getServerName());
        } else {
            hostUrl = String.format("%s://%s:%s", request.getScheme(), request.getServerName(), serverPort);
        }
        return hostUrl;
    }

    /**
     * Returns the URL of the current context + current view + query
     *
     * @param request
     * 				HttpServletRequest object to be processed
     *
     * @return current context + current view + query
     */
    public static String getSelfURL(HttpRequest request) {
        String url = getSelfURLhost(request);

        String requestUri = request.getRequestURI();
        String queryString = request.getQueryString();

        if (null != requestUri && !requestUri.isEmpty()) {
            url += requestUri;
        }

        if (null != queryString && !queryString.isEmpty()) {
            url += '?' + queryString;
        }
        return url;
    }

    /**
     * Returns the URL of the current host + current view.
     *
     * @param request
     * 				HttpServletRequest object to be processed
     *
     * @return current host + current view
     */
    public static String getSelfURLNoQuery(HttpRequest request) {
        return request.getRequestURL();
    }

    /**
     * Returns the routed URL of the current host + current view.
     *
     * @param request
     * 				HttpServletRequest object to be processed
     *
     * @return the current routed url
     */
    public static String getSelfRoutedURLNoQuery(HttpRequest request) {
        String url = getSelfURLhost(request);
        String requestUri = request.getRequestURI();
        if (null != requestUri && !requestUri.isEmpty()) {
            url += requestUri;
        }
        return url;
    }

}
