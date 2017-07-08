package com.onelogin.saml2.servlet;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.http.HttpResponse;
import com.onelogin.saml2.util.Util;

/**
 * ServletUtils class of OneLogin's Java Toolkit.
 *
 * A class that contains several auxiliary methods related to HttpRequest and HttpResponse
 */
public class ServletUtils {

	private ServletUtils() {
	      //not called
	}

    /**
     * Returns the protocol + the current host + the port (if different than
     * common ports).
     *
     * @param request
     * 				HttpRequest object to be processed
     *
     * @return the HOST URL
     */
    public static String getSelfURLhost(HttpRequest request) {
        final String hostUrl;
        final int serverPort = request.getServerPort();
        if ((serverPort == 80) || (serverPort == 443) || serverPort == 0) {
            hostUrl = String.format("%s://%s", request.getScheme(), request.getServerName());
        } else {
            hostUrl = String.format("%s://%s:%s", request.getScheme(), request.getServerName(), serverPort);
        }
        return hostUrl;
    }

    /**
     * @param request
     * 				HttpRequest object to be processed
     *
     * @return the server name
     */
    public static String getSelfHost(HttpRequest request) {
        return request.getServerName();
    }

    /**
     * Check if under https or http protocol
     *
     * @param request
     * 				HttpRequest object to be processed
     *
     * @return false if https is not active
     */
    public static boolean isHTTPS(HttpRequest request) {
        return request.isSecure();
    }

    /**
     * Returns the URL of the current context + current view + query
     *
     * @param request
     * 				HttpRequest object to be processed
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
     * 				HttpRequest object to be processed
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
     * 				HttpRequest object to be processed
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

    /**
     * Redirect to location url
     *
     * @param response
     * 				HttpResponse object to be used
     * @param location
     * 				target location url
     * @param parameters
     * 				GET parameters to be added
	 * @param stay
	 *            True if we want to stay (returns the url string) False to execute redirection
     * 
     * @return string the target URL
     * @throws IOException
     *
     * @see HttpResponse#sendRedirect(String)
     */
    public static String sendRedirect(HttpResponse response, String location, Map<String, String> parameters, Boolean stay) throws IOException {
        String target = location;

        if (!parameters.isEmpty()) {
        	boolean first = !location.contains("?");
            for (Map.Entry<String, String> parameter : parameters.entrySet())
            {
                if (first) {
                    target += "?";
                    first = false;
                } else {
                    target += "&";
                }
                target += parameter.getKey();
                if (!parameter.getValue().isEmpty()) {
                    target += "=" + Util.urlEncoder(parameter.getValue());
                }
            }
        }
        if (!stay) {
        	response.sendRedirect(target);
        }

        return target;
    }

    /**
     * Redirect to location url
     *
     * @param response
     * 				HttpResponse object to be used
     * @param location
     * 				target location url
     * @param parameters
     * 				GET parameters to be added
	 *
     * @throws IOException
     *
     * @see HttpResponse#sendRedirect(String)
     */
    public static void sendRedirect(HttpResponse response, String location, Map<String, String> parameters) throws IOException {
    	sendRedirect(response, location, parameters, false);
    }
    	
    /**
     * Redirect to location url
     *
     * @param response
     * 				HttpResponse object to be used
     * @param location
     * 				target location url
     *
     * @throws IOException
     *
     * @see HttpResponse#sendRedirect(String)
     */
    public static void sendRedirect(HttpResponse response, String location) throws IOException {
        Map<String, String> parameters  =new HashMap<String, String>();
        sendRedirect(response, location, parameters);
    }
}
