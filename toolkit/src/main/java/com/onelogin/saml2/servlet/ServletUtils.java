package com.onelogin.saml2.servlet;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;

import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.util.Util;

/**
 * ServletUtils class of OneLogin's Java Toolkit.
 *
 * A class that contains several auxiliary methods related to HttpServletRequest and HttpServletResponse
 */
public class ServletUtils {

	private ServletUtils() {
	      //not called
	}
	
	/**
     * Creates an HttpRequest from an HttpServletRequest.
     *
     * @param req the incoming HttpServletRequest
     * @return a HttpRequest
     */
    public static HttpRequest makeHttpRequest(HttpServletRequest req) {
    	@SuppressWarnings("unchecked")
        final Map<String, String[]> paramsAsArray = (Map<String, String[]>) req.getParameterMap();
        final Map<String, List<String>> paramsAsList = new HashMap<>();
        for (Map.Entry<String, String[]> param : paramsAsArray.entrySet()) {
            paramsAsList.put(param.getKey(), Arrays.asList(param.getValue()));
        }

        return new HttpRequest(req.getRequestURL().toString(), paramsAsList);
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
    public static String getSelfURLhost(HttpServletRequest request) {
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
     * @param request
     * 				HttpServletRequest object to be processed
     *
     * @return the server name
     */
    public static String getSelfHost(HttpServletRequest request) {
        return request.getServerName();
    }

    /**
     * Check if under https or http protocol
     *
     * @param request
     * 				HttpServletRequest object to be processed
     *
     * @return false if https is not active
     */
    public static boolean isHTTPS(HttpServletRequest request) {
        return request.isSecure();
    }

    /**
     * Returns the URL of the current context + current view + query
     *
     * @param request
     * 				HttpServletRequest object to be processed
     *
     * @return current context + current view + query
     */
    public static String getSelfURL(HttpServletRequest request) {
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
    public static String getSelfURLNoQuery(HttpServletRequest request) {
        return request.getRequestURL().toString();
    }

    /**
     * Returns the routed URL of the current host + current view.
     *
     * @param request
     * 				HttpServletRequest object to be processed
     *
     * @return the current routed url
     */
    public static String getSelfRoutedURLNoQuery(HttpServletRequest request) {
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
     * 				HttpServletResponse object to be used
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
     * @see javax.servlet.http.HttpServletResponse#sendRedirect(String)
     */
    public static String sendRedirect(HttpServletResponse response, String location, Map<String, String> parameters, Boolean stay) throws IOException {
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
     * 				HttpServletResponse object to be used
     * @param location
     * 				target location url
     * @param parameters
     * 				GET parameters to be added
	 *
     * @throws IOException
     *
     * @see javax.servlet.http.HttpServletResponse#sendRedirect(String)
     */
    public static void sendRedirect(HttpServletResponse response, String location, Map<String, String> parameters) throws IOException {
    	sendRedirect(response, location, parameters, false);
    }
    	
    /**
     * Redirect to location url
     *
     * @param response
     * 				HttpServletResponse object to be used
     * @param location
     * 				target location url
     *
     * @throws IOException
     *
     * @see HttpServletResponse#sendRedirect(String)
     */
    public static void sendRedirect(HttpServletResponse response, String location) throws IOException {
        Map<String, String> parameters  =new HashMap<String, String>();
        sendRedirect(response, location, parameters);
    }
}
