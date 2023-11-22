package com.onelogin.saml2.http;

import com.onelogin.saml2.util.Util;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class HttpResponseUtils {

    private HttpResponseUtils() {
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
     */
    public static String sendRedirect(HttpResponse response, String location, Map<String, String> parameters, Boolean stay) throws IOException {
        String target = location;

        if (!parameters.isEmpty()) {
            boolean first = !location.contains("?");
            for (Map.Entry<String, String> parameter : parameters.entrySet()) {
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
     */
    public static void sendRedirect(HttpResponse response, String location, Map<String, String> parameters) throws IOException {
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
     */
    public static void sendRedirect(HttpResponse response, String location) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        sendRedirect(response, location, parameters);
    }

}
