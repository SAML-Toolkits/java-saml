package com.onelogin.saml2.http;

import com.onelogin.saml2.util.Util;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Framework-agnostic definition of an HTTP request with a very minimal set of
 * methods needed to support the SAML handshake.
 *
 * @since 3.0.0
 */
public interface HttpRequest {

    int getServerPort();

    String getScheme();

    String getServerName();

    String getRequestURL();

    String getRequestURI();

    String getQueryString();

    void invalidateSession();

    Map<String, String[]> getParameterMap();

    default List<String> getParameters(String name) {
        final Map<String, String[]> paramsAsArray = getParameterMap();
        final Map<String, List<String>> paramsAsList = new HashMap<>();
        for (Map.Entry<String, String[]> param : paramsAsArray.entrySet()) {
            paramsAsList.put(param.getKey(), Arrays.asList(param.getValue()));
        }

        return paramsAsList.get(name);
    }

    default String getParameter(String name) {
        List<String> values = getParameters(name);
        return (values == null || values.isEmpty()) ? null : values.get(0);
    }

    default String getEncodedParameter(String name, String defaultValue) {
        String value = getEncodedParameter(name);
        return (value != null) ? value : Util.urlEncoder(defaultValue);
    }

    /**
     * Return an url encoded get parameter value
     * Prefer to extract the original encoded value directly from queryString since url
     * encoding is not canonical.
     *
     * @param name
     * @return the first value for the parameter, or null
     */
    default String getEncodedParameter(String name) {
        String queryString = getQueryString();
        Matcher matcher = Pattern.compile(Pattern.quote(name) + "=([^&#]+)").matcher(queryString);
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            return Util.urlEncoder(getParameter(name));
        }
    }

}
