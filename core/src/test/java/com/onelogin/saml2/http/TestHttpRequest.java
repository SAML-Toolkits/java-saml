package com.onelogin.saml2.http;

import static com.onelogin.saml2.util.Preconditions.checkNotNull;
import static java.util.Collections.unmodifiableList;
import static java.util.Collections.unmodifiableMap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;

/**
 * Framework-agnostic representation of an HTTP request, used only for testing.
 *
 * @since 3.0.0
 */
public class TestHttpRequest implements HttpRequest {

    public static final Map<String, List<String>> EMPTY_PARAMETERS = Collections.emptyMap();

    private final String requestURL;
    private final Map<String, List<String>> parameters;
    private final String queryString;

    /**
     * Creates a new HttpRequest.
     *
     * @param requestURL  the request URL (up to but not including query parameters)
     * @param queryString string that is contained in the request URL after the path
     */
    public TestHttpRequest(String requestURL, String queryString) {
        this(requestURL, EMPTY_PARAMETERS, queryString);
    }

    /**
     * Creates a new HttpRequest.
     *
     * @param requestURL  the request URL (up to but not including query parameters)
     * @param parameters the request query parameters
     * @param queryString string that is contained in the request URL after the path
     * @throws NullPointerException if any of the parameters is null
     */
    public TestHttpRequest(String requestURL, Map<String, List<String>> parameters, String queryString) {
        this.requestURL = checkNotNull(requestURL, "requestURL");
        this.parameters = unmodifiableCopyOf(checkNotNull(parameters, "queryParams"));
        this.queryString = StringUtils.trimToEmpty(queryString);
    }

    /**
     * @param name  the query parameter name
     * @param value the query parameter value
     * @return a new HttpRequest with the given query parameter added
     * @throws NullPointerException if any of the parameters is null
     */
    public TestHttpRequest addParameter(String name, String value) {
        checkNotNull(name, "name");
        checkNotNull(value, "value");

        final List<String> oldValues = parameters.containsKey(name) ? parameters.get(name) : new ArrayList<String>();
        final List<String> newValues = new ArrayList<>(oldValues);
        newValues.add(value);
        final Map<String, List<String>> params = new HashMap<>(parameters);
        params.put(name, newValues);

        return new TestHttpRequest(requestURL, params, queryString);
    }

    /**
     * @param name  the query parameter name
     * @return a new HttpRequest with the given query parameter removed
     * @throws NullPointerException if any of the parameters is null
     */
    public TestHttpRequest removeParameter(String name) {
        checkNotNull(name, "name");

        final Map<String, List<String>> params = new HashMap<>(parameters);
        params.remove(name);

        return new TestHttpRequest(requestURL, params, queryString);
    }

    @Override
    public int getServerPort() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getScheme() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getServerName() {
        throw new UnsupportedOperationException();
    }

    /**
     * The URL the client used to make the request. Includes a protocol, server name, port number, and server path, but
     * not the query string parameters.
     *
     * @return the request URL
     */
    @Override
    public String getRequestURL() {
        return requestURL;
    }

    @Override
    public String getRequestURI() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getQueryString() {
        return queryString;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<String> getParameters(String name) {
        List<String> values = parameters.get(name);
        return (values != null) ? values : Collections.emptyList();
    }

    @Override
    public void invalidateSession() {
        throw new UnsupportedOperationException();
    }

    /**
     * @return a map of all query parameters
     */
    public Map<String, List<String>> getParameters() {
        return parameters;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        TestHttpRequest that = (TestHttpRequest) o;
        return Objects.equals(requestURL, that.requestURL) &&
                Objects.equals(parameters, that.parameters) &&
                Objects.equals(queryString, that.queryString);
    }

    @Override
    public int hashCode() {
        return Objects.hash(requestURL, parameters, queryString);
    }

    @Override
    public String toString() {
        return "TestHttpRequest{" +
                "requestURL='" + requestURL + '\'' +
                ", parameters=" + parameters +
                ", queryString=" + queryString +
                '}';
    }

    private static Map<String, List<String>> unmodifiableCopyOf(Map<String, List<String>> orig) {
        Map<String, List<String>> copy = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : orig.entrySet()) {
            copy.put(entry.getKey(), unmodifiableList(new ArrayList<>(entry.getValue())));
        }

        return unmodifiableMap(copy);
    }

}
