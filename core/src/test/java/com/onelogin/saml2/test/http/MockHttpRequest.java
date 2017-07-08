package com.onelogin.saml2.test.http;

import com.onelogin.saml2.http.HttpRequest;

import org.apache.commons.lang3.StringUtils;
import java.util.*;

import static com.onelogin.saml2.util.Preconditions.checkNotNull;
import static java.util.Collections.unmodifiableList;
import static java.util.Collections.unmodifiableMap;

/**
 * Mock HttpRequest implementation for unit testing
 *
 * @since 2.2.0
 */
public class MockHttpRequest extends HttpRequest {

    public static final Map<String, List<String>> EMPTY_PARAMETERS = Collections.<String, List<String>>emptyMap();

    private final String requestURL;
    private final Map<String, List<String>> parameters;
    private final String queryString;

    /**
     * Creates a new HttpRequest.
     *
     * @param requestURL the request URL (up to but not including query parameters)
     * @throws NullPointerException if requestURL is null
     * @deprecated Not providing a queryString can cause HTTP Redirect binding to fail.
     */
    @Deprecated
    public MockHttpRequest(String requestURL) {
        this(requestURL, EMPTY_PARAMETERS);
    }

    /**
     * Creates a new HttpRequest.
     *
     * @param requestURL  the request URL (up to but not including query parameters)
     * @param queryString string that is contained in the request URL after the path
     */
    public MockHttpRequest(String requestURL, String queryString) {
        this(requestURL, EMPTY_PARAMETERS, queryString);
    }

    /**
     * Creates a new HttpRequest.
     *
     * @param requestURL  the request URL (up to but not including query parameters)
     * @param parameters the request query parameters
     * @throws NullPointerException if any of the parameters is null
     * @deprecated Not providing a queryString can cause HTTP Redirect binding to fail.
     */
    @Deprecated
    public MockHttpRequest(String requestURL, Map<String, List<String>> parameters) {
        this(requestURL, parameters, null);
    }

    /**
     * Creates a new HttpRequest.
     *
     * @param requestURL  the request URL (up to but not including query parameters)
     * @param parameters the request query parameters
     * @param queryString string that is contained in the request URL after the path
     * @throws NullPointerException if any of the parameters is null
     */
    public MockHttpRequest(String requestURL, Map<String, List<String>> parameters, String queryString) {
        this.requestURL = checkNotNull(requestURL, "requestURL");
        this.parameters = unmodifiableCopyOf(checkNotNull(parameters, "queryParams"));
        this.queryString = StringUtils.trimToEmpty(queryString);
    }

    @Override
    public boolean isSecure() {
        return false;
    }

    @Override
    public String getScheme() {
        return "http";
    }

    @Override
    public String getServerName() {
        return "localhost";
    }

    @Override
    public int getServerPort() {
        return 80;
    }

    @Override
    public String getQueryString() {
        return queryString;
    }

    @Override
    public String getRequestURI() {
        return requestURL;
    }

    /**
     * @param name  the query parameter name
     * @param value the query parameter value
     * @return a new HttpRequest with the given query parameter added
     * @throws NullPointerException if any of the parameters is null
     */
    public MockHttpRequest addParameter(String name, String value) {
        checkNotNull(name, "name");
        checkNotNull(value, "value");

        final List<String> oldValues = parameters.containsKey(name) ? parameters.get(name) : new ArrayList<String>();
        final List<String> newValues = new ArrayList<>(oldValues);
        newValues.add(value);
        final Map<String, List<String>> params = new HashMap<>(parameters);
        params.put(name, newValues);

        return new MockHttpRequest(requestURL, params, queryString);
    }

    /**
     * @param name  the query parameter name
     * @return a new HttpRequest with the given query parameter removed
     * @throws NullPointerException if any of the parameters is null
     */
    public MockHttpRequest removeParameter(String name) {
        checkNotNull(name, "name");

        final Map<String, List<String>> params = new HashMap<>(parameters);
        params.remove(name);

        return new MockHttpRequest(requestURL, params, queryString);
    }

    @Override
    public String getRequestURL() {
        return requestURL;
    }

    @Override
    public String getParameter(String name) {
        final List<String> values = parameters.get(name);
        return (values == null || values.isEmpty()) ? null : values.get(0);
    }

    @Override
    public void invalidateSession() {
        // Nothing to do
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        MockHttpRequest that = (MockHttpRequest) o;
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
        return "MockHttpRequest{" +
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
