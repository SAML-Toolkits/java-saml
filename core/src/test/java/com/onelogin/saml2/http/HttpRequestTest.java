package com.onelogin.saml2.http;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.Test;

public class HttpRequestTest {
    @Test
    public void testConstructorWithNoQueryParams() throws Exception {
        final String url = "url";

        final HttpRequest request = new HttpRequest(url);
        assertThat(request.getRequestURL(), equalTo(url));
        assertThat(request.getParameters(), equalTo(Collections.<String, List<String>>emptyMap()));
        assertThat(request.getParameters("x"), equalTo(Collections.<String>emptyList()));
        assertThat(request.getParameter("x"), nullValue());
    }

    @Test
    public void testConstructorWithQueryParams() throws Exception {
        final String url = "url";
        final String name = "name";
        final String value1 = "val1";
        final String value2 = "val2";

        final List<String> values = Arrays.asList(value1, value2);
        final Map<String, List<String>> parametersMap = singletonMap(name, values);

        final HttpRequest request = new HttpRequest(url, parametersMap);
        assertThat(request.getRequestURL(), equalTo(url));
        assertThat(request.getParameters(), equalTo(parametersMap));
        assertThat(request.getParameters(name), equalTo(values));
        assertThat(request.getParameter(name), equalTo(value1));
    }

    @Test
    public void testAddParameter() throws Exception {
        final String url = "some_url";
        final String name = "name";
        final String value = "value";

        final HttpRequest request = new HttpRequest(url).addParameter(name, value);
        assertThat(request.getRequestURL(), equalTo(url));
        assertThat(request.getParameters(), equalTo(singletonMap(name, singletonList(value))));
        assertThat(request.getParameters(name), equalTo(singletonList(value)));
        assertThat(request.getParameter(name), equalTo(value));
    }

    @Test
    public void testRemoveParameter() throws Exception {
        final String url = "some_url";
        final String name = "name";
        final String value = "value";

        HttpRequest request = new HttpRequest(url).addParameter(name, value);
        assertThat(request.getRequestURL(), equalTo(url));
        assertThat(request.getParameters(), equalTo(singletonMap(name, singletonList(value))));
        assertThat(request.getParameters(name), equalTo(singletonList(value)));
        assertThat(request.getParameter(name), equalTo(value));
        
        request = request.removeParameter(name);
        assertThat(request.getRequestURL(), equalTo(url));
        assertTrue(request.getParameters().isEmpty());
        assertTrue(request.getParameters(name).isEmpty());
        assertNull(request.getParameter(name));
    }
}
