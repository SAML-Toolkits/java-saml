package com.onelogin.saml2.test.http;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.onelogin.saml2.test.NaiveUrlEncoder;
import com.onelogin.saml2.util.Util;

public class MockHttpRequestTest {
    @Test
    public void testConstructorWithNoQueryParams() throws Exception {
        final String url = "url";

        final MockHttpRequest request = new MockHttpRequest(url);
        assertThat(request.getRequestURL(), equalTo(url));
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

        final MockHttpRequest request = new MockHttpRequest(url, parametersMap);
        assertThat(request.getRequestURL(), equalTo(url));
        assertThat(request.getParameter(name), equalTo(value1));
    }

    @Test
    public void testAddParameter() throws Exception {
        final String url = "some_url";
        final String name = "name";
        final String value = "value";

        final MockHttpRequest request = new MockHttpRequest(url).addParameter(name, value);
        assertThat(request.getRequestURL(), equalTo(url));
        assertThat(request.getParameter(name), equalTo(value));
    }

    @Test
    public void testRemoveParameter() throws Exception {
        final String url = "some_url";
        final String name = "name";
        final String value = "value";

        MockHttpRequest request = new MockHttpRequest(url).addParameter(name, value);
        assertThat(request.getRequestURL(), equalTo(url));
        assertThat(request.getParameter(name), equalTo(value));

        request = request.removeParameter(name);
        assertThat(request.getRequestURL(), equalTo(url));
        assertNull(request.getParameter(name));
    }

    @Test
    public void testGetEncodedParameter_encodesParametersNotOnQueryString() throws Exception {
        final String url = "url";
        final String name = "name";
        final String value1 = "val/1!";
        final String addedName = "added";
        final String addedValue = "added#value!";

        final List<String> values = singletonList(value1);
        final Map<String, List<String>> parametersMap = singletonMap(name, values);

        final MockHttpRequest request = new MockHttpRequest(url, parametersMap).addParameter(addedName, addedValue);

        assertThat(request.getEncodedParameter(name), equalTo(Util.urlEncoder(value1)));
        assertThat(request.getEncodedParameter(addedName), equalTo(Util.urlEncoder(addedValue)));
    }

    @Test
    public void testGetEncodedParameter_prefersValueFromQueryString() throws Exception {
        final String url = "url";
        final String name = "name";
        final String value1 = "value1";
        final String urlValue1 = "onUrl1";
        final String queryString = name + "=" + urlValue1;

        final List<String> values = singletonList(value1);
        final Map<String, List<String>> parametersMap = singletonMap(name, values);

        final MockHttpRequest request = new MockHttpRequest(url, parametersMap, queryString);

        assertThat(request.getEncodedParameter(name), equalTo(urlValue1));
        assertThat(request.getParameter(name), equalTo(value1));
    }

    @Test
    public void testGetEncodedParameter_returnsExactAsGivenInQueryString() throws Exception {
        final String url = "url";
        final String name = "name";
        String encodedValue1 = NaiveUrlEncoder.encode("do not alter!");
        final String queryString = name + "=" + encodedValue1;

        final MockHttpRequest request = new MockHttpRequest(url, queryString);

        assertThat(request.getEncodedParameter(name), equalTo(encodedValue1));
    }

    @Test
    public void testGetEncodedParameter_handlesMultipleValuesOnQueryString() throws Exception {
        final String url = "url";
        final String queryString = "k1=v1&k2=v2&k3=v3";

        final Map<String, List<String>> parametersMap = new HashMap<>();
        final MockHttpRequest request = new MockHttpRequest(url, parametersMap, queryString);

        assertThat(request.getEncodedParameter("k1"), equalTo("v1"));
        assertThat(request.getEncodedParameter("k2"), equalTo("v2"));
        assertThat(request.getEncodedParameter("k3"), equalTo("v3"));
    }

    @Test
    public void testGetEncodedParameter_stopsAtUrlFragment() throws Exception {
        final String url = "url";
        final String queryString = "first=&foo=bar#ignore";

        final MockHttpRequest request = new MockHttpRequest(url, queryString);

        assertThat(request.getEncodedParameter("foo"), equalTo("bar"));
    }

    @Test
    public void testGetEncodedParameter_withDefault_usesDefaultWhenParameterMissing() throws Exception {
        final String url = "url";
        final String foobar = "foo/bar!";

        final MockHttpRequest request = new MockHttpRequest(url);
        assertThat(request.getEncodedParameter("missing", foobar), equalTo(Util.urlEncoder(foobar)));
    }


    @Test
    public void testAddParameter_preservesQueryString() throws Exception {
        final String url = "url";
        final String name = "name";
        final String value1 = "val/1!";
        String encodedValue1 = NaiveUrlEncoder.encode(value1);
        final String queryString = name + "=" + encodedValue1;

        final Map<String, List<String>> parametersMap = new HashMap<>();
        final MockHttpRequest request = new MockHttpRequest(url, parametersMap, queryString).addParameter(name, value1);

        assertThat(request.getEncodedParameter(name), equalTo(encodedValue1));
    }

    @Test
    public void testRemoveParameter_preservesQueryString() throws Exception {
        final String url = "url";
        final String name = "name";
        final String value1 = "val/1!";
        String encodedValue1 = NaiveUrlEncoder.encode(value1);
        final String queryString = name + "=" + encodedValue1;

        final List<String> values = singletonList(value1);
        final Map<String, List<String>> parametersMap = singletonMap(name, values);

        final MockHttpRequest request = new MockHttpRequest(url, parametersMap, queryString).removeParameter(name);

        assertThat(request.getEncodedParameter(name), equalTo(encodedValue1));
    }
}
