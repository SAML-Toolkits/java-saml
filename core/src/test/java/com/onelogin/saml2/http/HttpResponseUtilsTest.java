package com.onelogin.saml2.http;

import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.singletonMap;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class HttpResponseUtilsTest {

    /**
     * Tests the sendRedirect method
     * Use Case: Check relative and absolute urls
     *
     * @throws IOException
     *
     * @see HttpResponseUtils#sendRedirect
     */
    @Test
    public void testSendRedirectRelative() throws IOException {
        HttpRequest request_1 = mock(HttpRequest.class);
        HttpResponse response_1 = mock(HttpResponse.class);
        // mock the getRequestURI() response
        when(request_1.getRequestURI()).thenReturn("/initial.jsp");
        HttpResponseUtils.sendRedirect(response_1, "http://example.com/expectedurl.jsp");
        // verify if a sendRedirect() was performed with the expected value
        verify(response_1).sendRedirect("http://example.com/expectedurl.jsp");

        HttpRequest request_2 = mock(HttpRequest.class);
        HttpResponse response_2 = mock(HttpResponse.class);
        when(request_2.getRequestURI()).thenReturn("/initial.jsp");
        HttpResponseUtils.sendRedirect(response_2, "/expectedurl.jsp");
        verify(response_2).sendRedirect("/expectedurl.jsp");
    }

    /**
     * Tests the sendRedirect method
     * Use Case: Support https and http
     *
     * @throws IOException
     *
     * @see HttpResponseUtils#sendRedirect
     */
    @Test
    public void testSendRedirectProtocol() throws IOException {
        HttpRequest request_1 = mock(HttpRequest.class);
        HttpResponse response_1 = mock(HttpResponse.class);
        when(request_1.getRequestURI()).thenReturn("/initial.jsp");
        HttpResponseUtils.sendRedirect(response_1, "http://example.com/expectedurl.jsp");
        verify(response_1).sendRedirect("http://example.com/expectedurl.jsp");

        HttpRequest request_2 = mock(HttpRequest.class);
        HttpResponse response_2 = mock(HttpResponse.class);
        when(request_2.getRequestURI()).thenReturn("/initial.jsp");
        HttpResponseUtils.sendRedirect(response_2, "https://example.com/expectedurl.jsp");
        verify(response_2).sendRedirect("https://example.com/expectedurl.jsp");
    }

    /**
     * Tests the sendRedirect method
     * Use Case: Support parameters
     *
     * @throws IOException
     *
     * @see HttpResponseUtils#sendRedirect
     */
    @Test
    public void testSendRedirectParams() throws IOException {
        Map<String, String> parameters = new HashMap<String, String>();
        HttpRequest request_1 = mock(HttpRequest.class);
        HttpResponse response_1 = mock(HttpResponse.class);
        when(request_1.getRequestURI()).thenReturn("/initial.jsp");
        HttpResponseUtils.sendRedirect(response_1, "http://example.com/expectedurl.jsp", parameters);
        verify(response_1).sendRedirect("http://example.com/expectedurl.jsp");

        parameters.put("test", "true");
        HttpRequest request_2 = mock(HttpRequest.class);
        HttpResponse response_2 = mock(HttpResponse.class);
        when(request_2.getRequestURI()).thenReturn("/initial.jsp");
        HttpResponseUtils.sendRedirect(response_2, "http://example.com/expectedurl.jsp", parameters);
        verify(response_2).sendRedirect("http://example.com/expectedurl.jsp?test=true");

        parameters.put("value1", "a");
        HttpRequest request_3 = mock(HttpRequest.class);
        HttpResponse response_3 = mock(HttpResponse.class);
        when(request_3.getRequestURI()).thenReturn("/initial.jsp");
        HttpResponseUtils.sendRedirect(response_3, "http://example.com/expectedurl.jsp", parameters);
        verify(response_3).sendRedirect("http://example.com/expectedurl.jsp?test=true&value1=a");

        parameters.put("novalue", "");
        HttpRequest request_4 = mock(HttpRequest.class);
        HttpResponse response_4 = mock(HttpResponse.class);
        when(request_4.getRequestURI()).thenReturn("/initial.jsp");
        HttpResponseUtils.sendRedirect(response_4, "http://example.com/expectedurl.jsp", parameters);
        verify(response_4).sendRedirect("http://example.com/expectedurl.jsp?novalue&test=true&value1=a");

        Map<String, String> parameters_2 = new HashMap<String, String>();
        parameters_2.put("novalue", "");
        HttpRequest request_5 = mock(HttpRequest.class);
        HttpResponse response_5 = mock(HttpResponse.class);
        when(request_5.getRequestURI()).thenReturn("/initial.jsp");
        HttpResponseUtils.sendRedirect(response_5, "http://example.com/expectedurl.jsp", parameters_2);
        verify(response_5).sendRedirect("http://example.com/expectedurl.jsp?novalue");
    }

    /**
     * Tests the sendRedirect method
     * Use Case: Stay and don't execute redirection
     *
     * @throws IOException
     *
     * @see HttpResponseUtils#sendRedirect
     */
    @Test
    public void testSendRedirectStay() throws IOException {
        HttpResponse response = mock(HttpResponse.class);
        Map<String, String> parameters = new HashMap<String, String>();

        String url = HttpResponseUtils.sendRedirect(response, "http://example.com/expectedurl.jsp", parameters, true);
        assertEquals("http://example.com/expectedurl.jsp", url);

        url = HttpResponseUtils.sendRedirect(response, "http://example.com/expectedurl.jsp?idpid=ffee-aabbb", singletonMap("SAMLRequest", "data"), true);
        assertEquals("http://example.com/expectedurl.jsp?idpid=ffee-aabbb&SAMLRequest=data", url);
    }

}
