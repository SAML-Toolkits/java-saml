package com.onelogin.saml2.test.servlet;

import static java.util.Collections.singletonMap;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.onelogin.saml2.http.HttpResponse;
import org.junit.Test;

import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.servlet.ServletUtils;

public class ServletUtilsTest {
    /**
     * Tests the sendRedirect method
     * Use Case: Check relative and absolute urls
     *
     * @throws IOException
     *
     * @see ServletUtils#sendRedirect
     */
    @Test
    public void testSendRedirectRelative() throws IOException {
        HttpResponse response_1 = mock(HttpResponse.class);
        // mock the getRequestURI() response
        ServletUtils.sendRedirect(response_1, "http://example.com/expectedurl.jsp");
        // verify if a sendRedirect() was performed with the expected value
        verify(response_1).sendRedirect("http://example.com/expectedurl.jsp");

        HttpResponse response_2 = mock(HttpResponse.class);
        ServletUtils.sendRedirect(response_2, "/expectedurl.jsp");
        verify(response_2).sendRedirect("/expectedurl.jsp");
    }

    /**
     * Tests the sendRedirect method
     * Use Case: Support https and http
     *
     * @throws IOException
     *
     * @see ServletUtils#sendRedirect
     */
    @Test
    public void testSendRedirectProtocol() throws IOException {
        HttpResponse response_1 = mock(HttpResponse.class);
        ServletUtils.sendRedirect(response_1, "http://example.com/expectedurl.jsp");
        verify(response_1).sendRedirect("http://example.com/expectedurl.jsp");

        HttpResponse response_2 = mock(HttpResponse.class);
        ServletUtils.sendRedirect(response_2, "https://example.com/expectedurl.jsp");
        verify(response_2).sendRedirect("https://example.com/expectedurl.jsp");
    }

    /**
     * Tests the sendRedirect method
     * Use Case: Support parameters
     *
     * @throws IOException
     *
     * @see ServletUtils#sendRedirect
     */
    @Test
    public void testSendRedirectParams() throws IOException {
        Map<String, String> parameters = new HashMap<String, String>();
        HttpResponse response_1 = mock(HttpResponse.class);
        ServletUtils.sendRedirect(response_1, "http://example.com/expectedurl.jsp", parameters);
        verify(response_1).sendRedirect("http://example.com/expectedurl.jsp");

        parameters.put("test", "true");
        HttpResponse response_2 = mock(HttpResponse.class);
        ServletUtils.sendRedirect(response_2, "http://example.com/expectedurl.jsp", parameters);
        verify(response_2).sendRedirect("http://example.com/expectedurl.jsp?test=true");

        parameters.put("value1", "a");
        HttpResponse response_3 = mock(HttpResponse.class);
        ServletUtils.sendRedirect(response_3, "http://example.com/expectedurl.jsp", parameters);
        verify(response_3).sendRedirect("http://example.com/expectedurl.jsp?test=true&value1=a");

        parameters.put("novalue", "");
        HttpResponse response_4 = mock(HttpResponse.class);
        ServletUtils.sendRedirect(response_4, "http://example.com/expectedurl.jsp", parameters);
        verify(response_4).sendRedirect("http://example.com/expectedurl.jsp?novalue&test=true&value1=a");

        Map<String, String> parameters_2 = new HashMap<String, String>();
        parameters_2.put("novalue", "");
        HttpResponse response_5 = mock(HttpResponse.class);
        ServletUtils.sendRedirect(response_5, "http://example.com/expectedurl.jsp", parameters_2);
        verify(response_5).sendRedirect("http://example.com/expectedurl.jsp?novalue");
    }

    /**
     * Tests the sendRedirect method
     * Use Case: Stay and don't execute redirection
     *
     * @throws IOException
     *
     * @see ServletUtils#sendRedirect
     */
    @Test
    public void testSendRedirectStay() throws IOException {
        HttpResponse response = mock(HttpResponse.class);
        Map<String, String> parameters = new HashMap<String, String>();
        
        String url = ServletUtils.sendRedirect(response, "http://example.com/expectedurl.jsp", parameters, true);
        assertEquals("http://example.com/expectedurl.jsp", url);
        
        url = ServletUtils.sendRedirect(response, "http://example.com/expectedurl.jsp?idpid=ffee-aabbb", singletonMap("SAMLRequest", "data"), true);
        assertEquals("http://example.com/expectedurl.jsp?idpid=ffee-aabbb&SAMLRequest=data", url);
    }
    
    /**
     * Tests the getSelfURLhost method
     *
     * @see ServletUtils#getSelfURLhost
     */
    @Test
    public void testGetSelfURLhost() {
        HttpRequest request_1 = mock(HttpRequest.class);
        when(request_1.getScheme()).thenReturn("http");
        when(request_1.getServerName()).thenReturn("example.com");
        when(request_1.getServerPort()).thenReturn(80);
        assertEquals("http://example.com", ServletUtils.getSelfURLhost(request_1));

        when(request_1.getServerPort()).thenReturn(81);
        assertEquals("http://example.com:81", ServletUtils.getSelfURLhost(request_1));

        when(request_1.getScheme()).thenReturn("https");
        when(request_1.getServerPort()).thenReturn(443);
        assertEquals("https://example.com", ServletUtils.getSelfURLhost(request_1));

        when(request_1.getServerPort()).thenReturn(444);
        assertEquals("https://example.com:444", ServletUtils.getSelfURLhost(request_1));
    }

    /**
     * Tests the getSelfHost method
     *
     * @see ServletUtils#getSelfHost
     */
    @Test
    public void testGetSelfHost() {
        HttpRequest request_1 = mock(HttpRequest.class);
        when(request_1.getServerName()).thenReturn("example.com");
        assertEquals("example.com", ServletUtils.getSelfHost(request_1));
    }

    /**
     * Tests the isHTTPS method
     *
     * @see ServletUtils#isHTTPS
     */
    @Test
    public void testIsHTTPS() {
        HttpRequest request_1 = mock(HttpRequest.class);
        when(request_1.isSecure()).thenReturn(false);
        assertEquals(false, ServletUtils.isHTTPS(request_1));

        when(request_1.isSecure()).thenReturn(true);
        assertEquals(true, ServletUtils.isHTTPS(request_1));
    }

    /**
     * Tests the getSelfURL method
     *
     * @see ServletUtils#getSelfURL
     */
    @Test
    public void testGetSelfURL() {
        HttpRequest request_1 = mock(HttpRequest.class);
        when(request_1.getScheme()).thenReturn("http");
        when(request_1.getServerName()).thenReturn("example.com");
        when(request_1.getRequestURI()).thenReturn("/test");
        when(request_1.getQueryString()).thenReturn("novalue&test=true&value1=a");
        assertEquals("http://example.com/test?novalue&test=true&value1=a", ServletUtils.getSelfURL(request_1));

        when(request_1.getRequestURI()).thenReturn("/");
        assertEquals("http://example.com/?novalue&test=true&value1=a", ServletUtils.getSelfURL(request_1));

        when(request_1.getRequestURI()).thenReturn("");
        assertEquals("http://example.com?novalue&test=true&value1=a", ServletUtils.getSelfURL(request_1));

        when(request_1.getRequestURI()).thenReturn(null);
        assertEquals("http://example.com?novalue&test=true&value1=a", ServletUtils.getSelfURL(request_1));

        HttpRequest request_2 = mock(HttpRequest.class);
        when(request_2.getScheme()).thenReturn("http");
        when(request_2.getServerName()).thenReturn("example.com");
        when(request_2.getRequestURI()).thenReturn("/test");
        assertEquals("http://example.com/test", ServletUtils.getSelfURL(request_2));

        when(request_2.getQueryString()).thenReturn("");
        assertEquals("http://example.com/test", ServletUtils.getSelfURL(request_2));

        when(request_2.getQueryString()).thenReturn(null);
        assertEquals("http://example.com/test", ServletUtils.getSelfURL(request_2));
    }

    /**
     * Tests the getSelfURLNoQuery method
     *
     * @see ServletUtils#getSelfURLNoQuery
     */
    @Test
    public void testGetSelfURLNoQuery() {
        HttpRequest request_1 = mock(HttpRequest.class);
        when(request_1.getRequestURL()).thenReturn("http://example.com/test");
        assertEquals("http://example.com/test", ServletUtils.getSelfURLNoQuery(request_1));
    }

    /**
     * Tests the getSelfRoutedURLNoQuery method
     *
     * @see ServletUtils#getSelfRoutedURLNoQuery
     */
    @Test
    public void testGetSelfRoutedURLNoQuery() {
        HttpRequest request_1 = mock(HttpRequest.class);
        when(request_1.getScheme()).thenReturn("http");
        when(request_1.getServerName()).thenReturn("example.com");
        when(request_1.getRequestURI()).thenReturn("/test");
        assertEquals("http://example.com/test", ServletUtils.getSelfRoutedURLNoQuery(request_1));

        when(request_1.getRequestURI()).thenReturn("");
        assertEquals("http://example.com", ServletUtils.getSelfRoutedURLNoQuery(request_1));

        when(request_1.getRequestURI()).thenReturn(null);
        assertEquals("http://example.com", ServletUtils.getSelfRoutedURLNoQuery(request_1));
    }

	@Test
	public void sendRedirectToShouldHandleUrlsWithQueryParams() throws Exception {
		// having
		final HttpResponse response = mock(HttpResponse.class);

		// when
		ServletUtils.sendRedirect(response, "https://sso.connect.pingidentity.com/sso/idp/SSO.saml2?idpid=ffee-aabbb", singletonMap("SAMLRequest", "data"));

		// then
		verify(response).sendRedirect("https://sso.connect.pingidentity.com/sso/idp/SSO.saml2?idpid=ffee-aabbb&SAMLRequest=data");
	}
}
