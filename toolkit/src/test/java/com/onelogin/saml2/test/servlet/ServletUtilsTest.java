package com.onelogin.saml2.test.servlet;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Test;

import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.servlet.ServletUtils;
import com.onelogin.saml2.test.NaiveUrlEncoder;

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
        HttpServletRequest request_1 = mock(HttpServletRequest.class);
        HttpServletResponse response_1 = mock(HttpServletResponse.class);
        // mock the getRequestURI() response
        when(request_1.getRequestURI()).thenReturn("/initial.jsp");
        ServletUtils.sendRedirect(response_1, "http://example.com/expectedurl.jsp");
        // verify if a sendRedirect() was performed with the expected value
        verify(response_1).sendRedirect("http://example.com/expectedurl.jsp");

        HttpServletRequest request_2 = mock(HttpServletRequest.class);
        HttpServletResponse response_2 = mock(HttpServletResponse.class);
        when(request_2.getRequestURI()).thenReturn("/initial.jsp");
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
        HttpServletRequest request_1 = mock(HttpServletRequest.class);
        HttpServletResponse response_1 = mock(HttpServletResponse.class);
        when(request_1.getRequestURI()).thenReturn("/initial.jsp");
        ServletUtils.sendRedirect(response_1, "http://example.com/expectedurl.jsp");
        verify(response_1).sendRedirect("http://example.com/expectedurl.jsp");

        HttpServletRequest request_2 = mock(HttpServletRequest.class);
        HttpServletResponse response_2 = mock(HttpServletResponse.class);
        when(request_2.getRequestURI()).thenReturn("/initial.jsp");
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
        HttpServletRequest request_1 = mock(HttpServletRequest.class);
        HttpServletResponse response_1 = mock(HttpServletResponse.class);
        when(request_1.getRequestURI()).thenReturn("/initial.jsp");
        ServletUtils.sendRedirect(response_1, "http://example.com/expectedurl.jsp", parameters);
        verify(response_1).sendRedirect("http://example.com/expectedurl.jsp");

        parameters.put("test", "true");
        HttpServletRequest request_2 = mock(HttpServletRequest.class);
        HttpServletResponse response_2 = mock(HttpServletResponse.class);
        when(request_2.getRequestURI()).thenReturn("/initial.jsp");
        ServletUtils.sendRedirect(response_2, "http://example.com/expectedurl.jsp", parameters);
        verify(response_2).sendRedirect("http://example.com/expectedurl.jsp?test=true");

        parameters.put("value1", "a");
        HttpServletRequest request_3 = mock(HttpServletRequest.class);
        HttpServletResponse response_3 = mock(HttpServletResponse.class);
        when(request_3.getRequestURI()).thenReturn("/initial.jsp");
        ServletUtils.sendRedirect(response_3, "http://example.com/expectedurl.jsp", parameters);
        verify(response_3).sendRedirect("http://example.com/expectedurl.jsp?test=true&value1=a");

        parameters.put("novalue", "");
        HttpServletRequest request_4 = mock(HttpServletRequest.class);
        HttpServletResponse response_4 = mock(HttpServletResponse.class);
        when(request_4.getRequestURI()).thenReturn("/initial.jsp");
        ServletUtils.sendRedirect(response_4, "http://example.com/expectedurl.jsp", parameters);
        verify(response_4).sendRedirect("http://example.com/expectedurl.jsp?novalue&test=true&value1=a");

        Map<String, String> parameters_2 = new HashMap<String, String>();
        parameters_2.put("novalue", "");
        HttpServletRequest request_5 = mock(HttpServletRequest.class);
        HttpServletResponse response_5 = mock(HttpServletResponse.class);
        when(request_5.getRequestURI()).thenReturn("/initial.jsp");
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
        HttpServletResponse response = mock(HttpServletResponse.class);
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
        HttpServletRequest request_1 = mock(HttpServletRequest.class);
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
        HttpServletRequest request_1 = mock(HttpServletRequest.class);
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
        HttpServletRequest request_1 = mock(HttpServletRequest.class);
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
        HttpServletRequest request_1 = mock(HttpServletRequest.class);
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

        HttpServletRequest request_2 = mock(HttpServletRequest.class);
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
        HttpServletRequest request_1 = mock(HttpServletRequest.class);
        StringBuffer url = new StringBuffer("http://example.com/test");
        when(request_1.getRequestURL()).thenReturn(url);
        assertEquals("http://example.com/test", ServletUtils.getSelfURLNoQuery(request_1));
    }

    /**
     * Tests the getSelfRoutedURLNoQuery method
     *
     * @see ServletUtils#getSelfRoutedURLNoQuery
     */
    @Test
    public void testGetSelfRoutedURLNoQuery() {
        HttpServletRequest request_1 = mock(HttpServletRequest.class);
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
    public void testMakeHttpRequest() throws Exception {
        final String url = "http://localhost:1234/a/b";
        final Map<String, String[]> paramAsArray = singletonMap("name", new String[]{"a"});

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer(url));
        when(servletRequest.getParameterMap()).thenReturn(paramAsArray);

        final String barNaiveEncoded = NaiveUrlEncoder.encode("bar"); //must differ from normal url encode
		when(servletRequest.getQueryString()).thenReturn("foo=" + barNaiveEncoded);

        final HttpRequest httpRequest = ServletUtils.makeHttpRequest(servletRequest);
        assertThat(httpRequest.getRequestURL(), equalTo(url));
        assertThat(httpRequest.getParameters(), equalTo(singletonMap("name", singletonList("a"))));
        assertThat(httpRequest.getEncodedParameter("foo"), equalTo(barNaiveEncoded));
    }

	@Test
	public void sendRedirectToShouldHandleUrlsWithQueryParams() throws Exception {
		// having
		final HttpServletResponse response = mock(HttpServletResponse.class);

		// when
		ServletUtils.sendRedirect(response, "https://sso.connect.pingidentity.com/sso/idp/SSO.saml2?idpid=ffee-aabbb", singletonMap("SAMLRequest", "data"));

		// then
		verify(response).sendRedirect("https://sso.connect.pingidentity.com/sso/idp/SSO.saml2?idpid=ffee-aabbb&SAMLRequest=data");
	}
}
