package com.onelogin.saml2.http;

import org.junit.Test;

import static java.util.Collections.singletonMap;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class HttpRequestUtilsTest {

    /**
     * Tests the getSelfURLhost method
     *
     * @see HttpRequestUtils#getSelfURLhost
     */
    @Test
    public void testGetSelfURLhost() {
        HttpRequest request_1 = mock(HttpRequest.class);
        when(request_1.getScheme()).thenReturn("http");
        when(request_1.getServerName()).thenReturn("example.com");
        when(request_1.getServerPort()).thenReturn(80);
        assertEquals("http://example.com", HttpRequestUtils.getSelfURLhost(request_1));

        when(request_1.getServerPort()).thenReturn(81);
        assertEquals("http://example.com:81", HttpRequestUtils.getSelfURLhost(request_1));

        when(request_1.getScheme()).thenReturn("https");
        when(request_1.getServerPort()).thenReturn(443);
        assertEquals("https://example.com", HttpRequestUtils.getSelfURLhost(request_1));

        when(request_1.getServerPort()).thenReturn(444);
        assertEquals("https://example.com:444", HttpRequestUtils.getSelfURLhost(request_1));
    }

    /**
     * Tests the getSelfURL method
     *
     * @see HttpRequestUtils#getSelfURL
     */
    @Test
    public void testGetSelfURL() {
        HttpRequest request_1 = mock(HttpRequest.class);
        when(request_1.getScheme()).thenReturn("http");
        when(request_1.getServerName()).thenReturn("example.com");
        when(request_1.getRequestURI()).thenReturn("/test");
        when(request_1.getQueryString()).thenReturn("novalue&test=true&value1=a");
        assertEquals("http://example.com/test?novalue&test=true&value1=a", HttpRequestUtils.getSelfURL(request_1));

        when(request_1.getRequestURI()).thenReturn("/");
        assertEquals("http://example.com/?novalue&test=true&value1=a", HttpRequestUtils.getSelfURL(request_1));

        when(request_1.getRequestURI()).thenReturn("");
        assertEquals("http://example.com?novalue&test=true&value1=a", HttpRequestUtils.getSelfURL(request_1));

        when(request_1.getRequestURI()).thenReturn(null);
        assertEquals("http://example.com?novalue&test=true&value1=a", HttpRequestUtils.getSelfURL(request_1));

        HttpRequest request_2 = mock(HttpRequest.class);
        when(request_2.getScheme()).thenReturn("http");
        when(request_2.getServerName()).thenReturn("example.com");
        when(request_2.getRequestURI()).thenReturn("/test");
        assertEquals("http://example.com/test", HttpRequestUtils.getSelfURL(request_2));

        when(request_2.getQueryString()).thenReturn("");
        assertEquals("http://example.com/test", HttpRequestUtils.getSelfURL(request_2));

        when(request_2.getQueryString()).thenReturn(null);
        assertEquals("http://example.com/test", HttpRequestUtils.getSelfURL(request_2));
    }

    /**
     * Tests the getSelfURLNoQuery method
     *
     * @see HttpRequestUtils#getSelfURLNoQuery
     */
    @Test
    public void testGetSelfURLNoQuery() {
        HttpRequest request_1 = mock(HttpRequest.class);
        when(request_1.getRequestURL()).thenReturn("http://example.com/test");
        assertEquals("http://example.com/test", HttpRequestUtils.getSelfURLNoQuery(request_1));
    }

    /**
     * Tests the getSelfRoutedURLNoQuery method
     *
     * @see HttpRequestUtils#getSelfRoutedURLNoQuery
     */
    @Test
    public void testGetSelfRoutedURLNoQuery() {
        HttpRequest request_1 = mock(HttpRequest.class);
        when(request_1.getScheme()).thenReturn("http");
        when(request_1.getServerName()).thenReturn("example.com");
        when(request_1.getRequestURI()).thenReturn("/test");
        assertEquals("http://example.com/test", HttpRequestUtils.getSelfRoutedURLNoQuery(request_1));

        when(request_1.getRequestURI()).thenReturn("");
        assertEquals("http://example.com", HttpRequestUtils.getSelfRoutedURLNoQuery(request_1));

        when(request_1.getRequestURI()).thenReturn(null);
        assertEquals("http://example.com", HttpRequestUtils.getSelfRoutedURLNoQuery(request_1));
    }

    @Test
    public void sendRedirectToShouldHandleUrlsWithQueryParams() throws Exception {
        // having
        final HttpResponse response = mock(HttpResponse.class);

        // when
        HttpResponseUtils.sendRedirect(response, "https://sso.connect.pingidentity.com/sso/idp/SSO.saml2?idpid=ffee-aabbb", singletonMap("SAMLRequest", "data"));

        // then
        verify(response).sendRedirect("https://sso.connect.pingidentity.com/sso/idp/SSO.saml2?idpid=ffee-aabbb&SAMLRequest=data");
    }

}
