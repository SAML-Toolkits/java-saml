package com.onelogin.saml2.test.http;

import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.http.JavaxHttpRequest;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author ashley.mercer@skylightipv.com
 */
public class JavaxHttpRequestTest {

    @Test
    public void testIsSecure() {
        final HttpServletRequest javaxRequest = mock(HttpServletRequest.class);
        final HttpRequest request = new JavaxHttpRequest(javaxRequest);

        when(javaxRequest.isSecure()).thenReturn(true);
        assertTrue(request.isSecure());

        when(javaxRequest.isSecure()).thenReturn(false);
        assertFalse(request.isSecure());
    }

    @Test
    public void testGetScheme() {
        final HttpServletRequest javaxRequest = mock(HttpServletRequest.class);
        final HttpRequest request = new JavaxHttpRequest(javaxRequest);

        when(javaxRequest.getScheme()).thenReturn("http");
        assertEquals(request.getScheme(), "http");
    }

    @Test
    public void testGetServerName() {
        final HttpServletRequest javaxRequest = mock(HttpServletRequest.class);
        final HttpRequest request = new JavaxHttpRequest(javaxRequest);

        when(javaxRequest.getServerName()).thenReturn("www.example.com");
        assertEquals(request.getServerName(), "www.example.com");
    }

    @Test
    public void testGetServerPort() {
        final HttpServletRequest javaxRequest = mock(HttpServletRequest.class);
        final HttpRequest request = new JavaxHttpRequest(javaxRequest);

        when(javaxRequest.getServerPort()).thenReturn(80);
        assertEquals(request.getServerPort(), 80);

        when(javaxRequest.getServerPort()).thenReturn(443);
        assertEquals(request.getServerPort(), 443);
    }

    @Test
    public void testGetQueryString() {
        final HttpServletRequest javaxRequest = mock(HttpServletRequest.class);
        final HttpRequest request = new JavaxHttpRequest(javaxRequest);

        when(javaxRequest.getQueryString()).thenReturn("foo=bar");
        assertEquals(request.getQueryString(), "foo=bar");
    }

    @Test
    public void testGetRequestURI() {
        final HttpServletRequest javaxRequest = mock(HttpServletRequest.class);
        final HttpRequest request = new JavaxHttpRequest(javaxRequest);

        when(javaxRequest.getRequestURI()).thenReturn("/test.html");
        assertEquals(request.getRequestURI(), "/test.html");
    }

    @Test
    public void testGetRequestURL() {
        final HttpServletRequest javaxRequest = mock(HttpServletRequest.class);
        final HttpRequest request = new JavaxHttpRequest(javaxRequest);

        when(javaxRequest.getRequestURL()).thenReturn(new StringBuffer("http://www.example.com/test"));
        assertEquals(request.getRequestURL(), "http://www.example.com/test");
    }

    @Test
    public void testGetParameter() {
        final HttpServletRequest javaxRequest = mock(HttpServletRequest.class);
        final HttpRequest request = new JavaxHttpRequest(javaxRequest);

        when(javaxRequest.getParameter("foo")).thenReturn("bar");
        assertEquals(request.getParameter("foo"), "bar");
    }
}
