package com.onelogin.saml2.test.http;

import com.onelogin.saml2.http.HttpResponse;
import com.onelogin.saml2.http.JavaxHttpResponse;
import org.junit.Test;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.Mockito.*;

/**
 * @author ashley.mercer@skylightipv.com
 */
public class JavaxHttpResponseTest {

    @Test
    public void testSendRedirect() throws IOException {
        final HttpServletResponse javaxResponse = mock(HttpServletResponse.class);
        final HttpResponse response = new JavaxHttpResponse(javaxResponse);

        response.sendRedirect("http://www.example.com");
        verify(javaxResponse, times(1)).sendRedirect(matches("http://www\\.example\\.com"));
    }
}
