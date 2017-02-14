package com.onelogin.saml2.test;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.junit.Assert;
import org.junit.Test;

import com.onelogin.saml2.util.Util;

public class NaiveUrlEncodeTest {

    @Test
    public void testDemonstratingUrlEncodingNotCanonical () throws UnsupportedEncodingException {
        String theString = "Hello World!";

        String naiveEncoded = NaiveUrlEncoder.encode(theString);
        String propperEncoded = Util.urlEncoder(theString);

        Assert.assertNotEquals("Encoded versions should differ", naiveEncoded, propperEncoded);
        Assert.assertEquals("Decoded versions equal", URLDecoder.decode(naiveEncoded, "UTF-8"), URLDecoder.decode(propperEncoded, "UTF-8"));
    }

}
