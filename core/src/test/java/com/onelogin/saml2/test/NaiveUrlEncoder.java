package com.onelogin.saml2.test;

import java.io.UnsupportedEncodingException;

public final  class NaiveUrlEncoder {

    private NaiveUrlEncoder () {
        //static class only
    }

    /**
     * Encodes ALL characters in URL using %xx encoding.<br>
     * This differs from 'normal' url encoding.
     * 
     * @param s string to be encoded
     * @return a string with the url-encoded values
     *
     * @throws UnsupportedEncodingException
     */
    public static String encode (String s) throws UnsupportedEncodingException {
        StringBuilder buf = new StringBuilder();
        for  (byte b : s.getBytes("UTF-8")) {
            buf.append("%");
            buf.append(String.format("%02x", b));
        }
        return buf.toString();
    }

}