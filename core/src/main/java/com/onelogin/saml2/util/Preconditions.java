package com.onelogin.saml2.util;

public final class Preconditions {
    /**
     * Throws a NullPointerException if {@code t} is null.
     *
     * @param t       the value to check for null
     * @param message the message to include in the thrown exception
     *
     * @return T 
     *
     * @throws NullPointerException if {@code t} is null
     */
    public static <T>T checkNotNull(T t, String message) {
        if (t == null) {
            throw new NullPointerException(message);
        } else {
            return t;
        }
    }

    private Preconditions() {
    }
}
