package com.onelogin.saml2.model;

import java.security.KeyStore;

/**
 * KeyStore class of OneLogin's Java Toolkit.
 *
 * A class that stores KeyStore details for Certificates and Private Key
 */
public class KeyStoreSettings {
    /**
     * KeyStore which stores certificates and key
     */
    private final KeyStore keyStore;

    /**
     * Alias for SP key entry
     */
    private final String spAlias;

    /**
     * Password for KeyStore
     */
    private final String storePass;

    /**
     * Constructor
     *
     * @param keyStore
     *            stores certificates and key
     * 
     * @param spAlias
     *            Alias for SP key entry
     *
     * @param storePass
     *            password to access KeyStore
     */
    public KeyStoreSettings(KeyStore keyStore, String spAlias, String storePass) {
        this.keyStore = keyStore;
        this.spAlias = spAlias;
        this.storePass = storePass;
    }

    /**
     * @return the keyStore
     */
    public final KeyStore getKeyStore() {
        return keyStore;
    }

    /**
     * @return the spAlias
     */
    public final String getSpAlias() {
        return spAlias;
    }

    /**
     * @return the storePass
     */
    public final String getStorePass() {
        return storePass;
    }

}