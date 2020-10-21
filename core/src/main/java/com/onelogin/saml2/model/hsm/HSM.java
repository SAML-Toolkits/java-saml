package com.onelogin.saml2.model.hsm;

public abstract class HSM {
	/**
	 * Sets the client to connect to the Azure Key Vault.
	 */
	public abstract void setClient();

	/**
	 * Wraps a key with a particular algorithm using the HSM
	 *
	 * @param algorithm The algorithm to use to wrap the key.
	 * @param key       The key to wrap
	 * @return A wrapped key.
	 */
	public abstract byte[] wrapKey(String algorithm, byte[] key);

	/**
	 * Unwraps a key with a particular algorithm using the HSM.
	 *
	 * @param algorithmUrl  The algorithm URL to use to unwrap the key.
	 * @param wrappedKey The key to unwrap
	 * @return An unwrapped key.
	 */
	public abstract byte[] unwrapKey(String algorithmUrl, byte[] wrappedKey);

	/**
	 * Encrypts an array of bytes with a particular algorithm using the HSM.
	 *
	 * @param algorithm The algorithm to use for encryption.
	 * @param plainText The array of bytes to encrypt.
	 * @return An encrypted array of bytes.
	 */
	public abstract byte[] encrypt(String algorithm, byte[] plainText);

	/**
	 * Decrypts an array of bytes with a particular algorithm using the HSM.
	 *
	 * @param algorithm  The algorithm to use for decryption.
	 * @param cipherText The encrypted array of bytes.
	 * @return A decrypted array of bytes.
	 */
	public abstract byte[] decrypt(String algorithm, byte[] cipherText);
}
