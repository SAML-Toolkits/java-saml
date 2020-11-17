package com.onelogin.saml2.model.hsm;

import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.onelogin.saml2.util.Constants;

import java.util.HashMap;

public class AzureKeyVault extends HSM {

	private String clientId;
	private String clientCredentials;
	private String tenantId;
	private String keyVaultId;
	private CryptographyClient akvClient;
	private HashMap<String, KeyWrapAlgorithm> algorithmMapping;

	/**
	 * Constructor to initialise an HSM object.
	 *
	 * @param clientId          The Azure Key Vault client ID.
	 * @param clientCredentials The Azure Key Vault client credentials.
	 * @param tenantId          The Azure Key Vault tenant ID.
	 * @param keyVaultId        The Azure Key Vault ID.
	 * @return AzureKeyVault
	 */
	public AzureKeyVault(String clientId, String clientCredentials, String tenantId, String keyVaultId) {
		this.clientId = clientId;
		this.clientCredentials = clientCredentials;
		this.tenantId = tenantId;
		this.keyVaultId = keyVaultId;

		this.algorithmMapping = createAlgorithmMapping();
	}

	/**
	 * Creates a mapping between the URLs received from the encrypted SAML
	 * assertion and the algorithms as how they are expected to be received from
	 * the Azure Key Vault.
	 *
	 * @return The algorithm mapping.
	 */
	private HashMap<String, KeyWrapAlgorithm> createAlgorithmMapping() {
		HashMap<String, KeyWrapAlgorithm> mapping = new HashMap<>();

		mapping.put(Constants.RSA_1_5, KeyWrapAlgorithm.RSA1_5);
		mapping.put(Constants.RSA_OAEP_MGF1P, KeyWrapAlgorithm.RSA_OAEP);
		mapping.put(Constants.A128KW, KeyWrapAlgorithm.A128KW);
		mapping.put(Constants.A192KW, KeyWrapAlgorithm.A192KW);
		mapping.put(Constants.A256KW, KeyWrapAlgorithm.A256KW);

		return mapping;
	}

	/**
	 * Retrieves the key wrap algorithm object based on the algorithm URL passed
	 * within the SAML assertion.
	 *
	 * @param algorithmUrl The algorithm URL.
	 * @return The KeyWrapAlgorithm.
	 */
	private KeyWrapAlgorithm getAlgorithm(String algorithmUrl) {
		return algorithmMapping.get(algorithmUrl);
	}

	/**
	 * Sets the client to connect to the Azure Key Vault.
	 */
	@Override
	public void setClient() {
		ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
			.clientId(clientId)
			.clientSecret(clientCredentials)
			.tenantId(tenantId)
			.build();

		HttpClient httpClient = new NettyAsyncHttpClientBuilder().build();

		this.akvClient = new CryptographyClientBuilder()
			.httpClient(httpClient)
			.credential(clientSecretCredential)
			.keyIdentifier(keyVaultId)
			.buildClient();
	}

	/**
	 * Wraps a key with a particular algorithm using the Azure Key Vault.
	 *
	 * @param algorithm The algorithm to use to wrap the key.
	 * @param key       The key to wrap
	 * @return A wrapped key.
	 */
	@Override
	public byte[] wrapKey(String algorithm, byte[] key) {
		return this.akvClient.wrapKey(KeyWrapAlgorithm.fromString(algorithm), key).getEncryptedKey();
	}

	/**
	 * Unwraps a key with a particular algorithm using the Azure Key Vault.
	 *
	 * @param algorithmUrl The algorithm to use to unwrap the key.
	 * @param wrappedKey   The key to unwrap
	 * @return An unwrapped key.
	 */
	@Override
	public byte[] unwrapKey(String algorithmUrl, byte[] wrappedKey) {
		return this.akvClient.unwrapKey(getAlgorithm(algorithmUrl), wrappedKey).getKey();
	}

	/**
	 * Encrypts an array of bytes with a particular algorithm using the Azure Key Vault.
	 *
	 * @param algorithm The algorithm to use for encryption.
	 * @param plainText The array of bytes to encrypt.
	 * @return An encrypted array of bytes.
	 */
	@Override
	public byte[] encrypt(String algorithm, byte[] plainText) {
		return this.akvClient.encrypt(EncryptionAlgorithm.fromString(algorithm), plainText).getCipherText();
	}

	/**
	 * Decrypts an array of bytes with a particular algorithm using the Azure Key Vault.
	 *
	 * @param algorithm  The algorithm to use for decryption.
	 * @param cipherText The encrypted array of bytes.
	 * @return A decrypted array of bytes.
	 */
	@Override
	public byte[] decrypt(String algorithm, byte[] cipherText) {
		return this.akvClient.decrypt(EncryptionAlgorithm.fromString(algorithm), cipherText).getPlainText();
	}
}
