package com.onelogin;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.apache.commons.codec.binary.Base64;


public class AccountSettings {
	private String certificate;
	private Certificate idp_cert;
	private String idp_sso_target_url;
	
	public String getCertificate() {
		return certificate;
	}
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	public String getIdp_sso_target_url() {
		return idp_sso_target_url;
	}
	public void setIdpSsoTargetUrl(String idp_sso_target_url) {
		this.idp_sso_target_url = idp_sso_target_url;
	}
	
	/**
	 * Loads certificate from a base64 encoded string
	 * @param certificate an base64 encoded string.
	 */
 	public void loadCertificate(String certificate) throws CertificateException {
		CertificateFactory fty = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(certificate.getBytes()));
		this.idp_cert = fty.generateCertificate(bais);
	}
	

	public Certificate getIdpCert() throws CertificateException {
		if(this.idp_cert == null){
			loadCertificate(this.certificate);
		}
		return this.idp_cert;
	}
	
	/**
	 * load and get a certificate from a encoded base64 byte array.
	 * @param certificate an encoded base64 byte array.
	 * @throws CertificateException In case it can't load the certificate.
	 */
	public Certificate getCert(byte[] certificate) throws CertificateException {
		CertificateFactory fty = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(certificate));
		idp_cert = fty.generateCertificate(bais);
		return idp_cert;
	}
}
