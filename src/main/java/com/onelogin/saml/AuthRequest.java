package com.onelogin.saml;

import com.onelogin.AccountSettings;
import com.onelogin.AppSettings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.commons.codec.binary.Base64;

public class AuthRequest {

	protected final String id;
	protected final String issueInstant;
	protected final AppSettings appSettings;
	protected AccountSettings accountSettings;
	protected static final int base64 = 1;
	protected Deflater deflater;

	public AuthRequest(AppSettings appSettings, AccountSettings accSettings){
		this.appSettings = appSettings;
		this.accountSettings = accSettings;
		id="_"+UUID.randomUUID().toString();
		SimpleDateFormat simpleDf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		simpleDf.setTimeZone(TimeZone.getTimeZone("UTC"));
		issueInstant = simpleDf.format(new Date());
	}

	public String getRequest(int format) throws XMLStreamException, IOException {
		String result = "";

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		XMLOutputFactory factory = XMLOutputFactory.newInstance();
		XMLStreamWriter writer = factory.createXMLStreamWriter(baos);

		writer.writeStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
		writer.writeNamespace("samlp","urn:oasis:names:tc:SAML:2.0:protocol");

		writer.writeAttribute("ID", id);
		writer.writeAttribute("Version", "2.0");
		writer.writeAttribute("IssueInstant", this.issueInstant);
		writer.writeAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		writer.writeAttribute("AssertionConsumerServiceURL", this.appSettings.getAssertionConsumerServiceUrl());

		writer.writeStartElement("saml","Issuer","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("saml","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters(this.appSettings.getIssuer());
		writer.writeEndElement();

		writer.writeStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");

		writer.writeAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
		writer.writeAttribute("AllowCreate", "true");
		writer.writeEndElement();

		writer.writeStartElement("samlp","RequestedAuthnContext","urn:oasis:names:tc:SAML:2.0:protocol");

		writer.writeAttribute("Comparison", "exact");

		writer.writeStartElement("saml","AuthnContextClassRef","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		writer.writeEndElement();

		writer.writeEndElement();
		writer.writeEndElement();
		writer.flush();
                
		result = encodeSAMLRequest(baos.toByteArray());
		return result;
	}

	protected String encodeSAMLRequest(byte[] pSAMLRequest) throws RuntimeException {

		Base64 base64Encoder = new Base64();

		try {
			ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
			Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);

			DeflaterOutputStream def = new DeflaterOutputStream(byteArray, deflater);
			def.write(pSAMLRequest);
			def.close();
			byteArray.close();

			String stream = new String(base64Encoder.encode(byteArray.toByteArray()));

			return stream.trim();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public String getSSOurl(String relayState) throws UnsupportedEncodingException, XMLStreamException, IOException{
		
		String ssourl = getSSOurl();
		if(relayState != null && !relayState.isEmpty()){
			ssourl = ssourl + "&RelayState=" + relayState;
		}
		return ssourl;
	}
	
	public String getSSOurl() throws UnsupportedEncodingException, XMLStreamException, IOException{
		String ssourl = accountSettings.getIdp_sso_target_url()+"?SAMLRequest=" + URLEncoder.encode(getRequest(base64),"UTF-8");
		return ssourl;
	}
	
}
