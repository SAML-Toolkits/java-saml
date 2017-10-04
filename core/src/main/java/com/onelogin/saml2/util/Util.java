package com.onelogin.saml2.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Iterator;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Period;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISOPeriodFormat;
import org.joda.time.format.PeriodFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.exception.XMLEntityException;


/**
 * Util class of OneLogin's Java Toolkit.
 *
 * A class that contains several auxiliary methods related to the SAML protocol
 */
public final class Util {
	/**
     * Private property to construct a logger for this class.
     */
	private static final Logger LOGGER = LoggerFactory.getLogger(Util.class);

    private static final DateTimeFormatter DATE_TIME_FORMAT = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(DateTimeZone.UTC);
	private static final DateTimeFormatter DATE_TIME_FORMAT_MILLS = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(DateTimeZone.UTC);
	public static final String UNIQUE_ID_PREFIX = "ONELOGIN_";
	public static final String RESPONSE_SIGNATURE_XPATH = "/samlp:Response/ds:Signature";
	public static final String ASSERTION_SIGNATURE_XPATH = "/samlp:Response/saml:Assertion/ds:Signature";
	/** Indicates if JAXP 1.5 support has been detected. */
	private static boolean JAXP_15_SUPPORTED = isJaxp15Supported();

	private Util() {
	      //not called
	}

	/**
	 * Method which uses the recommended way ( https://docs.oracle.com/javase/tutorial/jaxp/properties/error.html ) 
	 * of checking if JAXP >= 1.5 options are supported. Needed if the project which uses this library also has
	 * Xerces in it's classpath. 
	 * 
	 * If for whatever reason this method cannot determine if JAXP 1.5 properties are supported it will indicate the
	 * options are supported. This way we don't accidentally disable configuration options.
	 *
	 * @return
	 */
	public static boolean isJaxp15Supported() {
		boolean supported = true;		
		
		try {
			SAXParserFactory spf = SAXParserFactory.newInstance();
			SAXParser parser = spf.newSAXParser();
			parser.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "file");
		} catch (SAXException ex) {
			String err = ex.getMessage();
			if (err.contains("Property 'http://javax.xml.XMLConstants/property/accessExternalDTD' is not recognized.")) {
				//expected, jaxp 1.5 not supported
				supported = false;
			}
		} catch (Exception e) {
			LOGGER.info("An exception occurred while trying to determine if JAXP 1.5 options are supported.", e);
		}
		
		return supported;
	}
	
	/**
	 * This function load an XML string in a save way. Prevent XEE/XXE Attacks
	 *
	 * @param xml
	 * 				String. The XML string to be loaded.
	 *
	 * @return The result of load the XML at the Document or null if any error occurs
	 */
	public static Document loadXML(String xml) {
		try {
			if (xml.contains("<!ENTITY")) {
				throw new XMLEntityException("Detected use of ENTITY in XML, disabled to prevent XXE/XEE attacks");
			}
			return convertStringToDocument(xml);
		} catch (XMLEntityException e) {
			LOGGER.debug("Load XML error due XMLEntityException.", e);
		} catch (Exception e) {
			LOGGER.debug("Load XML error: " + e.getMessage(), e);
		}

		return null;
	}

	/**
	 * Extracts a node from the DOMDocument
	 *
	 * @param dom
	 * 				The DOMDocument
	 * @param query
	 * 				Xpath Expression
	 * @param context
	 * 				Context Node (DomElement)
	 *
	 * @return DOMNodeList The queried node
	 *
	 * @throws XPathExpressionException
	 */
	public static NodeList query(Document dom, String query, Node context) throws XPathExpressionException {
		NodeList nodeList;
		XPath xpath = XPathFactory.newInstance().newXPath();
		xpath.setNamespaceContext(new NamespaceContext() {

			@Override
			public String getNamespaceURI(String prefix) {
				String result = null;
				if (prefix.equals("samlp") || prefix.equals("samlp2")) {
					result = Constants.NS_SAMLP;
				} else if (prefix.equals("saml") || prefix.equals("saml2")) {
					result = Constants.NS_SAML;
				} else if (prefix.equals("ds")) {
					result = Constants.NS_DS;
				} else if (prefix.equals("xenc")) {
					result = Constants.NS_XENC;
				} else if (prefix.equals("md")) {
					result = Constants.NS_MD;
				}
				return result;
			}

			@Override
			public String getPrefix(String namespaceURI) {
				return null;
			}

			@SuppressWarnings("rawtypes")
			@Override
			public Iterator getPrefixes(String namespaceURI) {
				return null;
			}
		});

		if (context == null) {
			nodeList = (NodeList) xpath.evaluate(query, dom, XPathConstants.NODESET);
		} else {
			nodeList = (NodeList) xpath.evaluate(query, context, XPathConstants.NODESET);
		}
		return nodeList;
	}

	/**
	 * Extracts a node from the DOMDocument
	 *
	 * @param dom
	 * 				The DOMDocument
	 * @param query
	 * 				Xpath Expression
	 *
	 * @return DOMNodeList The queried node
	 *
	 * @throws XPathExpressionException
	 */
	public static NodeList query(Document dom, String query) throws XPathExpressionException {
		return query(dom, query, null);
	}

	/**
	 * This function attempts to validate an XML against the specified schema.
	 *
	 * @param xmlDocument
	 * 				The XML document which should be validated
	 * @param schemaUrl
	 *              The schema filename which should be used
	 *
	 * @return found errors after validation
	 */
	public static boolean validateXML(Document xmlDocument, URL schemaUrl) {
		try {

			if (xmlDocument == null) {
				throw new IllegalArgumentException("xmlDocument was null");
			}

			Schema schema = SchemaFactory.loadFromUrl(schemaUrl);
			Validator validator = schema.newValidator();
			
			if (JAXP_15_SUPPORTED) {
				// Prevent XXE attacks
				validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
				validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
			}

			XMLErrorAccumulatorHandler errorAcumulator = new XMLErrorAccumulatorHandler();
			validator.setErrorHandler(errorAcumulator);

			Source xmlSource = new DOMSource(xmlDocument);
			validator.validate(xmlSource);

			final boolean isValid = !errorAcumulator.hasError();
			if (!isValid) {
				LOGGER.warn("Errors found when validating SAML response with schema: " + errorAcumulator.getErrorXML());
			}
			return isValid;
		} catch (Exception e) {
			LOGGER.warn("Error executing validateXML: " + e.getMessage(), e);
			return false;
		}
	}

	/**
	 * Converts an XML in string format in a Document object
	 *
	 * @param xmlStr
	 * 				The XML string which should be converted
	 *
	 * @return the Document object
	 *
	 * @throws ParserConfigurationException 
	 * @throws SAXException 
	 * @throws IOException 
	 */
	public static Document convertStringToDocument(String xmlStr) throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory docfactory = DocumentBuilderFactory.newInstance();
		docfactory.setNamespaceAware(true);
		
		// do not expand entity reference nodes 
		docfactory.setExpandEntityReferences(false);
		
		docfactory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage", XMLConstants.W3C_XML_SCHEMA_NS_URI);
		
		// Add various options explicitly to prevent XXE attacks.
		// (adding try/catch around every setAttribute just in case a specific parser does not support it.
		try {
			// do not include external general entities
			docfactory.setAttribute("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
		} catch (Throwable e) {}
		try {
			// do not include external parameter entities or the external DTD subset
			docfactory.setAttribute("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
		} catch (Throwable e) {}
		try {
			docfactory.setAttribute("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
		} catch (Throwable e) {}
		try {
			docfactory.setAttribute("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);
		} catch (Throwable e) {}
		try {
			// ignore the external DTD completely
			docfactory.setAttribute("http://apache.org/xml/features/nonvalidating/load-external-dtd", Boolean.FALSE);
		} catch (Throwable e) {}
		try {
			// build the grammar but do not use the default attributes and attribute types information it contains
			docfactory.setAttribute("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", Boolean.FALSE);
		} catch (Throwable e) {}
		try {
			docfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		} catch (Throwable e) {}

		DocumentBuilder builder = docfactory.newDocumentBuilder();
		Document doc = builder.parse(new InputSource(new StringReader(xmlStr)));

		// Loop through the doc and tag every element with an ID attribute
		// as an XML ID node.
		XPath xpath = XPathFactory.newInstance().newXPath();
		XPathExpression expr;
		try {
			expr = xpath.compile("//*[@ID]");

			NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			for (int i = 0; i < nodeList.getLength(); i++) {
				Element elem = (Element) nodeList.item(i);
				Attr attr = (Attr) elem.getAttributes().getNamedItem("ID");
				elem.setIdAttributeNode(attr, true);
			}
		} catch (XPathExpressionException e) {
			return null;
		}

		return doc;
	}

	/**
	 * Converts an XML in Document format in a String
	 *
	 * @param doc
	 * 				The Document object
	 * @param c14n
	 *				If c14n transformation should be applied
	 *
	 * @return the Document object
	 */
	public static String convertDocumentToString(Document doc, Boolean c14n) {
		org.apache.xml.security.Init.init();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		if (c14n) {
			XMLUtils.outputDOMc14nWithComments(doc, baos);
		} else {
			XMLUtils.outputDOM(doc, baos);
		}
		
		return Util.toStringUtf8(baos.toByteArray());
	}
	
	/**
	 * Converts an XML in Document format in a String without applying the c14n transformation 
	 *
	 * @param doc
	 * 				The Document object
	 *
	 * @return the Document object
	 */
	public static String convertDocumentToString(Document doc) {
		return convertDocumentToString(doc, false);
	}

	/**
	 * Returns a certificate in String format (adding header and footer if required)
	 *
	 * @param cert
	 * 				A x509 unformatted cert
	 * @param heads
	 *              True if we want to include head and footer
	 *
	 * @return X509Certificate $x509 Formated cert
	 */
	public static String formatCert(String cert, Boolean heads) {
		String x509cert = StringUtils.EMPTY;

		if (cert != null) {		
			x509cert = cert.replace("\\x0D", "").replace("\r", "").replace("\n", "").replace(" ", "");

			if (!StringUtils.isEmpty(x509cert)) {
				x509cert = x509cert.replace("-----BEGINCERTIFICATE-----", "").replace("-----ENDCERTIFICATE-----", "");
			
				if (heads) {
					x509cert = "-----BEGIN CERTIFICATE-----\n" + chunkString(x509cert, 64) + "-----END CERTIFICATE-----";
				}
			}
		}
		return x509cert;
	}

	/**
	 * Returns a private key (adding header and footer if required).
	 *
	 * @param key
	 * 				A private key
	 * @param heads
	 *              True if we want to include head and footer
	 *
	 * @return Formated private key
	 */
	public static String formatPrivateKey(String key, boolean heads) {
		String xKey = StringUtils.EMPTY;

		if (key != null) {
			xKey = key.replace("\\x0D", "").replace("\r", "").replace("\n", "").replace(" ", "");
	
			if (!StringUtils.isEmpty(xKey)) {
				if (xKey.startsWith("-----BEGINPRIVATEKEY-----")) {
					xKey = xKey.replace("-----BEGINPRIVATEKEY-----", "").replace("-----ENDPRIVATEKEY-----", "");
	
					if (heads) {
						xKey = "-----BEGIN PRIVATE KEY-----\n" + chunkString(xKey, 64) + "-----END PRIVATE KEY-----";
					}
				} else {
	
					xKey = xKey.replace("-----BEGINRSAPRIVATEKEY-----", "").replace("-----ENDRSAPRIVATEKEY-----", "");
	
					if (heads) {
						xKey = "-----BEGIN RSA PRIVATE KEY-----\n" + chunkString(xKey, 64) + "-----END RSA PRIVATE KEY-----";
					}
				}
			}
		}
			
		return xKey;
	}	

	/**
	 * chunk a string
	 *
	 * @param str
	 * 				The string to be chunked
	 * @param chunkSize
	 *              The chunk size
	 *
	 * @return the chunked string
	 */
	private static String chunkString(String str, int chunkSize) {
		String newStr = StringUtils.EMPTY;
		int stringLength = str.length();
		for (int i = 0; i < stringLength; i += chunkSize) {
			if (i + chunkSize > stringLength) {
				chunkSize = stringLength - i;
			}
			newStr += str.substring(i, chunkSize + i) + '\n';
		}
		return newStr;
	}

	
	/**
	 * Load X.509 certificate
	 *
	 * @param certString
	 * 				 certificate in string format
	 *
	 * @return Loaded Certificate. X509Certificate object
	 *
	 * @throws CertificateException 
	 *
	 */
	public static X509Certificate loadCert(String certString) throws CertificateException {
		certString = formatCert(certString, true);
		X509Certificate cert;
		
		try {
			cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
				new ByteArrayInputStream(certString.getBytes(StandardCharsets.UTF_8)));
		} catch (IllegalArgumentException e){
			cert = null;
		}
		return cert;
	}

	/**
	 * Load private key
	 * 
	 * @param keyString
	 * 				 private key in string format
	 *
	 * @return Loaded private key. PrivateKey object
	 *
	 * @throws GeneralSecurityException 
	 */
	public static PrivateKey loadPrivateKey(String keyString) throws GeneralSecurityException {
		org.apache.xml.security.Init.init();

		String extractedKey = formatPrivateKey(keyString, false);
		extractedKey = chunkString(extractedKey, 64);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		
		PrivateKey privKey;
		try {
			byte[] encoded = Base64.decodeBase64(extractedKey);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
			privKey = kf.generatePrivate(keySpec);
		}
		catch(IllegalArgumentException e) {
			privKey = null;
		}

		return privKey;
	}

	/**
	 * Calculates the fingerprint of a x509cert
	 * 
	 * @param x509cert
	 * 				 x509 certificate
	 * @param alg
	 * 				 Digest Algorithm
	 *
	 * @return the formated fingerprint
	 */
	public static String calculateX509Fingerprint(X509Certificate x509cert, String alg) {
		String fingerprint = StringUtils.EMPTY;

		try {
			byte[] dataBytes = x509cert.getEncoded();
			if (alg == null || alg.isEmpty() || alg.equals("SHA-1")|| alg.equals("sha1")) {
				fingerprint = DigestUtils.sha1Hex(dataBytes);
			} else if (alg.equals("SHA-256") || alg .equals("sha256")) {
				fingerprint = DigestUtils.sha256Hex(dataBytes);
			} else if (alg.equals("SHA-384") || alg .equals("sha384")) {
				fingerprint = DigestUtils.sha384Hex(dataBytes);
			} else if (alg.equals("SHA-512") || alg.equals("sha512")) {
				fingerprint = DigestUtils.sha512Hex(dataBytes);
			} else {
				LOGGER.debug("Error executing calculateX509Fingerprint. alg " + alg + " not supported");
			}
		} catch (Exception e) {
			LOGGER.debug("Error executing calculateX509Fingerprint: "+ e.getMessage(), e);
		}
		return fingerprint.toLowerCase();
	}

	/**
	 * Calculates the SHA-1 fingerprint of a x509cert
	 * 
	 * @param x509cert
	 * 				 x509 certificate
	 *
	 * @return the SHA-1 formated fingerprint
	 */
	public static String calculateX509Fingerprint(X509Certificate x509cert) {
		return calculateX509Fingerprint(x509cert, "SHA-1");
	}

	/**
	 * Converts an X509Certificate in a well formated PEM string
	 *
	 * @param certificate
	 * 				 The public certificate
	 *
	 * @return the formated PEM string
	 */
	public static String convertToPem(X509Certificate certificate) {
		String pemCert = "";
		try {
			Base64 encoder = new Base64(64);
			String cert_begin = "-----BEGIN CERTIFICATE-----\n";
			String end_cert = "-----END CERTIFICATE-----";

			byte[] derCert = certificate.getEncoded();
			String pemCertPre = new String(encoder.encode(derCert));
			pemCert = cert_begin + pemCertPre + end_cert;

		} catch (Exception e) {
			LOGGER.debug("Error converting certificate on PEM format: "+ e.getMessage(), e);
		}
		return pemCert;
	}	

	/**
	 * Loads a resource located at a relative path
	 *
	 * @param relativeResourcePath
	 *				Relative path of the resource
	 *
	 * @return the loaded resource in String format
	 *
	 * @throws IOException
	 */
	public static String getFileAsString(String relativeResourcePath) throws IOException {
		InputStream is = Util.class.getResourceAsStream("/" + relativeResourcePath);
		if (is == null) {
			throw new FileNotFoundException(relativeResourcePath);
		}

		try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            copyBytes(new BufferedInputStream(is), bytes);

            return bytes.toString("utf-8");
        } finally {
            is.close();
        }
	}

	private static void copyBytes(InputStream is, OutputStream bytes) throws IOException {
		int res = is.read();
		while (res != -1) {
			bytes.write(res);
			res = is.read();
		}
	}

	/**
	 * Returns String Base64 decoded and inflated
	 *
	 * @param input
	 *				String input
	 *
	 * @return the base64 decoded and inflated string
	 */
	public static String base64decodedInflated(String input) {
		if (input.isEmpty()) {
			return input;
		}
		// Base64 decoder
		byte[] decoded = Base64.decodeBase64(input);
		
		// Inflater
		try {
			Inflater decompresser = new Inflater(true);
		    decompresser.setInput(decoded);
		    byte[] result = new byte[1024];
		    String inflated = "";
		    long limit = 0;
		    while(!decompresser.finished() && limit < 150) {
		    	int resultLength = decompresser.inflate(result);
		    	limit += 1; 
		    	inflated += new String(result, 0, resultLength, "UTF-8");
		    }
		    decompresser.end();
		    return inflated;
		} catch (Exception e) {
			return new String(decoded);
		}
	}

	/**
	 * Returns String Deflated and base64 encoded
	 *
	 * @param input
	 *				String input
	 *
	 * @return the deflated and base64 encoded string
	 * @throws IOException 
	 */
	public static String deflatedBase64encoded(String input) throws IOException {
		// Deflater
		ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
		Deflater deflater = new Deflater(Deflater.DEFLATED, true);
		DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
		deflaterStream.write(input.getBytes(Charset.forName("UTF-8")));
		deflaterStream.finish();
		// Base64 encoder
		return new String(Base64.encodeBase64(bytesOut.toByteArray()));
	}

	/**
	 * Returns String base64 encoded
	 *
	 * @param input
	 *				Stream input
	 *
	 * @return the base64 encoded string
	 */
	public static String base64encoder(byte [] input) {
		return toStringUtf8(Base64.encodeBase64(input));
	}

	/**
	 * Returns String base64 encoded
	 *
	 * @param input
	 * 				 String input
	 *
	 * @return the base64 encoded string
	 */
	public static String base64encoder(String input) {		
		return base64encoder(toBytesUtf8(input));
	}

	/**
	 * Returns String base64 decoded
	 *
	 * @param input
	 * 				 Stream input
	 *
	 * @return the base64 decoded bytes
	 */
	public static byte[] base64decoder(byte [] input) {		
		return Base64.decodeBase64(input);
	}

	/**
	 * Returns String base64 decoded
	 *
	 * @param input
	 * 				 String input
	 *
	 * @return the base64 decoded bytes
	 */
	public static byte[] base64decoder(String input) {		
		return base64decoder(toBytesUtf8(input));
	}

	/**
	 * Returns String URL encoded
	 *
	 * @param input
	 * 				 String input
	 *
	 * @return the URL encoded string
	 */
	public static String urlEncoder(String input) {
		if (input != null) {
			try {
				return URLEncoder.encode(input, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				LOGGER.error("URL encoder error.", e);
				throw new IllegalArgumentException();
			}
		} else {
			return null;
		}
	}

	/**
	 * Returns String URL decoded
	 *
	 * @param input
	 * 				 URL encoded input
	 *
	 * @return the URL decoded string
	 */
	public static String urlDecoder(String input) {
		if (input != null) {
			try {
				return URLDecoder.decode(input, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				LOGGER.error("URL decoder error.", e);
				throw new IllegalArgumentException();
			}
		} else {
			return null;
		}
	}

	/**
	 * Generates a signature from a string
	 *
	 * @param text
	 * 				 The string we should sign
	 * @param key
	 * 				 The private key to sign the string
	 * @param signAlgorithm
	 * 				 Signature algorithm method
	 *
	 * @return the signature
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public static byte[] sign(String text, PrivateKey key, String signAlgorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		org.apache.xml.security.Init.init();

        if (signAlgorithm == null) {
        	signAlgorithm = Constants.RSA_SHA1;
        }

        Signature instance = Signature.getInstance(signatureAlgConversion(signAlgorithm));
        instance.initSign(key);
        instance.update(text.getBytes());
        byte[] signature = instance.sign();

        return signature;
	}

	/**
	 * Converts Signature algorithm method name
	 *
	 * @param sign
	 * 				 signature algorithm method
	 *
	 * @return the converted signature name
	 */
	public static String signatureAlgConversion(String sign) {
		String convertedSignatureAlg = "";

		if (sign == null) {
			convertedSignatureAlg = "SHA1withRSA";
		} else if (sign.equals(Constants.DSA_SHA1)) {
			convertedSignatureAlg = "SHA1withDSA";
		} else if (sign.equals(Constants.RSA_SHA256)) {
			convertedSignatureAlg = "SHA256withRSA";
		} else if (sign.equals(Constants.RSA_SHA384)) {
			convertedSignatureAlg = "SHA384withRSA";
		} else if (sign.equals(Constants.RSA_SHA512)) {
			convertedSignatureAlg = "SHA512withRSA";
		} else {			
			convertedSignatureAlg = "SHA1withRSA";
		}

		return convertedSignatureAlg;
	}

	/**
	 * Validate the signature pointed to by the xpath
	 *
	 * @param doc The document we should validate
	 * @param cert The public certificate
	 * @param fingerprint The fingerprint of the public certificate
	 * @param alg The signature algorithm method
	 * @param xpath the xpath of the ds:Signture node to validate
	 *
	 * @return True if the signature exists and is valid, false otherwise.
	 */
	public static boolean validateSign(final Document doc, final X509Certificate cert, final String fingerprint,
									   final String alg, final String xpath) {
		try {
			final NodeList signatures = query(doc, xpath);
			return signatures.getLength() == 1 && validateSignNode(signatures.item(0), cert, fingerprint, alg);
		} catch (XPathExpressionException e) {
			LOGGER.warn("Failed to find signature nodes", e);		
		}
		return false;
	}

	/**
     * Validate signature (Metadata).
     *
     * @param doc
     *               The document we should validate
     * @param cert
     *               The public certificate
     * @param fingerprint
     *               The fingerprint of the public certificate
     * @param alg
     *               The signature algorithm method
     *
     * @return True if the sign is valid, false otherwise.
     */
    public static Boolean validateMetadataSign(Document doc, X509Certificate cert, String fingerprint, String alg) {
        NodeList signNodesToValidate;
		try {
			signNodesToValidate = query(doc, "/md:EntitiesDescriptor/ds:Signature");

			if (signNodesToValidate.getLength() == 0) {
				signNodesToValidate = query(doc, "/md:EntityDescriptor/ds:Signature");
				
				if (signNodesToValidate.getLength() == 0) {
					signNodesToValidate = query(doc, "/md:EntityDescriptor/md:SPSSODescriptor/ds:Signature|/md:EntityDescriptor/IDPSSODescriptor/ds:Signature");
				}
			}

			if (signNodesToValidate.getLength() > 0) {
				for (int i = 0; i < signNodesToValidate.getLength(); i++) {
					Node signNode =  signNodesToValidate.item(i);
					if (!validateSignNode(signNode, cert, fingerprint, alg)) {
						return false;
					}
				}
				return true;
			}
		} catch (XPathExpressionException e) {
			LOGGER.warn("Failed to find signature nodes", e);
		}
		return false;
    }
    
	/**
	 * Validate signature of the Node.
	 *
	 * @param signNode
	 * 				 The document we should validate
	 * @param cert
	 * 				 The public certificate
	 * @param fingerprint
	 * 				 The fingerprint of the public certificate
	 * @param alg
	 * 				 The signature algorithm method
	 *
	 * @return True if the sign is valid, false otherwise.
	 */
	public static Boolean validateSignNode(Node signNode, X509Certificate cert, String fingerprint, String alg) {
		Boolean res = false;
		try {
			org.apache.xml.security.Init.init();

			Element sigElement = (Element) signNode;
			XMLSignature signature = new XMLSignature(sigElement, "", true);

			if (cert != null) {
				res = signature.checkSignatureValue(cert);
			} else {
				KeyInfo keyInfo = signature.getKeyInfo();
				if (keyInfo != null && keyInfo.containsX509Data()) {
					X509Certificate providedCert = keyInfo.getX509Certificate();
					if (fingerprint.equals(calculateX509Fingerprint(providedCert, alg))) {						
						res = signature.checkSignatureValue(providedCert);
					}
				}
			}
		} catch (Exception e) {
			LOGGER.warn("Error executing validateSignNode: " + e.getMessage(), e);
		}
		return res;
	}

	/**
	 * Decrypt an encrypted element.
	 *
	 * @param encryptedDataElement
	 * 				 The encrypted element.
	 * @param inputKey
	 * 				 The private key to decrypt.
	 */
	public static void decryptElement(Element encryptedDataElement, PrivateKey inputKey) {
		try {
			org.apache.xml.security.Init.init();

			XMLCipher xmlCipher = XMLCipher.getInstance();
			xmlCipher.init(XMLCipher.DECRYPT_MODE, null);

			/* Check if we have encryptedData with a KeyInfo that contains a RetrievalMethod to obtain the EncryptedKey.
			   xmlCipher is not able to handle that so we move the EncryptedKey inside the KeyInfo element and
			   replacing the RetrievalMethod.
			*/

			NodeList keyInfoInEncData = encryptedDataElement.getElementsByTagNameNS(Constants.NS_DS, "KeyInfo");
			if (keyInfoInEncData.getLength() == 0) {
				throw new ValidationError("No KeyInfo inside EncryptedData element", ValidationError.KEYINFO_NOT_FOUND_IN_ENCRYPTED_DATA);
			}

			NodeList childs = keyInfoInEncData.item(0).getChildNodes();
			for (int i=0; i < childs.getLength(); i++) {
				if (childs.item(i).getLocalName() != null && childs.item(i).getLocalName().equals("RetrievalMethod")) {
					Element retrievalMethodElem = (Element)childs.item(i);
					if (!retrievalMethodElem.getAttribute("Type").equals("http://www.w3.org/2001/04/xmlenc#EncryptedKey")) {
						throw new ValidationError("Unsupported Retrieval Method found", ValidationError.UNSUPPORTED_RETRIEVAL_METHOD);
					}

					String uri = retrievalMethodElem.getAttribute("URI").substring(1);

					NodeList encryptedKeyNodes = ((Element) encryptedDataElement.getParentNode()).getElementsByTagNameNS(Constants.NS_XENC, "EncryptedKey");
					for (int j=0; j < encryptedKeyNodes.getLength(); j++) {
						if (((Element)encryptedKeyNodes.item(j)).getAttribute("Id").equals(uri)) {
							keyInfoInEncData.item(0).replaceChild(encryptedKeyNodes.item(j), childs.item(i));
						}
					}
				}
			}

			xmlCipher.setKEK(inputKey);
			xmlCipher.doFinal(encryptedDataElement.getOwnerDocument(), encryptedDataElement, false);
		} catch (Exception e) {
			LOGGER.warn("Error executing decryption: " + e.getMessage(), e);
		}
	}

	/**
	 * Clone a Document object.
	 *
	 * @param source
	 * 				 The Document object to be cloned.
	 *
 	 * @return the clone of the Document object
 	 *
	 * @throws ParserConfigurationException 
	 */
	public static Document copyDocument(Document source) throws ParserConfigurationException
	{
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	  	dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();

        Node originalRoot = source.getDocumentElement();

        Document copiedDocument = db.newDocument();
        Node copiedRoot = copiedDocument.importNode(originalRoot, true);
        copiedDocument.appendChild(copiedRoot);
        
        return copiedDocument;
	}

	/**
	 * Signs the Document using the specified signature algorithm with the private key and the public certificate.
	 *
	 * @param document
	 * 				 The document to be signed
	 * @param key
	 * 				 The private key
	 * @param certificate
	 * 				 The public certificate
	 * @param signAlgorithm
	 * 				 Signature Algorithm
	 * 
	 * @return the signed document in string format
	 * 
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 */
	public static String addSign(Document document, PrivateKey key, X509Certificate certificate, String signAlgorithm) throws XMLSecurityException, XPathExpressionException {
		org.apache.xml.security.Init.init();

		// Check arguments.
		if (document == null) {
			throw new IllegalArgumentException("Provided document was null");
		}

		if (document.getDocumentElement() == null) {
			throw new IllegalArgumentException("The Xml Document has no root element.");
		}

		if (key == null) {
			throw new IllegalArgumentException("Provided key was null");
		}
		
		if (certificate == null) {
			throw new IllegalArgumentException("Provided certificate was null");
		}

		if (signAlgorithm == null || signAlgorithm.isEmpty()) {
			signAlgorithm = Constants.RSA_SHA1;
		}

		// document.normalizeDocument();

		String c14nMethod = Constants.C14N_WC;

		// Signature object
		XMLSignature sig = new XMLSignature(document, null, signAlgorithm, c14nMethod);

		// Including the signature into the document before sign, because
		// this is an envelop signature
		Element root = document.getDocumentElement();
		document.setXmlStandalone(false);		

		// If Issuer, locate Signature after Issuer, Otherwise as first child.
		NodeList issuerNodes = Util.query(document, "//saml:Issuer", null);
		if (issuerNodes.getLength() > 0) {
			Node issuer =  issuerNodes.item(0);
			root.insertBefore(sig.getElement(), issuer.getNextSibling());
		} else {
			root.insertBefore(sig.getElement(), root.getFirstChild());
		}

		String id = root.getAttribute("ID");

		String reference = id;
		if (!id.isEmpty()) {
			root.setIdAttributeNS(null, "ID", true);
			reference = "#" + id;
		}

		// Create the transform for the document
		Transforms transforms = new Transforms(document);
		transforms.addTransform(Constants.ENVSIG);
		//transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
		transforms.addTransform(c14nMethod);
		sig.addDocument(reference, transforms, Constants.SHA1);

		// Add the certification info
		sig.addKeyInfo(certificate);			

		// Sign the document
		sig.sign(key);

		return convertDocumentToString(document, true);
	}

	/**
	 * Signs a Node using the specified signature algorithm with the private key and the public certificate.
	 *
	 * @param node
	 * 				 The Node to be signed
	 * @param key
	 * 				 The private key
	 * @param certificate
	 * 				 The public certificate
	 * @param signAlgorithm
	 * 				 Signature Algorithm
	 * 
	 * @return the signed document in string format
	 *
	 * @throws ParserConfigurationException
	 * @throws XMLSecurityException
	 * @throws XPathExpressionException
	 */
	public static String addSign(Node node, PrivateKey key, X509Certificate certificate, String signAlgorithm) throws ParserConfigurationException, XPathExpressionException, XMLSecurityException {
		// Check arguments.
		if (node == null) {
			throw new IllegalArgumentException("Provided node was null");
		}

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	  	dbf.setNamespaceAware(true);
		Document doc = dbf.newDocumentBuilder().newDocument();
		Node newNode = doc.importNode(node, true);
		doc.appendChild(newNode);

		return addSign(doc, key, certificate, signAlgorithm);
	}	
	
	/**
	 * Validates signed binary data (Used to validate GET Signature).
	 *
	 * @param signedQuery
	 * 				 The element we should validate
	 * @param signature
	 * 				 The signature that will be validate
	 * @param cert
	 * 				 The public certificate
	 * @param signAlg
	 * 				 Signature Algorithm
	 * 
	 * @return the signed document in string format
	 *
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public static Boolean validateBinarySignature(String signedQuery, byte[] signature, X509Certificate cert, String signAlg) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		Boolean valid = false;
		try {
			org.apache.xml.security.Init.init();

			String convertedSigAlg = signatureAlgConversion(signAlg);

			Signature sig = Signature.getInstance(convertedSigAlg); //, provider);
			sig.initVerify(cert.getPublicKey());
			sig.update(signedQuery.getBytes());
			
			valid = sig.verify(signature);
		} catch (Exception e) {
			LOGGER.warn("Error executing validateSign: " + e.getMessage(), e);
		}
		return valid;
	}

	/**
	 * Generates a nameID.
	 *
	 * @param value
	 * 				 The value
	 * @param spnq
	 * 				 SP Name Qualifier
	 * @param format
	 * 				 SP Format
	 * @param cert
	 * 				 IdP Public certificate to encrypt the nameID
	 *
	 * @return Xml contained in the document.
	 */
	public static String generateNameId(String value, String spnq, String format, X509Certificate cert) {
		String res = null;
		try {
		  	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		  	dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder().newDocument();
			Element nameId = doc.createElement("saml:NameID");
			if (spnq != null && !spnq.isEmpty()) {
				nameId.setAttribute("SPNameQualifier", spnq);
			}
			if (format != null && !format.isEmpty()) {
			nameId.setAttribute("Format", format);
			}
			nameId.appendChild(doc.createTextNode(value));
			doc.appendChild(nameId);

			if (cert != null) {
				// We generate a symmetric key
				Key symmetricKey = generateSymmetricKey();

				// cipher for encrypt the data
				XMLCipher xmlCipher = XMLCipher.getInstance(Constants.AES128_CBC);
				xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

				// cipher for encrypt the symmetric key
				XMLCipher keyCipher = XMLCipher.getInstance(Constants.RSA_1_5);
				keyCipher.init(XMLCipher.WRAP_MODE, cert.getPublicKey());

				// encrypt the symmetric key
				EncryptedKey encryptedKey = keyCipher.encryptKey(doc, symmetricKey);				

				// Add keyinfo inside the encrypted data
				EncryptedData encryptedData = xmlCipher.getEncryptedData();
				KeyInfo keyInfo = new KeyInfo(doc);
				keyInfo.add(encryptedKey);
				encryptedData.setKeyInfo(keyInfo);

				// Encrypt the actual data
				xmlCipher.doFinal(doc, nameId, false);

				// Building the result
				res = "<saml:EncryptedID>" + convertDocumentToString(doc) + "</saml:EncryptedID>";
			} else {
				res = convertDocumentToString(doc);
			}
		} catch (Exception e) {
			LOGGER.error("Error executing generateNameId: " + e.getMessage(), e);
		}
		return res;
	}

	/**
	 * Generates a nameID.
	 *
	 * @param value
	 * 				 The value
	 * @param spnq
	 * 				 SP Name Qualifier
	 * @param format
	 * 				 SP Format
	 *
	 * @return Xml contained in the document.
	 */
	public static String generateNameId(String value, String spnq, String format) {
		return generateNameId(value, spnq, format, null);
	}
	
	/**
	 * Method to generate a symmetric key for encryption
	 * 
	 * @return the symmetric key
	 *
	 * @throws Exception
	 */
	private static SecretKey generateSymmetricKey() throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		return keyGenerator.generateKey();
	}

	/**
	 * Generates a unique string (used for example as ID of assertions)
	 *
	 * @return A unique string
	 */
	public static String generateUniqueID() {
		return UNIQUE_ID_PREFIX + UUID.randomUUID();
	}

	/**
	 * Interprets a ISO8601 duration value relative to a current time timestamp.
	 *
	 * @param duration
	 *            The duration, as a string.
	 *
	 * @return int The new timestamp, after the duration is applied.
	 *
	 * @throws IllegalArgumentException
	 */
	public static long parseDuration(String duration) throws IllegalArgumentException {
		TimeZone timeZone = DateTimeZone.UTC.toTimeZone();
		return parseDuration(duration, Calendar.getInstance(timeZone).getTimeInMillis() / 1000);
	}

	/**
	 * Interprets a ISO8601 duration value relative to a given timestamp.
	 *
	 * @param durationString
	 * 				 The duration, as a string.
	 * @param timestamp 
	 *               The unix timestamp we should apply the duration to.
	 *
	 * @return the new timestamp, after the duration is applied In Seconds.
	 *
	 * @throws IllegalArgumentException
	 */
	public static long parseDuration(String durationString, long timestamp) throws IllegalArgumentException {
		boolean haveMinus = false;
	
		if (durationString.startsWith("-")) {
			durationString = durationString.substring(1);
			haveMinus = true;
		}

		PeriodFormatter periodFormatter = ISOPeriodFormat.standard().withLocale(new Locale("UTC"));
		Period period = periodFormatter.parsePeriod(durationString);

		DateTime dt = new DateTime(timestamp * 1000, DateTimeZone.UTC);

		DateTime result = null;
		if (haveMinus) {
			result = dt.minus(period);
		} else {
			result = dt.plus(period);
		}
		return result.getMillis() / 1000;
	}
	  
	/**
	 * @return the unix timestamp that matches the current time.
	 */
	public static Long getCurrentTimeStamp() {
		DateTime currentDate = new DateTime(DateTimeZone.UTC);
		return currentDate.getMillis() / 1000;
	}

	/**
	 * Compare 2 dates and return the the earliest
	 *
	 * @param cacheDuration
	 * 				 The duration, as a string.
	 * @param validUntil
	 * 				 The valid until date, as a string
	 *
	 * @return the expiration time (timestamp format).
	 */
	public static long getExpireTime(String cacheDuration, String validUntil) {
		long expireTime = 0;
		try {
			if (cacheDuration != null && !StringUtils.isEmpty(cacheDuration)) {
				expireTime = parseDuration(cacheDuration);
			}
	
			if (validUntil != null && !StringUtils.isEmpty(validUntil)) {
				DateTime dt = Util.parseDateTime(validUntil);
				long validUntilTimeInt = dt.getMillis() / 1000;
				if (expireTime == 0 || expireTime > validUntilTimeInt) {
					expireTime = validUntilTimeInt;
				}
			}
		} catch (Exception e) {
			LOGGER.error("Error executing getExpireTime: " + e.getMessage(), e);
		}
		return expireTime;
	}

	/**
	 * Compare 2 dates and return the the earliest
	 *
	 * @param cacheDuration
	 * 				 The duration, as a string.
	 * @param validUntil
	 * 				 The valid until date, as a timestamp
	 *
	 * @return the expiration time (timestamp format).
	 */
	public static long getExpireTime(String cacheDuration, long validUntil) {
		long expireTime = 0;
		try {
			if (cacheDuration != null && !StringUtils.isEmpty(cacheDuration)) {
				expireTime = parseDuration(cacheDuration);
			}	
			
			if (expireTime == 0 || expireTime > validUntil) {
				expireTime = validUntil;
			}
		} catch (Exception e) {
			LOGGER.error("Error executing getExpireTime: " + e.getMessage(), e);
		}
		return expireTime;
	}
	
	/**
	 * Create string form time In Millis with format yyyy-MM-ddTHH:mm:ssZ
	 *
	 * @param timeInMillis
	 * 				The time in Millis
	 *
	 * @return string with format yyyy-MM-ddTHH:mm:ssZ
	 */
	public static String formatDateTime(long timeInMillis) {
		return DATE_TIME_FORMAT.print(timeInMillis);
	}

	/**
	 * Create string form time In Millis with format yyyy-MM-ddTHH:mm:ssZ
	 *
	 * @param time
	 * 			The time
	 * @param millis
	 * 			Defines if the time is in Millis
	 *
	 * @return string with format yyyy-MM-ddTHH:mm:ssZ
	 */
	public static String formatDateTime(long time, boolean millis) {
		if (millis) {
			return DATE_TIME_FORMAT_MILLS.print(time);
		} else {
			return formatDateTime(time);
		}
	}

	/**
	 * Create calendar form string with format yyyy-MM-ddTHH:mm:ssZ // yyyy-MM-ddTHH:mm:ss.SSSZ
	 *
	 * @param dateTime
	 * 				 string with format yyyy-MM-ddTHH:mm:ssZ // yyyy-MM-ddTHH:mm:ss.SSSZ
	 *
	 * @return datetime
	 */
	public static DateTime parseDateTime(String dateTime) {
		
		DateTime parsedData = null;
		try {
			parsedData = DATE_TIME_FORMAT.parseDateTime(dateTime);
		} catch(Exception e) {
			return DATE_TIME_FORMAT_MILLS.parseDateTime(dateTime);
		}
		return parsedData;
	}

	private static String toStringUtf8(byte[] bytes) {
		try {
			return new String(bytes, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	private static byte[] toBytesUtf8(String str) {
		try {
			return str.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	
}
