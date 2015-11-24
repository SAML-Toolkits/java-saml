package com.onelogin.saml2.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Key;
import java.security.PrivateKey;
//import java.security.Provider;
//import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
//import javax.xml.crypto.dsig.dom.DOMValidateContext;
//import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import javax.xml.XMLConstants;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.joda.time.DateTime;
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
import org.xml.sax.SAXParseException;

import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.settings.SettingsBuilder;

/**
 * Util class of OneLogin's Java Toolkit.
 *
 * A class that contains several auxiliary methods related to the SAML protocol
 */ 
public abstract class Util {
	/**
     * Private property to construct a logger for this class.
     */
	private static final Logger LOGGER = LoggerFactory.getLogger(Util.class);
	
	private static final DateTimeFormatter DATE_TIME_FORMAT = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");
    private static final String DURATION_REG_EX = "#^(-?)P(?:(?:(?:(\\d+)Y)?(?:(\\d+)M)?(?:(\\d+)D)?(?:T(?:(\\d+)H)?(?:(\\d+)M)?(?:(\\d+)S)?)?)|(?:(\\d+)W))$#D";

	/**
	 * This function load an XML string in a save way. Prevent XEE/XXE Attacks
	 *
	 * @param xml
	 * 				The XML string to be loaded.
	 *
	 * @return The result of load the XML at the Document or null if any error occurs
	 *
     *
	 * @throws XMLEntityException
	 */
	public static Document loadXML(String xml) throws XMLEntityException {
		try {
			if (xml.contains("<!ENTITY")) {
				throw new XMLEntityException("Detected use of ENTITY in XML, disabled to prevent XXE/XEE attacks");
			}

			return convertStringToDocument(xml);
		} catch (ParserConfigurationException e) {
			LOGGER.debug("Load XML error due ParserConfigurationException.", e);
		} catch (SAXParseException e) {
			LOGGER.debug("Load XML error due SAXParseException.", e);		
		} catch (SAXException e) {
			LOGGER.debug("Load XML error due SAXException.", e);
		} catch (IOException e) {
			LOGGER.debug("Load XML error due IOException.", e);
		} catch (XMLEntityException e) {
			LOGGER.debug("Load XML error due XMLEntityException.", e);
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

			public String getNamespaceURI(String prefix) {
				String result = null;
				if (prefix.equals("samlp") || prefix.equals("samlp2"))
					result = Constants.NS_SAMLP;
				else if (prefix.equals("saml") || prefix.equals("saml2"))
					result = Constants.NS_SAML;
				else if (prefix.equals("ds"))
					result = Constants.NS_DS;
				else if (prefix.equals("xenc"))
					result = Constants.NS_XENC;
				return result;
			}

			public String getPrefix(String namespaceURI) {
				return null;
			}

			@SuppressWarnings("rawtypes")
			public Iterator getPrefixes(String namespaceURI) {
				return null;
			}
		});

		if (context == null)
			nodeList = (NodeList) xpath.evaluate(query, dom, XPathConstants.NODESET);
		else
			nodeList = (NodeList) xpath.evaluate(query, context, XPathConstants.NODESET);
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
	 *
	 * @throws Exception
	 */
	public static boolean validateXML(Document xmlDocument, URL schemaUrl) throws Exception {
		try {

			if (xmlDocument == null) {
				throw new IllegalArgumentException("xmlDocument was null");
			}

			Schema schema = SchemaFactory.loadFromUrl(schemaUrl);
			Validator validator = schema.newValidator();

			XMLErrorAccumulatorHandler errorAcumulator = new XMLErrorAccumulatorHandler();
			validator.setErrorHandler(errorAcumulator);

			Source xmlSource = new DOMSource(xmlDocument);
			validator.validate(xmlSource);

			return !errorAcumulator.hasError();
		} catch (Exception e) {
			LOGGER.debug("Error executing validateXML: " + e.getMessage(), e);
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
		} catch (Throwable t) {}
		try {
			// do not include external parameter entities or the external DTD subset
			docfactory.setAttribute("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
		} catch (Throwable t) {}
		try {
			docfactory.setAttribute("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
		} catch (Throwable t) {}
		try {
			docfactory.setAttribute("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);
		} catch (Throwable t) {}
		try {
			// ignore the external DTD completely
			docfactory.setAttribute("http://apache.org/xml/features/nonvalidating/load-external-dtd", Boolean.FALSE);
		} catch (Throwable t) {}
		try {
			// build the grammar but do not use the default attributes and attribute types information it contains
			docfactory.setAttribute("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", Boolean.FALSE);
		} catch (Throwable t) {}
		try {
			docfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		} catch (Throwable t) {}

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
			LOGGER.error("Error executing loadXML: " + e.getMessage(), e);
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
		return baos.toString();
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
	 * Returns a certificate in String format (adding header & footer if required)
	 *
	 * @param cert
	 * 				A x509 unformatted cert
	 * @param heads
	 *              True if we want to include head and footer
	 *
	 * @return X509Certificate $x509 Formated cert
	 *
	 * @throws CertificateException
	 */
	private static String formatCert(String cert, Boolean heads) {
		String x509cert = StringUtils.EMPTY;

		x509cert = cert.replace("\\x0D", "").replace("\r", "").replace("\n", "").replace(" ", "");
		if (!(StringUtils.isEmpty(x509cert) && x509cert != null)) {
			x509cert = x509cert.replace("-----BEGINCERTIFICATE-----", "").replace("-----ENDCERTIFICATE-----", "");
		}

		if (heads) {
			x509cert = "-----BEGIN CERTIFICATE-----\n" + chunkString(x509cert, 64) + "\n-----END CERTIFICATE-----";
		}

		return x509cert;
	}

	/**
	 * Returns a private key (adding header & footer if required).
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

		xKey = key.replace("\\x0D", "").replace("\r", "").replace("\n", "").replace(" ", "");

		if (!(StringUtils.isEmpty(xKey) && xKey != null)) {
			if (xKey.startsWith("-----BEGINPRIVATEKEY-----")) {
				xKey = xKey.replace("-----BEGINPRIVATEKEY-----", "").replace("-----ENDPRIVATEKEY-----", "");

				if (heads) {
					xKey = "-----BEGIN PRIVATE KEY-----\n" + chunkString(xKey, 64) + "\n-----END PRIVATE KEY-----";
				}
			} else if (xKey.startsWith("-----BEGINRSAPRIVATEKEY-----")) {

				xKey = xKey.replace("-----BEGINRSAPRIVATEKEY-----", "").replace("-----ENDRSAPRIVATEKEY-----", "");

				if (heads) {
					xKey = "-----BEGIN RSA PRIVATE KEY-----\n" + chunkString(xKey, 64) + "\n-----END RSA PRIVATE KEY-----";
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
	 * @throws UnsupportedEncodingException
	 */
	public static X509Certificate loadCert(String certString) throws CertificateException, UnsupportedEncodingException {
		certString = formatCert(certString, true);
		X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
				new ByteArrayInputStream(certString.getBytes("utf-8")));
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
	 * @throws IOException 
	 */
	public static PrivateKey loadPrivateKey(String keyString) throws GeneralSecurityException, IOException {
		org.apache.xml.security.Init.init();

		/*
		Security.addProvider(
		         new org.bouncycastle.jce.provider.BouncyCastleProvider()
		);
		*/

		keyString = formatPrivateKey(keyString, false);
		keyString = chunkString(keyString, 64);
		byte[] encoded = Base64.decodeBase64(keyString);
		KeyFactory kf = KeyFactory.getInstance("RSA");
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
	    PrivateKey privKey = (PrivateKey) kf.generatePrivate(keySpec);

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
		String data = StringUtils.EMPTY;
		String decodedString = StringUtils.EMPTY;

		if (alg == null || alg.isEmpty()) {
			alg = "SHA-1";
		}

		try {
			String pemString = convertToPem(x509cert);
			List<String> lines = Arrays.asList(pemString.split("\n"));
			for (String line : lines) {
				// Remove '\r' from end of line if present.
				line.trim();
				if (line == "-----BEGIN CERTIFICATE-----") {
					// Delete junk from before the certificate.
					data = StringUtils.EMPTY;
				} else if (line == "-----END CERTIFICATE-----") {
					// Ignore data after the certificate.
					break;
				} else if ((line == "-----BEGIN PUBLIC KEY-----")
						|| (line == "-----BEGIN RSA PRIVATE KEY-----")) {
					// This isn't an X509 certificate.
					return null;
				} else {
					// Append the current line to the certificate data
					data += line;
				}
			}
			byte[] dataBytes = data.getBytes("UTF8");
			MessageDigest crypt = MessageDigest.getInstance("SHA-1");
			crypt.reset();
			crypt.update(dataBytes);
			decodedString = new String(crypt.digest());
		} catch (Exception e) {
			LOGGER.debug("Error executing calculateX509Fingerprint: "+ e.getMessage(), e);
		}
		return decodedString.toLowerCase();
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
	private static String convertToPem(X509Certificate certificate) {
		String pemCert = "";
		try {
			Base64 encoder = new Base64(64);
			String cert_begin = "-----BEGIN CERTIFICATE-----\n";
			String end_cert = "-----END CERTIFICATE-----";

			byte[] derCert = certificate.getEncoded();
			String pemCertPre = new String(encoder.encode(derCert));
			pemCert = cert_begin + pemCertPre + end_cert;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return pemCert;
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
	 */
	public static String addSign(Document document, PrivateKey key, X509Certificate certificate, String signAlgorithm) {
		try {
			org.apache.xml.security.Init.init();

			// Check arguments.
			if (document == null)
				throw new IllegalArgumentException("document");

			if (document.getDocumentElement() == null)
				throw new Exception("The Xml Document has no root element.");

			if (key == null)
				throw new IllegalArgumentException("Key");

			if (signAlgorithm == null || signAlgorithm.isEmpty()) {
				signAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			}
			signAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;

			// document.normalizeDocument();

			String c14nMethod = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

			// Signature object
			XMLSignature sig = new XMLSignature(document, null, signAlgorithm, c14nMethod);

			// Including the signature into the document before sign, because
			// this is an envelop signature
			Element root = document.getDocumentElement();
			document.setXmlStandalone(false);
			root.insertBefore(sig.getElement(), root.getFirstChild());

			String reference = root.getAttribute("ID");
			if (!reference.isEmpty()) {
				reference = "#" + reference; 
			}

			// Create the transform for the document
			Transforms transforms = new Transforms(document);
			transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
			//transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
			transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
			sig.addDocument(reference, transforms,
					org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);

			// Add the certification info
			sig.addKeyInfo(certificate);			
			// sig.addKeyInfo(certificate.getPublicKey());

			// Sign the document
			sig.sign(key);

		} catch (Exception e) {
			LOGGER.debug("Error executing addSign: " + e.getMessage(), e);
		}

		return convertDocumentToString(document, true);
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
		org.apache.xml.security.Init.init();

		// Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		// Security.addProvider(provider);

		String convertedSigAlg = signatureAlgConversion(signAlg);

		Signature sig = Signature.getInstance(convertedSigAlg); //, provider);
		sig.initVerify(cert.getPublicKey());
		sig.update(signedQuery.getBytes());
		return sig.verify(signature);
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
			nameId.setAttribute("SPNameQualifier", spnq);
			nameId.setAttribute("Format", format);
			nameId.appendChild(doc.createTextNode(value));
			doc.appendChild(nameId);

			if (cert != null) {
				// We generate a symmetric key
				Key symmetricKey = GenerateSymmetricKey();

				// cipher for encrypt the data
				XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
				xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

				// cipher for encrypt the symmetric key
				XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
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
	 * Method to generate a symmetric key for encryption
	 * 
	 * @return the symmetric key
	 *
	 * @throws Exception
	 */
	private static SecretKey GenerateSymmetricKey() throws Exception {
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
		String uniqueIdSha1 = StringUtils.EMPTY;
		String uniqueId = StringUtils.EMPTY;

		try {
			Random r = new Random();
			Integer n = r.nextInt();

			String id = uniqid(n.toString(), true);

			MessageDigest crypt = MessageDigest.getInstance("SHA-1");
			crypt.reset();
			crypt.update(id.getBytes());
			uniqueIdSha1 = new BigInteger(1, crypt.digest()).toString(16);

			uniqueId = "ONELOGIN_" + uniqueIdSha1;
		} catch (Exception e) {
			LOGGER.error("Error executing generateUniqueID: " + e.getMessage(), e);
		}
		return uniqueId;
	}	

	/**
	 * Generates random UUID
	 * 
	 * @param prefix
	 *
	 * @param more_entropy
	 * 
	 * @return the random UUID
	 */
	public static String uniqid(String prefix, Boolean more_entropy) {
		if (prefix != null && StringUtils.isEmpty(prefix))
			prefix = StringUtils.EMPTY;

		if (!more_entropy) {
			return (String) (prefix + UUID.randomUUID().toString()).substring(
					0, 13);
		} else {
			return (String) (prefix + UUID.randomUUID().toString() + UUID
					.randomUUID().toString()).substring(0, 23);
		}
	}	

	/**
	 * Redirect to location url
	 * 
	 * @param response
	 * 				HttpServletResponse object to be used
	 * @param location
	 * 				target location url
	 * @param parameters
	 * 				GET parameters to be added
	 *
	 * @throws IOException
	 *
	 * @see javax.servlet.http.HttpServletResponse#sendRedirect(String)
	 */
	public static void sendRedirect(HttpServletResponse response, String location, Map<String, String> parameters) throws IOException {
		String target = location;

		if (!parameters.isEmpty()) {
			Boolean first = true;
			for (Map.Entry<String, String> parameter : parameters.entrySet())
			{
				if (first) {
					target += "?";
					first = false;
				} else {
					target += "&";
				}
				target += parameter.getKey() + "=" + Util.urlEncoder(parameter.getValue());
			}
		}

		response.sendRedirect(target);
	}

	/**
	 * Returns the protocol + the current host + the port (if different than
	 * common ports).
	 *
	 * @param request 
	 * 				HttpServletRequest object to be processed
	 *
	 * @return the HOST URL
	 */
	public static String getSelfURLhost(HttpServletRequest request) {
		String hostUrl = StringUtils.EMPTY;
		final int serverPort = request.getServerPort();
		if ((serverPort == 80) || (serverPort == 443)) {
			hostUrl = String.format("%s://%s", request.getScheme(), request.getServerName());
		} else {
			hostUrl = String.format("%s://%s:%s", request.getScheme(), request.getServerName(), serverPort);
		}
		return hostUrl;
	}

	/**
	 * @param request 
	 * 				HttpServletRequest object to be processed
	 *
	 * @return the server name
	 */
	public static String getSelfHost(HttpServletRequest request) {
		return request.getServerName();
	}

	/**
	 * Check if under https or http protocol
	 *
	 * @param request
	 * 				HttpServletRequest object to be processed
	 *
	 * @return false if https is not active
	 */
	public static boolean isHTTPS(HttpServletRequest request) {
		return request.isSecure();
	}

	/**
	 * Returns the URL of the current context + current view + query
	 * 
	 * @param request
	 * 				HttpServletRequest object to be processed
	 *
	 * @return current context + current view + query
	 */
	public static String getSelfURL(HttpServletRequest request) {
		return request.getRequestURI() + '?' + request.getQueryString();
	}

	/**
	 * Returns the URL of the current host + current view.
	 *
	 * @param request
	 * 				HttpServletRequest object to be processed
	 *
	 * @return current host + current view
	 */
	public static String getSelfURLNoQuery(HttpServletRequest request) {
		return getSelfURLhost(request) + request.getRequestURL().toString();
	}

	/**
	 * Returns the routed URL of the current host + current view.
	 *
	 * @param request
	 * 				HttpServletRequest object to be processed
	 *
	 * @return the current routed url
	 */
	public static String getSelfRoutedURLNoQuery(HttpServletRequest request) {
		return getSelfURLhost(request) + request.getRequestURI().toString();
	}

	/**
	 * Loads a resource
	 *
	 * @param path
	 *				Path of the resource
	 *
	 * @return the loaded resource
	 *
	 * @throws URISyntaxException
	 * @throws FileNotFoundException
	 */
	public static Path loadResource(String path) throws URISyntaxException, FileNotFoundException {
		URL myTestURL = ClassLoader.getSystemResource(path);
		if (myTestURL == null) {
			throw new FileNotFoundException(path);
		}
		return Paths.get(myTestURL.toURI());
	}

	/**
	 * Loads a resource located at a relative path
	 *
	 * @param relativeResourcePath
	 *				Relative path of the resource
	 *
	 * @return the loaded resource in String format
	 *
	 * @throws URISyntaxException
	 * @throws IOException 
	 */
	public static String getFileAsString(String relativeResourcePath) throws URISyntaxException, IOException {
		Path filepath = loadResource(relativeResourcePath);
		String fileAsString = new String(Files.readAllBytes(filepath));
		return fileAsString;
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
		// Base64 decoder
		byte[] decoded = Base64.decodeBase64(input);
		
		// Inflater
		try {
			Inflater decompresser = new Inflater(true);
		    decompresser.setInput(decoded);
		    byte[] result = new byte[2048];
		    int resultLength = decompresser.inflate(result);
		    decompresser.end();

		    String inflated =  new String(result, 0, resultLength, "UTF-8");
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
	 */
	public static String deflatedBase64encoded(String input) {
		try {
			// Deflater
			ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
			Deflater deflater = new Deflater(Deflater.DEFLATED, true);
			DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
			deflaterStream.write(input.getBytes(Charset.forName("UTF-8")));
			deflaterStream.finish();
			// Base64 encoder
			return new String(Base64.encodeBase64(bytesOut.toByteArray()));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
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
		return new String(Base64.encodeBase64(input));
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
		return base64encoder(input.getBytes());
	}

	/**
	 * Returns String base64 decoded
	 *
	 * @param input
	 * 				 Stream input
	 *
	 * @return the base64 decoded string
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
	 * @return the base64 decoded string
	 */
	public static byte[] base64decoder(String input) {		
		return base64decoder(input.getBytes());
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

		if (sign.equals(Constants.DSA_SHA1)) {
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
	 * Validate signature (Message or Assertion).
	 *
	 * @param doc
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
	public static Boolean validateSign(Document doc, X509Certificate cert, String fingerprint, String alg) {
		Boolean res = false;
		try {
			org.apache.xml.security.Init.init();

			NodeList signNodesToValidate = query(doc, "//ds:Signature", null);

			// Validate the first signature
			Node sigNode = signNodesToValidate.item(0);

			// Check if Reference URI is empty
			NodeList referenceNodes = query(doc, "//ds:Reference", sigNode);
			if (referenceNodes.getLength() > 0) {
				Element refEl = (Element) referenceNodes.item(0);
				if (refEl.hasAttribute("URI") && refEl.getAttribute("URI") == "") {
					Element parent = (Element) referenceNodes.item(0).getParentNode();
					refEl.setAttribute("URI", "#" + parent.getAttribute("ID"));
				}
			}			

			Element sigElement = (Element) sigNode;
			XMLSignature signature = new XMLSignature(sigElement, "");

			if (cert != null) {
				res = signature.checkSignatureValue(cert);

				/*
					// Another alternative
					
					DOMValidateContext ctx = new DOMValidateContext(cert.getPublicKey(), sigNode);
	
					// Workaound http://stackoverflow.com/questions/22196091/javax-xml-crypto-urireferenceexception-cannot-resolve-element-with-id-saml
					NodeList idAttributes = (NodeList) query(doc, "//*[@ID]", null);
					for (int i = 0; i < idAttributes.getLength(); i++) {
					    ctx.setIdAttributeNS((Element) idAttributes.item(i), null, "ID");
					}
					
					XMLSignatureFactory sigF = XMLSignatureFactory.getInstance("DOM"); 
					
					javax.xml.crypto.dsig.XMLSignature xmlSignature = sigF.unmarshalXMLSignature(ctx);
					res = xmlSignature.validate(ctx);
				 */			 
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
			LOGGER.debug("Error executing validateSign: " + e.getMessage(), e);
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
			xmlCipher.setKEK(inputKey);
			xmlCipher.doFinal(encryptedDataElement.getOwnerDocument(), encryptedDataElement, false);
		} catch (Exception e) {
			LOGGER.debug("Error executing decryption: " + e.getMessage(), e);
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
	 * Interprets a ISO8601 duration value relative to a current time timestamp.
	 * parseDuration(duration,Calendar.getInstance());
	 *
	 * @param duration
	 *            The duration, as a string.
	 *
	 * @return int The new timestamp, after the duration is applied.
	 *
	 * @throws IllegalArgumentException
	 */
	public static long parseDuration(String duration) throws IllegalArgumentException {
		return parseDuration(duration, Calendar.getInstance().getTimeInMillis() / 1000);
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
	
		if (durationString.matches(DURATION_REG_EX)) {
			throw new IllegalArgumentException("Invalid ISO 8601 duration: " + durationString);
		}
		boolean haveMinus = false;
	
		if (durationString.startsWith("-")) {
			durationString = durationString.substring(1);
			haveMinus = true;
		}
	
		PeriodFormatter periodFormatter = ISOPeriodFormat.standard();
		Period period = periodFormatter.parsePeriod(durationString);
		DateTime dt = new DateTime(timestamp * 1000);
	
		DateTime result = null;
		if (haveMinus) {
			result = dt.minus(period);
		} else {
			result = dt.plus(period);
		}
		return result.toGregorianCalendar().getTimeInMillis() / 1000;
	}
	  
	/**
	 * @return the unix timestamp that matches the current time.
	 */
	public static Long getCurrentTimeStamp() {
		Date currentDate = new Date();
		return currentDate.getTime() / 1000;
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
				long validUntilTimeInt = DATE_TIME_FORMAT.parseDateTime(validUntil).getMillis() / 1000 ;
				if (expireTime > validUntilTimeInt) {
					expireTime = validUntilTimeInt;
				}
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
	 *
	 * @return string with format yyyy-MM-ddTHH:mm:ssZ
	 */
	public static String formatDateTime(long timeInMillis) {
		return DATE_TIME_FORMAT.print(timeInMillis);
	}

	/**
	 * Create calendar form string with format yyyy-MM-ddTHH:mm:ssZ
	 *
	 * @param dateTime
	 * 				 string with format yyyy-MM-ddTHH:mm:ssZ
	 *
	 * @return calendar
	 */
	public static Calendar parseDateTime(String dateTime) {
		return DATE_TIME_FORMAT.parseDateTime(dateTime).toGregorianCalendar();
	}

}