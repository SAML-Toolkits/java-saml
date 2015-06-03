package com.onelogin.saml;

import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import com.onelogin.Constants;


public class Utils {
	static final String ISO8601DATEFORMAT = "yyyy-MM-ddTHH:mm:ssZ"; //"yyyy-MM-dd'T'HH:mm:ssX"; // "yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'";
	private static final Logger log = LoggerFactory.getLogger(Utils.class);

	/**
	 * Extracts a node from the DOMDocument
	 * 
	 * @param dom The DOMDocument
	 * @param query Xpath Expresion
	 * @param context Context Node (DomElement)
	 * @return DOMNodeList The queried node
	 * @throws XPathExpressionException
	 */
	public static NodeList query(Document dom, String query, Node context)
			throws XPathExpressionException {
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
	 * Get Status from a Response
	 * 
	 * @param dom The Response as XML
	 * @return array with the code and a message
	 * @throws Error 
	 */
	public static Map<String, String> getStatus(Document dom) throws Error {
		Map<String, String> status = new HashMap<String, String>();

		try {
			NodeList statusEntry = query(dom, "/samlp:Response/samlp:Status",
					null);
			if (statusEntry.getLength() == 0) {
				throw new Error("Missing Status on response");
			}

			NodeList codeEntry = query(dom,
					"/samlp:Response/samlp:Status/samlp:StatusCode",
					(Element) statusEntry.item(0));
			if (codeEntry.getLength() == 0) {
				throw new Error("Missing Status Code on response");
			}
			status.put("code",
					codeEntry.item(0).getAttributes().getNamedItem("Value").getNodeValue());

			NodeList messageEntry = query(dom,
					"/samlp:Response/samlp:Status/samlp:StatusMessage",
					(Element) statusEntry.item(0));
			if (messageEntry.getLength() == 0) {
				status.put("msg", "");
			} else {
				status.put("msg", messageEntry.item(0).getNodeValue());
			}
		} catch (Error e) {
			log.error("Error executing getStatus: " + e.getMessage());
			throw e;
		} catch (Exception ex) {
			log.error("Error executing getStatus: " + ex.getMessage(), ex);
		}

		return status;
	}


	/**
	 * Load an XML string in a save way. Prevent XEE/XXE Attacks
	 * 
	
	 * @param string xml The XML string to be loaded.
	 *            
	 * @return The document where load the xml.
	 */
	public static Document loadXML(String xml) throws Exception {
		if (xml.contains("<!ENTITY")) {
			throw new Exception(
					"Detected use of ENTITY in XML, disabled to prevent XXE/XEE attacks");
		}

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);

		// Add various options explicitly to prevent XXE attacks. add try/catch around every
		// setAttribute just in case a specific parser does not support it.
		try {
			factory.setAttribute("http://xml.org/sax/features/external-general-entities",
					Boolean.FALSE);
		} catch (Throwable t) {  /* OK.  Not all parsers will support this attribute */}
		try {
			factory.setAttribute("http://xml.org/sax/features/external-parameter-entities",
					Boolean.FALSE);
		} catch (Throwable t) {  /* OK.  Not all parsers will support this attribute */}
		try {
			factory.setAttribute("http://apache.org/xml/features/disallow-doctype-decl",
					Boolean.TRUE);
		} catch (Throwable t) {  /* OK.  Not all parsers will support this attribute */}
		try {
			factory.setAttribute("http://javax.xml.XMLConstants/feature/secure-processing",
					Boolean.TRUE);
		} catch (Throwable t) {  /* OK.  Not all parsers will support this attribute */ }
		try {
			factory.setAttribute("http://apache.org/xml/features/nonvalidating/load-external-dtd",
					Boolean.FALSE);
		} catch (Throwable t) {  /* OK.  Not all parsers will support this attribute */}
		try {
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		} catch (Throwable t) {  /* OK.  Not all parsers will support this attribute */}

		DocumentBuilder builder;

		try {
			builder = factory.newDocumentBuilder();
			Document doc = builder.parse(new InputSource(new StringReader(xml)));
			// Loop through the doc and tag every element with an ID attribute as an XML ID node.
			XPath xpath = XPathFactory.newInstance().newXPath();
			XPathExpression expr = xpath.compile("//*[@ID]");
			NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			for (int i=0; i<nodeList.getLength() ; i++) {
				Element elem = (Element) nodeList.item(i);
				Attr attr = (Attr) elem.getAttributes().getNamedItem("ID");
				elem.setIdAttributeNode(attr, true);
			}
			return doc;
		} catch (Exception e) {
			log.error("Error executing loadXML: " + e.getMessage(), e);
		}
		return null;
	}

	/**
	 * This function attempts to validate an XML against the specified schema.
	 * 
	 * @param xml The XML document which should be validated
	 * @param schema The schema filename which should be used
	 * @throws Exception
	 */
	public static Document validateXML(Document xml, String schemaName)
			throws Exception {
		return validateXML(getStringFromDocument(xml), schemaName);
	}

	/**
	 * This function attempts to validate an XML string against the specified
	 * schema. It will parse the string into a DOM document and validate this
	 * document against the schema.
	 * 
	 * @param xml The XML document which should be validated
	 * @param schema The schema filename which should be used
	 * @throws Exception
	 */
	public static Document validateXML(String xmlString, String schemaName, Boolean...debugMode)
			throws Exception {

		try {
			String schemaFullPath = "schemas" + File.separatorChar + schemaName;
			log.debug("schemaFullPath: " +schemaFullPath);
			ClassLoader classLoader = Utils.class.getClassLoader();
			URL schemaFile = classLoader.getResource(schemaFullPath);
			SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			Schema schema = schemaFactory.newSchema(schemaFile);
			Validator validator = schema.newValidator();
			XMLErrorHandler errorHandler = new XMLErrorHandler();
			validator.setErrorHandler(errorHandler);
			validator.validate(new StreamSource(new StringReader(xmlString)));

			if (errorHandler.getErrorXML().size() > 0) {
				throw new Error("Invalid XML. See the log");
			}
		} catch (Error e) {
			throw e;
		} catch (Exception ex) {
			log.error("Error executing validateXML: " + ex.getMessage(), ex);
			throw ex;
		}
		return convertStringToDocument(xmlString);
	}

	/**
	 * Validate signature (Message or Assertion).
	 * 
	 * @param xml The element we should validate
	 * @param cert The pubic cert
	 * @param fingerprint The fingerprint of the public cert
	 * @return True if the sign is valid, false otherwise.
	 */
	public static boolean validateSign(Node signatureElement, Certificate cert, String ...fingerprint) 
			throws Exception{
		boolean res = false;
		DOMValidateContext ctx = new DOMValidateContext(cert.getPublicKey(), signatureElement);
		XMLSignatureFactory sigF = XMLSignatureFactory.getInstance("DOM");		
		try {
			XMLSignature xmlSignature = sigF.unmarshalXMLSignature(ctx);
			res = xmlSignature.validate(ctx);
		} catch (MarshalException e) {
			log.error("Cannot locate Signature Node " + e.getMessage(), e);
			throw e;
		}catch (NullPointerException e) {
			log.error("Context can't be validated", e);
			throw e;
		}		
		return res;
	}


	/**
	 * Function to load a String into a Document
	 * 
	 * @param xmlStr
	 * @return
	 */
	private static Document convertStringToDocument(String xmlStr) {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder;
		try {
			builder = factory.newDocumentBuilder();
			Document doc = builder.parse(new InputSource(new StringReader(xmlStr)));
			return doc;
		} catch (Exception ex) {
			log.error("Error executing convertStringToDocument: " + ex.getMessage(), ex);
		}
		return null;
	}

	/**
	 * Function to get a String from a Document
	 * 
	 * @param doc Document
	 * @return string
	 */
	public static String getStringFromDocument(Document doc)    {
		try
		{
			DOMSource domSource = new DOMSource(doc);
			StringWriter writer = new StringWriter();
			StreamResult result = new StreamResult(writer);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			transformer.transform(domSource, result);
			writer.flush();
			return writer.toString();
		}
		catch(TransformerException ex)
		{
			log.error("Error executing getStringFromDocument: " + ex.getMessage(), ex);
			return null;
		}
	}



}


class XMLErrorHandler extends DefaultHandler {

	private static final Logger log = LoggerFactory.getLogger(XMLErrorHandler.class);
	protected final static Marker FATAL = MarkerFactory.getMarker("FATAL");
	List<String> errorXML = new ArrayList<String>();

	@Override
	public void error(SAXParseException e) throws SAXException {
		errorXML.add("ERROR: " + (e.getMessage()));
		log.error("ERROR: " + (e.getMessage()));
	}

	@Override
	public void fatalError(SAXParseException e) throws SAXException {
		errorXML.add("FATALERROR: " + (e.getMessage()));
		log.error(FATAL, "FATALERROR: " + (e.getMessage()));
	}

	public List<String> getErrorXML() {
		return errorXML;
	}

	public void setErrorXML(List<String> errorXML) {
		this.errorXML = errorXML;
	}

	@Override
	public void warning(SAXParseException e) throws SAXException {
		errorXML.add("WARNING: " + (e.getMessage()));
		log.warn("WARNING: " + (e.getMessage()));
	}
}
