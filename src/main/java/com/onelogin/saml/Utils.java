package com.onelogin.saml;

import java.io.StringReader;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.onelogin.Constants;
import com.onelogin.Error;

public class Utils {
	static final String ISO8601DATEFORMAT = "yyyy-MM-ddTHH:mm:ssZ"; //"yyyy-MM-dd'T'HH:mm:ssX"; // "yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'";
	private static final Logger log = LoggerFactory.getLogger(Utils.class);
	
	/**
	 * Extracts a node from the DOMDocument
	 * 
	 * @param dom
	 *            The DOMDocument
	 * @param query
	 *            Xpath Expresion
	 * @param context
	 *            Context Node (DomElement)
	 * @return DOMNodeList The queried node
	 * @throws XPathExpressionException
	 */
	public static NodeList query(Document dom, String query, Element context)
			throws XPathExpressionException {
		NodeList nodeList;

		XPath xpath = XPathFactory.newInstance().newXPath();
		xpath.setNamespaceContext(new NamespaceContext() {

			public String getNamespaceURI(String prefix) {
				String result = null;
				if (prefix.equals("samlp"))
					result = Constants.NS_SAMLP;
				else if (prefix.equals("sml"))
					result = Constants.NS_SAML;
				else if (prefix.equals("ds"))
					result = Constants.NS_DS;
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
			nodeList = (NodeList) xpath.evaluate(query, dom,
					XPathConstants.NODESET);
		else
			nodeList = (NodeList) xpath.evaluate(query, context,
					XPathConstants.NODESET);
		return nodeList;
	}
	
	/**
	 * Get Status from a Response
	 * 
	 * @param dom
	 *            The Response as XML
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
					codeEntry.item(0).getAttributes().getNamedItem("Value")
							.getNodeValue());

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
	 * @param DOMDocument
	 *            $dom The document where load the xml.
	 * @param string
	 *            $xml The XML string to be loaded.
	 * 
	 * @throws DOMExceptions
	 * 
	 * @throws Exception
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
			e.printStackTrace();
		}
		return null;
	}

}
