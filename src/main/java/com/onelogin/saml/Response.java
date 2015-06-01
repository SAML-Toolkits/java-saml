package com.onelogin.saml;

import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.onelogin.AccountSettings;
import com.onelogin.Constants;
import com.onelogin.Error;

public class Response {

	/**
     * A DOMDocument class loaded from the SAML Response (Decrypted).
     */
	private Document document;
	
	private NodeList assertions;
	private Element rootElement;
	private final AccountSettings accountSettings;
	private final Certificate certificate;
	private String response;
	private String currentUrl;
	private StringBuffer error;
	
	private static final Logger log = LoggerFactory.getLogger(Response.class);

	public Response(AccountSettings accountSettings) throws CertificateException {
		error = new StringBuffer();
		this.accountSettings = accountSettings;		
		certificate = new Certificate();
		certificate.loadCertificate(this.accountSettings.getCertificate());
	}
	
	public Response(AccountSettings accountSettings, String response) throws Exception {
		this(accountSettings);		
		loadXmlFromBase64(response);
	}

	public void loadXmlFromBase64(String responseStr) throws Exception {
		Base64 base64 = new Base64();
		byte[] decodedB = base64.decode(responseStr);
		this.response = new String(decodedB);
		this.document = Utils.loadXML(this.response);
		if(this.document == null){
			
		}
	}

	// isValid() function should be called to make basic security checks to responses.
	public boolean isValid(String... requestId){
		try{
			
			// Security Checks
			rootElement = document.getDocumentElement();
			rootElement.normalize();
			assertions = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");		
			
			
			// Check SAML version			
			if (!rootElement.getAttribute("Version").equals("2.0")) {
				throw new Exception("Unsupported SAML Version.");
			}
			
			// Check ID in the response	
			if (!rootElement.hasAttribute("ID")) {
				throw new Exception("Missing ID attribute on SAML Response.");
			}
			
			checkStatus();
						
			if (!this.validateNumAssertions()) {
				throw new Exception("SAML Response must contain 1 Assertion.");
			}
	
			NodeList nodes = document.getElementsByTagName("Signature");
			ArrayList<String> signedElements = new ArrayList<String>();
			for (int i = 0; i < nodes.getLength(); i++) {
				signedElements.add(nodes.item(i).getParentNode().getLocalName());
			}
			if (!signedElements.isEmpty()) {
				if(!this.validateSignedElements(signedElements)){
					throw new Exception("Found an unexpected Signature Element. SAML Response rejected");
				}
			}
			
			Document res = Utils.validateXML(this.document, "saml-schema-protocol-2.0.xsd");
			
			if(!(res instanceof Document)){
				throw new Exception("Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd");
			}
			
			if (rootElement.hasAttribute("InResponseTo")) {
				String responseInResponseTo = document.getDocumentElement().getAttribute("InResponseTo");
				if(requestId.length > 0 && responseInResponseTo.compareTo(requestId[0]) != 0){
					throw new Exception("The InResponseTo of the Response: "+ responseInResponseTo + ", does not match the ID of the AuthNRequest sent by the SP: "+ requestId[0]);
				}
            }
			
			// Validate Asserion timestamps
            if (!this.validateTimestamps()) {
                throw new Exception("Timing issues (please check your clock settings)");
            }
			
			// ------------ working validations until here!
            //TODO: more validations
	
			// Check destination
			String destinationUrl = rootElement.getAttribute("Destination");
			if (destinationUrl != null) {
				if(!destinationUrl.equals(currentUrl)){
					throw new Exception("The response was received at " + currentUrl + " instead of " + destinationUrl);
				}
			}
			
			// Check Audience 
			NodeList nodeAudience = document.getElementsByTagNameNS("*", "Audience");
			String audienceUrl = nodeAudience.item(0).getChildNodes().item(0).getNodeValue();
			if (audienceUrl != null) {
				if(!audienceUrl.equals(currentUrl)){
					throw new Exception(audienceUrl + " is not a valid audience for this Response");
				}
			}
			
			// Check SubjectConfirmation, at least one SubjectConfirmation must be valid
			NodeList nodeSubConf = document.getElementsByTagNameNS("*", "SubjectConfirmation");
			boolean validSubjectConfirmation = true;
			for(int i = 0; i < nodeSubConf.getLength(); i++){
				Node method = nodeSubConf.item(i).getAttributes().getNamedItem("Method");			
				if(method != null && !method.getNodeValue().equals("urn:oasis:names:tc:SAML:2.0:cm:bearer")){
					continue;
				}
				NodeList childs = nodeSubConf.item(i).getChildNodes();			
				for(int c = 0; c < childs.getLength(); c++){				
					if(childs.item(c).getLocalName().equals("SubjectConfirmationData")){
						
						Node recipient = childs.item(c).getAttributes().getNamedItem("Recipient");					
						if(recipient != null && !recipient.getNodeValue().equals(currentUrl)){
							validSubjectConfirmation = false;
						}
						
					}
				}
			}
			if (!validSubjectConfirmation) {
	            throw new Exception("A valid SubjectConfirmation was not found on this Response");
	        }
			
			
	//		if (setIdAttributeExists()) {
	//			tagIdAttributes(xmlDoc);
	//		}
	
			X509Certificate cert = certificate.getX509Cert();		
			DOMValidateContext ctx = new DOMValidateContext(cert.getPublicKey(), nodes.item(0));		
			XMLSignatureFactory sigF = XMLSignatureFactory.getInstance("DOM");		
			XMLSignature xmlSignature = sigF.unmarshalXMLSignature(ctx);		
	
			return xmlSignature.validate(ctx);
		}catch (Error e) {
			error.append(e.getMessage());
			return false;
		}catch(Exception e){
			e.printStackTrace();
		    error.append(e.getMessage());
			return false;
		}
	}

	public String getNameId() throws Exception {
		NodeList nodes = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID");
		if (nodes.getLength() == 0) {
			throw new Exception("No name id found in Document.");
		}
		return nodes.item(0).getTextContent();
	}

	public String getAttribute(String name) {
		HashMap attributes = getAttributes();
		if (!attributes.isEmpty()) {
			return attributes.get(name).toString();
		}
		return null;
	}

	public HashMap getAttributes() {
		HashMap<String, ArrayList> attributes = new HashMap<String, ArrayList>();
		NodeList nodes = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute");

		if (nodes.getLength() != 0) {
			for (int i = 0; i < nodes.getLength(); i++) {
				NamedNodeMap attrName = nodes.item(i).getAttributes();
				String attName = attrName.getNamedItem("Name").getNodeValue();
				NodeList children = nodes.item(i).getChildNodes();

				ArrayList<String> attrValues = new ArrayList<String>();
				for (int j = 0; j < children.getLength(); j++) {
					attrValues.add(children.item(j).getTextContent());
				}
				attributes.put(attName, attrValues);
			}
		} else {
			return null;
		}
		return attributes;
	}
	
	/**
     * Checks if the Status is success
	 * @throws Exception 
	 * @throws $statusExceptionMsg If status is not success
     */
	public Map<String, String>  checkStatus() throws Exception{
		Map<String, String> status = Utils.getStatus(document);
		if(status.containsKey("code") && !status.get("code").equals(Constants.STATUS_SUCCESS) ){
			String statusExceptionMsg = "The status code of the Response was not Success, was " + 
					status.get("code").substring(status.get("code").lastIndexOf(':') + 1);
			if(status.containsKey("msg")){
				statusExceptionMsg += " -> " + status.containsKey("msg");
			}
			throw new Exception(statusExceptionMsg);
		}

		return status;
		
	}
	
	/**
     * Verifies that the document only contains a single Assertion (encrypted or not).
     *
     * @return true if the document passes.
     */
	public boolean validateNumAssertions(){
		NodeList assertionNodes = this.document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
		if(assertionNodes != null && assertionNodes.getLength() == 1)
			return true;
		return false;
	}
	
	/**
     * Verifies that the document has the expected signed nodes.
     *
     * @return true if is valid
     */
	public boolean validateSignedElements(ArrayList<String> signedElements){
		if(signedElements.size() > 2){
			return false;
		}
		Map<String, Integer> occurrences = new HashMap<String, Integer>();
		for(String e:signedElements){
			if(occurrences.containsKey(e)){
				occurrences.put(e, occurrences.get(e).intValue() + 1);
			}else{
				occurrences.put(e, 1);
			}
		}
		
		if((occurrences.containsKey("Response") && occurrences.get("Response") > 1) ||
		  (occurrences.containsKey("Assertion") && occurrences.get("Assertion") > 1) ||
          !occurrences.containsKey("Response") && !occurrences.containsKey("Assertion")
      ) {
          return false;
      }
      return true;
	}
	
	/**
     * Verifies that the document is still valid according Conditions Element.
     *
     * @return true if still valid
     */
    public boolean validateTimestamps()
    {
    	NodeList timestampNodes = document.getElementsByTagNameNS("*", "Conditions");
    	if (timestampNodes.getLength() != 0) {
			for (int i = 0; i < timestampNodes.getLength(); i++) {
				NamedNodeMap attrName = timestampNodes.item(i).getAttributes();
				Node nbAttribute = attrName.getNamedItem("NotBefore");
				Node naAttribute = attrName.getNamedItem("NotOnOrAfter");
				Calendar now = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
				log.debug("now :"+ now.get(Calendar.HOUR_OF_DAY) + ":" + now.get(Calendar.MINUTE)+ ":" + now.get(Calendar.SECOND));
				// validate NotOnOrAfter using UTC
				if(naAttribute != null){						
					final Calendar notOnOrAfterDate = javax.xml.bind.DatatypeConverter.parseDateTime(naAttribute.getNodeValue());
					log.debug("notOnOrAfterDate :"+ notOnOrAfterDate.get(Calendar.HOUR_OF_DAY) + ":" + notOnOrAfterDate.get(Calendar.MINUTE)+ ":" + notOnOrAfterDate.get(Calendar.SECOND));
					if(now.equals(notOnOrAfterDate) || now.after(notOnOrAfterDate)){
						return false;
					}
				}
				// validate NotBefore using UTC
				if(nbAttribute != null){						
					final Calendar notBeforeDate = javax.xml.bind.DatatypeConverter.parseDateTime(nbAttribute.getNodeValue());
					log.debug("notBeforeDate :"+ notBeforeDate.get(Calendar.HOUR_OF_DAY) + ":" + notBeforeDate.get(Calendar.MINUTE)+ ":" + notBeforeDate.get(Calendar.SECOND));
					if(now.before(notBeforeDate)){
						return false;
					}
				}
			}
		}
        return true;
    }

	

	private boolean setIdAttributeExists() {
		for (Method method : Element.class.getDeclaredMethods()) {
			if (method.getName().equals("setIdAttribute")) {
				return true;
			}
		}
		return false;
	}

	private void tagIdAttributes(Document xmlDoc) {
		throw new UnsupportedOperationException("Not supported yet."); 
	}

	public void setDestinationUrl(String urld){
		currentUrl = urld;
	}
	
	public String getError() {
		if(error!=null)
			return error.toString();
		return "";
	}
	
	
}
