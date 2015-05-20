package com.onelogin.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;

import javax.xml.parsers.ParserConfigurationException;

import org.junit.Test;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;


public class UtilsTest {

	
	/**
     * Tests the loadXML method of the com.onelogin.saml.Utils
     *
     * @covers Utils.loadXML
     */
	 @Test
     public void testXMLAttacks()
     {
     	try{

         String attackXXE = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>" +
                       "<!DOCTYPE foo [" + 
                       "<!ELEMENT foo ANY >" +
                       "<!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>";
         try {
             Utils.loadXML(attackXXE);
             assertTrue(false);
         } catch (Exception e) {
             assertEquals("Detected use of ENTITY in XML, disabled to prevent XXE/XEE attacks", e.getMessage());
         }

         String xmlWithDTD = "<?xml version=\"1.0\"?>" +
                           "<!DOCTYPE results [" +
                             "<!ELEMENT results (result+)>" +
                             "<!ELEMENT result (#PCDATA)>" +
                           "]>" +
                           "<results>" +
                             "<result>test</result>" +
                           "</results>";
         
    	 Document res2 =Utils.loadXML(xmlWithDTD);
         assertNull(res2);
        

         String attackXEE = "<?xml version=\"1.0\"?>" +
                       "<!DOCTYPE results [<!ENTITY harmless \"completely harmless\">]>" +
                       "<results>" +
                         "<result>This result is &harmless;</result>" +
                       "</results>";
         try {
             Utils.loadXML(attackXEE);
             assertTrue(false);
         } catch (Exception e) {
             assertEquals("Detected use of ENTITY in XML, disabled to prevent XXE/XEE attacks", e.getMessage());
         }
     	}catch(DOMException e){
         	e.printStackTrace();
         	assertTrue(false);
         } catch (ParserConfigurationException e) {
				e.printStackTrace();
				assertTrue(false);
			} catch (Exception e) {
				e.printStackTrace();
			}
     }
	 
	 /**
      * Tests the loadXML method of the com.onelogin.saml.Utils
      *
      * @covers Utils.loadXML
      */
	 @Test
      public void testLoadXML()
      {
          try{
      	
          String metadataUnloaded = "<xml><EntityDescriptor>";
          boolean xmlvalidation = Utils.loadXML(metadataUnloaded) instanceof Document;
          assertFalse(xmlvalidation);

          String metadataInvalid = getFile("metadata/noentity_metadata_settings1.xml");
          xmlvalidation = Utils.loadXML(metadataInvalid) instanceof Document;
          assertTrue(xmlvalidation);

          String metadataOk = getFile("metadata/metadata_settings1.xml");
          xmlvalidation = Utils.loadXML(metadataOk) instanceof Document;
          assertTrue(xmlvalidation);
          
          String samlResponse = getFile("responses/open_saml_response.xml");
          xmlvalidation = Utils.loadXML(samlResponse) instanceof Document;
          assertTrue(xmlvalidation);
          
          }catch(DOMException e){
          	e.printStackTrace();
          	assertTrue(false);
          } catch (ParserConfigurationException e) {
				e.printStackTrace();
				assertTrue(false);
			} catch (Exception e) {
				e.printStackTrace();
				assertTrue(false);
			}
      }

	 private String getFile(String fileName) {
    	 
     	StringBuilder result = new StringBuilder("");
      
     	//Get file from resources folder
     	ClassLoader classLoader = getClass().getClassLoader();
     	File file = new File(classLoader.getResource(fileName).getFile());
      
     	try (Scanner scanner = new Scanner(file)) {
      
     		while (scanner.hasNextLine()) {
     			String line = scanner.nextLine();
     			result.append(line).append("\n");
     		}
      
     		scanner.close();
      
     	} catch (IOException e) {
     		e.printStackTrace();
     	}
      
     	return result.toString();
      
       }

}
