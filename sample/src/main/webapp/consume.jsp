<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.onelogin.*,com.onelogin.saml.*" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>SAML Assertion Page</title>
</head>
<body>
<%
  String certificateS ="MIIDGTCCAoKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzET"+
"MBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYD"+
"VQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2"+
"MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQI"+
"DApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9u"+
"ZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIGfMA0GCSqGSIb3DQEB"+
"AQUAA4GNADCBiQKBgQCsalDL15zSKeEGy9c0Hao7+G02x6k/MlZuCwEvkPKUcl9Q"+
"dGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxv"+
"Z2luLmNvbYIBATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADgYEANZvz"+
"lB1Aq84AdOvsn2XKxBB/PmNZLqnM1VWRPaNcvjafx7eHd5qayXFNQz+bOLujENmg"+
"Am5padbydG89SeefpOGcY2TMsVt0RUzxTnN3Zq5G6Ja2fAKOEX01ejdoPPMmStqq"+
"Sw8k1wPUU8uLYJG5wmjf0rCb8RVaeAwMc+wcEIA=";

  // user account specific settings. Import the certificate here
  AccountSettings accountSettings = new AccountSettings();
  accountSettings.setCertificate(certificateS);

  Response samlResponse = new Response(accountSettings);
  samlResponse.loadXmlFromBase64(request.getParameter("SAMLResponse"));
  samlResponse.setDestinationUrl(request.getRequestURL().toString()); 

  if (samlResponse.isValid()) {

    // the signature of the SAML Response is valid. The source is trusted
  	java.io.PrintWriter writer = response.getWriter();
  	writer.write("OK!");
  	String nameId = samlResponse.getNameId();
  	writer.write(nameId);
  	writer.flush();
	
  } else {

    // the signature of the SAML Response is not valid
  	java.io.PrintWriter writer = response.getWriter();
  	writer.write("Failed");
  	writer.flush();

  }
%>
</body>
</html>