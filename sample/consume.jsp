<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.onelogin.*,com.onelogin.saml.*,org.apache.log4j.Logger" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>SAML Assertion Page</title>
</head>
<body>
<%
  String certificateS ="MIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApD"+
    "YWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxv"+
    "Z2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTExMDMxMTAwMjc0OVoX"+
    "DTE2MDMxMDAwMjc0OVowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3Ju"+
    "aWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAX"+
    "BgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ"+
    "AoGBALfqtQf59sdh8AqMtrTMv1wONW53Rj29zzCPy1di3qJZ/PzHvYurTf9GVBz9"+
    "ZyNLBfkt16dhv/dLTzTxJVAqnKDRcnwhskLvWp+8nPnqnNDsousAYzMs63rYO+/f"+
    "qdt/19BZrpm7zZI6BWzQKimTLS0gYpgkqbreoKK+AdbbwtyXAgMBAAEwAwYBAAMB"+
    "AA==";

  // user account specific settings. Import the certificate here
  AccountSettings accountSettings = new AccountSettings();
  accountSettings.setCertificate(certificateS);

  Response samlResponse = new Response(accountSettings);
  samlResponse.loadXmlFromBase64(request.getParameter("SAMLResponse"));

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