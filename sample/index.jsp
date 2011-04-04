<%@page import="java.net.URLEncoder,org.apache.log4j.Logger"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.onelogin.saml.*,com.onelogin.*" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Auth Request</title>
<%
  AppSettings appSettings = new AppSettings();
  appSettings.setAssertionConsumerServiceUrl("http://68.169.49.120:8080/testOneLogin/consume.jsp");
  appSettings.setIssuer("user@onelogin.com");
  AccountSettings accSettings = new AccountSettings();
  accSettings.setIdp_sso_target_url("https://app.onelogin.com/saml/signon/20956");
  AuthRequest authReq = new AuthRequest(appSettings, accSettings);
  String reqString = accSettings.getIdp_sso_target_url()+"?SAMLRequest=" + AuthRequest.getRidOfCRLF(URLEncoder.encode(authReq.getRequest(AuthRequest.base64),"UTF-8"));
  response.sendRedirect(reqString);
%>
</head>
<body>

</body>
</html>