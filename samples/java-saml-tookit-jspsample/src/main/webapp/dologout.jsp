<%@page import="com.onelogin.saml2.Auth"%>
<%@page import="com.onelogin.saml2.authn.NameID"%>
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<jsp:useBean id="lgp" class="java.util.HashMap" scope="session"/>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
</head>
<body>
	<%
		Auth auth = new Auth(request, response);
		if (lgp.isEmpty())
			auth.logout();
		else
		{
			// added for the support of Shibboleth IdP3 logout
			NameID subject = (NameID) lgp.get("subject");
			String sesionIndex = (String) lgp.get("session-index");
			auth.logout(null, subject, sesionIndex, false);
		}
	%>
</body>
</html>
