This example was developed to show how Java Toolkit works.

Project Structure
-----------------

The src/main/java/ folder contains the files you'll copy into your Java application. You can also build the project by running `mvn package` and copy the
resulting jar into your project instead of relying on the source code directly. Note also that Apache Commons Codec is a dependency.

The sample/ folder has a minimal webapp which depends on the core code inside com/ folder and the files index.jsp and consume.jsp inside webapp-folder.
index.jsp and consume.jsp are the ones that actually handle the SAML conversation. Dependencies are configured in the pom.xml file.

SAML Overview for project
-------------------------

The index.jsp file acts as an initiater for the SAML conversation, if it should be initiated by the application.

This is called Service Provider Initiated SAML. The service provider creates a SAML Authentication Request and sends it to the identity provider (IdP), 
We authenticate at the IdP and then a Response is sent to the Consumer Service Url configured on index.jsp.

In order to know where to redirect the user with the authentication request, we need to establish the user's identity provider affinity.
This depends on your application. In this example, those validations are provided by consume.jsp, which is meant as a stub for you customization.

Running the sample
------------------

First install the core code into your local Maven repository with:

    mvn install

You can now run the web app sample which depends on this code:

    cd sample
    mvn jetty:run


What needs to be configured
----------------------------

In the example above, SAML settings are divided into two parts, the application specific (`const_assertion_consumer_service_url`, `const_issuer`, `const_name_identifier_format`) 
and the user/account specific (`idp_sso_target_url`, `x509certificate`). You'll need to add your own code here to identify the user or user origin (e.g. by subdomain, ip_address etc.).

The following information needs to be available on the account:

`appSettings.setAssertionConsumerServiceUrl`: The URL at which the SAML assertion should be received.

`appSettings.setIssuer`: The name of your application. Some identity providers might need this to establish the identity of the service provider requesting the login.

`accSettings.setIdpSsoTargetUrl`: The URL to which the authentication request should be sent. This would be on the identity provider.

`accountSettings.setCertificate`: The x509 certificate fingerprint. This is provided from the identity provider when setting up the relationship, for this version the certificate must be 1024-bit.

In OneLogin, for this sample project, you'll want to set the SAML Consumer URL to "http://localhost:8080" and the SAML Audience and SAML Recipient to "http://localhost:8080/consume.jsp"
