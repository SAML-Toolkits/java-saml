# OneLogin's SAML Java Toolkit

[![Build Status](https://travis-ci.org/onelogin/java-saml.svg?branch=master)](https://travis-ci.org/onelogin/java-saml) [![Coverage Status](https://coveralls.io/repos/github/onelogin/java-saml/badge.svg?branch=master)](https://coveralls.io/github/onelogin/java-saml?branch=master)

Add SAML support to your Java applications using this library.
Forget those complicated libraries and use that open source library provided and supported by OneLogin Inc.

2.8.0 uses xmlsec 2.2.3 which fixes [CVE-2021-40690](https://snyk.io/vuln/SNYK-JAVA-ORGAPACHESANTUARIO-1655558)

Version >= 2.5.0 compatible with java8 / java9. Not compatible with java7

2.5.0 sets the 'strict' setting parameter to true.

2.5.0 uses xmlsec 2.1.4 which fixes [CVE-2019-12400](https://snyk.io/vuln/SNYK-JAVA-ORGAPACHESANTUARIO-460281)

Version 2.0.0 - 2.4.0, compatible with java7 / java8.

We [introduced some incompatibilities](https://github.com/onelogin/java-saml/issues/90), that could be fixed and make it compatible with java6.

Version 1.1.2 is considered to be deprecated. If you have used it, we strongly recommend that you migrate to the new version. 
We rebuilt the toolkit on 2.0.0, so code/settings that you had been using in the previous version will no longer be compatible.


## Why add SAML support to my software?

SAML is an XML-based standard for web browser single sign-on and is defined by
the OASIS Security Services Technical Committee. The standard has been around 
since 2002, but lately it has become popular due to its advantages as follows:

 * **Usability** - One-click access from portals or intranets, deep linking, 
   password elimination and automatically renewing sessions make life
   easier for the user.
 * **Security** - Based on strong digital signatures for authentication and
   integrity, SAML is a secure single sign-on protocol that the largest
   and most security conscious enterprises in the world rely on.
 * **Speed** - SAML is fast. One browser redirect is all it takes to securely
   sign a user into an application.
 * **Phishing Prevention** - If you don’t have a password for an app, you
   can’t be tricked into entering it on a fake login page.
 * **IT Friendly** - SAML simplifies life for IT because it centralizes
   authentication, provides greater visibility and makes directory
   integration easier.
 * **Opportunity** - B2B cloud vendor should support SAML to facilitate the 
   integration of their product.


## General description

OneLogin's SAML Java toolkit lets you turn a Java application into a SP
(Service Provider) that can be connected to an IdP (Identity Provider).

Supports:

 * SSO and SLO (SP-Initiated and IdP-Initiated).
 * Assertion and nameId encryption.
 * Assertion signatures.
 * Message signatures: AuthNRequest, LogoutRequest, LogoutResponses.
 * Enable an Assertion Consumer Service endpoint.
 * Enable a Single Logout Service endpoint.
 * Publish the SP metadata (which can be signed).

Key features:

 * **saml2int** - Implements the SAML 2.0 Web Browser SSO Profile.
 * **Session-less** - Forget those common conflicts between the SP and
   the final app; the toolkit delegates session in the final app.
 * **Easy to use** - Programmer will be allowed to code high-level and
   low-level programming; 2 easy-to-use APIs are available.
 * **Tested** - Thoroughly tested.
 * **Popular** - OneLogin's customers use it. Add easy support to your java web projects.

## Security warning

In production, the **onelogin.saml2.strict** setting parameter MUST be set as **"true"**. Otherwise your environment is not secure and will be exposed to attacks.

In production also we highly recommend to register on the settings the IdP certificate instead of using the fingerprint method. The fingerprint, is a hash, so at the end is open to a collision attack that can end on a signature validation bypass. Other SAML toolkits deprecated that mechanism, we maintain it for compatibility and also to be used on test environment.

The IdPMetadataParser class does not validate in any way the URL that is introduced in order to be parsed. 

Usually the same administrator that handles the Service Provider also sets the URL to the IdP, which should be a trusted resource.

But there are other scenarios, like a SAAS app where the administrator of the app delegates this functionality to other users. In this case, extra precaution should be taken in order to validate such URL inputs and avoid attacks like SSRF.


## Installation
### Hosting
#### Github
The toolkit is hosted on github. You can download it from:
* Latest release: https://github.com/onelogin/java-saml/releases/latest
* Master repo: https://github.com/onelogin/java-saml/tree/master

#### Maven
The toolkit is hosted at [Sonatype OSSRH (OSS Repository Hosting)](http://central.sonatype.org/pages/ossrh-guide.html) that is synced to the Central Repository.

Install it as a maven dependency:
```xml
  <dependency>
      <groupId>com.onelogin</groupId>
      <artifactId>java-saml</artifactId>
      <version>2.6.0</version>
  </dependency>
```


### Dependencies
java-saml (com.onelogin:java-saml-toolkit) has the following dependencies:

*core:*
* org.apache.santuario:xmlsec
* joda-time:joda-time
* org.apache.commons:commons-lang3
* commons-codec:commons-codec
* testing:
  * org.hamcrest:hamcrest-core and org.hamcrest:hamcrest-library
  * junit:junit
  * org.mockito:mockito-core
* logging:
  * org.slf4j:slf4j-api
  * ch.qos.logback:logback-classic
* For CI:
  * org.jacoco:jacoco-maven-plugin

also the [Java Cryptography Extension (JCE)](https://en.wikipedia.org/wiki/Java_Cryptography_Extension) is required. If you don't have it, download the version of [jce-8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html), unzip it, and drop its content at
*${java.home}/jre/lib/security/*. JDK 9 and later offer the stronger cryptographic algorithms by default.

*toolkit:*
* com.onelogin:java-saml-core
* javax.servlet:servlet-api

*maven:*
* org.apache.maven.plugins:maven-jar-plugin
* org.apache.maven.plugins:maven-surefire-plugin
* org.apache.maven.plugins:maven-enforcer-plugin

For more info, open and read the different pom.xml files:
[core/pom.xml](https://github.com/onelogin/java-saml/blob/v2.5.0/core/pom.xml), [toolkit/pom.xml](https://github.com/onelogin/java-saml/blob/v2.5.0/toolkit/pom.xml)

## Working with the github repository code and Eclipse.
### Get the toolkit.
The toolkit is hosted on github. You can download it from:
* Latest release: https://github.com/onelogin/java-saml/releases/latest
* Master repo: https://github.com/onelogin/java-saml/tree/master

### Adding java-saml toolkit components as a project
1. Open Eclipse and set a workspace
2. File > Import > Maven : Existing Maven Projects > Select the path where the core folder of the Java Toolkit is  *<path>/java-saml/core*, resolve the Workspace project and select the pom.xml
3. File > Import > Maven : Existing Maven Projects > Select the path where the toolkit folder of the Java Toolkit is  *<path>/java-saml/toolkit*, resolve the Workspace project and select the pom.xml

### Adding the java-saml-tookit-jspsample as a project
1. File > Import > Maven : Existing Maven Projects > Select the path where the core folder of the Java Toolkit is  *<path>/java-saml/samples/java-saml-tookit-jspsample*, resolve the Workspace project and select the pom.xml

### Deploy the java-saml-tookit-jspsample

At the Package Explorer, select the jsp-sample project, 2nd bottom of the mouse and Run As > Run Server
Select a [Tomcat Server](http://crunchify.com/step-by-step-guide-to-setup-and-install-apache-tomcat-server-in-eclipse-development-environment-ide/) in order to deploy the server.

## Getting started
### Learning the toolkit

OneLogin's new SAML Java SAML Toolkit contains different folders (core, toolkit, samples) and some files.

Let's start describing them:

#### core (com.onelogin:java-saml-core) ####
This folder contains a maven project with the heart of java-saml, classes and methods to handle AuthNRequest, SAMLResponse, LogoutRequest, LogoutResponse and Metadata (low level API). In addition, it contains classes to load the settings of the toolkit and the HttpRequest class, a framework-agnostic representation of an HTTP request.

In the repo, at *src/main/java* you will find the source; at *src/main/resources/schemas*, there are xsd schemas used to validate the SAML messages; at *src/test/java* are the tests for its classes; and at *src/test/resources* can be found different settings, SAML messages and certificates used by the junit tests.


#### toolkit (com.onelogin:java-saml) ####
This folder contains a maven project with the Auth class to handle the low level classes of java-saml-core and the ServletUtils class to handle javax.servlet.http objects, used on the Auth class.
In the repo, at *src/main/java* you will find the source and at *src/test/java* the junit tests for the classes Auth and ServletUtils.

#### samples (com.onelogin:java-saml-tookit-samples) ####
This folder contains a maven project with a jsp app used to learn how the java-saml toolkit works.

Within the *java-saml-tookit-jspsample/src/main/webapp* folder are several jsp files, each one representing a different endpoint:
- *index.jsp* Index of the webapp.
- *dologin.jsp* SP-initiated SSO endpoint.
- *dologout.jsp* SP-initiated SLO endpoint.
- *acs.jsp* Service Provider Assertion Consumer Service endpoint.
- *attrs.jsp* Shows attributes collected from the SAMLResponse.
- *sls.jsp* Service Provider Single Logout Service endpoint.
- *metadata.jsp* Publish SP metadata.

At *java-saml-tookit-jspsample/src/main/resources* folder is the *onelogin.saml.properties* file which contains the SAML settings.

### How it works

#### Javadocs

* [toolkit (com.onelogin:java-saml)](https://onelogin.github.io/java-saml/toolkit/index.html)
* [core (com.onelogin:java-saml-core)](https://onelogin.github.io/java-saml/core/index.html)

#### Settings
First of all we need to configure the toolkit. The SP's info, the IdP's info, and in some cases, configuration for advanced security issues, such as signatures and encryption.

##### Properties File
All the settings are defined in one unique file; by default, the Auth class loads a *onelogin.saml.properties* file with the Auth() method, but if we named it in a different way, we can use Auth(filename);

Here are the list of properties to be defined on the settings file:
```properties
#  If 'strict' is True, then the Java Toolkit will reject unsigned
#  or unencrypted messages if it expects them signed or encrypted
#  Also will reject the messages if not strictly follow the SAML
onelogin.saml2.strict =  false

# Enable debug mode (to print errors)
onelogin.saml2.debug =  false


## Service Provider Data that we are deploying ##

#  Identifier of the SP entity  (must be a URI)
onelogin.saml2.sp.entityid = http://localhost:8080/java-saml-tookit-jspsample/metadata.jsp

# Specifies info about where and how the <AuthnResponse> message MUST be
# returned to the requester, in this case our SP.
# URL Location where the <Response> from the IdP will be returned
onelogin.saml2.sp.assertion_consumer_service.url = http://localhost:8080/java-saml-tookit-jspsample/acs.jsp

# SAML protocol binding to be used when returning the <Response>
# message.  Onelogin Toolkit supports for this endpoint the
# HTTP-POST binding only
onelogin.saml2.sp.assertion_consumer_service.binding = urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST

# Specifies info about where and how the <Logout Response> message MUST be
# returned to the requester, in this case our SP.
onelogin.saml2.sp.single_logout_service.url = http://localhost:8080/java-saml-tookit-jspsample/sls.jsp

# SAML protocol binding to be used when returning the <LogoutResponse> or sending the <LogoutRequest>
# message.  Onelogin Toolkit supports for this endpoint the
# HTTP-Redirect binding only
onelogin.saml2.sp.single_logout_service.binding = urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect

# Specifies constraints on the name identifier to be used to
# represent the requested subject.
# Take a look on core/src/main/java/com/onelogin/saml2/util/Constants.java to see the NameIdFormat supported
onelogin.saml2.sp.nameidformat = urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified

# Usually x509cert and privateKey of the SP are provided by files placed at
# the certs folder. But we can also provide them with the following parameters

onelogin.saml2.sp.x509cert =

# Future SP certificate, to be used during SP Key roll over
onelogin.saml2.sp.x509certNew =

# Requires Format PKCS#8   BEGIN PRIVATE KEY       
# If you have     PKCS#1   BEGIN RSA PRIVATE KEY  convert it by   openssl pkcs8 -topk8 -inform pem -nocrypt -in sp.rsa_key -outform pem -out sp.pem
onelogin.saml2.sp.privatekey =

# Organization
onelogin.saml2.organization.name = SP Java 
onelogin.saml2.organization.displayname = SP Java Example
onelogin.saml2.organization.url = http://sp.example.com
onelogin.saml2.organization.lang = en

# Contacts (use indexes to specify multiple contacts, multiple e-mail addresses per contact, multiple phone numbers per contact)
onelogin.saml2.sp.contact[0].contactType=administrative
onelogin.saml2.sp.contact[0].company=ACME
onelogin.saml2.sp.contact[0].given_name=Guy
onelogin.saml2.sp.contact[0].sur_name=Administrative
onelogin.saml2.sp.contact[0].email_address[0]=administrative@example.com
onelogin.saml2.sp.contact[0].email_address[1]=administrative2@example.com
onelogin.saml2.sp.contact[0].telephone_number[0]=+1-123456789
onelogin.saml2.sp.contact[0].telephone_number[1]=+1-987654321
onelogin.saml2.sp.contact[1].contactType=other
onelogin.saml2.sp.contact[1].company=Big Corp
onelogin.saml2.sp.contact[1].email_address=info@example.com

# Legacy contacts (legacy way to specify just a technical and a support contact with minimal info) 
onelogin.saml2.contacts.technical.given_name = Technical Guy
onelogin.saml2.contacts.technical.email_address = technical@example.com
onelogin.saml2.contacts.support.given_name = Support Guy
onelogin.saml2.contacts.support.email_address = support@example.com

## Identity Provider Data that we want connect with our SP ##

# Identifier of the IdP entity  (must be a URI)
onelogin.saml2.idp.entityid =

# SSO endpoint info of the IdP. (Authentication Request protocol)
# URL Target of the IdP where the SP will send the Authentication Request Message
onelogin.saml2.idp.single_sign_on_service.url =

# SAML protocol binding to be used to deliver the <AuthnRequest> message 
# to the IdP.  Onelogin Toolkit supports for this endpoint the
# HTTP-Redirect binding only
onelogin.saml2.idp.single_sign_on_service.binding = urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect

# SLO endpoint info of the IdP.
# URL Location of the IdP where the SP will send the SLO Request
onelogin.saml2.idp.single_logout_service.url =

# Optional SLO Response endpoint info of the IdP.
# URL Location of the IdP where the SP will send the SLO Response. If left blank, same URL as onelogin.saml2.idp.single_logout_service.url will be used.
# Some IdPs use a separate URL for sending a logout request and response, use this property to set the separate response url
onelogin.saml2.idp.single_logout_service.response.url =

# SAML protocol binding to be used when returning the <Response>
# message.  Onelogin Toolkit supports for this endpoint the
# HTTP-Redirect binding only
onelogin.saml2.idp.single_logout_service.binding = urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect

# Public x509 certificate of the IdP
onelogin.saml2.idp.x509cert =

# Instead of using the whole x509cert you can use a fingerprint in order to
# validate a SAMLResponse (but you still need the x509cert to validate LogoutRequest and LogoutResponse using the HTTP-Redirect binding).
# But take in mind that the fingerprint, is a hash, so at the end is open to a collision attack that can end on a signature validation bypass,
# that why we don't recommend it use for production environments.
# (openssl x509 -noout -fingerprint -in "idp.crt" to generate it,
# or add for example the -sha256 , -sha384 or -sha512 parameter)
#
# If a fingerprint is provided, then the certFingerprintAlgorithm is required in order to
# let the toolkit know which Algorithm was used. Possible values: sha1, sha256, sha384 or sha512
# 'sha1' is the default value.
# onelogin.saml2.idp.certfingerprint = 
# onelogin.saml2.idp.certfingerprint_algorithm = sha256

# Security settings
#

# Indicates that the nameID of the <samlp:logoutRequest> sent by this SP
# will be encrypted.
onelogin.saml2.security.nameid_encrypted = false

# Indicates whether the <samlp:AuthnRequest> messages sent by this SP
# will be signed.              [The Metadata of the SP will offer this info]
onelogin.saml2.security.authnrequest_signed = false

# Indicates whether the <samlp:logoutRequest> messages sent by this SP
# will be signed.
onelogin.saml2.security.logoutrequest_signed = false

# Indicates whether the <samlp:logoutResponse> messages sent by this SP
# will be signed.
onelogin.saml2.security.logoutresponse_signed = false

# Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest> and
# <samlp:LogoutResponse> elements received by this SP to be signed.
onelogin.saml2.security.want_messages_signed = false

# Indicates a requirement for the <saml:Assertion> elements received by this SP to be signed.
onelogin.saml2.security.want_assertions_signed = false

# Indicates a requirement for the Metadata of this SP to be signed.
# Right now supported null (in order to not sign) or true (sign using SP private key) 
onelogin.saml2.security.sign_metadata =

# Indicates a requirement for the Assertions received by this SP to be encrypted
onelogin.saml2.security.want_assertions_encrypted = false

# Indicates a requirement for the NameID received by this SP to be encrypted
onelogin.saml2.security.want_nameid_encrypted = false


# Authentication context.
# Set Empty and no AuthContext will be sent in the AuthNRequest,
# Set comma separated values urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos,urn:oasis:names:tc:SAML:2.0:ac:classes:Password
onelogin.saml2.security.requested_authncontext = urn:oasis:names:tc:SAML:2.0:ac:classes:Password

# Allows the authn comparison parameter to be set, defaults to 'exact'
onelogin.saml2.security.requested_authncontextcomparison = exact

# Allows duplicated names in the attribute statement
onelogin.saml2.security.allow_duplicated_attribute_name = false

# Indicates if the SP will validate all received xmls.
# (In order to validate the xml, 'strict' and 'wantXMLValidation' must be true).
onelogin.saml2.security.want_xml_validation = true

# Algorithm that the toolkit will use on signing process. Options:
#  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
#  'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
#  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
#  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
#  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
onelogin.saml2.security.signature_algorithm = http://www.w3.org/2001/04/xmldsig-more#rsa-sha256

# Algorithm that the toolkit will use on digest process. Options:
#  'http://www.w3.org/2000/09/xmldsig#sha1'
#  'http://www.w3.org/2001/04/xmlenc#sha256'
#  'http://www.w3.org/2001/04/xmldsig-more#sha384'
#  'http://www.w3.org/2001/04/xmlenc#sha512'
onelogin.saml2.security.digest_algorithm = http://www.w3.org/2001/04/xmlenc#sha256


# Reject Signatures with deprecated algorithms (sha1)
onelogin.saml2.security.reject_deprecated_alg = true

# Enable trimming of parsed Name IDs and attribute values
# SAML specification states that no trimming for string elements should be performed, so no trimming will be
# performed by default on extracted Name IDs and attribute values. However, some SAML implementations may add
# undesirable surrounding whitespace when outputting XML (possibly due to formatting/pretty-printing).
# These two options allow to optionally enable value trimming on extracted Name IDs (including issuers) and 
# attribute values.
onelogin.saml2.parsing.trim_name_ids = false
onelogin.saml2.parsing.trim_attribute_values = false

# Prefix used in generated Unique IDs.
# Optional, defaults to ONELOGIN_ or full ID is like ONELOGIN_ebb0badd-4f60-4b38-b20a-a8e01f0592b1.
# At minimun, the prefix can be non-numeric character such as "_".
# onelogin.saml2.unique_id_prefix = _
```


##### KeyStores

The Auth constructor supports the ability to read SP public cert/private key from a KeyStore. A KeyStoreSettings object must be provided with the KeyStore, the Alias and the KeyEntry password.

```java
import java.io.FileInputStream;
import java.security.KeyStore;
import com.onelogin.saml2.Auth
import com.onelogin.saml2.model.KeyStoreSettings

String keyStoreFile = "oneloginTestKeystore.jks";
String alias = "keywithpassword";
String storePass = "changeit";
String keyPassword = "keypassword";

KeyStore ks = KeyStore.getInstance("JKS");
ks.load(new FileInputStream(keyStoreFile), storePass.toCharArray());

KeyStoreSettings keyStoreSettings =  new keyStoreSettings(ks, alias, keyPassword);
Auth auth = new Auth(KeyStoreSettings keyStoreSetting);
```

##### Dynamic Settings
It is possible to build settings programmatically. You can load your values from different sources such as files, databases, or generated values.

The `SettingsBuilder` class exposes the method `fromValues(Map<String, Object> samlData)` which let you build your settings dynamically. The `key` strings are the same from the *Properties file*
```java
Map<String, Object> samlData = new HashMap<>();
samlData.put("onelogin.saml2.sp.entityid", "http://localhost:8080/java-saml-tookit-jspsample/metadata.jsp");
samlData.put("onelogin.saml2.sp.assertion_consumer_service.url", new URL("http://localhost:8080/java-saml-tookit-jspsample/acs.jsp"));
samlData.put("onelogin.saml2.security.want_xml_validation",true);
samlData.put("onelogin.saml2.sp.x509cert", myX509CertInstance);

SettingsBuilder builder = new SettingsBuilder();
Saml2Settings settings = builder.fromValues(samlData).build();
```

To instantiate the `Auth` class you write
```java
Auth auth = new Auth(settings, request, response);
```

#### The HttpRequest
java-saml-core uses HttpRequest class, a framework-agnostic representation of an HTTP request.

java-saml depends on javax.servlet:servlet-api, and the classes Auth and ServletUtils use HttpServletRequest and HttpServletResponse objects.

If you want to use anything different than javax.servlet.http, you will need to reimplement Auth and ServletUtils based on that new representation of the HTTP request/responses.

#### Initiate SSO
In order to send an AuthNRequest to the IdP:
```java
Auth auth = new Auth(request, response);
auth.login();
```
The AuthNRequest will be sent signed or unsigned based on the security settings 'onelogin.saml2.security.authnrequest_signed'.

The IdP will then return the SAML Response to the user's client. The client is then forwarded to the Attribute Consumer Service of the SP with this information.

We can set a 'RelayState' parameter containing a return url to the login function:
```java
String returnUrl = 'https://example.com';
auth.login(relayState=returnUrl)
```
The login method can receive 3 more optional parameters:
- *authnRequestParams* which in turn allows to shape the AuthNRequest with the following properties:
  - *forceAuthn* When true the AuthNRequest will have the `ForceAuthn` attribute set to `true`
  - *isPassive* When true the AuthNRequest will have the `IsPassive` attribute set to `true`
  - *setNameIdPolicy* When true the AuthNRequest will set a `NameIdPolicy` element
  - *allowCreate* When true, and *setNameIdPolicy* is also true, the AuthNRequest will have the `AllowCreate` attribute set to `true` on the `NameIdPolicy` element
  - *nameIdValueReq* Indicates to the IdP the subject that should be authenticated
- *stay* Set to true to stay (returns the url string), otherwise set to false to execute a redirection to that url (IdP SSO URL)
- *parameters* Use it to send extra parameters in addition to the AuthNRequest

By default, the login method initiates a redirect to the SAML Identity Provider. You can use the *stay* parameter, to prevent that, and execute the redirection manually. We need to use that if a match on the future SAMLResponse ID and the AuthNRequest ID to be sent is required.  That AuthNRequest ID must be extracted and stored for future validation, so we can't execute the redirection on the login.  Instead, set *stay* to true, then get that ID by
```
auth.getLastRequestId()
```
and later executing the redirection manually.


#### The SP Endpoints
Related to the SP there are 3 important endpoints: The metadata view, the ACS view and the SLS view. The toolkit provides at the demo of the samples folder those views.

##### SP Metadata
This code will provide the XML metadata file of our SP, based on the info that we provided in the settings files.
```java
Auth auth = new Auth();
Saml2Settings settings = auth.getSettings();
String metadata = settings.getSPMetadata();
List<String> errors = Saml2Settings.validateMetadata(metadata);
if (errors.isEmpty()) {
   out.println(metadata);
} else {
   response.setContentType("text/html; charset=UTF-8");
   for (String error : errors) {
       out.println("<p>"+error+"</p>");
   }
}
```
The getSPMetadata will return the metadata signed or not based on the security parameter of the settings `onelogin.saml2.security.sign_metadata`.

Before the XML metadata is exposed, a check takes place to ensure that the info to be provided is valid.

##### Attribute Consumer Service(ACS)
This code handles the SAML response that the IdP forwards to the SP through the user's client.
```java
Auth auth = new Auth(request, response);
auth.processResponse();
if (!auth.isAuthenticated()) {
   out.println("Not authenticated");
}

List<String> errors = auth.getErrors();
if (!errors.isEmpty()) {
    out.println(StringUtils.join(errors, ", "));
    if (auth.isDebugActive()) {
        String errorReason = auth.getLastErrorReason();
        if (errorReason != null && !errorReason.isEmpty()) {
            out.println(auth.getLastErrorReason());
        }
    }
} else {
    Map<String, List<String>> attributes = auth.getAttributes();
    String nameId = auth.getNameId();
    String nameIdFormat = auth.getNameIdFormat();
    String sessionIndex = auth.getSessionIndex();
    String nameidNameQualifier = auth.getNameIdNameQualifier();
    String nameidSPNameQualifier = auth.getNameIdSPNameQualifier();

    session.setAttribute("attributes", attributes);
    session.setAttribute("nameId", nameId);
    session.setAttribute("nameIdFormat", nameIdFormat);
    session.setAttribute("sessionIndex", sessionIndex);
    session.setAttribute("nameidNameQualifier", nameidNameQualifier);
    session.setAttribute("nameidSPNameQualifier", nameidSPNameQualifier);

    String relayState = request.getParameter("RelayState");

    if (relayState != null && relayState != ServletUtils.getSelfRoutedURLNoQuery(request)) {
        response.sendRedirect(request.getParameter("RelayState"));
    } else {
        if (attributes.isEmpty()) {
            out.println("You don't have any attributes");
        }
       else {
            Collection<String> keys = attributes.keySet();
            for(String name :keys){
                out.println(name);
                List<String> values = attributes.get(name);
                for(String value :values) {
                    out.println(" - " + value);
                }
            }
        }
    }
}
```
The SAML response is processed and then checked to ensure that there are no errors. It also verifies that the user is authenticated, and then the userdata is stored in the session.
At that point there are 2 possible alternatives:
- If no RelayState is provided, we could show the user data in this view or however we wanted.
- If RelayState is provided, a redirection take place.
Notice that we saved the user data in the session before the redirection to have the user data available at the RelayState view.

In order to retrieve attributes we use:
```
Map<String, List<String>> attributes = auth.getAttributes();
```

With this method we get a Map with all the user data provided by the IdP in the Assertion of the SAML Response.
```
{
    "cn": ["Jhon"],
    "sn": ["Doe"],
    "mail": ["Doe"],
    "groups": ["users", "members"]
}
```
Each attribute name can be used as a key to obtain the value. Every attribute is a list of values. A single-valued attribute is a list of a single element.

Before trying to get an attribute, check that the user is authenticated. If the user isn't authenticated, an empty Map will be returned. For example, if we call to getAttributes before a auth.processResponse, the getAttributes() will return an empty Map.

##### Single Logout Service (SLS)
This code handles the Logout Request and the Logout Responses.
```java
Auth auth = new Auth(request, response);
auth.processSLO();
List<String> errors = auth.getErrors();
if (errors.isEmpty()) {
   out.println("Sucessfully logged out");
} else {
   for(String error : errors) {
      out.println(error);
   }
}
```
If the SLS endpoints receives a Logout Response, the response is validated and the session of the HttpRequest could be closed.

If the SLS endpoints receives an Logout Request, the request is validated, the session is closed and a Logout Response is sent to the SLS endpoint of the IdP.

If we don't want that processSLO to destroy the session, pass the keepLocalSession parameter as true to the processSLO method.

#### Initiate SLO
In order to send a Logout Request to the IdP:
```java
Auth auth = new Auth(request, response);

String nameId = null;
if (session.getAttribute("nameId") != null) {
    nameId = session.getAttribute("nameId").toString();
}
String nameIdFormat = null;
if (session.getAttribute("nameIdFormat") != null) {
    nameIdFormat = session.getAttribute("nameIdFormat").toString();
}
String nameidNameQualifier = null;
if (session.getAttribute("nameidNameQualifier") != null) {
    nameIdFormat = session.getAttribute("nameidNameQualifier").toString();
}
String nameidSPNameQualifier = null;
if (session.getAttribute("nameidSPNameQualifier") != null) {
    nameidSPNameQualifier = session.getAttribute("nameidSPNameQualifier").toString();
}
String sessionIndex = null;
if (session.getAttribute("sessionIndex") != null) {
    sessionIndex = session.getAttribute("sessionIndex").toString();
}
auth.logout(null, new LogoutRequestParams(sessionIndex, nameId, nameIdFormat));
```java
The Logout Request will be sent signed or unsigned based on the security settings 'onelogin.saml2.security.logoutrequest_signed'

The IdP will return the Logout Response through the user's client to the Single Logout Service of the SP.

We can set a 'RelayState' parameter containing a return url to the login function:
```java
String returnUrl = 'https://example.com';
auth.logout(relayState=returnUrl)
```

Also there are other 3 optional parameters that can be set:
- *logoutRequestParams* which in turn allows to shape the LogoutRequest with the following properties:
  - *sessionIndex* Identifies the session of the user
  - *nameId* That will be used to build the LogoutRequest. If no *nameId* parameter is set and the auth object processed a SAML Response with a `NameID`, then this `NameID` will be used
  - *nameidFormat* The `NameID` `Format` that will be set on the LogoutRequest
  - *nameIdNameQualifier* The `NameID` `NameQualifier` that will be set on the LogoutRequest
  - *nameIdSPNameQualifier* The `NameID` `SPNameQualifier` that will be set on the LogoutRequest
- *stay* True if we want to stay (returns the url string) False to execute a redirection to that url (IdP SLS URL)
- *parameters* Use it to send extra parameters in addition to the LogoutRequest

By default the logout method initiates a redirect to the SAML Identity Provider. You can use the *stay* parameter, to prevent that, and execute the redirection manually. We need to use that
if a match on the future LogoutResponse ID and the LogoutRequest ID to be sent is required, that LogoutRequest ID must be extracted and stored for future validation so we can't execute the redirection on the logout, instead set stay to true, then get that ID by

```java
auth.getLastRequestId()
```
and later executing the redirection manually.

### Extending the provided implementation

All the provided SAML message classes (`AuthnRequest`, `SamlResponse`, `LogoutRequest`, `LogoutResponse`) can be extended to add or change the processing behavior. 

In particular, the classes used to produce outgoing messages (`AuthnRequest`, `LogoutRequest`, and `LogoutResponse`) also provide a `postProcessXml` method that can be overridden to customise the generation of the corresponding SAML message XML, along with the ability to pass in proper extensions of the input parameter classes (`AuthnRequestParams`, `LogoutRequestParams`, and `LogoutResponseParams` respectively).

Once you have prepared your extension classes, in order to make the `Auth` class use them, an appropriate `SamlMessageFactory` implementation can be specified. As an example, assuming you've created two extension classes `AuthnRequestEx` and `SamlResponseEx` to customise the creation of AuthnRequest SAML messages and the validation of SAML responses respectively, as well as an extended `AuthnRequestParamsEx` input parameter class to drive the AuthnRequest generation post-processing, you can do the following:

```java
Auth auth = new Auth(request, response);
auth.setSamlMessageFactory(new SamlMessageFactory() {
	@Override
	public AuthnRequest createAuthnRequest(Saml2Settings settings, AuthnRequestParams params) {
		return new AuthnRequestEx(settings, (AuthnRequestParamsEx) params);
	}

	@Override
	public SamlResponse createSamlResponse(Saml2Settings settings, HttpRequest request) throws Exception {
		return new SamlResponseEx(settings, request);
	}
}); 
// then proceed with login...
auth.login(relayState, new AuthnRequestParamsEx()); // the custom generation of AuthnReqeustEx will be executed
// ... or process the response as usual
auth.processResponse(); // the custom validation of SamlResponseEx will be executed
```

### Working behind load balancer

Is possible that asserting request URL and Destination attribute of SAML response fails when working behind load balancer with SSL offload.

You should be able to workaround this by configuring your server so that it is aware of the proxy and returns the original url when requested.

For Apache Tomcat this is done by setting the proxyName, proxyPort, scheme and secure attributes for the Connector. See [here](http://serverfault.com/questions/774300/ssl-offloading-from-apache-to-tomcat-get-overwritten-somewhere) for an example.


### IdP with multiple certificates
 
 In some scenarios the IdP uses different certificates for
 signing/encryption, or is under key rollover phase and more than one certificate is published on IdP metadata.
 
 In order to handle that the toolkit offers the `onelogin.saml2.idp.x509certMulti` parameters where you can set additional certificates that will be used to validate IdP signature. However just the certificate set in `onelogin.saml2.idp.x509cert` parameter will be used for encrypting.
 

### Replay attacks

In order to avoid replay attacks, you can store the ID of the SAML messages already processed, to avoid processing them twice. Since the Messages expires and will be invalidated due that fact, you don't need to store those IDs longer than the time frame that you currently accepting.

Get the ID of the last processed message with the getLastMessageId method of the Auth object.

## Demo included in the toolkit
The Onelogin's Java Toolkit allows you to provide the settings in a unique file as described at the [Settings  section](https://github.com/onelogin/java-saml/#Settings).

#### SP setup
Configure the SP part and review the metadata of the IdP and complete the IdP info. Later configure how the toolkit will work enabling/disabling the security settings.

#### IdP setup

Once the SP is configured, the metadata of the SP is published at the /metadata.jsp url. Based on that info, configure the IdP.

#### How it works
Lets imagine we deploy the jsp example project at *http://localhost:8080/java-saml-tookit-jspsample/*.

1. First time you access to the main view *http://localhost:8080/java-saml-tookit-jspsample/index.jsp*, you can select to login and return to the same view or login and be redirected to  the attribute view (attrs).

2. When you click on a link,:

  2.1. In the first link, we are redirected to the */dologin.jsp* view. An AuthNRequest is sent to the IdP, we authenticate at the IdP and then a Response is sent to the SP, specifically to the Assertion Consumer Service view: /acs.jsp. There the SAMLResponse is validated, the NameID and user attributes extracted and stored in the session. Notice that a RelayState parameter is set to the url that initiated the process, the dologin.jsp url, but we are not redirecting the user to that view, and instead we present user data on the /acs.jsp view.

  2.2. In the second link we are redirected to the */dologin.jsp* view with a 'attrs' GET parameter. An AuthNRequest is sent to the IdP with the /attrs.jsp view as RelayState parameter, we authenticate at the IdP and then a Response is sent to the SP, specifically to the Assertion Consumer Service view: /acs.jsp. There the SAMLResponse is validated, the NameID and user attributes extracted and stored in the session and we are redirected to the RelayState view, the attrs.jsp view where user data is read from session and prompted.

3. The single log out functionality could be tested by 2 ways.

  3.1. SLO Initiated by SP. Click on the "logout" link at the SP, after that we are redirected to the /dologout.jsp view where a Logout Request is sent to the IdP, the session at the IdP is closed and replies to the SP a Logout Response (sent to the Single Logout Service endpoint). The SLS endpoint /sls.jsp of the SP process the Logout Response and if is valid, close the user session of the local app. Notice that the SLO Workflow starts and ends at the SP.

  3.2. SLO Initiated by IdP. In this case, the action takes place on the IdP side, the logout process is initiated at the IdP, it sends a Logout Request to the SP (SLS endpoint, /sls.jsp). The SLS endpoint of the SP process the Logout Request and if is valid, close the session of the user at the local app and send a Logout Response to the IdP (to the SLS endpoint of the IdP). The IdP receives the Logout Response, process it and close the session at the IdP. Notice that the SLO Workflow starts and ends at the IdP.
