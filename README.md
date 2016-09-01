# OneLogin's SAML Java Toolkit

[![Coverage Status](https://coveralls.io/repos/github/onelogin/java-saml/badge.svg?branch=v2.0.0)](https://coveralls.io/github/onelogin/java-saml?branch=v2.0.0)

Version 2.0.0

Not ready yet, it lacks documentation and not officially distributed.

Unit test compatible with java6 / java7 (java8 experiences an issue with PowerMock)
Make sure maven & your IDE uses this java version.

## TODOs

- Documentation
- Cleanup the project anb prepare for publication
- Publish on Maven central
- Be able to add cert/key on settings providing the filename instead the string
- Support KeyStore files (https://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html)
- Support RSA Private Keys

## Working with Eclipse.

### Adding the toolkit as a project

1. Open Eclipse and set a workspace
2. File > Import > Maven : Existing Maven Projects > Select the path where the core folder of the Java Toolkit is  <path>/java-saml/core, resolve the Wordkspace project and select the pom.xml

### Adding the jsp-samlple as a project

3. File > Import > Maven : Existing Maven Projects > Select the path where the core folder of the Java Toolkit is  <path>/java-saml/samples/java-saml-jspsample, resolve the Wordkspace project and select the pom.xml

### Deploy the jsp-sample

At the Package Explorer, select the jsp-sample project, 2nd bottom of the mouse and Run As > Run Server
Select a Tomcat Server in order to deploy the server.
