# OneLogin's SAML Java Toolkit

Version 2.0.0

Not ready yet, it lacks documentation and not officially distributed.


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

### Unit Tests

Known issues while testing:

 * [ECLEmma coverage plugin incompatible with PowerMock](http://stackoverflow.com/questions/23363212/powermock-eclemma-coverage-issue)
  
 * When using @PrepareForTest and PowerMockito the breakpoints not does [not stop when debugging](http://stackoverflow.com/questions/35140575/powermockito-junit-and-eclemma-debugging-dosent-work). The solution is define Rules.

 * Java7+ enforces bytecode verification and with Powermock you can experience a [java.lang.VerifyError](http://www.notonlyanecmplace.com/java-7-enforces-bytecode-verification/).
   At Java8 bytecode verification is mandatory and there is no option to disable it :(