PKI Messages Generator library
=============================
This package contains the java library to generate a parse PKI Message according to the PKI Message
specification to be used by different implementations that need to send and or receive these kind
of messages.


Overview
-----------------------------
The main API library is the file pkimessages.jar which contains all the necessary classes. For details 
see the javadoc in the *docs* library.

For example usages and more documentation go to docs/index.html with your browser.

Only JDK 1.5+ is supported.

More Documentation
-----------------------------

For more details regarding the protocol, see the [PKI Message](PKIMessage_Protocol_Specification_1.0_Revision_1.1.doc) 

Library Dependencies
-----------------------------

The following libraries is required for the API to run and is included in the *lib* directory of the distribution:

* log4j-1.2.8.jar
* bcprov-jdk15-1.44.jar
* xmlsec-1.5.2.jar

For JDK build is also the following libraries required:

* jaxb-api-2.0.jar
* jaxb-impl-2.0.5.jar

Using the API
-----------------------------
The main interface in the library is the org.certificateservices.ca.pkimessages.PKIMessageParser, 
with the default implementation called DefaultPKIMessageParser. It's in charge of generating 
(including signing) and parsing (including verification) of PKI Message XML messages.

It's recommended to create a PKIMessageParser using the PKIMessageParserFactory in which 
it's possible to dynamically define which implementation that is created. But before a 
PKIMessageParser can be created you have to implement a 
org.certificateservices.ca.pkimessages.PKIMessageSecurityProvider which is in charge of
providing a signing key/certificate as well as validating and authorizing certificates 
sent by other parties in the communication.

To Parse a message use the pKIMessageParser.parseMessage(..) method and to generate a
message use the gen\<MessageName\>(..) methods.

Available configuration settings
-----------------------------
The following settings can be used to customize the PKI message generation.

| Key                                           | Description                                                                      | Default                                                          |
|:-----------                                   |:-----------                                                                      |:------------                                                     |
| pkimessage.sourceid                           |The name of the source node in the generated messages.                            | Must be set.                                                     |
| pkimessage.sign                               |If generated messages should be signed, either "TRUE" or "FALSE"                  | "TRUE"                                                           |
| pkimessage.requiresignature                   |If recieved messages must have a valid signature, either "TRUE" or "FALSE"        |  "TRUE"                                                          |
| pkimessage.name.\<payload type in lowercase\> |A custom name of a PKI message (field in the header)                              | The payload type name in mixed case.                             |
| pkimessage.parser.impl                        |Setting indicating which implementation of PKI Message Parser created by factory. | "org.certificateservices.ca.pkimessages.DefaultPKIMessageParser" |
| pkimessage.messagenamecatalogue.impl          |Implementation if a custon message name lookup catalogue should be used.          | DefaultMessageNameCatalogue.class.getName()

JDK 1.5
-----------------------------

There exists two versions of this API, one for JDK 1.6+ and one for JDK 1.5
with different library requirements.

To build for JDK 1.5 use maven profile -Pjdk15 and it will result in a jar with -jdk15 appended
to the version name.

Dependent libraries using 1.5 should use the -jdk15 version from the repository.

For Developers of this API
-----------------------------

This is a maven project, just check-it out
and build with mvn 2:

Main command to build a binary distribution is:

###Other commands:

  To clean:
  
    mvn clean

  To compile:
  
    mvn compile

  To test:
  
    mvn test

  To package (This generates both a binary and source distribution):
  
    mvn package

  To build site:
  
    mvn site

  To build site with code coverage report (integration tests must have been setup first):
  
    mvn clean verify site -Pclover.report
    

### Eclipse notes

Import the project with a eclipse supporting maven 2 and almost everything should be set-up
automatically, only add src/test/groovy as source folder and you should be ready to go.


