# Certservice-messages Project

This a project containing Java code to generate and parse various messages within other certservice projects.

It mainly consists of the following parts:

* CS Message 2.0 (core message format) with a set of Payload Parsers (which also are generators).
	* Credential Management Payload Parser
	* Key Store Managment Payload Parser
	* System Configuration Payload Parser
	* Assertion Payload Parser
	* Authorization Payload Parser
	* Encrypted CS Message Payload Parser

* PKI Message generator (Older core message format) containing messages for credential management. 

* Framework for generating and parsing Receipt Messages (but no actual message implementation exists in this project. See org.certificateservices.messages.receipts package for details. To implement a custom kind of receipt message used by certservice-ejbcacomponents or certservice-ejbcaproviders implement a custom RecieptParser, add the jar to the main applications classpath and use settings defined in certservice-ejbcacomponents or certservice-ejbcaproviders to specify your implementation.

* Framework for generating and parsing Heartbeat Messages (but no actual message implementation exists in this project. See org.certificateservices.messages.heartbeat package for details. To implement a custom kind of receipt message used by certservice-ejbcacomponents or certservice-ejbcaproviders implement a custom HeartBeatParser, add the jar to the main applications classpath and use settings defined in certservice-ejbcacomponents or certservice-ejbcaproviders to specify your implementation.

# Message Specification Documentation

For detailed documentation of each available message and its content see directory src/site/resources.

# Using CS Message 2.0 Framework to generate or parse messages.

Before you start generating or parsing a CS Message 2.0 you need to initialize it once using a call to org.certificateservices.messages.csmessages.initCSMessageParser(MessageSecurityProvider securityProvider, Properties config). You can later retrieve the CSMessageParser using the getCSMessageParser() metod. As security provider you can either implement your own of use the org.certificateservices.messages.SimpleMessageSecurityProvider.

## Main Configuration Settings

By default is the DefaultCSMessageManager returned, but a custom implementation implementing CSMessageParser can be used as well

Settings for the configuration manager are:

| Key                                    | Description                                                       | Default value |
|----------------------------------------|-------------------------------------------------------------------|---------------|
| csmessage.parser.impl                  | Implementation of CS Message Parser that should be used.          | org.certificateservices.messages.csmessages.DefaultCSMessageParser |

## DefaultCSMessageParser Settings

The default CS Message Parser have the following setting (pkimessage variants of the key is accepted for backward compability, see section for PKI Messages):

| Key                                    | Description                                                        | Default value |
|----------------------------------------|--------------------------------------------------------------------|---------------|
| csmessage.sourceid                     | Source Id system sending messages, (Required)                      | No Default    |
| csmessage.sign                         | If generated messages should be signed.                            | true          |
| csmessage.requiresignature             | If parsed message has to have a valid signature.                   | true          |
| csmessage.messagenamecatalogue.impl    | If custom message name catalogue should be used.                   | See below     |

As default is Default Message Name Catalogue (setting the 'name' element in the message header), The default implementation takes the element name of the payload and sets it as message name. But specific organisations might have their own custom message names.

## SimpleMessageSecurityProvider Settings.

The simple message security provider uses a set of JKS as backend storage of its keys and have
the following settings.

| Key                                              | Description                                                                    | Default value |
|--------------------------------------------------|--------------------------------------------------------------------------------|---------------|
| simplesecurityprovider.signingkeystore.path      | Setting indicating the path to the signing JKS key store (Required)            | No Default    |
| simplesecurityprovider.signingkeystore.password  | Setting indicating the password to the signing key store (Required)            | No Default    |
| simplesecurityprovider.signingkeystore.alias     | The alias of the certificate to use in the signing key store (Required)        | No Default    |
| simplesecurityprovider.decryptkeystore.path      | The path to the decrypt JKS key store (optional, if not set is signing keystore used for both signing and encryption) | No Default    |
| simplesecurityprovider.decryptkeystore.password  | The password to the decrypt JKS key store (optional, if not set is signing keystore used for both signing and encryption) | No Default    |
| simplesecurityprovider.decryptkeystore.defaultkey.alias | the alias of the decryption key to use if no specific key is known. (optional, if not set is same as signing keystore alias used.) | No Default    |
| simplesecurityprovider.trustkeystore.path      | The path to the trust JKS key store (Required)            | No Default    |
| simplesecurityprovider.trustkeystore.password  | The password to the trust JKS key store (Required)            | No Default    |
| simplesecurityprovider.signature.algorithm     | Signature algorithm scheme to use, possible values are: RSAWithSHA256            | RSAWithSHA256    |
| simplesecurityprovider.encryption.algorithm    | Encryption algorithm scheme to use, possible values are: RSA_OAEP_WITH_AES256, RSA_PKCS1_5_WITH_AES256 | RSA_OAEP_WITH_AES256 |

## Generating CS 2.0 Messages using payload parser.

After initializing the CS Message Parser it is possible to generate messages using a payload parser. Payload parser can be retrived from org.certificateservices.messages.csmessages.PayloadParserRegistry using the method getParser(String namespace). It is also possible to add your own implementations of a payload parser by using the register() method.

For examples on using the payload parser, especially on using it in combination with assertions. See work-flow examples in src/test/groovy/org/certificateservices/messages/csmessages/examples directory.

### Available Payload Parsers.

The following build in pay load parser exists.

* Credential Management Payload Parser, to generate credential management messages, See org.certificateservices.messages.credmanagement.CredManagementPayloadParser

* Key Store Managment Payload Parser for generate key store management messages, see org.certificateservices.messages.keystoremgmt.KeystoreMgmtPayloadParser

* System Configuration Payload Parser to generate system configuration messages, see org.certificateservices.messages.sysconfig.SysConfigPayloadParser

* Assertion Payload Parser to generate assertions inserted into other payload messages, see org.certificateservices.messages.assertion.AssertionPayloadParser

* Encrypted CS Message Payload Parser, not actually a payload but encrypts an entire CS Message into an Encrypted variant, see org.certificateservices.messages.encryptedcsmessage.EncryptedCSMessagePayloadParser

# Generating older PKI Messages

PKI Message was the first generation messages sent between clients and CA, mainly for requesting certificates.

To start generating or parsing messages create a PKI Message Parser using the org.certificateservices.messages.pkimessages.PKIMessageParserFactory
and instansiate a parser with the method genPKIMessageParser(MessageSecurityProvider securityProvider, Properties config). The MessageSecurityProvider
is the same as for CS Message Parser but doens't use any encryption functionality. 

## Main Configuration Settings

The following general setting exists for PKI Message Parsers:

| Key                                    | Description                                                       | Default value |
|----------------------------------------|-------------------------------------------------------------------|---------------|
| pkimessage.parser.impl                  | Implementation of PKI Message Parser that should be used.          | org.certificateservices.messages.pkimessages.DefaultPKIMessageParser |

## DefaultCSMessageParser Settings

For the DefaultPKIMessageParser also exists the following settings:

| Key                                    | Description                                                        | Default value |
|----------------------------------------|--------------------------------------------------------------------|---------------|
| pkimessage.sourceid                    | Source Id system sending messages, (Required)                      | No Default    |
| pkimessage.sign                        | If generated messages should be signed.                            | true          |
| pkimessage.requiresignature            | If parsed message has to have a valid signature.                   | true          |
| pkimessage.messagenamecatalogue.impl   | If custom message name catalogue should be used.                   | See below     |


# For Developers of this API

This is a maven project, just check-it out and build with mvn 2 and java 6 +:

Main command to build a binary distribution is:

## Other commands:

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
    

##  Eclipse notes

Import the project with a eclipse supporting maven 2 and almost everything should be set-up
automatically, only add src/test/groovy as source folder and you should be ready to go.
