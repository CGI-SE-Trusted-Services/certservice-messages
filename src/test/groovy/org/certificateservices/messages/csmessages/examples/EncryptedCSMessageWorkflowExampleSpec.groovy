package org.certificateservices.messages.csmessages.examples

import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBElement;

import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.SimpleMessageSecurityProvider;
import org.certificateservices.messages.TestUtils;
import org.certificateservices.messages.assertion.AssertionData;
import org.certificateservices.messages.assertion.AssertionPayloadParser;
import org.certificateservices.messages.assertion.jaxb.AssertionType;
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser;
import org.certificateservices.messages.credmanagement.jaxb.ChangeCredentialStatusResponse;
import org.certificateservices.messages.csmessages.CSMessageParser;
import org.certificateservices.messages.csmessages.CSMessageParserManager;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParser;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.csmessages.constants.AvailableCredentialTypes;
import org.certificateservices.messages.csmessages.jaxb.ApprovalStatus;
import org.certificateservices.messages.csmessages.jaxb.Approver;
import org.certificateservices.messages.csmessages.jaxb.ApproverType;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.CSRequest;
import org.certificateservices.messages.csmessages.jaxb.CSResponse;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.IsApprovedResponseType;
import org.certificateservices.messages.csmessages.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;
import org.certificateservices.messages.csmessages.jaxb.TokenRequest;
import org.certificateservices.messages.encryptedcsmessage.EncryptedCSMessagePayloadParser;
import org.certificateservices.messages.utils.DefaultSystemTime;
import org.certificateservices.messages.utils.MessageGenerateUtils;

import spock.lang.Shared;
import spock.lang.Specification
import static org.certificateservices.messages.csmessages.TestMessages.*
import static org.certificateservices.messages.TestUtils.*

/**
 * Examples on how to use the API when encrypting and decryting encrypted CS Messages.
 * <p>
 * This example only deals with the message generation aspects of the workflow. 
 * 
 * @author Philip Vendil
 *
 */
class EncryptedCSMessageWorkflowExampleSpec extends ExampleSpecification {
	
	// Simplest configuration using signing and encryption keystore with same key.
	// The KEYSTORELOCATION and TRUSTSTORE locations is replaeced in this script for the test to run.
	static def exampleConfig = """
simplesecurityprovider.signingkeystore.path=KEYSTORELOCATION
simplesecurityprovider.signingkeystore.password=tGidBq0Eep
simplesecurityprovider.signingkeystore.alias=test
simplesecurityprovider.trustkeystore.path=TRUSTSTORELOCATION
simplesecurityprovider.trustkeystore.password=foo123

csmessage.sourceid=SomeClientSystem
"""


	@Shared X509Certificate recepient
	
	
	def setupSpec(){
		Properties config = getConfig(exampleConfig)
		
		// Required initialization code, only needed once for an application.
		
		// Start with setting up MessageSecurityProvider, one implementation is SimpleMessageSecurityProvider
		// using Java key stores to store it's signing and encryption keys.
		MessageSecurityProvider secProv = new SimpleMessageSecurityProvider(config);
		// This mocking is for testing only (to avoid failure due to expired certificates)
		secProv.systemTime = TestUtils.mockSystemTime("2013-10-01")
		
		// Create and initialize the Default Message Provider with the security provider.
		// For client should the usually not need a reference to the CSMessageParser, use the PayloadParser
		// from PayloadParserRegistry should have all the necessary functions.
		CSMessageParserManager.initCSMessageParser(secProv, config)
		
		
		
		// Receipient key of more sensitive in-bound systems that might want to audit who approved a request. 
		recepient = secProv.getDecryptionCertificate(MessageSecurityProvider.DEFAULT_DECRYPTIONKEY)
		
	}
	

	
	def "Example of Encrypted CS Message Workflow"(){
		setup: "For this example we will need the credential management and assertion payload parser"
		CredManagementPayloadParser cmpp = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE);
		EncryptedCSMessagePayloadParser encpp = PayloadParserRegistry.getParser(EncryptedCSMessagePayloadParser.NAMESPACE);
		when: "Step 1: Try to generate plain text CS Request"
		// On Client:
		byte[] plainTextRequest = cmpp.genChangeCredentialStatusRequest(MessageGenerateUtils.generateRandomUUID(), "SomeServerSystem", "SomeOrg", "CN=SomeIssuerId", "1234", 100, "10", null, null);
		// Then encrypt this message to the receipient on the server
		byte[] encryptedRequest = encpp.genEncryptedCSMessage(plainTextRequest, [recepient])
		// Then send the encrypted request to the server
		
		
		// On Server:
		// Use the encrypted payload parser to support encryted message, but unencrypted messages can be parsed as well in the same way as the other payload parsers
		CSMessage requestMessage = encpp.parseMessage(encryptedRequest)
		// If decryption key isn't found is MessageContentException thrown with a cause of NoDecryptionKeyFoundException
		// A plain text message works just as well
		CSMessage requestMessage2 = encpp.parseMessage(plainTextRequest)
		
		then:
		requestMessage.getID() == requestMessage2.getID()
	}
	

}