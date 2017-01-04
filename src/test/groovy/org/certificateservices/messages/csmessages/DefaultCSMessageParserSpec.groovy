/************************************************************************
 *                                                                       *
 *  Certificate Service - Messages                                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.messages.csmessages;

import groovy.util.slurpersupport.GPathResult
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.MessageSecurityProvider

import java.security.Security
import java.security.cert.X509Certificate
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.parsers.DocumentBuilder;

import org.apache.xml.security.Init
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.assertion.AssertionPayloadParser
import org.certificateservices.messages.saml2.assertion.jaxb.AssertionType;
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser;
import org.certificateservices.messages.credmanagement.jaxb.FieldValue
import org.certificateservices.messages.csmessages.jaxb.ApprovalStatus;
import org.certificateservices.messages.csmessages.jaxb.Attribute;
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.csmessages.jaxb.CSResponse;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;
import org.certificateservices.messages.dummy.DummyPayloadParser;
import org.certificateservices.messages.dummy.jaxb.SomePayload;
import org.certificateservices.messages.saml2.protocol.jaxb.ResponseType;
import org.certificateservices.messages.sysconfig.SysConfigPayloadParser;
import org.certificateservices.messages.sysconfig.jaxb.GetActiveConfigurationRequest
import org.certificateservices.messages.utils.SystemTime
import org.w3c.dom.Document
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.messages.csmessages.DefaultCSMessageParser.*
import static org.certificateservices.messages.csmessages.TestMessages.*
import static org.certificateservices.messages.TestUtils.*

public class DefaultCSMessageParserSpec extends Specification{
	
	
	org.certificateservices.messages.sysconfig.jaxb.ObjectFactory sysConfigOf = new org.certificateservices.messages.sysconfig.jaxb.ObjectFactory()
	static ObjectFactory of = new ObjectFactory();
	DefaultCSMessageParser mp = new DefaultCSMessageParser()
	DefaultCSMessageParser requestMessageParser = new DefaultCSMessageParser()
	DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
	
	AssertionPayloadParser assertionPayloadParser
	CredManagementPayloadParser credManagementPayloadParser
	
	public static final String TEST_ID = "12345678-1234-4444-8000-123456789012"
	
	List<X509Certificate> recipients
	def fv1
	def fv2
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
	}
	
	def setup(){
		Properties requestConfig = new Properties();
		requestConfig.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMEREQUESTER");
		requestMessageParser =  CSMessageParserManager.initCSMessageParser(secprov,requestConfig)


		
		Properties config = new Properties();
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID");
		mp.init(secprov, config)
		
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE)
		assertionPayloadParser.systemTime = Mock(SystemTime)
		assertionPayloadParser.systemTime.getSystemTime() >> new Date(1436279213000)
		
		
		credManagementPayloadParser = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE)
		
		
		X509Certificate validCert = secprov.getDecryptionCertificate(secprov.decryptionKeyIds.iterator().next())
		recipients = [validCert]
		
		fv1 = new FieldValue();
		fv1.key = "someKey1"
		fv1.value = "someValue1"
		fv2 = new FieldValue();
		fv2.key = "someKey2"
		fv2.value = "someValue2"
	
	}
	
	def "Verify init()"(){
		expect:
		PayloadParserRegistry.configurationCallback != null
		mp.properties != null
		mp.securityProvider instanceof DummyMessageSecurityProvider
		mp.messageNameCatalogue != null
		mp.jaxbData.jaxbContext != null
		mp.jaxbData.csMessageMarshallers.size() == SUPPORTED_CSMESSAGE_VERSIONS.length
		mp.jaxbData.csMessageUnmarshallers.size() == SUPPORTED_CSMESSAGE_VERSIONS.length
		mp.sourceId == "SOMESOURCEID"
	}
	


	def "Verify that generateIsApprovalRequest() generates a valid xml message and generateIsApprovalResponse() generates a valid CSMessageResponseData"(){
		when:
		byte[] requestMessage = requestMessageParser.generateIsApprovedRequest(TEST_ID, "SOMESOURCEID", "someorg", "123-212", createOriginatorCredential(), null);
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.IsApprovedRequest
		then:
		messageContainsPayload requestMessage, "cs:IsApprovedRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","IsApprovedRequest", createOriginatorCredential())
		payloadObject.approvalId == "123-212"
		
		when:
		CSMessage request = mp.parseMessage(requestMessage)
		CSMessageResponseData rd = mp.generateIsApprovedResponse("SomeRelatedEndEntity", request, ApprovalStatus.APPROVED, createAssertions())
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IsApprovedResponse
		
		then:
		messageContainsPayload rd.responseData, "cs:IsApprovedResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "IsApprovedResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IsApprovedResponse", createOriginatorCredential())
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.approvalId == "123-212"
		payloadObject.approvalStatus == ApprovalStatus.APPROVED.toString()
		payloadObject.assertions.Assertion.size() == 2
		payloadObject.assertions.Assertion[0].AttributeStatement.Attribute[0].AttributeValue == "APPROVAL_TICKET"
	}
	
	
	def "Verify that generateGetApprovalRequest() generates a valid xml message  generateGetApprovalResponse() generates a valid CSMessageResponseData"(){
		setup:
		SysConfigPayloadParser scpp = PayloadParserRegistry.getParser(SysConfigPayloadParser.NAMESPACE);
		when:
		byte[] reqData = scpp.generateGetActiveConfigurationRequest(TEST_ID, "someDest", "someorg", "SomeApp", null, null)

		byte[] requestMessage = requestMessageParser.generateGetApprovalRequest(TEST_ID, "SOMESOURCEID", "someorg", reqData, createOriginatorCredential(), null);
		
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetApprovalRequest

		then:
		
		messageContainsPayload requestMessage, "cs:GetApprovalRequest"
		messageContainsPayload requestMessage, "sysconfig:GetActiveConfigurationRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetApprovalRequest", createOriginatorCredential())
		payloadObject.requestPayload.GetActiveConfigurationRequest.application == "SomeApp"
		payloadObject.requestPayload.GetActiveConfigurationRequest.organisationShortName == "someorg"
		
		when:
		CSMessage request = mp.parseMessage(requestMessage)
		CSMessageResponseData rd = mp.generateGetApprovalResponse("SomeRelatedEndEntity", request, "123-212",ApprovalStatus.APPROVED, createAssertions())
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetApprovalResponse
		
		then:
		messageContainsPayload rd.responseData, "cs:GetApprovalResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetApprovalResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetApprovalResponse", createOriginatorCredential())
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.approvalId == "123-212"
		payloadObject.approvalStatus == ApprovalStatus.APPROVED.toString()
		payloadObject.assertions.Assertion.size() == 2
		payloadObject.assertions.Assertion[0].AttributeStatement.Attribute[0].AttributeValue == "APPROVAL_TICKET"
		
		when:
		mp.parseMessage(getApprovalRequestWithInvalidRequestPayload)

		then:
		thrown MessageContentException		

	}

	
	def "Verify that genCSFailureResponse() generates correct failure response message"(){
		setup:
		byte[] requestMessage = mp.generateIsApprovedRequest(TEST_ID, "somedest", "someorg", "someid", null, null);
		when:
		CSMessageResponseData rd = mp.genCSFailureResponse("SomeRelatedEndEntity", requestMessage, RequestStatus.ILLEGALARGUMENT, "SomeFailureMessage", "somedest", createOriginatorCredential())
		def xml = slurpXml(rd.responseData)
		then:
		messageContainsPayload rd.responseData, "cs:FailureResponse"
		
		verifyCSMessageResponseData  rd, "somedest", TEST_ID, false, "FailureResponse", "SomeRelatedEndEntity"		
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "somedest", "someorg","FailureResponse", createOriginatorCredential())
		
		xml.payload.FailureResponse.inResponseTo == TEST_ID
		xml.payload.FailureResponse.status == "ILLEGALARGUMENT"
		xml.payload.FailureResponse.failureMessage == "SomeFailureMessage"
		
		when:
		rd = mp.genCSFailureResponse("SomeRelatedEndEntity", requestMessage, RequestStatus.ILLEGALARGUMENT, null, "somedest", createOriginatorCredential())
		xml = slurpXml(rd.responseData)
	
		then:
		xml.payload.FailureResponse.inResponseTo == TEST_ID
		xml.payload.FailureResponse.status == "ILLEGALARGUMENT"
		xml.payload.FailureResponse.failureMessage.size() == 0
	}
	
	def "Verify that getSigningCertificate parses signer certificate"(){
		expect:
		mp.requireSignature()
		mp.getSigningCertificate(simpleCSMessage) instanceof X509Certificate
		when:
		mp.requireSignature = false
		then:
		mp.getSigningCertificate(simpleCSMessage) == null

		when:
		mp.requireSignature = true
		mp.getSigningCertificate(simpleCSMessageWithBadCertificate)
		then:
		thrown MessageContentException
		
	}
	
	def "Verify that genCSMessage() generates a valid header structure"(){
		when: "Create minimal cs message"
		CSMessage m = mp.genCSMessage("2.0", "2.1", null, null, "somedest", "someorg", null, createPayLoad(), null)
		then:
		m.id != null && m.id != TEST_ID;
		m.timeStamp != null
		m.organisation == "someorg"
		m.name == "GetActiveConfigurationRequest"
		m.sourceId == "SOMESOURCEID"
		m.destinationId == "somedest"
		m.originator == null
		m.assertions == null
		m.payload.any instanceof GetActiveConfigurationRequest
		m.version == "2.0"
		m.payLoadVersion == "2.1"
		m.signature == null
		
		when: "Create full cs message"
		m = mp.genCSMessage("2.0", "2.1", "NameRequest", TEST_ID, "somedest", "someorg", createOriginatorCredential(), createPayLoad(), null)
		then:
		m.id == TEST_ID;
		m.timeStamp != null
		m.organisation == "someorg"
		m.name == "GetActiveConfigurationRequest"
		m.sourceId == "SOMESOURCEID"
		m.destinationId == "somedest"
		m.originator.credential.displayName == "SomeOrignatorDisplayName"
		m.payload.any instanceof GetActiveConfigurationRequest
		m.version == "2.0"
		m.payLoadVersion == "2.1"
		m.signature == null
	}
	
	
	def "Verify populateSuccessfulResponse handles both CSResponse and JAXBElement input"(){
		setup:
		CSMessage request = mp.parseMessage(mp.generateIsApprovedRequest(TEST_ID, "somedest", "someorg", "someid", null, null));
		
		when:
		CSResponse csResponse = sysConfigOf.createGetActiveConfigurationResponse()
		mp.populateSuccessfulResponse(csResponse, request)
		then:
		csResponse.status == RequestStatus.SUCCESS
		csResponse.inResponseTo == TEST_ID
		csResponse.failureMessage == null
		
		when:
		Object jaxbResponse = of.createIsApprovedResponse(of.createIsApprovedResponseType())
		mp.populateSuccessfulResponse(jaxbResponse, request)
		then:
		jaxbResponse.value.status == RequestStatus.SUCCESS
		jaxbResponse.value.inResponseTo == TEST_ID
		jaxbResponse.value.failureMessage == null
		
		when:
		mp.populateSuccessfulResponse(new Integer(1), request)
		then:
		thrown MessageProcessingException
	}
	
	def "Verify that marshallAndSignCSMessage generates correct signatures"(){
		setup:
		def csMessage = mp.genCSMessage("2.0", "2.0", null, TEST_ID, "somedest", "someorg", null, createPayLoad(), createAssertions())
		expect:
		mp.requireSignature()
		
		when:
		String msg = new String(mp.marshallAndSignCSMessage(csMessage), "UTF-8")
		then:
		msg =~ "ds:Signature"
		mp.parseMessage(msg.getBytes("UTF-8"))
		
		when:
		mp.requireSignature = false
		msg = new String(mp.marshallAndSignCSMessage(csMessage), "UTF-8")
		
		then:
		msg !=~ "ds:Signature"
		
		
	}


	def "Verify that parseMessage performsValidation if flag is set to true"(){
		setup:
		def orgSecProv = mp.xmlSigner.messageSecurityProvider
		def csMessage = mp.genCSMessage("2.0", "2.0", null, TEST_ID, "somedest", "someorg", null, createPayLoad(), createAssertions())
		byte[] msg = mp.marshallAndSignCSMessage(csMessage)
		mp.xmlSigner.messageSecurityProvider = Mock(MessageSecurityProvider)
		when:
		mp.parseMessage(msg, true)
		then:
		1 * mp.xmlSigner.messageSecurityProvider.isValidAndAuthorized(_,_) >> true

		cleanup:
		true
		mp.xmlSigner.messageSecurityProvider  = orgSecProv
	}

	def "Verify that parseMessage doesn't performsValidation if flag is set to false"(){
		setup:
		def orgSecProv = mp.xmlSigner.messageSecurityProvider
		def csMessage = mp.genCSMessage("2.0", "2.0", null, TEST_ID, "somedest", "someorg", null, createPayLoad(), createAssertions())
		byte[] msg = mp.marshallAndSignCSMessage(csMessage)
		mp.xmlSigner.messageSecurityProvider = Mock(MessageSecurityProvider)
		when:
		mp.parseMessage(msg, false)
		then:
		0 * mp.xmlSigner.messageSecurityProvider.isValidAndAuthorized(_,_)

		cleanup:
		true
		mp.xmlSigner.messageSecurityProvider  = orgSecProv
	}

	
	
	def "Verify validateCSMessage() method"(){
		when: "Verify that valid message passes validation"
		mp.validateCSMessage(mp.getVersionFromMessage(simpleCSMessage), mp.parseMessage(simpleCSMessage), getDoc(simpleCSMessage),true)
		then:
		true
		
		when: "Verify that non CSMessage object throws MessageContentException"
		mp.validateCSMessage(null, new Object(), null, true)
		then:
		thrown MessageContentException
		
		when: "Verify invalid signature throws MessageContentException"
		mp.validateCSMessage(mp.getVersionFromMessage(cSMessageWithInvalidSignature), mp.parseMessage(cSMessageWithInvalidSignature), getDoc(cSMessageWithInvalidSignature), true)
		then:
		final MessageContentException e1 = thrown()
		e1.message =~ "signed message"
		
		when: "Verify invalid payload throws MessageContentException"
		mp.validateCSMessage(mp.getVersionFromMessage(simpleCSMessageWithInvalidPayload), mp.parseMessage(simpleCSMessageWithInvalidPayload), getDoc(simpleCSMessageWithInvalidPayload), true)
		then:
		final MessageContentException e2 = thrown()
		e2.message =~ "parsing payload"
		
	}
	
	def "Verify that verifyCSMessageVersion returns true for supported versions and throws MessageContentException for unsupported versions"(){
		expect:
		mp.verifyCSMessageVersion(SUPPORTED_CSMESSAGE_VERSIONS[0]) 
		
		when:
		mp.verifyCSMessageVersion("unsupported")
		
		then:
		thrown MessageContentException
	}
	
	def "Verify that validateSignature correctly parses the ds:Signature object and verifies the signature"(){
		expect:
		mp.requireSignature() == true
		
		when:
		mp.validateSignature(getDoc(simpleCSMessage), true)
		// Verify that no exception is thrown
		mp.validateSignature(getDoc(cSMessageWithInvalidSignature), true)
		then:
		thrown MessageContentException
		
		when:
		mp.validateSignature(getDoc(simpleCSMessageWithoutSignature), true)
		then:
		thrown MessageContentException
		
		when:
		mp.requireSignature = false
		mp.validateSignature(getDoc(cSMessageWithInvalidSignature), true)
		mp.validateSignature(getDoc(simpleCSMessageWithoutSignature), true)
		
		then:
		true // No exception was thrown for invalid signature
		
	}
	
	def "Verify that DocumentBuilder is create and cached"(){
		when:
		DocumentBuilder db = mp.getDocumentBuilder()
		then:
		mp.documentBuilder == db
	}
	
	def "Verify that getVersionFromMessage parses version and payload version from message"(){
		when:
		CSMessageVersion v = mp.getVersionFromMessage(simpleCSMessagePayloadVersion2_1)
		then:
		v.messageVersion == "2.0"
		v.payLoadVersion == "2.1"
	}
	
	@Unroll
	def "Verify that getVersionFromMessage throws MessageContentException for invalid message data"(){
		when:
	    mp.getVersionFromMessage(message)
		then:
		thrown MessageContentException
		where:
		message << [ simpleCSMessageWithEmptyVersion, simpleCSMessageWithEmptyPayloadVersion, simpleCSMessageWithoutVersion, simpleCSMessageWithoutPayloadVersion, invalidXML]
	}
	
	@Unroll
	def "Verify that signMessages() returns #expected for property: #property"(){
		setup:
		Properties p = new Properties()
		p.load(new StringReader(property))
		mp.properties = p
		mp.signMessages = null
		expect:
		mp.signMessages() == expected
		mp.signMessages == expected
		
		where:
		property                     | expected
		"notset="                    | true
		"csmessage.sign= tRue "      | true
		"csmessage.sign= False "     | false
		"pkimessage.sign= tRue "     | true
		"pkimessage.sign= False "    | false
	}
	
	def "Verify that signMessages() throws MessageProcessingException if missconfigured"(){
		setup:
		Properties p = new Properties()
		p.load(new StringReader("csmessage.sign= InvalidBoolean "))
		mp.properties = p
		mp.signMessages = null
		
		when:
		mp.signMessages() 

		then:
		thrown (MessageProcessingException)

	}
	
	def "Verify that getMessageNameCatalogue() generates MessageNameCatalogue correctly"(){
		setup:
		def p = new Properties();
		expect: "Verify that default Message Name Catalogue is returned by default"
		mp.getMessageNameCatalogue(p) instanceof DefaultMessageNameCatalogue
		
		when: "Generate a cusom MessageNameCatalogue and verify that initilize is called"
		p.setProperty(SETTING_MESSAGE_NAME_CATALOGUE_IMPL, TestMessageNameCatalogue.class.getName())
		TestMessageNameCatalogue tmnc = mp.getMessageNameCatalogue(p)
		then:
		tmnc.initCalled
		
		when: "Verify that MessageProcessingException is thrown if invalid classpath is configured"
		p.setProperty(SETTING_MESSAGE_NAME_CATALOGUE_IMPL, "somepkg.InvalidClass")
		mp.getMessageNameCatalogue(p)
		then:
		thrown MessageProcessingException
		
	}
	
	@Unroll
	def "Verify that requireSignature() returns #expected for property: #property"(){
		setup:
		Properties p = new Properties()
		p.load(new StringReader(property))
		mp.properties = p
		mp.requireSignature == null
		expect:
		mp.requireSignature() == expected
		mp.requireSignature == expected
		
		where:
		property                                 | expected
		"notset="                  			     | true
		"csmessage.requiresignature= tRue "      | true
		"csmessage.requiresignature= False "     | false
		"pkimessage.requiresignature= tRue "     | true
		"pkimessage.requiresignature= False "    | false
	}
	
	def "Verify that requireSignature() throws MessageProcessingException if missconfigured"(){
		setup:
		Properties p = new Properties()
		p.load(new StringReader("csmessage.requiresignature= InvalidBoolean "))
		mp.properties = p
		
		when:
		mp.requireSignature()

		then:
		thrown (MessageProcessingException)

	}
	
	def "Verify that getMessageSecurityProvider()  isnt null"(){
		expect:
		mp.getMessageSecurityProvider() != null
	}
	
	def "Verify that JAXB Related Data helper method works"(){
		setup:		
	
		mp.jaxbData.getJAXBIntrospector()
		expect: // Verify that JAXB data isn't cleaned
		mp.jaxbData.jaxbClassPath =~ "org.certificateservices.messages.csmessages.jaxb"
		mp.jaxbData.jaxbClassPath =~ ":org.certificateservices.messages.sysconfig.jaxb"
		mp.jaxbData.jaxbContext != null
		mp.jaxbData.jaxbIntrospector != null
		mp.jaxbData.csMessageMarshallers.size() != 0
		mp.jaxbData.csMessageUnmarshallers.size() != 0
		
		
		when:
		mp.jaxbData.clearAllJAXBData()
		
		then:
		mp.jaxbData.jaxbClassPath == ""
		mp.jaxbData.jaxbContext == null
		mp.jaxbData.payLoadValidatorCache.size() == 0
		mp.jaxbData.jaxbIntrospector == null
		mp.jaxbData.csMessageMarshallers.size() == 0
		mp.jaxbData.csMessageUnmarshallers.size() == 0
		
		mp.jaxbData.getJAXBContext() != null
		mp.jaxbData.getJAXBIntrospector() != null
		mp.jaxbData.getCSMessageMarshaller("2.0") != null 
		mp.jaxbData.getCSMessageUnmarshaller("2.0") != null
		mp.jaxbData.getPayLoadValidatorFromCache(SysConfigPayloadParser.NAMESPACE, "2.0", "2.0") != null
		
		mp.jaxbData.jaxbClassPath =~ "org.certificateservices.messages.csmessages.jaxb"
		mp.jaxbData.jaxbContext !=null
		mp.jaxbData.jaxbIntrospector != null
		mp.jaxbData.csMessageMarshallers.size() == 1
		mp.jaxbData.csMessageUnmarshallers.size() == 1

		when: "Try to add a dummy payload parser"
		
		PayloadParserRegistry.register(DummyPayloadParser.NAMESPACE, DummyPayloadParser.class)
		
		then: "Verify that jaxbContext is cleared after new registration"
		mp.jaxbData.jaxbContext == null
		
		when:
		mp.jaxbData.getJAXBContext() != null
		mp.jaxbData.getJAXBIntrospector() != null
		mp.jaxbData.getCSMessageMarshaller("2.0") != null
		mp.jaxbData.getCSMessageUnmarshaller("2.0") != null
		mp.jaxbData.getPayLoadValidatorFromCache(SysConfigPayloadParser.NAMESPACE, "2.0", "2.0") != null
		mp.jaxbData.getPayLoadValidatorFromCache(DummyPayloadParser.NAMESPACE, "2.0", "2.0") != null
		then:
		mp.jaxbData.jaxbClassPath =~ "org.certificateservices.messages.dummy.jaxb"
		mp.jaxbData.jaxbContext != null
		mp.jaxbData.jaxbIntrospector != null
		mp.jaxbData.csMessageMarshallers.size() == 1
		mp.jaxbData.csMessageUnmarshallers.size() == 1
		when: "Try to generate new payload with registered dummy parser"
		// Test to generate and parse new payload parser
		DummyPayloadParser dp = PayloadParserRegistry.getParser(DummyPayloadParser.NAMESPACE)
		byte[] data = mp.generateCSRequestMessage(TEST_ID, "someDest", "SomeOrg", "2.0", dp.genSomePayload("SomeValue"), null)
		CSMessage cSMessage = mp.parseMessage(data)
		SomePayload somePayload = cSMessage.getPayload().getAny()
		
		then:
		somePayload.someValue == "SomeValue"
	
		when: "Try to remove dummy parser again and check that it's not possible to parse dummy messages any more."
		PayloadParserRegistry.deregister(DummyPayloadParser.NAMESPACE)
		then: "Verify that jaxbContext is cleared after de-registration"
		mp.jaxbData.jaxbContext == null
		
		when:
		mp.jaxbData.getJAXBContext() != null
		mp.jaxbData.getJAXBIntrospector() != null
		mp.jaxbData.getCSMessageMarshaller("2.0") != null
		mp.jaxbData.getCSMessageUnmarshaller("2.0") != null
		mp.jaxbData.getPayLoadValidatorFromCache(SysConfigPayloadParser.NAMESPACE, "2.0", "2.0") != null
		then:
		mp.jaxbData.jaxbClassPath !=~ "org.certificateservices.messages.dummy.jaxb"
		mp.jaxbData.jaxbContext != null
		mp.jaxbData.jaxbIntrospector != null
		mp.jaxbData.csMessageMarshallers.size() == 1
		mp.jaxbData.csMessageUnmarshallers.size() == 1
		
		when: "Verify that parsing a message with dummy data throws MessageContentException"
		mp.parseMessage(data)
		then:
		thrown MessageContentException
	}
	
	
	@Unroll
	def "Verify that getMarshaller returns a marshaller for CS Message Version: #version"(){
		setup:
		CSMessage m = new CSMessage();
		m.version = version
		expect:
		mp.getMarshaller(m) instanceof Marshaller
		where:
		version << DefaultCSMessageParser.SUPPORTED_CSMESSAGE_VERSIONS
	}
	
	def "Test to generate a ChangeCredentialStatusRequest with two assertions, verify that validation of assertions is ok"(){
		setup:
		ResponseType ticketResp =  assertionPayloadParser.parseAttributeQueryResponse(assertionPayloadParser.genDistributedAuthorizationTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"], recipients))
		JAXBElement<AssertionType> ticketAssertion = assertionPayloadParser.getAssertionFromResponseType(ticketResp)
		JAXBElement<AssertionType> approvalResp = assertionPayloadParser.parseApprovalTicket(assertionPayloadParser.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"], null, null,null))
		def assertions = [approvalResp, ticketAssertion]
		when:
		byte[] requestData = credManagementPayloadParser.genChangeCredentialStatusRequest(TEST_ID, "somedst", "someorg", "someissuer", "123", 100, "", null, assertions)
		//printXML(requestData)
		def xml = slurpXml(requestData)
		then:
		xml.assertions.size() == 1
		xml.assertions.Assertion.size() == 2
		xml.assertions.Assertion[0].AttributeStatement.Attribute[0].AttributeValue == "APPROVAL_TICKET"
		xml.assertions.Assertion[1].AttributeStatement.Attribute[0].AttributeValue == "AUTHORIZATION_TICKET"
		
		when: "Test to parse ticket with assertion "
		CSMessage csMessage = credManagementPayloadParser.parseMessage(requestData)
		
		then:
		csMessage != null
	}

	private void verifyCSHeaderMessage(byte[] messageData, GPathResult xmlMessage, String expectedSourceId, String expectedDestinationId, String expectedOrganisation, String expectedName, Credential expectedOriginator){
		verifyCSHeaderMessage(messageData, xmlMessage, expectedSourceId, expectedDestinationId, expectedOrganisation, expectedName, expectedOriginator, mp)
	}
	
	private static void verifyCSHeaderMessage(byte[] messageData, GPathResult xmlMessage, String expectedSourceId, String expectedDestinationId, String expectedOrganisation, String expectedName, Credential expectedOriginator, DefaultCSMessageParser mp){
		String message = new String(messageData,"UTF-8")
		assert message.contains("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"")
		assert message.contains("xmlns:cs=\"http://certificateservices.org/xsd/csmessages2_0\"")
		assert message.contains("xsi:schemaLocation=\"http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd\"")
		
		assert DefaultCSMessageParser.SUPPORTED_CSMESSAGE_VERSIONS.find { 
			it == xmlMessage.@version.toString() 
			}
		assert xmlMessage.@ID != null
		assert xmlMessage.name == expectedName
		assert xmlMessage.sourceId == expectedSourceId
		assert xmlMessage.destinationId == expectedDestinationId
		assert xmlMessage.organisation == expectedOrganisation
		assert xmlMessage.payload != null
		assert xmlMessage.@payloadVersion != null
		assert xmlMessage.@timeStamp != null
		
		if(expectedOriginator != null){
			assert xmlMessage.originator.credential.displayName == expectedOriginator.displayName
		}
		
		assert xmlMessage.Signature != null
		mp.validateSignature(mp.getDocumentBuilder().parse(new ByteArrayInputStream(message.getBytes())), true)
	}
	
	public static void verifySuccessfulBasePayload(GPathResult payLoadObject, String expectedResponseTo){
	  assert payLoadObject.inResponseTo == expectedResponseTo
	  assert payLoadObject.status == "SUCCESS"
	  assert payLoadObject.failureMessage.size() == 0
	}
	
	private Object createPayLoad(){
		GetActiveConfigurationRequest payLoad = sysConfigOf.createGetActiveConfigurationRequest()
		payLoad.application = "asdf"
		payLoad.organisationShortName = "SomeOrg"
		
		return payLoad
	}
	

	public static Credential createOriginatorCredential(){
		Credential c = of.createCredential();
		

		c.credentialRequestId = 123
		c.credentialType = "SomeCredentialType"
		c.credentialSubType = "SomeCredentialSubType"
		c.uniqueId = "SomeOriginatorUniqueId"
		c.displayName = "SomeOrignatorDisplayName"
		c.serialNumber = "SomeSerialNumber"
		c.issuerId = "SomeIssuerId"
		c.status = 100
		c.credentialData = "12345ABCEF"
		
		GregorianCalendar gc = new GregorianCalendar();
		gc.setTime(new Date(1234L));
		
		c.issueDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		c.issueDate.setTimezone(60)
		
		gc = new GregorianCalendar();
		gc.setTime(new Date(2234L));
		c.expireDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		c.expireDate.setTimezone(60)
		gc = new GregorianCalendar();
		gc.setTime(new Date(3234L));
		c.validFromDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		c.validFromDate.setTimezone(60)
		Attribute attr = of.createAttribute();
		attr.setKey("someattrkey")
		attr.setValue("someattrvalue")
		
		c.setAttributes(new Credential.Attributes())
		c.getAttributes().getAttribute().add(attr)

		c.setUsages(new Credential.Usages())
		c.getUsages().getUsage().add("someusage")
		

		return c
	}
	
	private List<Object> createAssertions(){
		def as1 = assertionPayloadParser.parseApprovalTicket(assertionPayloadParser.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"], null, null,null))
		def as2 = assertionPayloadParser.parseApprovalTicket(assertionPayloadParser.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","2345",["fdasdf", "asdf"], null,null,null))
		return [as1,as2];
	}
	
	private Document getDoc(byte[] message){
		return mp.getDocumentBuilder().parse(new ByteArrayInputStream(message))
	}
}
