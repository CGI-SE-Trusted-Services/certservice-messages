package org.certificateservices.messages.credmanagement;

import java.security.KeyStore;
import java.util.List;

import javax.xml.datatype.DatatypeFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.utils.Base64;
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.TestUtils;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.csmessages.jaxb.Attribute;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.CredentialRequest;
import org.certificateservices.messages.csmessages.jaxb.Organisation;
import org.certificateservices.messages.csmessages.jaxb.Token;
import org.certificateservices.messages.csmessages.jaxb.User;
import org.certificateservices.messages.credmanagement.jaxb.FieldValue;
import org.certificateservices.messages.credmanagement.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.jaxb.CredentialStatusList;
import org.certificateservices.messages.csmessages.jaxb.TokenRequest;
import org.certificateservices.messages.utils.MessageGenerateUtils;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

class CredManagementPayloadParserSpec extends Specification {
	
	CredManagementPayloadParser pp;
	ObjectFactory of = new ObjectFactory()
	org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()
	Calendar cal = Calendar.getInstance();
	
	
	def setupSpec(){
		Init.init();
	}
	

	def setup(){
		setupRegisteredPayloadParser();
		
		pp = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE);
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "org.certificateservices.messages.credmanagement.jaxb"
		pp.getNameSpace() == "http://certificateservices.org/xsd/credmanagement2_0"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getDefaultPayloadVersion() == "2.0"
		pp.getSupportedVersions() == ["2.0"] as String[]
	}
	
	
	def "Verify that genIssueTokenCredentialsRequest() generates a valid xml message and genIssueTokenCredentialsResponse() generates a valid CSMessageResponseData"(){
		
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genIssueTokenCredentialsRequest(TEST_ID, "SOMESOURCEID", "someorg", createTokenRequest(), null,  createOriginatorCredential(), null)
		printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.IssueTokenCredentialsRequest
		
		pp.parseMessage(requestMessage) // verify that the message parses
		
		then:
		messageContainsPayload requestMessage, "credmanagement:IssueTokenCredentialsRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","IssueTokenCredentialsRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.tokenRequest.user == "someuser"
		payloadObject.fieldValues.size() == 0
		
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		requestMessage = pp.genIssueTokenCredentialsRequest(TEST_ID, "SOMESOURCEID", "someorg", createTokenRequest(), createFieldValues(),  createOriginatorCredential(), null)
		//printXML(requestMessage)
		xml = slurpXml(requestMessage)
		payloadObject = xml.payload.IssueTokenCredentialsRequest

		then:
		messageContainsPayload requestMessage, "credmanagement:IssueTokenCredentialsRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","IssueTokenCredentialsRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.tokenRequest.user == "someuser"
		payloadObject.fieldValues.fieldValue[0].key == "someKey1"
		payloadObject.fieldValues.fieldValue[1].key == "someKey2"
		
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genIssueTokenCredentialsResponse("SomeRelatedEndEntity", request,  createCredentials(100), createCredentials(160), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IssueTokenCredentialsResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IssueTokenCredentialsResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "IssueTokenCredentialsResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IssueTokenCredentialsResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.tokenRequest.user == "someuser"
		payloadObject.credentials.credential[0].status == "100"
		payloadObject.revokedCredentials.credential[0].status == "160"

		expect:
		pp.parseMessage(rd.responseData)
		
		when:
		rd = pp.genIssueTokenCredentialsResponse("SomeRelatedEndEntity", request,  createCredentials(100), null, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IssueTokenCredentialsResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IssueTokenCredentialsResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "IssueTokenCredentialsResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IssueTokenCredentialsResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.tokenRequest.user == "someuser"
		payloadObject.credentials.credential[0].status == "100"
		payloadObject.revokedCredentials.size() == 0

		expect:
		pp.parseMessage(rd.responseData)
		
		when:
		rd = pp.genIssueTokenCredentialsResponse("SomeRelatedEndEntity", request,  createCredentials(100), [], null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IssueTokenCredentialsResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IssueTokenCredentialsResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "IssueTokenCredentialsResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IssueTokenCredentialsResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.tokenRequest.user == "someuser"
		payloadObject.credentials.credential[0].status == "100"
		payloadObject.revokedCredentials.size() == 0

		expect:
		pp.parseMessage(rd.responseData)
				
		when: // Verify that a bad requests throws MessageContentException
		request = pp.parseMessage(pp.genGetCredentialRequest(TEST_ID, "SOMESOURCEID", "someorg", "someCredentialSubType","someIssuerId", "someSerialNumber",  createOriginatorCredential(), null))
		pp.genIssueTokenCredentialsResponse("SomeRelatedEndEntity", request,  createCredentials(100), [], null)
		then:
		thrown MessageContentException
	}
	
	def "Verify that genChangeCredentialStatusRequest() generates a valid xml message and genChangeCredentialStatusResponse() generates a valid CSMessageResponseData"(){
		setup:
		cal.set(2014, 11, 01)
		Date revokeDate = cal.getTime()
		
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genChangeCredentialStatusRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", "someSerialNumber", 100, "someReasonInformation",  createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.ChangeCredentialStatusRequest

		then:
		messageContainsPayload requestMessage, "credmanagement:ChangeCredentialStatusRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","ChangeCredentialStatusRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		payloadObject.newCredentialStatus == "100"
		payloadObject.serialNumber == "someSerialNumber"
		payloadObject.reasonInformation == "someReasonInformation"
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genChangeCredentialStatusResponse("SomeRelatedEndEntity", request,  "someIssuerId", "someSerialNumber", 100, "someReasonInformation",revokeDate, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.ChangeCredentialStatusResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:ChangeCredentialStatusResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "ChangeCredentialStatusResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","ChangeCredentialStatusResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.issuerId == "someIssuerId"
		payloadObject.serialNumber == "someSerialNumber"
		payloadObject.credentialStatus == "100"
		payloadObject.revocationDate  =~ "2014-12-01"
		payloadObject.reasonInformation == "someReasonInformation"
		
		expect:
		pp.parseMessage(rd.responseData)

	}

	def "Verify that genGetCredentialRequest() generates a valid xml message and genGetCredentialResponse() generates a valid CSMessageResponseData"(){
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetCredentialRequest(TEST_ID, "SOMESOURCEID", "someorg", "someCredentialSubType","someIssuerId", "someSerialNumber",  createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetCredentialRequest

		then:
		messageContainsPayload requestMessage, "credmanagement:GetCredentialRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetCredentialRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		payloadObject.credentialSubType == "someCredentialSubType"
		payloadObject.serialNumber == "someSerialNumber"
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetCredentialResponse("SomeRelatedEndEntity", request, createCredential(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetCredentialResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:GetCredentialResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetCredentialResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetCredentialResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.credential.displayName == "SomeDisplayName"

		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genGetCredentialStatusListRequest() generates a valid xml message and genGetCredentialStatusListResponse() generates a valid CSMessageResponseData"(){
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetCredentialStatusListRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", 123L, "someListType", createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetCredentialStatusListRequest

		then:
		messageContainsPayload requestMessage, "credmanagement:GetCredentialStatusListRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetCredentialStatusListRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		payloadObject.credentialStatusListType == "someListType"
		payloadObject.serialNumber == "123"
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetCredentialStatusListResponse("SomeRelatedEndEntity", request, createCredentialStatusList(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetCredentialStatusListResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:GetCredentialStatusListResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetCredentialStatusListResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetCredentialStatusListResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.credentialStatusList.credentialStatusListType == "SomeCredentialStatusListType"

		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genGetIssuerCredentialsRequest() generates a valid xml message and genGetIssuerCredentialsResponse() generates a valid CSMessageResponseData"(){
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetIssuerCredentialsRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetIssuerCredentialsRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:GetIssuerCredentialsRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetIssuerCredentialsRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetIssuerCredentialsResponse("SomeRelatedEndEntity", request, createCredential(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetIssuerCredentialsResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:GetIssuerCredentialsResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetIssuerCredentialsResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetIssuerCredentialsResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.credential.displayName == "SomeDisplayName"

		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genIsIssuerRequest() generates a valid xml message and genIsIssuerResponse() generates a valid CSMessageResponseData"(){
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genIsIssuerRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.IsIssuerRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:IsIssuerRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","IsIssuerRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genIsIssuerResponse("SomeRelatedEndEntity", request, true, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IsIssuerResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IsIssuerResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "IsIssuerResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IsIssuerResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.isIssuer == "true"

		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genIssueCredentialStatusListRequest() generates a valid xml message and genIssueCredentialStatusListResponse() generates a valid CSMessageResponseData"(){
		setup:
		cal.set(2014, 11, 01)
		Date notBefore = cal.getTime()
		cal.set(2015, 00, 01)
		Date notAfter = cal.getTime()
		
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genIssueCredentialStatusListRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", "someListType",true, notBefore, notAfter, createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.IssueCredentialStatusListRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:IssueCredentialStatusListRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","IssueCredentialStatusListRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		payloadObject.credentialStatusListType == "someListType"
		payloadObject.force == "true"
		payloadObject.requestedValidFromDate =~ "2014-12-01"
		payloadObject.requestedNotAfterDate =~ "2015-01-01"
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genIssueCredentialStatusListResponse("SomeRelatedEndEntity", request, createCredentialStatusList(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IssueCredentialStatusListResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IssueCredentialStatusListResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "IssueCredentialStatusListResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IssueCredentialStatusListResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.credentialStatusList.credentialStatusListType == "SomeCredentialStatusListType"
		 
		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genIssueCredentialStatusListResponseWithoutRequest() generates a valid xml message and a valid CSMessageResponseData"(){
		when:
		CSMessageResponseData rd = pp.genIssueCredentialStatusListResponseWithoutRequest("2.0", "2.0", "SomeRelatedEndEntity", "SOMEREQUESTER", "IssueCredentialStatusListRequest", "someorg", createCredentialStatusList(), createOriginatorCredential(), null)

		//printXML(rd.responseData)
		def xml = slurpXml(rd.responseData)
		def payloadObject = xml.payload.IssueCredentialStatusListResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IssueCredentialStatusListResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "IssueCredentialStatusListResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IssueCredentialStatusListResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, xml.@ID.toString())
		
		payloadObject.credentialStatusList.credentialStatusListType == "SomeCredentialStatusListType"
		 
		expect:
		pp.parseMessage(rd.responseData)

	}
	
	
	def "Verify that genRemoveCredentialRequest() generates a valid xml message and genRemoveCredentialResponse() generates a valid CSMessageResponseData"(){
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genRemoveCredentialRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", "someSerialNumber",  createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.RemoveCredentialRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:RemoveCredentialRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","RemoveCredentialRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		payloadObject.serialNumber == "someSerialNumber"
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genRemoveCredentialResponse("SomeRelatedEndEntity", request, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.RemoveCredentialResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:RemoveCredentialResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "RemoveCredentialResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","RemoveCredentialResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		

		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genFetchHardTokenDataRequest() generates a valid xml message and genFetchHardTokenDataResponse() generates a valid CSMessageResponseData"(){
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genFetchHardTokenDataRequest(TEST_ID, "SOMESOURCEID", "someorg", "someTokenSerial", "someRelatedCredentialSerialNumber", "someRelatedCredentialIssuerId", createCredential(), createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.FetchHardTokenDataRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:FetchHardTokenDataRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","FetchHardTokenDataRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.tokenSerial == "someTokenSerial"
		payloadObject.relatedCredentialSerialNumber == "someRelatedCredentialSerialNumber"
		payloadObject.relatedCredentialIssuerId == "someRelatedCredentialIssuerId"
		payloadObject.adminCredential.displayName == "SomeDisplayName"
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genFetchHardTokenDataResponse("SomeRelatedEndEntity", request, "someTokenSerial", "someencrypteddata".getBytes(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.FetchHardTokenDataResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:FetchHardTokenDataResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "FetchHardTokenDataResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","FetchHardTokenDataResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.tokenSerial == "someTokenSerial"
		new String(Base64.decode(((String)payloadObject.encryptedData))) == "someencrypteddata"
		
		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genStoreHardTokenDataRequest() generates a valid xml message and genStoreHardTokenDataResponse() generates a valid CSMessageResponseData"(){
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genStoreHardTokenDataRequest(TEST_ID, "SOMESOURCEID", "someorg", "someTokenSerial", "someRelatedCredentialSerialNumber", "someRelatedCredentialIssuerId", "someencrypteddata".getBytes(), createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.StoreHardTokenDataRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:StoreHardTokenDataRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","StoreHardTokenDataRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.tokenSerial == "someTokenSerial"
		payloadObject.relatedCredentialSerialNumber == "someRelatedCredentialSerialNumber"
		payloadObject.relatedCredentialIssuerId == "someRelatedCredentialIssuerId"
		new String(Base64.decode(((String)payloadObject.encryptedData))) == "someencrypteddata"
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genStoreHardTokenDataResponse("SomeRelatedEndEntity", request, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.StoreHardTokenDataResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:StoreHardTokenDataResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "StoreHardTokenDataResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","StoreHardTokenDataResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		expect:
		pp.parseMessage(rd.responseData)

	}
	
	
	def "Verify that genGetTokensRequest() generates a valid xml message and genGetTokensResponse() generates a valid CSMessageResponseData"(){
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetTokensRequest(TEST_ID, "SOMESOURCEID", "someorg", "someserial", true, createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetTokensRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:GetTokensRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetTokensRequest", createOriginatorCredential(), pp.csMessageParser)

		payloadObject.serialNumber == "someserial"
		payloadObject.exactMatch == "true"	
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetTokensResponse("SomeRelatedEndEntity", request, createTokens(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetTokensResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:GetTokensResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetTokensResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetTokensResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.tokens.token.size() == 2
		
		expect:
		pp.parseMessage(rd.responseData)

	}
		
	def "Verify that genGetUsersRequest() generates a valid xml message and genGetUsersResponse() generates a valid CSMessageResponseData"(){
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetUsersRequest(TEST_ID, "SOMESOURCEID", "someorg", "someuniqueid", true, createOriginatorCredential(), null)
//        printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetUsersRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:GetUsersRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetUsersRequest", createOriginatorCredential(), pp.csMessageParser)


		payloadObject.uniqueId == "someuniqueid"
		payloadObject.exactMatch == "true"
		
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetUsersResponse("SomeRelatedEndEntity", request, createUsers(), null)
//		printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetUsersResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:GetUsersResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetUsersResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetUsersResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.users.user.size() == 2
		
		expect:
		pp.parseMessage(rd.responseData)

	}

	private List<User> createUsers(){
		return [createUser("user1"),createUser("user2",[createToken("321")])]
	}
	
	private User createUser(String id, List<Token> tokens = createTokens()){
		User user = csMessageOf.createUser();
		user.attributes = new User.Attributes()
		user.attributes.attribute.add(createAttribute("somekey", "somevalue"))
		
		user.dateCreated = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1233123L))
		user.lastUpdated  = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1243123L))
		user.uniqueId = id
		user.displayName = "User " + id
		user.status = "100"
		user.description = "some desc"
		
		user.tokens = new User.Tokens() 
		for(Token t : tokens){
			user.tokens.token.add(t)
		}
		
		return user;
	}

	
	private Token createToken(String serial){
		Token t = csMessageOf.createToken()
		
		t.attributes = new Token.Attributes()
		t.attributes.attribute.add(createAttribute("sometokenkey", "sometokenvalue"))
		
		t.credentials = new Token.Credentials()
		t.credentials.credential.addAll(createCredentials())
		
		t.dateCreated = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1253123L))
		t.lastUpdated  = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1273123L))
		
		t.expireDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1283123L))
		t.issueDate  = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1213123L))
		t.requestDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1203123L))
		t.validFromDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1243123L))
		
		t.serialNumber = serial
		t.status = 200
		t.tokenClass = "SomeTokenClass"
		t.tokenContainer = "SomeTokenContainer"
		t.tokenType = "SomeTokenType"
		
		return t;
	}
	
	private List<Token> createTokens(){
		return [createToken("serial123"),createToken("serial124")]
	}
	
	private Attribute createAttribute(String key, String value){
		Attribute retval = csMessageOf.createAttribute();
		retval.setKey(key)
		retval.setValue(value)
		return retval
	}
	
	
	private TokenRequest createTokenRequest(){
		TokenRequest retval = csMessageOf.createTokenRequest();
		retval.user = "someuser";
		retval.tokenContainer = "SomeTokenContainer"
		retval.tokenType = "SomeTokenType"
		retval.tokenClass = "SomeTokenClass"
		
		CredentialRequest cr = csMessageOf.createCredentialRequest();
		cr.credentialRequestId = 123
		cr.credentialType = "SomeCredentialType"
		cr.credentialSubType = "SomeCredentialSubType"
		cr.x509RequestType = "SomeX509RequestType"
		cr.credentialRequestData = "12345ABC"
		
		retval.setCredentialRequests(new TokenRequest.CredentialRequests())
		retval.getCredentialRequests().getCredentialRequest().add(cr)

		return retval
	}
	
	private Credential createCredential(int status = 100){
		Credential c = csMessageOf.createCredential();

		c.credentialRequestId = 123
		c.credentialType = "SomeCredentialType"
		c.credentialSubType = "SomeCredentialSubType"
		c.uniqueId = "SomeUniqueId"
		c.displayName = "SomeDisplayName"
		c.serialNumber = "SomeSerialNumber"
		c.issuerId = "SomeIssuerId"
		c.status = status
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
		Attribute attr = createAttribute("someattrkey", "someattrvalue")
		
		c.setAttributes(new Credential.Attributes())
		c.getAttributes().getAttribute().add(attr)

		c.setUsages(new Credential.Usages())
		c.getUsages().getUsage().add("someusage")
		
		return c
	}
	
	private List<Credential> createCredentials(int status = 100){
		List<Credential> retval = [];
		retval.add(createCredential(status))

		return retval
	}
	

	
	private CredentialStatusList createCredentialStatusList(){
		CredentialStatusList retval = csMessageOf.createCredentialStatusList();
		retval.credentialStatusListType = "SomeCredentialStatusListType"
		retval.credentialType = "SomeCredentialType"
		retval.description = "SomeDescription"
		GregorianCalendar gc = new GregorianCalendar();
		gc.setTime(new Date(1234L));
		retval.expireDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		retval.expireDate.setTimezone(60)
		gc.setTime(new Date(1235L));
		retval.issueDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		retval.issueDate.setTimezone(60)
		retval.issuerId = "SomeIssuerId"
		retval.listData = "12345ABCEF"
		retval.serialNumber = 16L
		gc.setTime(new Date(1236L));
		retval.validFromDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		retval.validFromDate.setTimezone(60)
		return retval
	}
	
	private List<FieldValue> createFieldValues(){
		def retval = []
		FieldValue fv1 = of.createFieldValue()
		fv1.setKey("someKey1")
		fv1.setValue("someValue1")
		retval.add(fv1)
		FieldValue fv2 = of.createFieldValue()
		fv2.setKey("someKey2")
		fv2.setValue("someValue2")
		retval.add(fv2)
		
		return retval
	}
	
	
}
