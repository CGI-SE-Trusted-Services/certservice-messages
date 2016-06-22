package org.certificateservices.messages.authorization

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.datatype.DatatypeFactory;

import org.apache.xml.security.Init;
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.TestUtils;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.csmessages.jaxb.Attribute;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.CredentialRequest;
import org.certificateservices.messages.csmessages.jaxb.Organisation;
import org.certificateservices.messages.keystoremgmt.jaxb.CredentialRequestParams;
import org.certificateservices.messages.keystoremgmt.jaxb.KeyInfo;
import org.certificateservices.messages.keystoremgmt.jaxb.KeyStatus;
import org.certificateservices.messages.keystoremgmt.jaxb.KeyStore;
import org.certificateservices.messages.keystoremgmt.jaxb.KeyStoreStatus;
import org.certificateservices.messages.keystoremgmt.jaxb.ObjectFactory;
import org.certificateservices.messages.keystoremgmt.jaxb.X509CredentialRequestParams;
import org.certificateservices.messages.utils.MessageGenerateUtils;

import spock.lang.Specification

import java.security.Security;

import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

class AuthorizationPayloadParserSpec extends Specification {
	
	AuthorizationPayloadParser pp;
	ObjectFactory of = new ObjectFactory()
	org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init();
	}
	
	def setup(){
		setupRegisteredPayloadParser();
		
		pp = PayloadParserRegistry.getParser(AuthorizationPayloadParser.NAMESPACE);
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "org.certificateservices.messages.authorization.jaxb"
		pp.getNameSpace() == "http://certificateservices.org/xsd/authorization2_0"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getDefaultPayloadVersion() == "2.0"
		pp.getSupportedVersions() == ["2.0"] as String[]
	}

	def "Verify that genGetRequesterRolesRequest() generates a valid xml message and genGetRequesterRolesResponse() generates a valid CSMessageResponseData"(){
		when:
		pp.csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetRequesterRolesRequest(TEST_ID, "SOMESOURCEID", "someorg", createOriginatorCredential(), null)
        //printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetRequesterRolesRequest
		then:
		messageContainsPayload requestMessage, "auth:GetRequesterRolesRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetRequesterRolesRequest", createOriginatorCredential(), pp.csMessageParser)
		
		when:
		pp.csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetRequesterRolesResponse("SomeRelatedEndEntity", request, ["role1","role2"], null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetRequesterRolesResponse
		
		then:
		messageContainsPayload rd.responseData, "auth:GetRequesterRolesResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetRequesterRolesResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetRequesterRolesResponse", createOriginatorCredential(), pp.csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		expect:
		pp.parseMessage(rd.responseData)
		
	}

}
