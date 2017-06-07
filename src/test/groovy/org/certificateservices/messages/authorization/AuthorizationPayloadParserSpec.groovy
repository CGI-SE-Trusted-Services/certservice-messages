package org.certificateservices.messages.authorization

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.authorization.jaxb.GetRequesterRolesRequest
import org.certificateservices.messages.authorization.jaxb.TokenTypePermission
import org.certificateservices.messages.authorization.jaxb.TokenTypePermissionType
import org.certificateservices.messages.authorization.jaxb.TokenTypeRuleRestriction
import org.certificateservices.messages.authorization.jaxb.TokenTypeRuleRestrictionType
import org.certificateservices.messages.csmessages.CSMessageParserManager
import org.certificateservices.messages.utils.CSMessageUtils;

import org.apache.xml.security.Init;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.authorization.jaxb.ObjectFactory;

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

	DefaultCSMessageParser csMessageParser

	def setup(){
		setupRegisteredPayloadParser();
		csMessageParser = CSMessageParserManager.getCSMessageParser()
		pp = PayloadParserRegistry.getParser(AuthorizationPayloadParser.NAMESPACE);
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "org.certificateservices.messages.authorization.jaxb"
		pp.getNameSpace() == "http://certificateservices.org/xsd/authorization2_0"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getSchemaAsInputStream("2.1") != null
		pp.getDefaultPayloadVersion() == "2.1"
		pp.getSupportedVersions() == ["2.1","2.0"] as String[]
	}

	def "Verify that genGetRequesterRolesRequest() generates a valid xml message and genGetRequesterRolesResponse() generates a valid CSMessageResponseData without any token type query"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetRequesterRolesRequest(TEST_ID, "SOMESOURCEID", "someorg", createOriginatorCredential(), null)
        //printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetRequesterRolesRequest
		then:
		messageContainsPayload requestMessage, "auth:GetRequesterRolesRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetRequesterRolesRequest", createOriginatorCredential(), csMessageParser)
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetRequesterRolesResponse("SomeRelatedEndEntity", request, ["role1","role2"], null, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetRequesterRolesResponse
		
		then:
		messageContainsPayload rd.responseData, "auth:GetRequesterRolesResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetRequesterRolesResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetRequesterRolesResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		expect:
		pp.parseMessage(rd.responseData)
		
	}

	def "Verify that genGetRequesterRolesRequest() generates a valid xml message and genGetRequesterRolesResponse() generates a valid CSMessageResponseData with a list of token type queries"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetRequesterRolesRequest(TEST_ID, "SOMESOURCEID", "someorg", ["testTokenType1","testTokenType2"],createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetRequesterRolesRequest
		then:
		payloadObject.tokenTypePermissionQuery.tokenType[0] == "testTokenType1"
		payloadObject.tokenTypePermissionQuery.tokenType[1] == "testTokenType2"
		messageContainsPayload requestMessage, "auth:GetRequesterRolesRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetRequesterRolesRequest", createOriginatorCredential(), csMessageParser)

		CSMessage request = pp.parseMessage(requestMessage)
		GetRequesterRolesRequest r = CSMessageUtils.getPayload(request)
		r.tokenTypePermissionQuery.tokenType[0] == "testTokenType1"
		r.tokenTypePermissionQuery.tokenType[1] == "testTokenType2"

		when:
		csMessageParser.sourceId = "SOMESOURCEID"

		List<TokenTypePermission> tokenTypePermissions = []
		r.tokenTypePermissionQuery.tokenType.each{
			TokenTypePermission ttp = of.createTokenTypePermission()
			ttp.tokenType = it
			ttp.ruleType = TokenTypePermissionType.MODIFYANDISSUE
			ttp.restrictions = of.createTokenTypePermissionRestrictions()
			TokenTypeRuleRestriction ttrr = of.createTokenTypeRuleRestriction()
			ttrr.type = TokenTypeRuleRestrictionType.TOKENCLASS
			ttrr.value = "temporary"
			ttp.restrictions.restriction.add(ttrr)
			tokenTypePermissions << ttp
		}

		CSMessageResponseData rd = pp.genGetRequesterRolesResponse("SomeRelatedEndEntity", request, ["role1","role2"], tokenTypePermissions, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetRequesterRolesResponse

		then:

		payloadObject.roles.role[0] == "role1"
		payloadObject.roles.role[1] == "role2"

		payloadObject.tokenTypePermissions.tokenTypePermission[0].tokenType == "testTokenType1"
		payloadObject.tokenTypePermissions.tokenTypePermission[0].ruleType == "MODIFYANDISSUE"
		payloadObject.tokenTypePermissions.tokenTypePermission[0].restrictions.restriction.type == "TOKENCLASS"
		payloadObject.tokenTypePermissions.tokenTypePermission[0].restrictions.restriction.value == "temporary"
		payloadObject.tokenTypePermissions.tokenTypePermission[1].tokenType == "testTokenType2"

		messageContainsPayload rd.responseData, "auth:GetRequesterRolesResponse"

		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetRequesterRolesResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetRequesterRolesResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)

		expect:
		pp.parseMessage(rd.responseData)

	}

}
