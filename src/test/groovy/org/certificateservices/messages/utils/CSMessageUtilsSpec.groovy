package org.certificateservices.messages.utils
import org.certificateservices.messages.DummyMessageSecurityProvider
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser;
import org.certificateservices.messages.credmanagement.jaxb.IsIssuerRequest;
import org.certificateservices.messages.csmessages.CSMessageParser;
import org.certificateservices.messages.csmessages.CSMessageParserManager;
import org.certificateservices.messages.csmessages.PayloadParser;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.csmessages.jaxb.IsApprovedRequest;
import org.certificateservices.messages.utils.MessageGenerateUtils;

import spock.lang.Specification

class CSMessageUtilsSpec extends Specification {

	
	CSMessageParser csMessageParser
	String messageId = MessageGenerateUtils.generateRandomUUID()
	Properties props = new Properties()
	
	CSMessage isApprovedRequestMessage
	CSMessage getApprovedRequestMessage
	
	static def config = """
csmessage.sourceid=SomeClientSystem
"""
	def setup(){
		props.load(new StringReader(config))
		csMessageParser = CSMessageParserManager.initCSMessageParser(new DummyMessageSecurityProvider(), props)
		
		CredManagementPayloadParser credParser = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE)
		
		isApprovedRequestMessage = csMessageParser.parseMessage(csMessageParser.generateIsApprovedRequest(messageId, "someid", "someorg", "1234", null, null))
		byte[] request =credParser.genIsIssuerRequest(messageId, "someid", "someorg", "CN=SomeIssuer", null, null)
		getApprovedRequestMessage = csMessageParser.parseMessage(csMessageParser.generateGetApprovalRequest(messageId, "someid", "someorg", request, null, null))
	}
	
	def "Verify that getPayload returns the payload of a CS Message"(){
		expect:
		CSMessageUtils.getPayload(isApprovedRequestMessage) instanceof IsApprovedRequest

	}
	
	def "Verify that getPayload returns null if cs message parser parameter is null"(){
		expect:
		CSMessageUtils.getPayload(null) == null
	}
	
	def "Verify that getPayloadName returns correct paylaod name for non null cs message"(){
		expect:
		CSMessageUtils.getPayloadName(isApprovedRequestMessage) == "IsApprovedRequest"
	}
	
	def "Verify that getPayloadName throwns MessageContentException for null cs message"(){
		when:
		CSMessageUtils.getPayloadName(null)
		then:
		thrown MessageContentException
	}
	
	def "Verify that getRelatedPayload returns the related payload object inside a GetApprovalRequest"(){
		expect:
		CSMessageUtils.getRelatedPayload(getApprovedRequestMessage) instanceof IsIssuerRequest
	}
	
	def "Verify that getRelatedPayload throws MessageContentException if supplied argument isn't an GetApprovalRequest"(){
		when:
		CSMessageUtils.getRelatedPayload(isApprovedRequestMessage)
		then:
		thrown MessageContentException
	}
	
	def "Verify that getRelatedPayload throws MessageContentException if supplied argument is null"(){
		when:
		CSMessageUtils.getRelatedPayload(null)
		then:
		thrown MessageContentException
	}
	
	def "Verify that getRelatedPayloadName returns the related payload name inside a GetApprovalRequest"(){
		expect:
		CSMessageUtils.getRelatedPayloadName(getApprovedRequestMessage) == "IsIssuerRequest"
	}
	
	def "Verify that getRelatedPayloadName throws MessageContentException if supplied argument isn't an GetApprovalRequest"(){
		when:
		CSMessageUtils.getRelatedPayloadName(isApprovedRequestMessage)
		then:
		thrown MessageContentException
	}
	
	def "Verify that getRelatedPayloadName throws MessageContentException if supplied argument is null"(){
		when:
		CSMessageUtils.getRelatedPayloadName(null)
		then:
		thrown MessageContentException
	}
}