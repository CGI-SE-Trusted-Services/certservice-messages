package org.certificateservices.messages.assertion

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.csmessages.CSMessageParserManager

import java.security.Security
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBElement;

import org.apache.xml.security.Init
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.saml2.assertion.jaxb.AssertionType;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.utils.SystemTime;

import spock.lang.Shared;
import spock.lang.Specification

import static org.certificateservices.messages.TestUtils.*

class AuthorizationAssertionDataSpec extends Specification {
	
	 
	
	@Shared X509Certificate cert
	@Shared AssertionPayloadParser assertionPayloadParser
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
		setupRegisteredPayloadParser();
		
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
		assertionPayloadParser.systemTime = Mock(SystemTime)
		assertionPayloadParser.systemTime.getSystemTime() >> new Date(1436279213000)
		assertionPayloadParser.samlAssertionMessageParser.systemTime = assertionPayloadParser.systemTime
		
		cert = CSMessageParserManager.getCSMessageParser().messageSecurityProvider.getDecryptionCertificate(MessageSecurityProvider.DEFAULT_DECRYPTIONKEY)
		
	}
	
	def "Verify that constructor sets all fields and getters retieves correct data"(){
		when:
		JAXBElement<AssertionType> assertion = genAuthorizationAssertion()
		AuthorizationAssertionData ad = assertionPayloadParser.parseAndDecryptAssertion(assertion)
		then:
		ad instanceof AuthorizationAssertionData
		ad.getId() == assertion.value.getID()
		ad.getRoles() == ["role1","role2"]
	}

	
	def "Verify that toString returns a string"(){
		setup:
		AuthorizationAssertionData ad = assertionPayloadParser.parseAndDecryptAssertion(genAuthorizationAssertion())
		expect:
		ad.toString() != null
	}
	
	private JAXBElement<AssertionType> genAuthorizationAssertion(){
		byte[] ticketData = assertionPayloadParser.genDistributedAuthorizationTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"], [cert])
		JAXBElement<AssertionType> assertion = assertionPayloadParser.getAssertionFromResponseType(assertionPayloadParser.parseAttributeQueryResponse(ticketData))
	}

}
