package org.certificateservices.messages.assertion

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBElement;

import org.apache.xml.security.Init;
import org.apache.xml.security.utils.Base64;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.assertion.jaxb.AssertionType;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.utils.SystemTime;

import spock.lang.Shared;
import spock.lang.Specification
import spock.lang.Unroll;
import static org.certificateservices.messages.assertion.AssertionTypeEnum.*
import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

class AuthorizationAssertionDataSpec extends Specification {
	
	 
	
	@Shared X509Certificate cert
	@Shared AssertionPayloadParser assertionPayloadParser
	
	def setupSpec(){
		Init.init()
		setupRegisteredPayloadParser();
		
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
		assertionPayloadParser.systemTime = Mock(SystemTime)
		assertionPayloadParser.systemTime.getSystemTime() >> new Date(1436279213000)
		
		cert = assertionPayloadParser.csMessageParser.messageSecurityProvider.getDecryptionCertificate(MessageSecurityProvider.DEFAULT_DECRYPTIONKEY)
		
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
