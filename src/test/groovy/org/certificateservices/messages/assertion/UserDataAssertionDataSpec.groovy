package org.certificateservices.messages.assertion

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBElement;

import org.apache.xml.security.Init;
import org.apache.xml.security.utils.Base64;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.assertion.jaxb.AssertionType;
import org.certificateservices.messages.credmanagement.jaxb.FieldValue;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.utils.SystemTime;

import spock.lang.Shared;
import spock.lang.Specification
import spock.lang.Unroll;
import static org.certificateservices.messages.assertion.AssertionTypeEnum.*
import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

class UserDataAssertionDataSpec extends Specification {
	

	def fv1
	def fv2
	
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
	
	def setup(){
		
		fv1 = new FieldValue();
		fv1.key = "someKey1"
		fv1.value = "someValue1"
		fv2 = new FieldValue();
		fv2.key = "someKey2"
		fv2.value = "someValue2"
	
	}
	
	def "Verify that constructor sets all fields and getters retieves correct data"(){
		when:
		JAXBElement<AssertionType> assertion = genUserDataAssertion()
		UserDataAssertionData ad = assertionPayloadParser.parseAndDecryptAssertion(assertion)
		then:
		ad instanceof UserDataAssertionData
		ad.getId() == assertion.value.getID()
		
		ad.getDisplayName() == "someDisplayName"
		ad.getFieldValues().size() == 2
		ad.getFieldValues()[0].key == "someKey1"
		ad.getFieldValues()[0].value == "someValue1"
		ad.getFieldValues()[1].key == "someKey2"
		ad.getFieldValues()[1].value == "someValue2"
	}
	
	def "Verify that toString returns a string"(){
		setup:
		UserDataAssertionData ad = assertionPayloadParser.parseAndDecryptAssertion(genUserDataAssertion())
		expect:
		ad.toString() != null
	}
	
	private JAXBElement<AssertionType> genUserDataAssertion(){
		byte[] ticketData = assertionPayloadParser.genUserDataTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","someDisplayName",[fv1, fv2], [cert])
		JAXBElement<AssertionType> assertion = assertionPayloadParser.getAssertionFromResponseType(assertionPayloadParser.parseAttributeQueryResponse(ticketData))
		
	}

}
