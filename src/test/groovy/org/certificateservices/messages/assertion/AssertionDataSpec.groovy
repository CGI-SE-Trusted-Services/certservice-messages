package org.certificateservices.messages.assertion

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBElement;

import org.apache.xml.security.Init;
import org.apache.xml.security.utils.Base64;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.assertion.jaxb.AssertionType;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.utils.SystemTime;

import spock.lang.Shared;
import spock.lang.Specification
import spock.lang.Unroll;
import static org.certificateservices.messages.assertion.AssertionTypeEnum.*
import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

class AssertionDataSpec extends Specification {
	
	AssertionData ad 
	
	@Shared AssertionPayloadParser assertionPayloadParser
	
	def setupSpec(){
		Init.init()
		setupRegisteredPayloadParser();
		
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
		assertionPayloadParser.systemTime = Mock(SystemTime)
		assertionPayloadParser.systemTime.getSystemTime() >> new Date(1436279213000)
	}
	
	def setup(){
		ad = new TestAssertionData(assertionPayloadParser)
	}
	
	def "Verify that parseCommonData sets all fields and getters retieves correct data"(){
		setup:
		byte[] ticketData = assertionPayloadParser.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"], null, null,null)
		def assertion = assertionPayloadParser.parseApprovalTicket(ticketData)
		
		when:
		ad.parse(assertion)
		
		then:
		ad.getId() == assertion.value.getID()
		ad.getNotBefore().time == 1436279212427L
		ad.getNotOnOrAfter().time == 1436279312427L
		ad.getSubjectId() == "SomeSubject"
		ad.getSignCertificate().subjectDN.toString() == "O=Demo Customer1 AT, CN=test"
	}
	
	def "Verify that hashCode() and equals() only compares id"(){
		setup:
		AssertionData ad1 = new TestAssertionData(assertionPayloadParser);
		ad1.id = "123"
		AssertionData ad2 = new TestAssertionData(assertionPayloadParser);
		ad2.id = "123"
		AssertionData ad3 = new TestAssertionData(assertionPayloadParser);
		ad3.id = "124"
		expect:

		ad1.hashCode() == ad2.hashCode()
		ad2.hashCode() != ad3.hashCode()
		ad1 == ad2
		ad3 != ad2
		
	}

	
	public class TestAssertionData extends AssertionData{
		
		public TestAssertionData(AssertionPayloadParser a){
			super(a)
		}

		@Override
		public void parse(JAXBElement<AssertionType> assertion)
				throws MessageContentException, MessageProcessingException {
			parseCommonData(assertion)
			
		}
				
		public void setID(String id){
			this.id = id;
		}
	}

}