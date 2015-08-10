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
import org.certificateservices.messages.utils.DefaultSystemTime;
import org.certificateservices.messages.utils.SystemTime;

import spock.lang.Shared;
import spock.lang.Specification
import spock.lang.Unroll;
import static org.certificateservices.messages.assertion.AttributeQueryTypeEnum.*
import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

class AttributeQueryDataSpec extends Specification {
	
	
	
	@Shared AssertionPayloadParser assertionPayloadParser
	
	def setupSpec(){
		Init.init()
		setupRegisteredPayloadParser();
		
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);

	}
	
	def setup(){
		assertionPayloadParser.systemTime = new DefaultSystemTime()
	}

	@Unroll
	def "Verify that parse() method sets all fields propely for type: #type"(){
		when:
		AttributeQueryData aqd  = assertionPayloadParser.parseAttributeQuery(genAttributeQuery(type, "SomeSubject"))
		
		then:
		aqd.getID() != null
		aqd.getSubjectId() == "SomeSubject"
		aqd.getType() == type
		where:
		type << AttributeQueryTypeEnum.values()
	}
	
	def "Verify that hashCode() and equals() only compares id"(){
		setup:
		AttributeQueryData aqd1 = assertionPayloadParser.parseAttributeQuery(genAttributeQuery(AUTHORIZATION_TICKET, "SomeSubject1"))
		aqd1.id = "123"
		AttributeQueryData aqd2 = assertionPayloadParser.parseAttributeQuery(genAttributeQuery(USER_DATA, "SomeSubject2"))
		aqd2.id = "123"
		AttributeQueryData aqd3 = assertionPayloadParser.parseAttributeQuery(genAttributeQuery(AUTHORIZATION_TICKET, "SomeSubject1"))
		aqd3.id = "124"
		expect:

		aqd1.hashCode() == aqd2.hashCode()
		aqd2.hashCode() != aqd3.hashCode()
		aqd1 == aqd2
		aqd3 != aqd2
		
	}
	
	def "verify that toString() generates a string"(){
		expect:
		assertionPayloadParser.parseAttributeQuery(genAttributeQuery(AUTHORIZATION_TICKET, "SomeSubject1")).toString() instanceof String
	}


	private byte[] genAttributeQuery(AttributeQueryTypeEnum type, String subjectId){
		switch(type){
			case AUTHORIZATION_TICKET:
			 return assertionPayloadParser.genDistributedAuthorizationRequest(subjectId)
			 case USER_DATA: 
			 return assertionPayloadParser.genUserDataRequest(subjectId)
		}
		return null
	}

}
