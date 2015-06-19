package org.certificateservices.messages.assertion;

import java.security.KeyStore;
import java.util.List;

import javax.xml.datatype.DatatypeFactory;

import org.apache.xml.security.utils.Base64;
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.TestUtils;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.assertion.jaxb.ObjectFactory;
import org.certificateservices.messages.utils.MessageGenerateUtils;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

class AssertionPayloadParserSpec extends Specification {
	
	AssertionPayloadParser pp;
	ObjectFactory of = new ObjectFactory()
	org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()
	Calendar cal = Calendar.getInstance();
	
	

	def setup(){
		setupRegisteredPayloadParser();
		
		pp = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "org.certificateservices.messages.assertion.jaxb"
		pp.getNameSpace() == "urn:oasis:names:tc:SAML:2.0:assertion"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getDefaultPayloadVersion() == "2.0"
		pp.getSupportedVersions() == ["2.0"] as String[]
	}
	

	
}
