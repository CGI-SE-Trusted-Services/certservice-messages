package org.certificateservices.ca.pkimessages

import java.security.PrivateKey
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.certificateservices.ca.pkimessages.DummyPKIMessageSecurityProvider;
import org.certificateservices.ca.pkimessages.jaxb.IsIssuerRequest
import org.certificateservices.ca.pkimessages.jaxb.IsIssuerResponse
import org.certificateservices.ca.pkimessages.jaxb.ObjectFactory;
import org.certificateservices.ca.pkimessages.jaxb.PKIMessage;
import org.certificateservices.ca.pkimessages.jaxb.PKIResponse
import org.junit.BeforeClass;
import org.junit.Test;

import spock.lang.Specification


class DefaultMessageNameCatalogueSpec extends Specification {
	

	static MessageNameCatalogue messageNameCatalogue;
	
	@BeforeClass
	def setupSpec(){		
		Properties config = new Properties();
		config.setProperty(DefaultMessageNameCatalogue.SETTING_MESSAGE_NAME_PREFIX + "isissuerrequest", "SomeOtherName");
		messageNameCatalogue = new DefaultMessageNameCatalogue();
		messageNameCatalogue.init(config);
	}

	
	@Test
	def "Test default name is returned as the simple name of the payload element class."(){
		expect:
		messageNameCatalogue.lookupName(null, new IsIssuerResponse()) == "IsIssuerResponse"
	}
	
	@Test
	def "Test that overriden name is returned when setting for payload element exists."(){
		expect:
		messageNameCatalogue.lookupName(null,new IsIssuerRequest()) == "SomeOtherName"
	}
	
	@Test
	def "Test that by default is 'FailureResponse' returned for a PKIResponse."(){
		expect:
		messageNameCatalogue.lookupName(null,new PKIResponse()) == "FailureResponse"
	}


}
