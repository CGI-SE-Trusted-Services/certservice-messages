package org.certificateservices.messages.pkimessages

import java.security.PrivateKey
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.certificateservices.messages.pkimessages.jaxb.IsIssuerRequest
import org.certificateservices.messages.pkimessages.jaxb.IsIssuerResponse
import org.certificateservices.messages.pkimessages.jaxb.ObjectFactory;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.PKIResponse
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.pkimessages.PKIMessageResponseData;
import org.junit.BeforeClass;
import org.junit.Test;

import spock.lang.Specification


class PKIMessageResponseDataSpec extends Specification {
	
	
	@Test
	def "Test isForwardable works correctly"(){
		setup:
		Set<String> excluded = ["DEST1", "DEST2"]
		expect:
		!new PKIMessageResponseData(null, "DEST1", null, true).isForwardable(excluded)
		!new PKIMessageResponseData(null, "DEST2", null, true).isForwardable(excluded)
		!new PKIMessageResponseData(null, "DEST3", null, false).isForwardable(excluded)
		new PKIMessageResponseData(null, "DEST3", null, true).isForwardable(excluded)
	}
	




}
