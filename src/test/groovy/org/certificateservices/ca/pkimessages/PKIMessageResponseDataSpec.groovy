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
