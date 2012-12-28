package org.certificateservices.ca.pkimessages

import java.security.PrivateKey
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.certificateservices.ca.pkimessages.DummyPKIMessageSecurityProvider;
import org.junit.Test;

import spock.lang.Specification


class DummyPKIMessageSecurityProviderSpec extends Specification {
	
	@Test
	def "Test that getSigningKey() returns a valid signing key"(){
		when:
		  DummyPKIMessageSecurityProvider prov = new DummyPKIMessageSecurityProvider();
		  PrivateKey key = prov.getSigningKey();
		then:
		 assert key != null
		 assert key instanceof RSAPrivateKey
	}
	
	@Test
	def "Test that getSigningCertificate() returns a valid signing certificate"(){
		when:
		  DummyPKIMessageSecurityProvider prov = new DummyPKIMessageSecurityProvider();
		  X509Certificate cert = prov.getSigningCertificate();
		then:
		 assert cert != null
		 assert cert instanceof X509Certificate
	}

}
