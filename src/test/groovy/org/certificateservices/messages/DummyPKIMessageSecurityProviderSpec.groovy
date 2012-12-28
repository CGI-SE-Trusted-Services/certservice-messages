package org.certificateservices.messages

import java.security.PrivateKey
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.junit.Test;

import spock.lang.Specification


class DummyPKIMessageSecurityProviderSpec extends Specification {
	
	@Test
	def "Test that getSigningKey() returns a valid signing key"(){
		when:
		  DummyMessageSecurityProvider prov = new DummyMessageSecurityProvider();
		  PrivateKey key = prov.getSigningKey();
		then:
		 assert key != null
		 assert key instanceof RSAPrivateKey
	}
	
	@Test
	def "Test that getSigningCertificate() returns a valid signing certificate"(){
		when:
		  DummyMessageSecurityProvider prov = new DummyMessageSecurityProvider();
		  X509Certificate cert = prov.getSigningCertificate();
		then:
		 assert cert != null
		 assert cert instanceof X509Certificate
	}

}
