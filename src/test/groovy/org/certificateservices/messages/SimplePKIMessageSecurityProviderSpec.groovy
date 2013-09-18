package org.certificateservices.messages

import java.security.PrivateKey
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.bouncycastle.util.encoders.Base64;
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.SimpleMessageSecurityProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import spock.lang.Shared;
import spock.lang.Specification


class SimplePKIMessageSecurityProviderSpec extends Specification {
	
	@Shared SimpleMessageSecurityProvider prov

	def setupSpec(){
		Properties config = new Properties();
		config.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_PATH, this.getClass().getResource("/dummykeystore.jks").getPath())
		config.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_PASSWORD, "tGidBq0Eep")
		config.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_ALIAS, "test")
		
		config.setProperty(SimpleMessageSecurityProvider.SETTING_TRUSTKEYSTORE_PATH, this.getClass().getResource("/testtruststore.jks").getPath())
		config.setProperty(SimpleMessageSecurityProvider.SETTING_TRUSTKEYSTORE_PASSWORD, "foo123")
		prov = new SimpleMessageSecurityProvider(config);
	}
	
	@Test
	def "Test that getSigningKey() returns a valid signing key"(){
		when:
		  PrivateKey key = prov.getSigningKey();
		then:
		 assert key != null
		 assert key instanceof RSAPrivateKey
	}
	
	@Test
	def "Test that getSigningCertificate() returns a valid signing certificate"(){
		when:
		  X509Certificate cert = prov.getSigningCertificate();
		then:
		 assert cert != null
		 assert cert instanceof X509Certificate
	}
	
	@Test
	def "Test that isValidAndAuthorized() trust a trusted certificate"(){
		when:
		  X509Certificate cert = prov.getSigningCertificate();
		then:
		 assert prov.isValidAndAuthorized(cert, "someorg")
	}
	
	@Test
	def "Test that isValidAndAuthorized() does not trust an untrusted certificate"(){
		setup:
		CertificateFactory cf = CertificateFactory.getInstance("X.509")
		when:
		
		  X509Certificate cert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(base64Cert)))
		then:
		 assert !prov.isValidAndAuthorized(cert, "someorg")
	}
	
	public static byte[] base64Cert =("MIIDLTCCAhWgAwIBAgIIYmVP6xQ/t3QwDQYJKoZIhvcNAQEFBQAwJDETMBEGA1UE" +
		"AwwKVGVzdCBlSURDQTENMAsGA1UECgwEVGVzdDAeFw0xMTEwMjExNDM2MzlaFw0z" +
		"MTEwMjExNDM2MzlaMCQxEzARBgNVBAMMClRlc3QgZUlEQ0ExDTALBgNVBAoMBFRl" +
		"c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDecUf5if2UdWbV/HIj" +
		"h6U3XIymmh28wo8VVxPIbV1A8Yxz7QaMkP8vqaDwHnB1B6mHEjn4VyVogxWxI70I" +
		"wPudUL+Oxkc9ZL7H7zkbi6l2d/n85PjyZvdarCwcBzpEqIRsc+Wa3bGFKBpdZjwL" +
		"XjuuI4YWx+uUrQ96X+WusvFcb8C4Ru3w/K8Saf7yLJNvqmTJrgAOeKY49Jnp9V5x" +
		"9dGe+xpHR3t2xhJ5HXhm+SeUsrH5fHXky7/OVKvLPOXSve+1KHpyp+eOxxgYozTh" +
		"5k+viL0pP9G3AbEPp1mXtxCNzRjUgNlG0BDSIbowD5JciLkz8uYbamLzoUiz1KzZ" +
		"uCfXAgMBAAGjYzBhMB0GA1UdDgQWBBT6HyWgz7ykq9BxTCaULtOIjen3bDAPBgNV" +
		"HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFPofJaDPvKSr0HFMJpQu04iN6fdsMA4G" +
		"A1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQUFAAOCAQEAbG7Y+rm82Gz1yIWVFKBf" +
		"XxDee7UwX2pyKdDfvRf9lFLxXv4LKBnuM5Zlb2RPdAAe7tTMtnYDwOWs4Uniy57h" +
		"YrCKU3v80u4uZoH8FNCG22APWQ+xa5UQtuq0yRf2xp2e4wjGZLQZlYUbePAZEjle" +
		"0E2YIa/kOrlvy5Z62sj24yczBL9uHfWpQUefA1+R9JpbOj0WEk+rAV0xJ2knmC/R" +
		"NzHWz92kL6UKUFzyBXBiBbY7TSVjO+bV/uPaTEVP7QhJk4Cahg1a7h8iMdF78ths" +
		"+xMeZX1KyiL4Dpo2rocZAvdL/C8qkt/uEgOjwOTdmoRVxkFWcm+DRNa26cclBQ4t" +
		"Vw==").getBytes();
}
