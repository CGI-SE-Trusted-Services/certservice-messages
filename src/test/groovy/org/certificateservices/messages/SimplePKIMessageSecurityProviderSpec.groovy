package org.certificateservices.messages

import static org.certificateservices.messages.SimpleMessageSecurityProvider.*

import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.text.SimpleDateFormat

import org.apache.xml.security.utils.Base64
import org.certificateservices.messages.utils.SystemTime
import org.certificateservices.messages.utils.XMLEncrypter

import spock.lang.Specification

class SimplePKIMessageSecurityProviderSpec extends Specification {
	
	SimpleMessageSecurityProvider prov
	
	X509Certificate testCert
	Properties config
	String signKeyKeyId

	def setup(){
		CertificateFactory cf = CertificateFactory.getInstance("X.509")
		testCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(base64Cert)))
		
		config = new Properties();
		config.setProperty(SETTING_SIGNINGKEYSTORE_PATH, this.getClass().getResource("/dummykeystore.jks").getPath())
		config.setProperty(SETTING_SIGNINGKEYSTORE_PASSWORD, "tGidBq0Eep")
		config.setProperty(SETTING_SIGNINGKEYSTORE_ALIAS, "test")
		
		config.setProperty(SETTING_TRUSTKEYSTORE_PATH, this.getClass().getResource("/testtruststore.jks").getPath())
		config.setProperty(SETTING_TRUSTKEYSTORE_PASSWORD, "foo123")
		config.setProperty(SETTING_ENCRYPTION_ALGORITHM_SCHEME, " RSA_pkcs1_5_WITH_AES256 ")
		prov = new SimpleMessageSecurityProvider(config);
		
		signKeyKeyId = XMLEncrypter.generateKeyId(prov.getSigningCertificate().getPublicKey())
	}
	
	def "Verify that provider is initialized properly"(){
		expect:
		prov.signingAlgorithmScheme == SigningAlgorithmScheme.RSAWithSHA256
		prov.encryptionAlgorithmScheme == EncryptionAlgorithmScheme.RSA_PKCS1_5_WITH_AES256
	}
	
	def "Test that getSigningKey() returns a valid signing key"(){
		when:
		  PrivateKey key = prov.getSigningKey();
		then:
		 assert key != null
		 assert key instanceof RSAPrivateKey
	}
	
	def "Test that getSigningCertificate() returns a valid signing certificate"(){
		when:
		  X509Certificate cert = prov.getSigningCertificate();
		then:
		 assert cert != null
		 assert cert instanceof X509Certificate
	}
	
	
	def "Test that isValidAndAuthorized() trust a trusted certificate"(){
		setup:
		prov.systemTime = TestUtils.mockSystemTime("2013-10-01")
		when:
		X509Certificate cert = prov.getSigningCertificate();
		then:
		prov.isValidAndAuthorized(cert, "someorg")
	}
	
	
	def "Test that isValidAndAuthorized() does not trust an untrusted certificate"(){
		setup:
		prov.systemTime = TestUtils.mockSystemTime("2013-10-01")
		expect:
		  !prov.isValidAndAuthorized(testCert, "someorg")
	}
	
	
	def "Test that isValidAndAuthorized() does not trust an expired certificate"(){
		setup:
		prov.systemTime = TestUtils.mockSystemTime("2017-10-01")
		when:
		X509Certificate cert = prov.getSigningCertificate();
		then:
		!prov.isValidAndAuthorized(cert, "someorg")
	}
	
	
	def "Test that isValidAndAuthorized() does not trust an not yet valid certificate"(){
		setup:
		prov.systemTime = TestUtils.mockSystemTime("2001-10-01")
		when:
		X509Certificate cert = prov.getSigningCertificate();
		then:
		!prov.isValidAndAuthorized(cert, "someorg")
	}
	
	def "Verify that signature key is used as decryption key if no decrytion key has been specified."(){
		expect:
		prov.defaultDecryptionKeyId == signKeyKeyId
		prov.getDecryptionKeyIds().size() == 1
		prov.getDecryptionKeyIds().iterator().next() == signKeyKeyId
		prov.getDecryptionCertificate(null) == prov.getSigningCertificate()
		prov.getDecryptionCertificateChain(null).length == 2
		prov.getDecryptionCertificateChain(null)[0] == prov.getSigningCertificate()
		prov.getDecryptionKey(null) == prov.getSigningKey()
		
	}
	
	def "Verify that if separate encryption keystore is loaded its keys are separate from signing keystores"(){
		setup:
		config.setProperty(SETTING_DECRYPTKEYSTORE_PATH, this.getClass().getResource("/decryptionks.jks").getPath())
		config.setProperty(SETTING_DECRYPTKEYSTORE_PASSWORD, "password")
		config.setProperty(SETTING_DECRYPTKEYSTORE_DEFAULTKEY_ALIAS, "key1")
		
		prov = new SimpleMessageSecurityProvider(config);
		def ks = prov.getDecryptionKeyStore(config)
		
		def keyId1 = XMLEncrypter.generateKeyId(ks.getCertificate("key1").publicKey)
		def keyId2 = XMLEncrypter.generateKeyId(ks.getCertificate("key2").publicKey)
		def keyId3 = XMLEncrypter.generateKeyId(ks.getCertificate("key3").publicKey)
		
		expect:
		keyId1 != signKeyKeyId
		prov.defaultDecryptionKeyId == keyId1
		prov.getDecryptionKeyIds().size() == 3
		prov.getDecryptionKeyIds().contains(keyId1)
		prov.getDecryptionKeyIds().contains(keyId2)
		prov.getDecryptionKeyIds().contains(keyId3)
		
		prov.getDecryptionCertificate(null) == ks.getCertificate("key1")
		prov.getDecryptionCertificateChain(null).length == 1
		prov.getDecryptionCertificateChain(null)[0] == ks.getCertificate("key1")
		prov.getDecryptionKey(null) == ks.getKey("key1","password".toCharArray())
		
		prov.getDecryptionCertificate(keyId1) == ks.getCertificate("key1")
		prov.getDecryptionCertificateChain(keyId1).length == 1
		prov.getDecryptionCertificateChain(keyId1)[0] == ks.getCertificate("key1")
		prov.getDecryptionKey(keyId1) == ks.getKey("key1","password".toCharArray())
		
		prov.getDecryptionCertificate(keyId2) == ks.getCertificate("key2")
		prov.getDecryptionCertificateChain(keyId2).length == 1
		prov.getDecryptionCertificateChain(keyId2)[0] == ks.getCertificate("key2")
		prov.getDecryptionKey(keyId2) == ks.getKey("key2","password".toCharArray())
		
		prov.getDecryptionCertificate(keyId3) == ks.getCertificate("key3")
		prov.getDecryptionCertificateChain(keyId3).length == 1
		prov.getDecryptionCertificateChain(keyId3)[0] == ks.getCertificate("key3")
		prov.getDecryptionKey(keyId3) == ks.getKey("key3","password".toCharArray())
		
	}
	
	def "Verify that getDecryptionKeyStore fetches separate encryption keystore if configured otherwise returns signature keystore"(){
		expect: "Sign keystore has only two entries"
		prov.getDecryptionKeyStore(config).size() == 2
		when:
		config.setProperty(SETTING_DECRYPTKEYSTORE_PATH, this.getClass().getResource("/decryptionks.jks").getPath())
		config.setProperty(SETTING_DECRYPTKEYSTORE_PASSWORD, "password")
		then:
		prov.getDecryptionKeyStore(config).size() == 3
	}
	
	def "Verify that getDecryptionKeyStorePassword() that fetches the correct password depending on weither simplesecurityprovider.decryptkeystore.path is set or not."(){
		expect: "Verify that sign keystore password is returned if no decryptkeystore path is set."
		new String(prov.getDecryptionKeyStorePassword(config)) == "tGidBq0Eep"
		when:
		Properties config = new Properties()
		config.setProperty(SETTING_DECRYPTKEYSTORE_PATH, "somepath")
		config.setProperty(SETTING_DECRYPTKEYSTORE_PASSWORD, "somepassword")
		then:
		new String(prov.getDecryptionKeyStorePassword(config)) == "somepassword"
		when:
		prov.getDecryptionKeyStorePassword(new Properties())
		then:
		thrown MessageProcessingException
	}
	
	def "Verify that getDefaultDecryptionAlias first checks for setting simplesecurityprovider.encryptkeystore.defaultkey.alias then fallbacks to simplesecurityprovider.signingkeystore.alias before throwing MessageProcessingException"(){
		setup:
		Properties config = new Properties()
		config.setProperty(SETTING_DECRYPTKEYSTORE_DEFAULTKEY_ALIAS, "somedefaultkey")
		config.setProperty(SETTING_SIGNINGKEYSTORE_ALIAS, "somesignalias")
		expect:
		prov.getDefaultDecryptionAlias(config) ==  "somedefaultkey"
		when:
		config.remove(SETTING_DECRYPTKEYSTORE_DEFAULTKEY_ALIAS)
		then:
		prov.getDefaultDecryptionAlias(config) ==  "somesignalias"
		when:
		config.remove(SETTING_SIGNINGKEYSTORE_ALIAS)
		prov.getDefaultDecryptionAlias(config)
		then:
		thrown MessageProcessingException
	}
	
	def "Verify getKeyStore() returns a valid JKS keystore, or throws exception if key store couldn't be read"(){
		expect:
		prov.getKeyStore(config, SETTING_SIGNINGKEYSTORE_PATH, SETTING_SIGNINGKEYSTORE_PASSWORD) instanceof KeyStore
		when:
		config.setProperty(SETTING_SIGNINGKEYSTORE_PATH, "invalid")
		prov.getKeyStore(config, SETTING_SIGNINGKEYSTORE_PATH, SETTING_SIGNINGKEYSTORE_PASSWORD)
		then:
		thrown MessageProcessingException
		
		when:
		config.setProperty(SETTING_SIGNINGKEYSTORE_PATH, this.getClass().getResource("/dummykeystore.jks").getPath())
		config.setProperty(SETTING_SIGNINGKEYSTORE_PASSWORD, "INVALID")
		prov.getKeyStore(config, SETTING_SIGNINGKEYSTORE_PATH, SETTING_SIGNINGKEYSTORE_PASSWORD)
		then:
		thrown MessageProcessingException
		
	}
	

	
	def "Verify that findAlgorithm find correct algoritm"(){
		expect:
		prov.findAlgorithm(EncryptionAlgorithmScheme.values(), config, SETTING_ENCRYPTION_ALGORITHM_SCHEME, DEFAULT_ENCRYPTION_ALGORITHM_SCHEME) == EncryptionAlgorithmScheme.RSA_PKCS1_5_WITH_AES256
		prov.findAlgorithm(SigningAlgorithmScheme.values(), config, SETTING_SIGNATURE_ALGORITHM_SCHEME, DEFAULT_SIGNATURE_ALGORITHM_SCHEME) == DEFAULT_SIGNATURE_ALGORITHM_SCHEME
		
		when:
		Properties emptyConf = new Properties()
		emptyConf.setProperty(SETTING_ENCRYPTION_ALGORITHM_SCHEME, " ")
		then:
		prov.findAlgorithm(EncryptionAlgorithmScheme.values(), emptyConf, SETTING_ENCRYPTION_ALGORITHM_SCHEME, DEFAULT_ENCRYPTION_ALGORITHM_SCHEME) == DEFAULT_ENCRYPTION_ALGORITHM_SCHEME
		
		when:
		Properties invalidConf = new Properties()
		invalidConf.setProperty(SETTING_ENCRYPTION_ALGORITHM_SCHEME, "NOexisting")
		prov.findAlgorithm(EncryptionAlgorithmScheme.values(), invalidConf, SETTING_ENCRYPTION_ALGORITHM_SCHEME, DEFAULT_ENCRYPTION_ALGORITHM_SCHEME) 
		then:
		thrown MessageProcessingException
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
