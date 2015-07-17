package org.certificateservices.messages;

import org.apache.xml.security.encryption.XMLCipher;

import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.messages.EncryptionAlgorithmScheme.*

public class EncryptionAlgorithmSchemeSpec extends Specification{
	
	@Unroll
	def "Verify that encryption algorithm #algorithm has data encryption URI #dataalgvalue and a key encryption algorithm URI: #keyalgvalue"(){
		expect:
		algorithm.getDataEncryptionAlgorithmURI() == dataalgvalue
		algorithm.getKeyEncryptionAlgorithmURI() == keyalgvalue
		where:
		algorithm                   | dataalgvalue                                            | keyalgvalue
		RSA_PKCS1_5_WITH_AES256     | "http://www.w3.org/2001/04/xmlenc#aes256-cbc"           | "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
		RSA_OAEP_WITH_AES256        | "http://www.w3.org/2001/04/xmlenc#aes256-cbc"           | "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
			
	}

}
