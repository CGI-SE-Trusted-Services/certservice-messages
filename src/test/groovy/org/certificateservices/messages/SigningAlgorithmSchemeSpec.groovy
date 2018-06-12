package org.certificateservices.messages;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.messages.SigningAlgorithmScheme.*

class SigningAlgorithmSchemeSpec extends Specification{
	
	@Unroll
	def "Verify that signature algorithm #algorithm has hash URI #hashurivalue and a signature algorithm URI: #urivalue"(){
		expect:
		algorithm.getHashAlgorithmURI() == hashurivalue
		algorithm.getSignatureAlgorithmURI() == signurivalue
		where:
		algorithm                   | hashurivalue                                            | signurivalue
		RSAWithSHA256               | "http://www.w3.org/2001/04/xmlenc#sha256"               | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		RSAWithSHA512               | "http://www.w3.org/2001/04/xmlenc#sha512"               | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
		ECDSAWithSHA256             | "http://www.w3.org/2001/04/xmlenc#sha256"               | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
		ECDSAWithSHA512             | "http://www.w3.org/2001/04/xmlenc#sha512"               | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
		
	}

}
