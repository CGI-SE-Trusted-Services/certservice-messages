package org.certificateservices.messages.saml2.assertion

import org.certificateservices.messages.saml2.BaseSAMLMessageParser
import org.certificateservices.messages.saml2.CommonSAMLMessageParserSpecification


class SAMLAssertionMessageParserSpec extends CommonSAMLMessageParserSpecification {

	
	def "Verify that JAXBPackages(), getNameSpace(), getSignatureLocationFinder(), getDefaultSchemaLocations(), getOrganisationLookup() returns the correct values"(){
		expect:
		samp.getJAXBPackages() == SAMLAssertionMessageParser.BASE_JAXB_CONTEXT
		samp.getNameSpace() == BaseSAMLMessageParser.ASSERTION_NAMESPACE
		samp.getSignatureLocationFinder() == samp.assertionSignatureLocationFinder
		samp.getDefaultSchemaLocations().length== 4
		samp.getOrganisationLookup() == null
	}

    // generateSimpleAssertion is tested by AssertionPayloadParserSpec

    // TODO verify Signature verifyAssertionSignature


}
