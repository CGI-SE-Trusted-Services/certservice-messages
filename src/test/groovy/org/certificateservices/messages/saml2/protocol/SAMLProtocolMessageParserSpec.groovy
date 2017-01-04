package org.certificateservices.messages.saml2.protocol

import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.saml2.BaseSAMLMessageParser
import org.certificateservices.messages.saml2.CommonSAMLMessageParserSpecification
import org.certificateservices.messages.saml2.assertion.jaxb.ConditionsType
import org.certificateservices.messages.saml2.assertion.jaxb.NameIDType
import org.certificateservices.messages.saml2.assertion.jaxb.SubjectType
import org.certificateservices.messages.saml2.protocol.jaxb.*
import org.certificateservices.messages.utils.MessageGenerateUtils

import static org.certificateservices.messages.TestUtils.slurpXml

class SAMLProtocolMessageParserSpec extends CommonSAMLMessageParserSpecification {


	SAMLProtocolMessageParser spmp;

	def setup(){
		spmp = new SAMLProtocolMessageParser();
		spmp.init(new Properties(),secProv);
		spmp.systemTime = mockedSystemTime
	}


	
	def "Verify that JAXBPackages(), getNameSpace(), getSignatureLocationFinder(), getDefaultSchemaLocations(), getOrganisationLookup() returns the correct values"(){
		expect:
		spmp.getJAXBPackages() == SAMLProtocolMessageParser.BASE_JAXB_CONTEXT
		spmp.getNameSpace() == BaseSAMLMessageParser.PROTOCOL_NAMESPACE
		spmp.getSignatureLocationFinder() == spmp.samlpSignatureLocationFinder
		spmp.getDefaultSchemaLocations().length== 4
		spmp.getOrganisationLookup() == null
	}
	

	def "Generate full AuthNRequest and verify that it is populated correctly"(){
		when:
		NameIDType issuer = of.createNameIDType();
		issuer.setValue("SomeIssuer");

		ExtensionsType extensions = samlpOf.createExtensionsType()
		extensions.any.add(dsignObj.createKeyName("SomeKeyName"))

		SubjectType subject = of.createSubjectType()
		NameIDType subjectNameId =of.createNameIDType()
		subjectNameId.setValue("SomeSubject");
		subject.getContent().add(of.createNameID(subjectNameId));

		NameIDPolicyType nameIdPolicy = samlpOf.createNameIDPolicyType()
		nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted")

		ConditionsType conditions = of.createConditionsType()
		conditions.setNotBefore(MessageGenerateUtils.dateToXMLGregorianCalendar(simpleDateFormat.parse("2016-02-1")))
		conditions.setNotOnOrAfter(MessageGenerateUtils.dateToXMLGregorianCalendar(simpleDateFormat.parse("2016-02-12")))

		RequestedAuthnContextType requestedAuthnContext = samlpOf.createRequestedAuthnContextType()
		requestedAuthnContext.authnContextClassRef.add("SomeContextClassRef")
		requestedAuthnContext.setComparison(AuthnContextComparisonType.EXACT)

		ScopingType scoping = samlpOf.createScopingType()
		scoping.setProxyCount(new BigInteger("123"))

		byte[] authNRequest = spmp.genAuthNRequest(true,false,"SomeProtocolBinding", 1,"http://assertionConsumerServiceURL",2,"SomeProviderName","SomeDestination","SomeConsent", issuer, extensions, subject, nameIdPolicy, conditions, requestedAuthnContext, scoping, true)

		def xml = slurpXml(authNRequest)
		//printXML(authNRequest)

		then:
		xml.@AssertionConsumerServiceIndex == "1"
		xml.@AssertionConsumerServiceURL == "http://assertionConsumerServiceURL"
		xml.@AttributeConsumingServiceIndex == "2"
		xml.@Consent == "SomeConsent"
		xml.@Destination == "SomeDestination"
		xml.@ID.toString().startsWith("_")
		xml.@IsPassive == "false"
		xml.@IssueInstant.toString().startsWith("20")
		xml.@ProtocolBinding == "SomeProtocolBinding"
		xml.@ProviderName == "SomeProviderName"
		xml.@Version == "2.0"

		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 1
		xml.Extensions.KeyName == "SomeKeyName"
		xml.Subject.NameID == "SomeSubject"
		xml.NameIDPolicy.@Format == "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"
		xml.Conditions.@NotBefore == "2016-01-31T22:00:00.000+01:00"
		xml.Conditions.@NotOnOrAfter == "2016-02-11T22:00:00.000+01:00"
		xml.RequestedAuthnContext.@Comparison == "exact"
		xml.RequestedAuthnContext.AuthnContextClassRef == "SomeContextClassRef"
		xml.Scoping.@ProxyCount == "123"
		when:
		AuthnRequestType art = spmp.parseMessage(authNRequest, true)

		then:
		art.getIssuer().value == "SomeIssuer"

		when:
		authNRequest = spmp.genAuthNRequest(true,false,"SomeProtocolBinding", 1,"http://assertionConsumerServiceURL",2,"SomeProviderName","SomeDestination","SomeConsent", issuer, extensions, subject, nameIdPolicy, conditions, requestedAuthnContext, scoping, false)

		xml = slurpXml(authNRequest)
		//printXML(authNRequest)
		then:
		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 0

		when:
		art = spmp.parseMessage(authNRequest, false)
		then:
		art.getIssuer().value == "SomeIssuer"

		when: "Verify that unsigned message throws exception if signature is required"
		spmp.parseMessage(authNRequest, true)
		then:
		thrown MessageContentException

	}

	def "Generate minimal AuthNRequest and verify that it is populated correctly"(){
		when:
		byte[] authNRequest = spmp.genAuthNRequest(null,null,null, null,null,null,null,null,null, null, null, null, null, null, null, null, true)

		def xml = slurpXml(authNRequest)
		//printXML(authNRequest)

		then:
		xml.@ID.toString().startsWith("_")
		xml.@IssueInstant.toString().startsWith("20")
		xml.@Version == "2.0"

		xml.Signature.SignedInfo.size() == 1

		when:
		AuthnRequestType art = spmp.parseMessage(authNRequest, true)

		then:
		art.getID().startsWith("_")

	}


}
