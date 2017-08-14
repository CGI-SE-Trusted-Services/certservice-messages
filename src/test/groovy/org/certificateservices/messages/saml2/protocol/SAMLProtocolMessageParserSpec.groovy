package org.certificateservices.messages.saml2.protocol

import org.certificateservices.messages.ContextMessageSecurityProvider
import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.assertion.ResponseStatusCodes
import org.certificateservices.messages.saml2.BaseSAMLMessageParser
import org.certificateservices.messages.saml2.CommonSAMLMessageParserSpecification
import org.certificateservices.messages.saml2.assertion.SAMLAssertionMessageParser
import org.certificateservices.messages.saml2.assertion.jaxb.AssertionType
import org.certificateservices.messages.saml2.assertion.jaxb.ConditionsType
import org.certificateservices.messages.saml2.assertion.jaxb.NameIDType
import org.certificateservices.messages.saml2.assertion.jaxb.SubjectType
import org.certificateservices.messages.saml2.protocol.jaxb.*
import org.certificateservices.messages.utils.MessageGenerateUtils
import spock.lang.IgnoreRest

import javax.xml.bind.JAXBElement

import static org.certificateservices.messages.TestUtils.printXML
import static org.certificateservices.messages.TestUtils.slurpXml
import static org.certificateservices.messages.ContextMessageSecurityProvider.DEFAULT_CONTEXT

class SAMLProtocolMessageParserSpec extends CommonSAMLMessageParserSpecification {


	SAMLProtocolMessageParser spmp;
	SAMLAssertionMessageParser samp;

	def setup(){
		spmp = new SAMLProtocolMessageParser();
		spmp.init(secProv);
		spmp.systemTime = mockedSystemTime

		samp = new SAMLAssertionMessageParser()
		samp.init(secProv)
		samp.systemTime = mockedSystemTime;
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
		conditions.setNotBefore(MessageGenerateUtils.dateToXMLGregorianCalendar(simpleDateFormat.parse("2016-02-01")))
		conditions.setNotOnOrAfter(MessageGenerateUtils.dateToXMLGregorianCalendar(simpleDateFormat.parse("2016-02-12")))

		RequestedAuthnContextType requestedAuthnContext = samlpOf.createRequestedAuthnContextType()
		requestedAuthnContext.authnContextClassRef.add("SomeContextClassRef")
		requestedAuthnContext.setComparison(AuthnContextComparisonType.EXACT)

		ScopingType scoping = samlpOf.createScopingType()
		scoping.setProxyCount(new BigInteger("123"))

		byte[] authNRequest = spmp.genAuthNRequest(DEFAULT_CONTEXT,"_1234512341234",true,false,"SomeProtocolBinding", 1,"http://assertionConsumerServiceURL",2,"SomeProviderName","SomeDestination","SomeConsent", issuer, extensions, subject, nameIdPolicy, conditions, requestedAuthnContext, scoping, true)

		def xml = slurpXml(authNRequest)
		//printXML(authNRequest)

		then:
		xml.@AssertionConsumerServiceIndex == "1"
		xml.@AssertionConsumerServiceURL == "http://assertionConsumerServiceURL"
		xml.@AttributeConsumingServiceIndex == "2"
		xml.@Consent == "SomeConsent"
		xml.@Destination == "SomeDestination"
		xml.@ID.toString() == "_1234512341234"
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
		xml.Conditions.@NotBefore != null
		xml.Conditions.@NotOnOrAfter != null
		xml.RequestedAuthnContext.@Comparison == "exact"
		xml.RequestedAuthnContext.AuthnContextClassRef == "SomeContextClassRef"
		xml.Scoping.@ProxyCount == "123"
		when:
		AuthnRequestType art = spmp.parseMessage(DEFAULT_CONTEXT,authNRequest, true)

		then:
		art.getIssuer().value == "SomeIssuer"

		when:
		authNRequest = spmp.genAuthNRequest(DEFAULT_CONTEXT,"_1234512341234",true,false,"SomeProtocolBinding", 1,"http://assertionConsumerServiceURL",2,"SomeProviderName","SomeDestination","SomeConsent", issuer, extensions, subject, nameIdPolicy, conditions, requestedAuthnContext, scoping, false)

		xml = slurpXml(authNRequest)
		//printXML(authNRequest)
		then:
		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 0

		when:
		art = spmp.parseMessage(DEFAULT_CONTEXT,authNRequest, false)
		then:
		art.getIssuer().value == "SomeIssuer"

		when: "Verify that unsigned message throws exception if signature is required"
		spmp.parseMessage(DEFAULT_CONTEXT,authNRequest, true)
		then:
		thrown MessageContentException

	}


	def "Generate minimal AuthNRequest and verify that it is populated correctly"(){
		when:
		byte[] authNRequest = spmp.genAuthNRequest(DEFAULT_CONTEXT,"_1234512341234",null,null,null, null,null,null,null,null,null, null, null, null, null, null, null, null, true)

		def xml = slurpXml(authNRequest)
		//printXML(authNRequest)
		AuthnRequestType art = spmp.parseMessage(DEFAULT_CONTEXT,authNRequest, true)

		then:
		xml.@ID == "_1234512341234"
		xml.@IssueInstant.toString().startsWith("20")
		xml.@Version == "2.0"

		xml.Signature.SignedInfo.size() == 1

		art.getID().startsWith("_")

	}

	def "Generate a full Response and verify all fields are populated correctly"(){
		when:
		NameIDType issuer = of.createNameIDType()
		issuer.setValue("SomeIssuer")

		ExtensionsType extensions = samlpOf.createExtensionsType()
		extensions.any.add(dsignObj.createKeyName("SomeKeyName"))

		SubjectType subject = of.createSubjectType()
		NameIDType subjectNameId =of.createNameIDType()
		subjectNameId.setValue("SomeSubject");
		subject.getContent().add(of.createNameID(subjectNameId));

		StatusDetailType statusDetailType = samlpOf.createStatusDetailType()
		statusDetailType.any.add(dsignObj.createKeyName("SomeKeyName"))

		// TODO EncryptedAssertion

		JAXBElement<AssertionType> assertion1 = samp.generateSimpleAssertion("someIssuer", new Date(1436279212000), new Date(1436279412000), "SomeSubject1",null)
		JAXBElement<AssertionType> assertion2 = samp.generateSimpleAssertion("someIssuer2", new Date(1436279212000), new Date(1436279412000), "SomeSubject2",null)

		byte[] response = spmp.genResponse(DEFAULT_CONTEXT,"SomeResponseTo",issuer,"SomeDestination","SomeConsent", extensions,ResponseStatusCodes.RESPONDER,"SomeStatusMessage", statusDetailType,[assertion1,assertion2], true, true);

		//printXML(response)
		def xml = slurpXml(response)
		then:
		xml.@Consent == "SomeConsent"
		xml.@Destination == "SomeDestination"
		xml.@ID.toString().startsWith("_")
		xml.@IssueInstant.toString().startsWith("20")
		xml.@Version == "2.0"

		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 1
		xml.Extensions.KeyName == "SomeKeyName"

		xml.Status.StatusCode.@Value == "urn:oasis:names:tc:SAML:2.0:status:Responder"
		xml.Status.StatusMessage == "SomeStatusMessage"
		xml.Status.StatusDetail.KeyName == "SomeKeyName"

		xml.Assertion[0].Signature.SignedInfo.size() == 1
		xml.Assertion[1].Signature.SignedInfo.size() == 1

		when: "Verify that is is parsable"
		ResponseType r = spmp.parseMessage(DEFAULT_CONTEXT,response,true)

		then:
		r.signature != null


		when: "Verify that it is possible to generate SAMLP signed only messages"
		response = spmp.genResponse(DEFAULT_CONTEXT,"SomeResponseTo",issuer,"SomeDestination","SomeConsent", extensions,ResponseStatusCodes.RESPONDER,"SomeStatusMessage", statusDetailType,[assertion1,assertion2], false, true);

		//printXML(response)
		xml = slurpXml(response)
		then:
		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 1

		xml.Assertion[0].Signature.size() == 0
		xml.Assertion[1].Signature.size() == 0

		when: "Verify that is is parsable"
		r = spmp.parseMessage(DEFAULT_CONTEXT,response,true)

		then:
		r.signature != null

		when: "Verify that it is possible to generate Assertion signed only messages"
		response = spmp.genResponse(DEFAULT_CONTEXT,"SomeResponseTo",issuer,"SomeDestination","SomeConsent", extensions,ResponseStatusCodes.RESPONDER,"SomeStatusMessage", statusDetailType,[assertion1,assertion2], true, false);

		//printXML(response)
		xml = slurpXml(response)
		then:
		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 0

		xml.Assertion[0].Signature.size() == 1
		xml.Assertion[1].Signature.size() == 1

		when: "Verify that is is parsable"
		r = spmp.parseMessage(DEFAULT_CONTEXT,response,false)

		then:
		r.signature == null
		samp.verifyAssertionSignature(DEFAULT_CONTEXT,r.getAssertionOrEncryptedAssertion()[0])
		samp.verifyAssertionSignature(DEFAULT_CONTEXT,r.getAssertionOrEncryptedAssertion()[1])

		when:
		((AssertionType) r.getAssertionOrEncryptedAssertion()[0]).issuer.value = "SomeChanged"
		samp.verifyAssertionSignature(DEFAULT_CONTEXT,r.getAssertionOrEncryptedAssertion()[0])
		then:
		thrown MessageContentException

	}


}
