package org.certificateservices.messages.saml2.metadata

import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.saml2.BaseSAMLMessageParser
import org.certificateservices.messages.saml2.CommonSAMLMessageParserSpecification
import org.certificateservices.messages.saml2.assertion.jaxb.AttributeType
import org.certificateservices.messages.saml2.metadata.jaxb.*
import org.certificateservices.messages.utils.MessageGenerateUtils
import org.certificateservices.messages.xenc.jaxb.EncryptionMethodType

import javax.xml.bind.JAXBElement
import javax.xml.datatype.DatatypeFactory
import javax.xml.datatype.Duration
import javax.xml.namespace.QName

import static org.certificateservices.messages.TestUtils.printXML
import static org.certificateservices.messages.TestUtils.slurpXml

class SAMLMetaDataMessageParserSpec extends CommonSAMLMessageParserSpecification {

	SAMLMetaDataMessageParser smdmp = new SAMLMetaDataMessageParser();

	ObjectFactory mdOf = new ObjectFactory()

	Date validUntil
	Duration cacheDuration

	def setup() {
		smdmp.init(secProv);
		smdmp.systemTime = mockedSystemTime

		validUntil = simpleDateFormat.parse("2016-02-1")
		cacheDuration = DatatypeFactory.newInstance().newDuration(true,(int) 1,(int) 1,(int) 1,(int) 1,(int) 1,(int) 1)
	}

	def "Verify that JAXBPackages(), getNameSpace(), getSignatureLocationFinder(), getDefaultSchemaLocations(), getOrganisationLookup() returns the correct values"(){
		expect:
		smdmp.getJAXBPackages() == SAMLMetaDataMessageParser.BASE_JAXB_CONTEXT
		smdmp.getNameSpace() == SAMLMetaDataMessageParser.NAMESPACE
		smdmp.getSignatureLocationFinder() instanceof SAMLMetaDataMessageParser.SAML2MetaDataSignatureLocationFinder
		smdmp.getDefaultSchemaLocations().length== 4
		smdmp.getDefaultSchemaLocations()[0] == DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION;
		smdmp.getDefaultSchemaLocations()[1] == DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION;
		smdmp.getDefaultSchemaLocations()[2] == BaseSAMLMessageParser.ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
		smdmp.getDefaultSchemaLocations()[3] == SAMLMetaDataMessageParser.METADATA_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
		smdmp.getOrganisationLookup() == null
	}

	def "Verify that generateEntityDescriptor populates the datastructure correctly"(){
		when: "generate full data structure"
		EntityDescriptorType dt = smdmp.genEntityDescriptor("SomeEntityId", validUntil,cacheDuration, createExtensions(),
		                                   [createIDP(), createSP()], createOrganisation(),
		                                   createContactPersons(), createMetadataLocations(), createOtherAttributes());
		byte[] dtd = smdmp.marshall(mdOf.createEntityDescriptor(dt))
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@entityID == "SomeEntityId"
		xml.@validUntil == MessageGenerateUtils.dateToXMLGregorianCalendar(validUntil)
		xml.@cacheDuration == "P1Y1M1DT1H1M1S"
		xml.@"ds:Algorithm" == "http://somealg"
		xml.Extensions.size() == 1
		xml.IDPSSODescriptor.size() == 1
		xml.SPSSODescriptor.size() == 1
		xml.Organization.size() == 1
		xml.ContactPerson.size() == 2
		xml.AdditionalMetadataLocation.size() == 1

		when: "try to parse"
		dt = smdmp.parseMessage(dtd,false)
		then:
		dt != null

		when: "Generate minimal data structure"
		dt = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createIDP()], null,
				null, null, null);
		dtd = smdmp.marshall(mdOf.createEntityDescriptor(dt))
		//printXML(dtd)
		xml = slurpXml(dtd)

		then:
		xml.@ID.toString().startsWith("_")
		xml.@entityID == "SomeEntityId"
		xml.IDPSSODescriptor.size() == 1

		when: "try to parse"
		dt = smdmp.parseMessage(dtd,false)
		then:
		dt != null

		when: "Try to generate with one affiliation descriptor"
		dt = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createAffiliationDescriptor()], null,
				null, null, null);
		dtd = smdmp.marshall(mdOf.createEntityDescriptor(dt))
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@entityID == "SomeEntityId"
		xml.AffiliationDescriptor.size() == 1

		when: "Verify that adding two affiliation descriptors throws MessageContentException"
		smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createAffiliationDescriptor(),createAffiliationDescriptor()], null,
				null, null, null);
		then:
		thrown MessageContentException

		when: "Verify that mixing affiliation descriptor with other types throws MessageContentException"
		smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createAffiliationDescriptor(),createIDP()], null,
				null, null, null);
		then:
		thrown MessageContentException

		when: "Verify that no descriptors throws MessageContentException"
		smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[], null,
				null, null, null);
		then:
		thrown MessageContentException
	}

	def "Verify that genEntitiesDescriptor generates valid data structure"(){
		setup:
		EntityDescriptorType edt1 = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createIDP()], null,
				null, null, null);
		EntityDescriptorType edt2 = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createSP()], null,
				null, null, null);
		when: "Generate full data structure"
		EntitiesDescriptorType dt = smdmp.genEntitiesDescriptor(validUntil,cacheDuration,"SomeName",createExtensions(),[edt1,edt2]);

		byte[] dtd = smdmp.marshall(mdOf.createEntitiesDescriptor(dt))
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@Name == "SomeName"
		xml.@validUntil == MessageGenerateUtils.dateToXMLGregorianCalendar(validUntil)
		xml.@cacheDuration == "P1Y1M1DT1H1M1S"
		xml.Extensions.size() == 1
		xml.EntityDescriptor.size() == 2

		when: "Generate minimal data structure"
		dt = smdmp.genEntitiesDescriptor(null,null,null,null,[edt1]);
		dtd = smdmp.marshall(mdOf.createEntitiesDescriptor(dt))
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.EntityDescriptor.size() == 1

	}

	def "Verify that genIDPSSODescriptor populates correctly"(){
		when: "Generate a full IDPSSODescriptor"

		IDPSSODescriptorType dt = smdmp.genIDPSSODescriptor(validUntil,cacheDuration,["urn:oasis:names:tc:SAML:2.0:protocol","urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"],
		                                   "http://someerrorURL", createExtensions(), createKeyDescriptor(),createOrganisation(),
				                           createContactPersons(),createOtherAttributes(), createArtifactResolutionServices(),
		                                   createSingleLogoutServices(), createManageNameIDServices(), ["nameid1","nameid2"],
		                                   true, createSingleSignOnServices(),createNameIDMappingServices(),createAssertionIDRequestServices(),
		                                   ["attrprofile1","attrprofile2"], createSAMLAttributes())
		byte[] dtd = smdmp.marshall(mdOf.createIDPSSODescriptor(dt));
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@validUntil == MessageGenerateUtils.dateToXMLGregorianCalendar(validUntil)
		xml.@cacheDuration == "P1Y1M1DT1H1M1S"
		xml.@protocolSupportEnumeration == "urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"
		xml.@errorURL == "http://someerrorURL"
		xml.@"ds:Algorithm" == "http://somealg"
		xml.@WantAuthnRequestsSigned == true
		xml.Extensions.size() == 1
		xml.KeyDescriptor.size() == 1
		xml.Organization.size() == 1
		xml.ContactPerson.size() == 2
		xml.ArtifactResolutionService.size() == 2
		xml.ArtifactResolutionService[0].@Binding == "http://artificatresbinding1.com"
		xml.ArtifactResolutionService[0].@index == "1"
		xml.SingleLogoutService.size() == 2
		xml.SingleLogoutService[0].@Binding == "http://slbinding1.com"
		xml.ManageNameIDService.size() == 2
		xml.ManageNameIDService[0].@Binding == "http://mnidbinding1.com"
		xml.NameIDFormat.size() == 2
		xml.NameIDFormat[0] == "nameid1"
		xml.SingleSignOnService.size() == 2
		xml.SingleSignOnService[0].@Binding == "http://ssobinding1.com"
		xml.NameIDMappingService.size() == 2
		xml.NameIDMappingService[0].@Binding == "http://nidmbinding1.com"
		xml.AssertionIDRequestService.size() == 2
		xml.AssertionIDRequestService[0].@Binding == "http://aidrbinding1.com"
		xml.AttributeProfile.size() == 2
		xml.AttributeProfile[0] == "attrprofile1"
		xml.Attribute.size() == 2
		xml.Attribute[0].@Name == "SomeAttr1"

		when: "Try to parse and validate schema"
		dt = smdmp.parseMessage(dtd, false)
		then:
		dt != null

		when: "Generate a minimal IDPSSODescriptor"
		dt = smdmp.genIDPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, createSingleSignOnServices(),null,null,null,null	)
		dtd = smdmp.marshall(mdOf.createIDPSSODescriptor(dt));
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@protocolSupportEnumeration == "urn:oasis:names:tc:SAML:2.0:protocol"
		xml.SingleSignOnService.size() == 2
		xml.SingleSignOnService[0].@Binding == "http://ssobinding1.com"

		when: "Try to parse and validate schema"
		dt = smdmp.parseMessage(dtd, false)
		then:
		dt != null
	}

	def "Verify that genSPSSODescriptor populates correctly"(){
		when: "Generate a full SPSSODescriptor"

		SPSSODescriptorType dt = smdmp.genSPSSODescriptor(validUntil,cacheDuration,["urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"],
				"http://someerrorURL", createExtensions(), createKeyDescriptor(),createOrganisation(),
				createContactPersons(),createOtherAttributes(), createArtifactResolutionServices(),
				createSingleLogoutServices(), createManageNameIDServices(), ["nameid1","nameid2"],
				true, false, createAssertionConsumerServices(), createAttributeConsumingServices())
		byte[] dtd = smdmp.marshall(mdOf.createSPSSODescriptor(dt));
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@validUntil == MessageGenerateUtils.dateToXMLGregorianCalendar(validUntil)
		xml.@cacheDuration == "P1Y1M1DT1H1M1S"
		xml.@protocolSupportEnumeration == "urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"
		xml.@errorURL == "http://someerrorURL"
		xml.@"ds:Algorithm" == "http://somealg"
		xml.@AuthnRequestsSigned == true
		xml.@WantAssertionsSigned == false
		xml.Extensions.size() == 1
		xml.KeyDescriptor.size() == 1
		xml.Organization.size() == 1
		xml.ContactPerson.size() == 2
		xml.ArtifactResolutionService.size() == 2
		xml.ArtifactResolutionService[0].@Binding == "http://artificatresbinding1.com"
		xml.ArtifactResolutionService[0].@index == "1"
		xml.SingleLogoutService.size() == 2
		xml.SingleLogoutService[0].@Binding == "http://slbinding1.com"
		xml.ManageNameIDService.size() == 2
		xml.ManageNameIDService[0].@Binding == "http://mnidbinding1.com"
		xml.NameIDFormat.size() == 2
		xml.NameIDFormat[0] == "nameid1"
		xml.AssertionConsumerService.size() == 2
		xml.AssertionConsumerService[0].@index == "1"
		xml.AssertionConsumerService[0].@Binding == "http://acbinding1.com"
		xml.AttributeConsumingService.size() == 1

		when: "Try to parse and validate schema"
		dt = smdmp.parseMessage(dtd, false)
		then:
		dt != null

		when: "Generate a minimal IDPSSODescriptor"
		dt = smdmp.genSPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, null,createAssertionConsumerServices(),null)
		dtd = smdmp.marshall(mdOf.createSPSSODescriptor(dt));
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@protocolSupportEnumeration == "urn:oasis:names:tc:SAML:2.0:protocol"
		xml.AssertionConsumerService.size() == 2
		xml.AssertionConsumerService[0].@Binding == "http://acbinding1.com"

		when: "Try to parse and validate schema"
		dt = smdmp.parseMessage(dtd, false)
		then:
		dt != null
	}


	def "Verify that genOrganization generates an organisation correctly"(){
		when:
		OrganizationType o = smdmp.genOrganization(createExtensions(),createOrganizationNames(),createOrganizationDisplayNames(),
		                                           createOrganizationURLs(),createOtherAttributes())
		then:
		o.extensions != null
		o.organizationName.size() == 2
		o.organizationName[0].value == "SomeCompany"
		o.organizationName[1].value == "Namn"
		o.organizationDisplayName.size() == 2
		o.organizationDisplayName[0].value == "Some Company"
		o.organizationDisplayName[1].value == "VisbartNamn"
		o.organizationURL.size() == 2
		o.organizationURL[0].value == "http://en.someorg.org"
		o.organizationURL[1].value == "http://sv.someorg.org"
		o.otherAttributes.size() == 1
		when: "Try to marshall"
		byte[] od = smdmp.marshall(mdOf.createOrganization(o))
		then:
		od != null;
		when: "Try to create minimal structure"
		o = smdmp.genOrganization(null,createOrganizationNames(),createOrganizationDisplayNames(),
				createOrganizationURLs(),null)
		then:
		o.extensions == null
		o.otherAttributes.size() == 0
		when: "Verify that at least on organsiationName must exist"
		smdmp.genOrganization(null,null,createOrganizationDisplayNames(),
				createOrganizationURLs(),null)
		then:
		thrown MessageContentException
		when: "Verify that at least on organsiationDisplayName must exist"
		smdmp.genOrganization(null,createOrganizationNames(),[],
				createOrganizationURLs(),null)
		then:
		thrown MessageContentException
		when: "Verify that at least on organsiationName must exist"
		smdmp.genOrganization(null,createOrganizationNames(),createOrganizationDisplayNames(),
				null,null)
		then:
		thrown MessageContentException

	}

	def "Verify that genContactType generates an contact person correctly"(){
		when:
		ContactType ct = smdmp.genContactType(ContactTypeType.ADMINISTRATIVE,createExtensions(), "SomeCompany",
				"SomeGivenName", "SomeSurname", ["email1@test.com","email2@test.com"],
		         ["12345","54321"], createOtherAttributes())
		then:
		ct.contactType == ContactTypeType.ADMINISTRATIVE
		ct.extensions != null
		ct.company  == "SomeCompany"
		ct.givenName == "SomeGivenName"
		ct.surName == "SomeSurname"
		ct.emailAddress.size() == 2
		ct.emailAddress[0]  == "email1@test.com"
		ct.emailAddress[1]  == "email2@test.com"
		ct.telephoneNumber.size() == 2
		ct.telephoneNumber[0]  == "12345"
		ct.telephoneNumber[1]  == "54321"
		ct.otherAttributes.size() == 1
		when: "try to marshall"
		byte[] ctd = smdmp.marshall(mdOf.createContactPerson(ct))
		//printXML(ctd)
		then:
		ctd != null
		when: "try to generate a minimal contact type"
		ct = smdmp.genContactType(ContactTypeType.BILLING,null,null,null,null,null,null,null)
		then:
		ct.contactType == ContactTypeType.BILLING
		ct.extensions == null
		ct.company == null
		ct.givenName == null
		ct.surName == null
		ct.emailAddress.size() == 0
		ct.telephoneNumber.size() == 0
		ct.otherAttributes.size() == 0
	}

	def "Verify genKeyDescriptor() generates a valid key descriptor"(){

		when:
		KeyDescriptorType kdt = smdmp.genKeyDescriptor(KeyTypes.ENCRYPTION,secProv.getSigningCertificate(),createEncryptionMethods())
		then:
		kdt.use == KeyTypes.ENCRYPTION
		kdt.keyInfo.content.size() == 1
		kdt.encryptionMethod.size() == 2
		when: "Try to marshall"
		byte[] kdtd = smdmp.marshall(mdOf.createKeyDescriptor(kdt))
		//printXML(kdtd)
		def xml = slurpXml(kdtd)
		then:
		xml.KeyInfo.X509Data.X509Certificate.size() == 1

	}

	def "Verify genEndpoint() generates a valid endpoint type"(){
		when:
		EndpointType et = smdmp.genEndpoint("SomeBinding","SomeLocation", "SomeResponseLocation",
		createAnyXML(), createOtherAttributes());
		then:
		et.binding == "SomeBinding"
		et.location == "SomeLocation"
		et.responseLocation == "SomeResponseLocation"
		et.getAny().size() == 2
		et.getOtherAttributes().size() == 1
		when:
		byte[] etd = smdmp.marshall(mdOf.createAssertionIDRequestService(et))
		//printXML(etd)
		def xml = slurpXml(etd)
		then:
		etd != null
		xml.@"ds:Algorithm" == "http://somealg"
		xml.KeyName.size() == 2
		xml.KeyName[0] == "SomeKeyName1"
		xml.KeyName[1] == "SomeKeyName2"
		when: "Generate minimal"
		et = smdmp.genEndpoint("SomeBinding","SomeLocation", null,null,null)
		etd = smdmp.marshall(mdOf.createAssertionIDRequestService(et))
		//printXML(etd)
		xml = slurpXml(etd)
		then:
		xml.KeyName.size() == 0

	}

	def "Verify genAttributeConsumingService populates correctly"(){
		when: "Generate full data structure"
		AttributeConsumingServiceType t = smdmp.genAttributeConsumingService(1,true,createServiceNames(),createServiceDescriptions(),createRequestedAttributes())
		byte[] td = smdmp.marshall(mdOf.createAttributeConsumingService(t))
		//printXML(td);
		def xml = slurpXml(td)
		then:
		xml.@index == 1
		xml.@isDefault == true
		xml.ServiceName.size() == 2
		xml.ServiceName[0] == "ServiceName"
		xml.ServiceDescription.size() == 2
		xml.ServiceDescription[0] == "ServiceDescription"
		xml.RequestedAttribute.size() == 2
		xml.RequestedAttribute[0].@isRequired == true
		xml.RequestedAttribute[0].@Name == "SomeAttr1"

		when: "Generate minimal data structure"
		t = smdmp.genAttributeConsumingService(1,null,createServiceNames(),null,createRequestedAttributes())
		td = smdmp.marshall(mdOf.createAttributeConsumingService(t))
		//printXML(td);
		xml = slurpXml(td)
		then:
		xml.@index == 1
		xml.ServiceName.size() == 2
		xml.RequestedAttribute.size() == 2
	}

	def "Verify genIndextedEndpoint() generates a valid endpoint type"(){
		when:
		EndpointType et = smdmp.genIndexedEndpoint("SomeBinding","SomeLocation", "SomeResponseLocation",
				1, true,
				createAnyXML(), createOtherAttributes());
		then:
		et.binding == "SomeBinding"
		et.location == "SomeLocation"
		et.responseLocation == "SomeResponseLocation"
		et.index == 1
		et.isDefault == true
		et.getAny().size() == 2
		et.getOtherAttributes().size() == 1
	}

	def "Verify that signed EntitiesDescriptor are generated correctly"(){
		setup:
		EntityDescriptorType edt1 = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createIDP()], null,
				null, null, null);
		EntityDescriptorType edt2 = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createSP()], null,
				null, null, null);
		when:
		byte[] edd = smdmp.genEntitiesDescriptor(validUntil,cacheDuration,"SomeName",createExtensions(),[edt1,edt2], true);
		//printXML(edd)
		def xml = slurpXml(edd)
		then:
		xml.Signature.size() == 1

		when:
		EntitiesDescriptorType edt = smdmp.parseMessage(edd,true)
		then:
		edt.signature != null


		when:
		edd = smdmp.genEntitiesDescriptor(null,null,null,null,[edt1], true);
		//printXML(edd)
		xml = slurpXml(edd)
		then:
		xml.Signature.size() == 1

		when:
		edt = smdmp.parseMessage(edd,true)
		then:
		edt.signature != null

		when:
		edd = smdmp.genEntitiesDescriptor(null,null,null,null,[edt1], false);
		//printXML(edd)
		xml = slurpXml(edd)
		then:
		xml.Signature.size() == 0

		when:
		smdmp.parseMessage(edd,true)
		then:
		thrown MessageContentException

		when:
		edt = smdmp.parseMessage(edd,false)
		then:
		edt.signature == null
	}

	def "Verify that signed EntityDescriptor are generated correctly"(){
		when:
		byte[] edd = smdmp.genEntityDescriptor("SomeEntityId", validUntil,cacheDuration, createExtensions(),
				[createIDP(), createSP()], createOrganisation(),
				createContactPersons(), createMetadataLocations(), createOtherAttributes(),true);
		//printXML(edd)
		def xml = slurpXml(edd)
		then:
		xml.Signature.size() == 1

		when:
		EntityDescriptorType edt = smdmp.parseMessage(edd,true)
		then:
		edt.signature != null


		when:
		edd = smdmp.genEntityDescriptor("SomeEntityId", null,null, null, [createIDP()], null, null, null, null, true);
		//printXML(edd)
		xml = slurpXml(edd)
		then:
		xml.Signature.size() == 1

		when:
		edt = smdmp.parseMessage(edd,true)
		then:
		edt.signature != null

		when:
		edd = smdmp.genEntityDescriptor("SomeEntityId", null,null, null, [createIDP()], null, null, null, null, false);
		//printXML(edd)
		xml = slurpXml(edd)
		then:
		xml.Signature.size() == 0

		when:
		smdmp.parseMessage(edd,true)
		then:
		thrown MessageContentException

		when:
		edt = smdmp.parseMessage(edd,false)
		then:
		edt.signature == null
	}

	def "Verify that signed IDPSSODescriptor are generated correctly"() {
		when:
		IDPSSODescriptorType dt = smdmp.genIDPSSODescriptor(validUntil, cacheDuration, ["urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"],
				"http://someerrorURL", createExtensions(), createKeyDescriptor(), createOrganisation(),
				createContactPersons(), createOtherAttributes(), createArtifactResolutionServices(),
				createSingleLogoutServices(), createManageNameIDServices(), ["nameid1", "nameid2"],
				true, createSingleSignOnServices(), createNameIDMappingServices(), createAssertionIDRequestServices(),
				["attrprofile1", "attrprofile2"], createSAMLAttributes())
		JAXBElement<IDPSSODescriptorType> jdt = mdOf.createIDPSSODescriptor(dt)
		byte[] dtd = smdmp.marshallAndSign(jdt)
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.Signature.size() == 1

		when:
		dt = smdmp.parseMessage(dtd,true)
		then:
		dt.signature != null

		when:
		dt = smdmp.genIDPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, createSingleSignOnServices(),null,null,null,null	)
		jdt = mdOf.createIDPSSODescriptor(dt)
		dtd = smdmp.marshallAndSign(jdt)
		printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.Signature.size() == 1

		when:
		dt = smdmp.parseMessage(dtd,true)
		then:
		dt.signature != null
	}

	def "Verify that signed SPSSODescriptor are generated correctly"() {
		when:
		SPSSODescriptorType dt = smdmp.genSPSSODescriptor(validUntil,cacheDuration,["urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"],
				"http://someerrorURL", createExtensions(), createKeyDescriptor(),createOrganisation(),
				createContactPersons(),createOtherAttributes(), createArtifactResolutionServices(),
				createSingleLogoutServices(), createManageNameIDServices(), ["nameid1","nameid2"],
				true, false, createAssertionConsumerServices(), createAttributeConsumingServices())
		byte[] dtd = smdmp.marshallAndSign(mdOf.createSPSSODescriptor(dt));
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.Signature.size() == 1

		when:
		dt = smdmp.parseMessage(dtd,true)
		then:
		dt.signature != null

		when:
		dt = smdmp.genSPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, null,createAssertionConsumerServices(),null)
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.Signature.size() == 1

		when:
		dt = smdmp.parseMessage(dtd,true)
		then:
		dt.signature != null
	}

	private ExtensionsType createExtensions(){
		ExtensionsType extensions = mdOf.createExtensionsType()
		extensions.any.add(dsignObj.createKeyName("SomeKeyName"))
		return extensions;
	}

	private List<Object> createAnyXML(){
		return [dsignObj.createKeyName("SomeKeyName1"),dsignObj.createKeyName("SomeKeyName2")]
	}

	private List<LocalizedNameType> createOrganizationNames(){
		LocalizedNameType orgENName = mdOf.createLocalizedNameType()
		orgENName.lang = "en"
		orgENName.value = "SomeCompany"
		LocalizedNameType orgSVName = mdOf.createLocalizedNameType()
		orgSVName.lang = "sv"
		orgSVName.value = "Namn"
		return [orgENName, orgSVName]
	}

	private List<LocalizedNameType> createOrganizationDisplayNames(){
		LocalizedNameType orgENDisplayName = mdOf.createLocalizedNameType()
		orgENDisplayName.lang = "en"
		orgENDisplayName.value = "Some Company"
		LocalizedNameType orgSVDisplayName = mdOf.createLocalizedNameType()
		orgSVDisplayName.lang = "sv"
		orgSVDisplayName.value = "VisbartNamn"
		return [orgENDisplayName, orgSVDisplayName]
	}

	private List<LocalizedNameType> createOrganizationURLs(){
		LocalizedURIType orgENURI = mdOf.createLocalizedURIType()
		orgENURI.lang = "en"
		orgENURI.value = "http://en.someorg.org"
		LocalizedURIType orgSVURI = mdOf.createLocalizedURIType()
		orgSVURI.lang = "sv"
		orgSVURI.value = "http://sv.someorg.org"
		return [orgENURI, orgSVURI]
	}

	private Map<QName,String> createOtherAttributes(){
		Map retval = [:]
		retval.put(new QName("http://www.w3.org/2000/09/xmldsig#","Algorithm"), "http://somealg")
		return retval
	}

	private List<EncryptionMethodType> createEncryptionMethods(){
		org.certificateservices.messages.xenc.jaxb.ObjectFactory encOf = new org.certificateservices.messages.xenc.jaxb.ObjectFactory();
		EncryptionMethodType emt1 = encOf.createEncryptionMethodType()
		emt1.algorithm = "http://alg1"
		EncryptionMethodType emt2 = encOf.createEncryptionMethodType()
		emt2.algorithm = "http://alg2"
		return [emt1,emt2]
	}

	private List<KeyDescriptorType> createKeyDescriptor(){
		return [smdmp.genKeyDescriptor(KeyTypes.ENCRYPTION,secProv.getSigningCertificate(),createEncryptionMethods())]
	}

	private OrganizationType createOrganisation(){
		return smdmp.genOrganization(createExtensions(),createOrganizationNames(),createOrganizationDisplayNames(),
				createOrganizationURLs(),createOtherAttributes())
	}

	private List<ContactType> createContactPersons(){
		return [smdmp.genContactType(ContactTypeType.ADMINISTRATIVE,null, "SomeCompany",null,null,null,null,null),
				smdmp.genContactType(ContactTypeType.BILLING,null, "SomeCompany",null,null,null,null,null)]
	}

	private List<IndexedEndpointType> createArtifactResolutionServices(){
		return [smdmp.genIndexedEndpoint("http://artificatresbinding1.com","http://artificatreslocation1.com", null, 1 , null,null,null),
				smdmp.genIndexedEndpoint("http://artificatresbinding2.com","http://artificatreslocation2.com", null, 1 , null,null,null)]
	}
	private List<EndpointType> createSingleLogoutServices(){
		return [smdmp.genEndpoint("http://slbinding1.com","http://sllocation1.com", null,null,null),
				smdmp.genEndpoint("http://slbinding2.com","http://sllocation2.com", null,null,null)]
	}
	private List<EndpointType> createManageNameIDServices(){
		return [smdmp.genEndpoint("http://mnidbinding1.com","http://mnidlocation1.com", null,null,null),
				smdmp.genEndpoint("http://mnidbinding2.com","http://mnidlocation2.com", null,null,null)]
	}

	private List<EndpointType> createSingleSignOnServices(){
		return [smdmp.genEndpoint("http://ssobinding1.com","http://ssolocation1.com", null,null,null),
				smdmp.genEndpoint("http://ssobinding2.com","http://ssolocation2.com", null,null,null)]
	}

	private List<EndpointType> createNameIDMappingServices(){
		return [smdmp.genEndpoint("http://nidmbinding1.com","http://nidmlocation1.com", null,null,null),
				smdmp.genEndpoint("http://nidmbinding2.com","http://nidmlocation2.com", null,null,null)]
	}

	private List<EndpointType> createAssertionIDRequestServices(){
		return [smdmp.genEndpoint("http://aidrbinding1.com","http://aidrlocation1.com", null,null,null),
				smdmp.genEndpoint("http://aidrbinding2.com","http://aidrlocation2.com", null,null,null)]
	}

	private List<AttributeType> createSAMLAttributes(){
		AttributeType attr1 = of.createAttributeType()
		attr1.name = "SomeAttr1"
		attr1.attributeValue.add("SomeValue1")
		AttributeType attr2 = of.createAttributeType()
		attr2.name = "SomeAttr2"
		attr2.attributeValue.add("SomeValue2")
		return [attr1, attr2]
	}

	private List<RequestedAttributeType> createRequestedAttributes(){
		RequestedAttributeType attr1 = mdOf.createRequestedAttributeType();
		attr1.name = "SomeAttr1"
		attr1.attributeValue.add("SomeValue1")
		attr1.setIsRequired(true);
		RequestedAttributeType attr2 = mdOf.createRequestedAttributeType();
		attr2.name = "SomeAttr2"
		attr2.attributeValue.add("SomeValue2")
		return [attr1, attr2]
	}

	private List<LocalizedNameType> createServiceDescriptions(){
		LocalizedNameType enName = mdOf.createLocalizedNameType()
		enName.lang = "en"
		enName.value = "ServiceDescription"
		LocalizedNameType svName = mdOf.createLocalizedNameType()
		svName.lang = "sv"
		svName.value = "TjänstBeskr"
		return [enName, svName]
	}

	private List<LocalizedNameType> createServiceNames(){
		LocalizedNameType enName = mdOf.createLocalizedNameType()
		enName.lang = "en"
		enName.value = "ServiceName"
		LocalizedNameType svName = mdOf.createLocalizedNameType()
		svName.lang = "sv"
		svName.value = "TjänstNamn"
		return [enName, svName]
	}

	private List<IndexedEndpointType> createAssertionConsumerServices(){
		return [smdmp.genIndexedEndpoint("http://acbinding1.com","http://aclocation1.com", null, 1 , null,null,null),
				smdmp.genIndexedEndpoint("http://acbinding2.com","http://aclocation2.com", null, 1 , null,null,null)]
	}

	private List<AttributeConsumingServiceType> createAttributeConsumingServices(){
		return [smdmp.genAttributeConsumingService(1,true,createServiceNames(),createServiceDescriptions(),createRequestedAttributes())]
	}

	private IDPSSODescriptorType createIDP(){
		return smdmp.genIDPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, createSingleSignOnServices(),null,null,null,null	)
	}

	private SPSSODescriptorType createSP(){
		return smdmp.genSPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, null,createAssertionConsumerServices(),null)
	}

	private List<AdditionalMetadataLocationType> createMetadataLocations(){
		AdditionalMetadataLocationType t = mdOf.createAdditionalMetadataLocationType()
		t.setNamespace(DefaultCSMessageParser.XMLDSIG_NAMESPACE)
		t.value="http://somevalue"
		return [t]
	}

	private AffiliationDescriptorType createAffiliationDescriptor(){
		AffiliationDescriptorType t = mdOf.createAffiliationDescriptorType()
		t.setAffiliationOwnerID("SomeOwnerId")
		t.getAffiliateMember().add("SomeMember")
		return t
	}
}
