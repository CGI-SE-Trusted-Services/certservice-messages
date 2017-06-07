package org.certificateservices.messages.saml2.assertion

import org.certificateservices.messages.ContextMessageSecurityProvider
import org.certificateservices.messages.saml2.BaseSAMLMessageParser
import org.certificateservices.messages.saml2.CommonSAMLMessageParserSpecification
import org.certificateservices.messages.saml2.assertion.jaxb.AssertionType


class SAMLAssertionMessageParserSpec extends CommonSAMLMessageParserSpecification {

	
	def "Verify that JAXBPackages(), getNameSpace(), getSignatureLocationFinder(), getDefaultSchemaLocations(), getOrganisationLookup() returns the correct values"(){
		expect:
		samp.getJAXBPackages() == SAMLAssertionMessageParser.BASE_JAXB_CONTEXT
		samp.getNameSpace() == BaseSAMLMessageParser.ASSERTION_NAMESPACE
		samp.getSignatureLocationFinder() == samp.assertionSignatureLocationFinder
		samp.getDefaultSchemaLocations().length== 4
		samp.getOrganisationLookup() == null
	}


	def "Verify that decryptEncryptedAssertion decrypts encrypted assertion properly"(){
		setup:
		ContextMessageSecurityProvider.Context context = ContextMessageSecurityProvider.DEFAULT_CONTEXT
		AssertionType assertion1JaxB = samp.parseMessage(context,assertion1,true)

		when:
		def encryptedAssertion = samp.genEncryptedAssertion(context,assertion1, [secProv.getDecryptionCertificate(null)],false)

		then:
		encryptedAssertion.value.encryptedData != null
		when:
		def decryptedAssertion = samp.decryptEncryptedAssertion(context,encryptedAssertion.value, true)
		then:
		decryptedAssertion.value.getID() == assertion1JaxB.getID()

	}

    // generateSimpleAssertion is tested by AssertionPayloadParserSpec


	static byte[] assertion1 = """<?xml version="1.0" encoding="UTF-8"?>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_07f34316c5d43fae293c108ae890316194" IssueInstant="2017-02-10T09:49:53.168Z" Version="2.0"><saml2:Issuer>https://m00-mg-local.idpst.funktionstjanster.se/samlv2/idp/metadata/6/8</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_07f34316c5d43fae293c108ae890316194"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>bC3Fg9v3nWUcbSt5jBQeco+RnpwGpeW6GhWvIteuCPA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>VTP94Ukih4Y4ZhO8L3TVnCHJNq/1bYIqnvwrHHMYSliG+8zjZ5Mv8+zURx2fSJQXyOr8QgNO4QjQgvov9mv7KBtyKznYnXQ0amA7gdivrBgGaRKEqyDG+s3ow7A2L0Y3mjXVaXggel0CjbWI1BwtiAOi1b5RrmddJ5OY3g6+hEq5y6FJ31WpGp+eW5abbJr57KWN4kptzh+vj3PvdGsS3KbqoFws7lez1F89QdpoSWCwxB4eyfxlULWXtAdtrVDKAl7DI/yWS6/sS6ZQ3YyYtvIlFX2GOAX5HxE3XDl3inY6txSTKGn2iLoGEO9GuOAH7qer26fDZ8wZNZETgTA7TQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIFDDCCA/SgAwIBAgISESF1HlPpLVNc8FXl3XKQmw8TMA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNV
                        BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSIwIAYDVQQDExlBbHBoYVNTTCBDQSAt
                        IFNIQTI1NiAtIEcyMB4XDTE2MDUxMTE1NTk0MloXDTE5MDUxMjE1NTk0MlowSjEhMB8GA1UECxMY
                        RG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMSUwIwYDVQQDDBwqLmlkcHN0LmZ1bmt0aW9uc3RqYW5z
                        dGVyLnNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwB0Re+LHfYNloxNMdTjIFgX6
                        KMklQt1ZTI0bpAg+4g5s+xctNaXiYtlu9qEB/TDkP8d/DWY4wB6+q1xQoyxIVrqttsfB9Am/FwNE
                        1QCzjMRgRzGE6W+zZ9yY2xKHon5orW/LHIRR0Td4rm6w2dbq7zFqLMZ6fCsVWIKrsnn4TrubdUOf
                        zi6nk39AoElSeOgATUavS/q64zM6gMnF/9xsXLkcvc3vjjy9D1SUHhxbnP0XHix1U7HIT2xO0yuo
                        xG6o38oHN79nxBt7zB9XQJgpKoJ1FXC0fFLaXG4XrXyfMn2b2q5ZfZ0Jme8bkOtM+83k1RqRxYHX
                        5sN2qh72T+s7dwIDAQABo4IB6DCCAeQwDgYDVR0PAQH/BAQDAgWgMFcGA1UdIARQME4wQgYKKwYB
                        BAGgMgEKCjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0
                        b3J5LzAIBgZngQwBAgEwQwYDVR0RBDwwOoIcKi5pZHBzdC5mdW5rdGlvbnN0amFuc3Rlci5zZYIa
                        aWRwc3QuZnVua3Rpb25zdGphbnN0ZXIuc2UwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcD
                        AQYIKwYBBQUHAwIwPgYDVR0fBDcwNTAzoDGgL4YtaHR0cDovL2NybDIuYWxwaGFzc2wuY29tL2dz
                        L2dzYWxwaGFzaGEyZzIuY3JsMIGJBggrBgEFBQcBAQR9MHswQgYIKwYBBQUHMAKGNmh0dHA6Ly9z
                        ZWN1cmUyLmFscGhhc3NsLmNvbS9jYWNlcnQvZ3NhbHBoYXNoYTJnMnIxLmNydDA1BggrBgEFBQcw
                        AYYpaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL2dzYWxwaGFzaGEyZzIwHQYDVR0OBBYEFGbT
                        MGqoTeCNLPjKx0OWk7jkC8ypMB8GA1UdIwQYMBaAFPXN1TwIUPlqTzq3l9pWg+Zp0mj3MA0GCSqG
                        SIb3DQEBCwUAA4IBAQB3YQJjlxAXiHTlrHCRfOI7ZY7znwACvgKXVK4i+veUG6QOpQDrXX2LwRuZ
                        fC9p6s7UK+mivdk/vPVeBtLzDVk3laQVEG9YgKtBqg0ceZKLmurAn4XDEzblc/YGejJSbNwRTedQ
                        kuEtWPIA3A2NpNlsdFA1lFRg9q8k688bfY1gtHLirw9/AzxlSPxzr7SMZsMA/DPbAduaA/WjXQhw
                        kxRBNGphzcPYT4/Wmey5gK00aJKgF4V2Eq37eY3Rm1Fqh2zpN1gCAFgbeaSa0V6+jB0Padt+YVcF
                        mlGfiAZYFqMbKOE2VoVuxVknAiPLQXUr/PgnQLAjrnZzLYxNEEkhieA6</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_07f84d05d65d647391c67ed7355c530c29</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData Address="85.119.130.112" InResponseTo="_8482c6de-90be-4fa2-b9b9-fa09f9906462" NotOnOrAfter="2017-02-10T09:54:53.168Z" Recipient="https://st-esign.signatureservice.se/mission/acs/ea696372b9fc461b"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2017-02-10T09:44:53.168Z" NotOnOrAfter="2017-02-10T09:54:53.168Z"><saml2:AudienceRestriction><saml2:Audience>https://st-esign.signatureservice.se/metadata/ea696372b9fc461b</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2017-02-10T09:49:53.168Z" SessionIndex="_075e42b47fb05f588ba1ed9f7dceae0c79"><saml2:SubjectLocality Address="85.119.130.112"/><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml2:Attribute Name="Subject_CountryName"><saml2:AttributeValue xsi:type="xs:string">SE</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:1.3.6.1.5.5.7.9.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">M</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:1.3.6.1.5.5.7.9.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">19790515</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="age"><saml2:AttributeValue xsi:type="xs:string">38</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Issuer_CommonName"><saml2:AttributeValue xsi:type="xs:string">Testbank A Customer CA3 v1 for BankID Test</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Issuer_OrganizationName"><saml2:AttributeValue xsi:type="xs:string">Testbank A AB (publ)</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="SecurityLevelDescription"><saml2:AttributeValue xsi:type="xs:string">MobileTwofactorContract</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="SecurityLevel"><saml2:AttributeValue xsi:type="xs:string">3</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="ValidationOcspResponse"><saml2:AttributeValue xsi:type="xs:string">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</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="sn_id"><saml2:AttributeValue xsi:type="xs:string">7905155573</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="sn_type"><saml2:AttributeValue xsi:type="xs:string">19</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="CertificateSerialNumber"><saml2:AttributeValue xsi:type="xs:string">6990815854c47312</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Subject_OrganisationName"><saml2:AttributeValue xsi:type="xs:string">Testbank A AB (publ)</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:1.2.752.29.4.13" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">197905155573</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">DANIEL</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">ERIKSSON</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">DANIEL ERIKSSON</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:1.2.752.201.3.2" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">Js1T-T98S</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>""".replaceAll("\n","").getBytes("UTF-8")


}
