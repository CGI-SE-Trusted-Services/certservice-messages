package org.certificateservices.messages.utils;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.bind.JAXBElement;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.EncryptionConstants;
import org.certificateservices.messages.EncryptionAlgorithmScheme;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.NoDecryptionKeyFoundException;
import org.certificateservices.messages.assertion.AssertionPayloadParser;
import org.certificateservices.messages.assertion.AssertionPayloadParser.EncryptedAssertionXMLConverter;
import org.certificateservices.messages.assertion.jaxb.AssertionType;
import org.certificateservices.messages.assertion.jaxb.AttributeStatementType;
import org.certificateservices.messages.assertion.jaxb.AttributeType;
import org.certificateservices.messages.assertion.jaxb.EncryptedElementType;
import org.certificateservices.messages.assertion.jaxb.NameIDType;
import org.certificateservices.messages.assertion.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.utils.XMLEncrypter;
import org.certificateservices.messages.utils.XMLEncrypter.DecryptedXMLConverter;
import org.certificateservices.messages.xenc.jaxb.EncryptedDataType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

public class XMLEncrypterSpec extends Specification {
	
	ObjectFactory of = new ObjectFactory()
	X509Certificate testCert
	AssertionPayloadParser assertionPayloadParser
	XMLEncrypter xmlEncrypter
	List<X509Certificate> threeReceipients
	List<X509Certificate> twoReceiptiensValidFirst
	List<X509Certificate> twoReceiptiensValidLast
	List<X509Certificate> noValidReceiptients
	
	def setupSpec(){
		Init.init()
	}


	def setup(){
		setupRegisteredPayloadParser();
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
		
		assertionPayloadParser.systemTime = new DefaultSystemTime()
		CertificateFactory cf = CertificateFactory.getInstance("X.509")
		testCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(base64Cert)))
		
		xmlEncrypter = new XMLEncrypter(assertionPayloadParser.csMessageParser.messageSecurityProvider, assertionPayloadParser.getDocumentBuilder(),
			 assertionPayloadParser.getAssertionMarshaller(),
			 assertionPayloadParser.getAssertionUnmarshaller())
		
		threeReceipients = new ArrayList<X509Certificate>();
		for(String keyId : assertionPayloadParser.csMessageParser.messageSecurityProvider.decryptionKeyIds){
			threeReceipients.add(assertionPayloadParser.csMessageParser.messageSecurityProvider.getDecryptionCertificate(keyId))
		}
		
		X509Certificate validCert = assertionPayloadParser.csMessageParser.messageSecurityProvider.getDecryptionCertificate(assertionPayloadParser.csMessageParser.messageSecurityProvider.decryptionKeyIds.iterator().next())
		
		twoReceiptiensValidFirst = new ArrayList<X509Certificate>();
		twoReceiptiensValidFirst.add(validCert)
		twoReceiptiensValidFirst.add(testCert)
		
		twoReceiptiensValidLast = new ArrayList<X509Certificate>();
		twoReceiptiensValidLast.add(testCert)
		twoReceiptiensValidLast.add(validCert)
		
		noValidReceiptients = new ArrayList<X509Certificate>();
		noValidReceiptients.add(testCert)
		
	}
	
	@Unroll
	def "Verify that encryptElement generates encrypted XML document with included certificate using encryption scheme: #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipher = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI());
		xmlEncrypter.encDataXMLCipher = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI());
		
		AttributeType attributeType1 = of.createAttributeType()
		attributeType1.getAttributeValue().add("Hej Svejs")
		attributeType1.setName("SomeAttribute")
		def attribute1 = of.createAttribute(attributeType1)
		
		
		when:
		Document encDoc = xmlEncrypter.encryptElement(attribute1, threeReceipients, false);
		String encXML = docToString(encDoc)
		//println encXML
		
		def xml = new XmlSlurper().parse(new StringReader(encXML)); 
		then:
		xml.@Type == "http://www.w3.org/2001/04/xmlenc#Element"
		xml.EncryptionMethod.@Algorithm == encScheme.getDataEncryptionAlgorithmURI()
		xml.KeyInfo.EncryptedKey.size() == 3
		xml.KeyInfo.EncryptedKey[0].EncryptionMethod.@Algorithm == encScheme.getKeyEncryptionAlgorithmURI()
		xml.KeyInfo.EncryptedKey[0].KeyInfo.X509Data.X509Certificate.toString().trim() == testcertdata1
		xml.KeyInfo.EncryptedKey[0].CipherData.toString().length() > 0
		xml.CipherData.toString().length() > 0
		true
		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}
	
	
	@Unroll
	def "Verify that encryptElement generates encrypted XML document with included keyid using encryption scheme: #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipher = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI());
		xmlEncrypter.encDataXMLCipher = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI());		
		
		when:
		Document encDoc = xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), threeReceipients, true);
		String encXML = docToString(encDoc)
//		println encXML
		
		def xml = new XmlSlurper().parse(new StringReader(encXML));
		then:
		xml.@Type == "http://www.w3.org/2001/04/xmlenc#Element"
		xml.EncryptionMethod.@Algorithm == encScheme.getDataEncryptionAlgorithmURI()
		xml.KeyInfo.EncryptedKey.size() == 3
		xml.KeyInfo.EncryptedKey[0].EncryptionMethod.@Algorithm == encScheme.getKeyEncryptionAlgorithmURI()
		xml.KeyInfo.EncryptedKey[0].KeyInfo.KeyName == "A2a5JrfZL6oHCSexVqT9GyeV66QaYYY1YbqU+/eDkyc="
		xml.KeyInfo.EncryptedKey[0].CipherData.toString().length() > 0
		xml.CipherData.toString().length() > 0
		true
		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}
	

	@Unroll
	def "Verify that decryptDocument decrypts document encrypted with certificate as keyinfo using encryption scheme: #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipher = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI());
		xmlEncrypter.encDataXMLCipher = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI());
		def encDoc = docToStringToDoc(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), twoReceiptiensValidFirst, false))
		when:
        JAXBElement<AttributeType> decryptedAttribute = xmlEncrypter.decryptDocument(encDoc)
		AttributeType attributeType = decryptedAttribute.getValue();
		then:
		attributeType.getName() == "SomeAttribute"
		attributeType.getAttributeValue().get(0) == "Hej Svejs"
		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}
	
	
	@Unroll
	def "Verify that decryptDocument decrypts document encrypted with keyname as keyinfo using encryption scheme: #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipher = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI());
		xmlEncrypter.encDataXMLCipher = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI());
		def encDoc = docToStringToDoc(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), twoReceiptiensValidFirst, true))
		when:
		JAXBElement<AttributeType> decryptedAttribute = xmlEncrypter.decryptDocument(encDoc)
		AttributeType attributeType = decryptedAttribute.getValue();
		then:
		attributeType.getName() == "SomeAttribute"
		attributeType.getAttributeValue().get(0) == "Hej Svejs"
		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}
	
	@Unroll
	def "Verify that decryptDocument decrypts document even if valid key info isn't the first one using : #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipher = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI());
		xmlEncrypter.encDataXMLCipher = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI());
		def encDoc = docToStringToDoc(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), twoReceiptiensValidLast, true))
		when:
		JAXBElement<AttributeType> decryptedAttribute = xmlEncrypter.decryptDocument(encDoc)
		AttributeType attributeType = decryptedAttribute.getValue();
		then:
		attributeType.getName() == "SomeAttribute"
		attributeType.getAttributeValue().get(0) == "Hej Svejs"
		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}
	

	def "Verify that decryptDocument throws NoDecryptionKeyFoundException if no valid key info could be found"(){
		setup:
		xmlEncrypter.encKeyXMLCipher = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getKeyEncryptionAlgorithmURI());
		xmlEncrypter.encDataXMLCipher = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getDataEncryptionAlgorithmURI());
		def encDoc = docToStringToDoc(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), noValidReceiptients, true))
		when:
		xmlEncrypter.decryptDocument(encDoc)
		
		then:
		thrown NoDecryptionKeyFoundException
		
		when:
		def encDoc2 = docToStringToDoc(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), new ArrayList(), true))
		xmlEncrypter.decryptDocument(encDoc2)
		then:
		thrown NoDecryptionKeyFoundException
		
	}
	
	
	def "Verify that decryptDocument can decrypt Assertion containing multiple encrypted SAMLAttributes with the same reciepients"(){
		setup:
		xmlEncrypter.encKeyXMLCipher = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getKeyEncryptionAlgorithmURI());
		xmlEncrypter.encDataXMLCipher = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getDataEncryptionAlgorithmURI());
		def encDoc = genComplexSAMLWithToEncryptedData()
		when:
		JAXBElement<AttributeType> assertion = xmlEncrypter.decryptDocument(encDoc, new EncryptedAssertionXMLConverter())
		AssertionType assertionType = assertion.getValue()
		AttributeStatementType attributeStatement = assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().get(0);
		AttributeType attr1 = attributeStatement.getAttributeOrEncryptedAttribute().get(0)
		AttributeType attr2 = attributeStatement.getAttributeOrEncryptedAttribute().get(1)
		then:
		attributeStatement.getAttributeOrEncryptedAttribute().size() == 2
		attr1.getName() == "SomeAttribute1"
		attr2.getName() == "SomeAttribute2"
	}
	
	def "Verify that generateKeyId generates a valid id as Base64 encoded SHA-256 hash or throws MessageProcessingException if generation fails"(){
		expect:
		XMLEncrypter.generateKeyId(testCert.getPublicKey()) == "yrhA2ngreu9CwRBvbfKReRFRmZk/GB50/vT6IhgT8no="
		when:
		XMLEncrypter.generateKeyId(null)
		then:
		thrown MessageProcessingException
	}
	
	def "Verify verifyCiphers accepts supported chiphers and thrown MessageContentException for unsupported chiphers"(){
		setup:
		Document encryptedDoc = xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute1","Hej Svejs1" ), twoReceiptiensValidLast, true)
		Element encryptedElement = encryptedDoc.getDocumentElement()
		when:
		xmlEncrypter.verifyCiphers(encryptedElement)
		then:
		true
		
		when:
		Element encryptionMethod = encryptedElement.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTIONMETHOD).item(0);
		encryptionMethod.setAttribute(EncryptionConstants._ATT_ALGORITHM, "INVALID")
		
		xmlEncrypter.verifyCiphers(encryptedElement)
		then:
		thrown MessageContentException
	}
	
	private def genSAMLAttribute(String name, String value){
		AttributeType attributeType1 = of.createAttributeType()
		attributeType1.getAttributeValue().add(value)
		attributeType1.setName(name)
		return of.createAttribute(attributeType1)
		
	}
	
	private String docToString(Document doc) throws Exception {

		ByteArrayOutputStream bo = new ByteArrayOutputStream();

		TransformerFactory factory = TransformerFactory.newInstance();
		Transformer transformer = factory.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		DOMSource source = new DOMSource(doc);
		StreamResult result = new StreamResult(bo);
		transformer.transform(source, result);

		bo.close();
		return new String(bo.toByteArray(),"UTF-8")
				
	}
	

	
	private Document docToStringToDoc(Document doc) throws Exception{
		return xmlEncrypter.documentBuilder.parse(new ByteArrayInputStream(docToString(doc).getBytes("UTF-8")));
	}
	
	private Document genComplexSAMLWithToEncryptedData(){
		NameIDType nameIdType = of.createNameIDType()
		nameIdType.setValue("SomeIssuer")
		
		JAXBElement<EncryptedDataType> encDataElement1 = xmlEncrypter.unmarshaller.unmarshal(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute1","Hej Svejs1" ), twoReceiptiensValidLast, true))
		JAXBElement<EncryptedDataType> encDataElement2 = xmlEncrypter.unmarshaller.unmarshal(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute2","Hej Svejs2" ), twoReceiptiensValidLast, true))
		
		EncryptedElementType encryptedElementType1 = of.createEncryptedElementType();
		encryptedElementType1.setEncryptedData(encDataElement1.getValue());
		
		EncryptedElementType encryptedElementType2 = of.createEncryptedElementType();
		encryptedElementType2.setEncryptedData(encDataElement2.getValue());
		
		AttributeStatementType attributeStatementType = of.createAttributeStatementType()
		attributeStatementType.attributeOrEncryptedAttribute.add(encryptedElementType1)
		attributeStatementType.attributeOrEncryptedAttribute.add(encryptedElementType2)
			
		AssertionType assertionType = of.createAssertionType();
		assertionType.setID("_" +MessageGenerateUtils.generateRandomUUID())
		assertionType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date()))
		assertionType.setIssuer(nameIdType)
		assertionType.setVersion("2.0")
		assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(attributeStatementType)
	
		def assertion = of.createAssertion(assertionType)
		
		byte[] signedAssertion = assertionPayloadParser.marshallAndSignAssertion(assertion)
		
		//println new String(signedAssertion,"UTF-8")
		return xmlEncrypter.documentBuilder.parse(new ByteArrayInputStream(signedAssertion))
	}

	def testcertdata1 = """MIIDcTCCAlmgAwIBAgIEZf08dzANBgkqhkiG9w0BAQsFADBpMRAwDgYDVQQGEwdVbmtub3duMRAw
DgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYDVQQKEwd0ZXN0b3JnMRAwDgYD
VQQLEwdVbmtub3duMQ0wCwYDVQQDEwRrZXkxMB4XDTE1MDcwNjEwNDYwMloXDTM1MDMyMzEwNDYw
MlowaTEQMA4GA1UEBhMHVW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93
bjEQMA4GA1UEChMHdGVzdG9yZzEQMA4GA1UECxMHVW5rbm93bjENMAsGA1UEAxMEa2V5MTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKEFZfEUkqVw3fe9YfPuK+X/GdAJgw2zvZ8QNY3J
X/dJjMjefjDlZIkAM1zaVzjxiu94UhrS/CEL+ouLWgRi3dvtOYCsilkTjl6NPKwPFkU1EfRVOVnP
aJoaqeLLvDck+iN/f+0xtOd1YY6vZZivPeXAOIonMWprxzaFUi///1tL5QSQ09FUR6EHNPtFk8Aj
CGF7j7Y1DCwayfYYe5auyPvRNbJ2IkmEemrWina8uV6v2gqIhjj3HPe8idUkQfsbd7Cn5036ETLb
NIHCF9MhAQO4VvScmucaZZcbJAsc6uJ/djCX5Omfqm2E7DWpDQDHKLG1fln65txJpPa23WTa5fEC
AwEAAaMhMB8wHQYDVR0OBBYEFM1cn0IBTznpUe1AXJKrOrvsoofRMA0GCSqGSIb3DQEBCwUAA4IB
AQCPuSHK/1NX+nWby67SRC/xYpYenLqyjh6vdrxA8AfqOuZq0HNoGPmAQc6HQn3aX1FJ+6sViohl
1SqI38F9raB8Opqg8e0zONEZV1FNtS2V7Sx/IA0WcxnsoMuWReYKqVR+yffqsgn89q3MUWwuD9Yx
sSRjPxCeBd7arAgZv72PriiqxvvFCGoXrX5Prng8euS/gIeDQZBNEWC3MzbLty8QwMqKFd0+V2fz
LaRMArYLp0nS3TwF24KdgaKuSyA0nq1j/ZNyi/TowrNPA4FLE2f/1akjn3mvgpn62XQoPO1BfZCq
utkUJrOx5P7ZIr91erXUfsQbPDsQkcjAi3IPJFAr"""
	
   def testchipherdata1 = """DOFOukwwk3Xj0J0LJ3op/MLQh/HeeGj4KkKKUchLOKc6LJvGfLIpN1QqT9DAY1rmpMQYu0H7JOPu
        JRAX63XUD5XV5KXfSXS2G23/oQcVelRbUjtdDa9RivbkNZo2SjkgsNxyhj2kVkUDok7yT5Qxrg85
        eHRIWoTVzjuwzS4duHzkje0wS7oc/Iuq7Rb1W1D2/l1YWOSKmThBh1GafmHaDLzxcgFdmn3dfVp7
        wfnYQU96dseWUgBUHfZKLewQCZOwz2IywrHuHdxjGEc4dOgHw4mV/ePLxiJAeCPjxkg4+ZgBaiZH
        JhkQQOYbPIcTvePsleUVfc2hq2RWCd9rpsHjZA=="""
	
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