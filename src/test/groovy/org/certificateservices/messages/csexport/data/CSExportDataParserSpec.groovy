package org.certificateservices.messages.csexport.data

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.DummyMessageSecurityProvider
import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.csexport.data.CSExportDataParser
import org.certificateservices.messages.csexport.data.jaxb.CSExport
import org.certificateservices.messages.csexport.data.jaxb.FieldConstraint
import org.certificateservices.messages.csexport.data.jaxb.ObjectFactory
import org.certificateservices.messages.csexport.data.jaxb.Organisation
import org.certificateservices.messages.csexport.data.jaxb.TokenType
import org.certificateservices.messages.utils.MessageGenerateUtils
import spock.lang.Specification

import java.security.Security

import static org.certificateservices.messages.TestUtils.*

class CSExportDataParserSpec extends Specification {
	
	CSExportDataParser p;
	static ObjectFactory of = new ObjectFactory()

	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init();
	}
	
	def setup(){
		DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
		p = new CSExportDataParser(secprov, true)
	}

	def "Verify that constructor sets all fields"(){
		expect:
		p.xmlSigner != null
		p.requireSignature
	}


	def "Verify that parse method validates against schema"(){
		setup:
		def exp = of.createCSExport()
		exp.setID(MessageGenerateUtils.generateRandomUUID())
		byte[] data = p.marshallAndSign(exp)
		when:
		p.parse(data)
		then:
		thrown MessageContentException
		
	}	
	
	def "Verify that marshall and parse generates and parser valid XML"(){
		setup:
		def org = genOrganisation()
		def tt = genTokenType()
		when:
		byte[] data = p.genCSExport_1_x("1.0",[org],[tt])
		String message = new String(data, "UTF-8")
		//printXML(message)
		def xml = slurpXml(message)
		then:
        message =~ 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
        message =~ 'xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0"'
		
		xml.@version == CSExportDataParser.VERSION_1_0
		def o = xml.organisations.organisation[0]
		o.shortName == "testorg1"
		o.displayName == "Test Org"
		o.matchAdminWith == "SomeMatch"
		o.issuerDistinguishedName == "CN=IssuerDistingueshedName"

		def t = xml.tokenTypes.tokenType[0]
		t.name == "tokentype1"
		t.displayName == "Token Type 1"

		when:
		CSExport exp = p.parse(data)
		
		then:
		exp != null

		when: "Verify that empty lists works as well"
		CSExport emptyListExp = p.parse(p.genCSExport_1_x("1.0",[],[]))
		then:
		emptyListExp.getOrganisations() == null
		emptyListExp.getTokenTypes() == null

		when: "Verify that  null lists works as well"
		CSExport nullListExp = p.parse(p.genCSExport_1_x("1.0",null,null))
		then:
		nullListExp.getOrganisations() == null
		nullListExp.getTokenTypes() == null

		when: "Verify that 1.1 generation is supported"
		def ttWithConditional = genTokenType("1.1")
		data = p.genCSExport_1_x("1.1",[org],[ttWithConditional])
		message = new String(data, "UTF-8")
		//printXML(message)
		xml = slurpXml(message)
		then:
		message =~ 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
		message =~ 'xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0"'

		xml.@version == CSExportDataParser.VERSION_1_1
		def o2 = xml.organisations.organisation[0]
		o2.shortName == "testorg1"

		def t2 = xml.tokenTypes.tokenType[0]
		t2.name == "tokentype1"
		t2.fieldConstraints.fieldConstraint[0].relatedField == "SomeRelatedField"
	}

	def "Verify that genCSExport_1_0AsObject generates a valid JAXB element with signature and i marshallable to byte[]"(){
		setup:
		def org = genOrganisation()
		def tt = genTokenType()
		when:
		CSExport csExport = p.genCSExport_1_xAsObject("1.0",[org],[tt])
		then:
		csExport.organisations.organisation.size() == 1
		csExport.tokenTypes.tokenType.size() == 1
		csExport.signature.keyInfo.content.size() == 1

		when:
		byte[] data = p.marshallCSExportData(csExport)
		String message = new String(data,"UTF-8")
		//printXML(message)
		def xml = slurpXml(message)
		then:
		message =~ 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
		message =~ 'xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0"'

		xml.@version == CSExportDataParser.VERSION_1_0
		def o = xml.organisations.organisation[0]
		o.shortName == "testorg1"
		o.displayName == "Test Org"
		o.matchAdminWith == "SomeMatch"
		o.issuerDistinguishedName == "CN=IssuerDistingueshedName"

		def t = xml.tokenTypes.tokenType[0]
		t.name == "tokentype1"
		t.displayName == "Token Type 1"

	}

	def "Verify that parser verifies signatures if required"(){
		setup:
		byte[] data = p.genCSExport_1_x("1.0",[genOrganisation()],[genTokenType()])
		String msg = new String(data,"UTF-8")
		boolean expectionThrown = false
		when:
		msg = msg.replace("<csexd:shortName>testorg1</csexd:shortName>","<csexd:shortName>testorg2</csexd:shortName>")

		def exp = p.parse(msg.getBytes("UTF-8"))
		then:
		thrown MessageContentException

		when:
		p.requireSignature = false
		then:
		p.parse(msg.getBytes("UTF-8")) != null
	}

	def "Verify that trying to parse a 1.1 xml using version 1.0 parser generates error"(){
		setup: // Generate 1.1 data with 1.0 version tag
		def org = genOrganisation()
		def tt = genTokenType("1.1")
		byte[] data = p.genCSExport_1_x("1.0",[org],[tt])

		when:
		p.parse(data)
		then:
		thrown MessageContentException

	}





	public static Organisation genOrganisation(){
		Organisation o = of.createOrganisation()
		o.setShortName("testorg1")
		o.setDisplayName("Test Org")
		o.setMatchAdminWith("SomeMatch")
		o.setIssuerDistinguishedName("CN=IssuerDistingueshedName")

		return o
	}

	public static TokenType genTokenType(String version = "1.0"){
		TokenType tt = of.createTokenType()

		tt.setName("tokentype1")
		tt.setDisplayName("Token Type 1")

		if(version == "1.1"){
			FieldConstraint fc = of.createFieldConstraint()
			fc.relatedField = "SomeRelatedField"

			tt.fieldConstraints = new TokenType.FieldConstraints()
			tt.fieldConstraints.fieldConstraint.add(fc)
		}

		return tt
	}
}
