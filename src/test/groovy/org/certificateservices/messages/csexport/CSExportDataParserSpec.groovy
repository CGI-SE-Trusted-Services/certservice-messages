package org.certificateservices.messages.csexport

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.DummyMessageSecurityProvider
import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.csexport.jaxb.CSExport
import org.certificateservices.messages.csexport.jaxb.ObjectFactory
import org.certificateservices.messages.csexport.jaxb.Organisation
import org.certificateservices.messages.csexport.jaxb.TokenType
import org.certificateservices.messages.utils.MessageGenerateUtils
import spock.lang.Specification

import java.security.Security

import static org.certificateservices.messages.TestUtils.printXML
import static org.certificateservices.messages.TestUtils.slurpXml

class CSExportDataParserSpec extends Specification {
	
	CSExportDataParser p;
	ObjectFactory of = new ObjectFactory()

	
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
		byte[] data = p.genCSExport_1_0([org],[tt])
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
		CSExport emptyListExp = p.parse(p.genCSExport_1_0([],[]))
		then:
		emptyListExp.getOrganisations() == null
		emptyListExp.getTokenTypes() == null

		when: "Verify that  null lists works as well"
		CSExport nullListExp = p.parse(p.genCSExport_1_0(null,null))
		then:
		nullListExp.getOrganisations() == null
		nullListExp.getTokenTypes() == null
	}

	def "Verify that parser verifies signatures if required"(){
		setup:
		byte[] data = p.genCSExport_1_0([genOrganisation()],[genTokenType()])
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





	private Organisation genOrganisation(){
		Organisation o = of.createOrganisation()
		o.setShortName("testorg1")
		o.setDisplayName("Test Org")
		o.setMatchAdminWith("SomeMatch")
		o.setIssuerDistinguishedName("CN=IssuerDistingueshedName")

		return o
	}

	private TokenType genTokenType(){
		TokenType tt = of.createTokenType()

		tt.setName("tokentype1")
		tt.setDisplayName("Token Type 1")

		return tt
	}
}
