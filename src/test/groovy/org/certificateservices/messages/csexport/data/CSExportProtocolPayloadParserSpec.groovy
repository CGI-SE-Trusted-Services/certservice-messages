package org.certificateservices.messages.csexport.data

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.csexport.data.jaxb.CSExport
import org.certificateservices.messages.csexport.protocol.jaxb.*
import org.certificateservices.messages.csexport.protocol.CSExportProtocolPayloadParser
import org.certificateservices.messages.csmessages.CSMessageParserManager
import org.certificateservices.messages.csmessages.CSMessageResponseData
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.csmessages.PayloadParserRegistry
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import spock.lang.Specification

import java.security.Security

import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

class CSExportProtocolPayloadParserSpec extends Specification {

	CSExportProtocolPayloadParser pp;
	CSExportDataParser csExportDataParser;
	ObjectFactory of = new ObjectFactory()
	org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init();
	}

	DefaultCSMessageParser csMessageParser

	def setup(){
		setupRegisteredPayloadParser();
		csMessageParser = CSMessageParserManager.getCSMessageParser()
		pp = PayloadParserRegistry.getParser(CSExportProtocolPayloadParser.NAMESPACE);
		csExportDataParser = new CSExportDataParser(csMessageParser.messageSecurityProvider, true)
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "org.certificateservices.messages.csexport.protocol.jaxb"
		pp.getNameSpace() == "http://certificateservices.org/xsd/cs_export_protocol2_0"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getDefaultPayloadVersion() == "2.0"
		pp.getSupportedVersions() == ["2.0"] as String[]
	}

	def "Verify that genGetCSExportRequest() generates a valid xml message and genGetCSExportResponse() generates a valid CSMessageResponseData without any query paramters"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetCSExportRequest(TEST_ID, "SOMESOURCEID", "someorg","1.0",null,createOriginatorCredential( ), null)
        //printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetCSExportRequest
		then:
		messageContainsPayload requestMessage, "csexp:GetCSExportRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetCSExportRequest", createOriginatorCredential(), csMessageParser)
		payloadObject.@exportDataVersion == "1.0"
		payloadObject.queryParameters.size() == 0
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		CSExport csExportData = csExportDataParser.genCSExport_1_0AsObject([CSExportDataParserSpec.genOrganisation()], [CSExportDataParserSpec.genTokenType()])
		CSMessageResponseData rd = pp.genGetCSExportResponse("SomeRelatedEndEntity", request, "1.0", csExportData, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetCSExportResponse
		
		then:
		messageContainsPayload rd.responseData, "csexp:GetCSExportResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetCSExportResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetCSExportResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)


		when:
		CSMessage resp = pp.parseMessage(rd.responseData)
		GetCSExportResponse pl = resp.getPayload().any
		CSExport csExport = pp.getCSExportDataFromResponse(resp)

		then:
		pl.exportDataVersion == "1.0"
		csExport.organisations.organisation.size() == 1
		csExport.tokenTypes.tokenType.size() == 1
		csExport.signature.keyInfo.content.size() == 1
		
	}

	def "Verify that generation using query parameters generates valid XML"(){
		setup:
		QueryParameter q1 = new QueryParameter()
		q1.type = "SomeType1"
		q1.value = "SomeValue"
		QueryParameter q2 = new QueryParameter()
		q2.type = "SomeType2"

		when:
		byte[] requestMessage = pp.genGetCSExportRequest(TEST_ID, "SOMESOURCEID", "someorg","1.0",[q1,q2],createOriginatorCredential( ), null)
		printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetCSExportRequest
		then:
		payloadObject.queryParameters.size() == 1
		payloadObject.queryParameters.queryParameter.size() == 2
		payloadObject.queryParameters.queryParameter[0].type == "SomeType1"
		payloadObject.queryParameters.queryParameter[0].value == "SomeValue"
		payloadObject.queryParameters.queryParameter[1].type == "SomeType2"

		when:
		pp.parseMessage(pp.genGetCSExportRequest(TEST_ID, "SOMESOURCEID", "someorg","1.0",[new QueryParameter()],createOriginatorCredential( ), null));
		then:
		thrown MessageContentException
	}

}
