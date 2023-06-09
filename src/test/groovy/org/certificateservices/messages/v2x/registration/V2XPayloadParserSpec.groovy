/************************************************************************
 *                                                                       *
 *  Certificate Service - Messages                                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.messages.v2x.registration

import org.apache.xml.security.Init
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import org.certificateservices.messages.csmessages.CSMessageParserManager
import org.certificateservices.messages.csmessages.CSMessageResponseData
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.csmessages.PayloadParserRegistry
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.utils.MessageGenerateUtils
import org.certificateservices.messages.v2x.registration.jaxb.*
import spock.lang.Specification

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security

import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

/**
 * Unit tests for V2XPayloadParser
 *
 * @author Philip Vendil 2020-01-29
 */
class V2XPayloadParserSpec extends Specification {

    V2XPayloadParser pp
    static ObjectFactory of = new ObjectFactory()
    org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()

    DefaultCSMessageParser csMessageParser
    def currentTimeZone

    KeyPair signKeys

    def setupSpec(){
        Security.addProvider(new BouncyCastleProvider())
        Init.init()

        // Use english - make test locale independent.
        Locale.setDefault(new Locale("en", "US"))
    }

    def setup(){
        currentTimeZone = TimeZone.getDefault()
        TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))
        setupRegisteredPayloadParser()
        csMessageParser = CSMessageParserManager.getCSMessageParser()
        pp = PayloadParserRegistry.getParser(V2XPayloadParser.NAMESPACE)

        KeyPairGenerator kf = KeyPairGenerator.getInstance("EC","BC")
        kf.initialize(ECNamedCurveTable.getParameterSpec("P-256"))
        signKeys = kf.generateKeyPair()
    }

    def cleanup(){
        TimeZone.setDefault(currentTimeZone)
    }

    def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
        expect:
        pp.getJAXBPackage() == "org.certificateservices.messages.v2x.registration.jaxb"
        pp.getNameSpace() == "http://certificateservices.org/xsd/v2x_registration_2_0"
        pp.getSchemaAsInputStream("2.0") != null
        pp.getDefaultPayloadVersion() == "2.0"
        pp.getSupportedVersions() == ["2.0"] as String[]
    }

    def "Verify that generateRegisterITSSRequest() generates a valid xml message and generateRegisterITSResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateRegisterITSSRequest(TEST_ID, "SOMESOURCEID",  "someorg",
                "someEcuType", "SomeITSId", signKeys.public.encoded, "someEAName","someECProfile", "someATProfile", genAppPermissions(),
                new Date(5000L), new Date(15000L), genRegions([1,2,3]),createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.RegisterITSSRequest
        then:
        messageContainsPayload requestMessage, "v2x:RegisterITSSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","RegisterITSSRequest", createOriginatorCredential(), csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        payloadObject.canonicalPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        payloadObject.eaName == "someEAName"
        payloadObject.ecProfile == "someECProfile"
        payloadObject.atProfile == "someATProfile"
        payloadObject.itssValidFrom == "1970-01-01T01:00:05.000+01:00"
        payloadObject.itssValidTo == "1970-01-01T01:00:15.000+01:00"
        payloadObject.regions.identifiedRegions.countryOnly.size() == 3
        payloadObject.regions.identifiedRegions.countryOnly[0] == 1
        payloadObject.regions.identifiedRegions.countryOnly[1] == 2
        payloadObject.regions.identifiedRegions.countryOnly[2] == 3
        payloadObject.ecuType == "someEcuType"
        verifyAppPermissions(payloadObject.atPermissions)
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateRegisterITSSResponse("SomeRelatedEndEntity", request,  "someEcuType",
                "SomeITSId", genEcKeyType(), "someEAName","someECProfile", "someATProfile", genAppPermissions(),
                new Date(5000L), new Date(15000L), genRegions([1,2,3]), ITSSStatusType.ACTIVE)
		printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.RegisterITSSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:RegisterITSSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "RegisterITSSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","RegisterITSSResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)
        verifyAppPermissions(payloadObject.atPermissions)
        verifyFullResponsePayload(payloadObject)

        expect:
        pp.parseMessage(rd.responseData)

        when: // Generate message with pre-populated payload
        RegisterITSSResponse payload = new RegisterITSSResponse()
        pp.populateBaseV2XResponseType(payload, "someEcuType",
                "SomeITSId", genEcKeyType(), "someEAName","someECProfile", "someATProfile", genAppPermissions(),
                new Date(5000L), new Date(15000L), genRegions([1,2,3]),ITSSStatusType.ACTIVE)
        rd = pp.generateRegisterITSSResponse("SomeRelatedEndEntity", request,  payload)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.RegisterITSSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:RegisterITSSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "RegisterITSSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","RegisterITSSResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)
        verifyAppPermissions(payloadObject.atPermissions)
        verifyFullResponsePayload(payloadObject)

        expect:
        pp.parseMessage(rd.responseData)


    }

    def "Verify that generateRegisterITSSRequest() generates a valid xml message with minimal required values and generateRegisterITSResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateRegisterITSSRequest(TEST_ID, "SOMESOURCEID", "someorg",
                 "someEcuType", "SomeITSId", signKeys.public.encoded,
                 "someEAName",null, null, genAppPermissions(),null,
                null, null,null, null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.RegisterITSSRequest
        then:
        messageContainsPayload requestMessage, "v2x:RegisterITSSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","RegisterITSSRequest", null, csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        payloadObject.canonicalPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        payloadObject.eaName == "someEAName"
        payloadObject.ecuType == "someEcuType"
        verifyAppPermissions(payloadObject.atPermissions)
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateRegisterITSSResponse("SomeRelatedEndEntity", request,
                "someEcuType", "SomeITSId", genEcKeyType(), "someEAName",null, null,
                genAppPermissions(),null,null,null,ITSSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.RegisterITSSResponse
        then:
        messageContainsPayload rd.responseData, "v2x:RegisterITSSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "RegisterITSSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","RegisterITSSResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)

    }

    def "Verify that generateUpdateITSSRequest() generates a valid xml message and generateUpdateITSResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateUpdateITSSRequest(TEST_ID, "SOMESOURCEID", "someorg",
                "someEcuType","SomeITSId", signKeys.public.encoded, "someEAName", "someECProfile", "someATProfile", genAppPermissions(),
                new Date(5000L), new Date(15000L), genRegions([1,2,3]), createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.UpdateITSSRequest
        then:
        messageContainsPayload requestMessage, "v2x:UpdateITSSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","UpdateITSSRequest", createOriginatorCredential(), csMessageParser)

        payloadObject.ecuType == "someEcuType"
        payloadObject.canonicalId == "SomeITSId"
        payloadObject.canonicalPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        payloadObject.eaName == "someEAName"
        payloadObject.ecProfile == "someECProfile"
        payloadObject.atProfile == "someATProfile"
        payloadObject.itssValidFrom == "1970-01-01T01:00:05.000+01:00"
        payloadObject.itssValidTo == "1970-01-01T01:00:15.000+01:00"
        payloadObject.regions.identifiedRegions.countryOnly.size() == 3
        payloadObject.regions.identifiedRegions.countryOnly[0] == 1
        payloadObject.regions.identifiedRegions.countryOnly[1] == 2
        payloadObject.regions.identifiedRegions.countryOnly[2] == 3
        verifyAppPermissions(payloadObject.atPermissions)
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateUpdateITSSResponse("SomeRelatedEndEntity", request,
                 "someEcuType", "SomeITSId",
                genEcKeyType(), "someEAName","someECProfile", "someATProfile", genAppPermissions(),
                new Date(5000L), new Date(15000L), genRegions([1,2,3]),ITSSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.UpdateITSSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:UpdateITSSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "UpdateITSSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","UpdateITSSResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyFullResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)
        expect:
        pp.parseMessage(rd.responseData)

        when: // Generate message with pre-populated payload
        UpdateITSSResponse payload = new UpdateITSSResponse()
        pp.populateBaseV2XResponseType(payload,"someEcuType", "SomeITSId",
                genEcKeyType(), "someEAName","someECProfile", "someATProfile", genAppPermissions(),
                new Date(5000L), new Date(15000L), genRegions([1,2,3]),ITSSStatusType.ACTIVE)
        rd = pp.generateUpdateITSSResponse("SomeRelatedEndEntity", request,payload)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.UpdateITSSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:UpdateITSSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "UpdateITSSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","UpdateITSSResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyFullResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)
        expect:
        pp.parseMessage(rd.responseData)
    }

    def "Verify that generateUpdateITSSRequest() generates a valid xml message with minimal required values and generateUpdateITSResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateUpdateITSSRequest(TEST_ID, "SOMESOURCEID", "someorg","someEcuType","SomeITSId", signKeys.public.encoded,
                null,null, null, null, null, null, null,null, null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.UpdateITSSRequest
        then:
        messageContainsPayload requestMessage, "v2x:UpdateITSSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","UpdateITSSRequest", null, csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        payloadObject.canonicalPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateUpdateITSSResponse("SomeRelatedEndEntity", request,
                 "someEcuType",
                "SomeITSId", genEcKeyType(),"someEAName", null, null,
                genAppPermissions(),null,null,null,ITSSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.UpdateITSSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:UpdateITSSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "UpdateITSSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","UpdateITSSResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)

    }

    def "Verify that generateGetITSSRequest() generates a valid xml message and generateGetITSSResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateGetITSSDataRequest(TEST_ID, "SOMESOURCEID", "someorg",  "SomeITSId", false, createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.GetITSSDataRequest
        then:
        messageContainsPayload requestMessage, "v2x:GetITSSDataRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID",
                "someorg","GetITSSDataRequest", null, csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateGetITSSDataResponse("SomeRelatedEndEntity", request,
                 "someEcuType",
                "SomeITSId", genEcKeyType(), "someEAName",null, null,genAppPermissions(),
                null,null,null,ITSSStatusType.ACTIVE, null)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.GetITSSDataResponse

        then:
        messageContainsPayload rd.responseData, "v2x:GetITSSDataResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "GetITSSDataResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","GetITSSDataResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)

        when: // Generate message with pre-populated payload
        GetITSSDataResponse payload = new GetITSSDataResponse()
        pp.populateBaseV2XResponseType(payload,                 "someEcuType",
                "SomeITSId", genEcKeyType(), "someEAName",null, null,genAppPermissions(),
                null,null,null,ITSSStatusType.ACTIVE)

        rd = pp.generateGetITSSDataResponse("SomeRelatedEndEntity", request,payload)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.GetITSSDataResponse

        then:
        messageContainsPayload rd.responseData, "v2x:GetITSSDataResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "GetITSSDataResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","GetITSSDataResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)
    }

    def "Verify that generateGetITSSRequest() generates a valid xml message and generateGetITSSResponse() with enrolment credentials included"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateGetITSSDataRequest(TEST_ID, "SOMESOURCEID", "someorg",  "SomeITSId", true, createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.GetITSSDataRequest
        then:
        messageContainsPayload requestMessage, "v2x:GetITSSDataRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID",
                "someorg","GetITSSDataRequest", null, csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        payloadObject.includeEC == "true"
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateGetITSSDataResponse("SomeRelatedEndEntity", request,
                "someEcuType",
                "SomeITSId", genEcKeyType(), "someEAName",null, null,genAppPermissions(),
                null,null,null,ITSSStatusType.ACTIVE, genECs())
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.GetITSSDataResponse

        then:
        messageContainsPayload rd.responseData, "v2x:GetITSSDataResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "GetITSSDataResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","GetITSSDataResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)
        verifyEnrolmentCredentials(payloadObject.enrolmentCredentials)

        expect:
        pp.parseMessage(rd.responseData)

    }

    def "Verify that generateDeactivateITSSRequest() generates a valid xml message and generateDeactivateITSRequest() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateDeactivateITSSRequest(TEST_ID, "SOMESOURCEID", "someorg",
                "SomeITSId", createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.DeactivateITSSRequest
        then:
        messageContainsPayload requestMessage, "v2x:DeactivateITSSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID",
                "someorg","DeactivateITSSRequest", null, csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateDeactivateITSSResponse("SomeRelatedEndEntity", request,
                "someEcuType",
                "SomeITSId", genEcKeyType(),"someEAName", null, null,genAppPermissions(),
                null,null,null,ITSSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.DeactivateITSSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:DeactivateITSSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "DeactivateITSSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","DeactivateITSSResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)

        when: // Generate message with pre-populated payload
        DeactivateITSSResponse payload = new DeactivateITSSResponse()
        pp.populateBaseV2XResponseType(payload,                "someEcuType",
                "SomeITSId", genEcKeyType(),"someEAName", null, null,genAppPermissions(),
                null,null,null,ITSSStatusType.ACTIVE)
        rd = pp.generateDeactivateITSSResponse("SomeRelatedEndEntity", request,payload)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.DeactivateITSSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:DeactivateITSSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "DeactivateITSSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","DeactivateITSSResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)
    }

    def "Verify that generateReactivateITSSRequest() generates a valid xml message and generateReactivateITSRequest() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateReactivateITSSRequest(TEST_ID, "SOMESOURCEID", "someorg",
                "SomeITSId", createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.ReactivateITSSRequest
        then:
        messageContainsPayload requestMessage, "v2x:ReactivateITSSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID",
                "someorg","ReactivateITSSRequest", null, csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateReactivateITSSResponse("SomeRelatedEndEntity", request,
                "someEcuType",
                "SomeITSId", genEcKeyType(), "someEAName",null, null,genAppPermissions(),
                null,null,null,ITSSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.ReactivateITSSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:ReactivateITSSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "ReactivateITSSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","ReactivateITSSResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)

        when: // Generate message with pre-populated payload
        ReactivateITSSResponse payload = new ReactivateITSSResponse()
        pp.populateBaseV2XResponseType(payload,                "someEcuType",
                "SomeITSId", genEcKeyType(),"someEAName", null, null,genAppPermissions(),
                null,null,null,ITSSStatusType.ACTIVE)
        rd = pp.generateReactivateITSSResponse("SomeRelatedEndEntity", request,payload)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.ReactivateITSSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:ReactivateITSSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "ReactivateITSSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","ReactivateITSSResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)
    }


    static RegionsType genRegions(List identifiedRegionsList){
        RegionsType.IdentifiedRegions identifiedRegions = of.createRegionsTypeIdentifiedRegions()
        identifiedRegions.countryOnly.addAll(identifiedRegionsList)
        RegionsType regionsType = of.createRegionsType()
        regionsType.setIdentifiedRegions(identifiedRegions)
        return regionsType
    }

    void verifyFullResponsePayload(def payloadObject){
        assert payloadObject.canonicalId == "SomeITSId"
        assert payloadObject.canonicalPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        assert payloadObject.eaName == "someEAName"
        assert payloadObject.ecProfile == "someECProfile"
        assert payloadObject.atProfile == "someATProfile"
        assert payloadObject.itssValidFrom == "1970-01-01T01:00:05.000+01:00"
        assert payloadObject.itssValidTo == "1970-01-01T01:00:15.000+01:00"
        assert payloadObject.regions.identifiedRegions.countryOnly.size() == 3
        assert payloadObject.regions.identifiedRegions.countryOnly[0] == 1
        assert payloadObject.regions.identifiedRegions.countryOnly[1] == 2
        assert payloadObject.regions.identifiedRegions.countryOnly[2] == 3
        assert payloadObject.ecuType == "someEcuType"
        assert payloadObject.itssStatus == "ACTIVE"
    }

    void verifyMinimalResponsePayload(def payloadObject){
        assert payloadObject.canonicalId == "SomeITSId"
        assert payloadObject.canonicalPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        assert payloadObject.itssStatus == "ACTIVE"
        assert payloadObject.eaName == "someEAName"
    }

    void verifyAppPermissions(def atPermissions){
        assert atPermissions.appPermission.size() == 3
        assert atPermissions.appPermission[0].@psId == "32"
        assert atPermissions.appPermission[0] == "01020304"
        assert atPermissions.appPermission[1].@psId == "99"
        assert atPermissions.appPermission[1].@type == "opaque"
        assert atPermissions.appPermission[1] == "02030405"
        assert atPermissions.appPermission[2].@psId == "98"
        assert atPermissions.appPermission[2].@type == "bitmap"
        assert atPermissions.appPermission[2] == "03040506"
    }

    CanonicalKeyType genEcKeyType(){
        CanonicalKeyType initECKey = of.createCanonicalKeyType()
        initECKey.setPublicVerificationKey(signKeys.public.encoded)
        return initECKey
    }

    List<AppPermissionsType> genAppPermissions(){
        AppPermissionsType appPerm1 = new AppPermissionsType()
        appPerm1.psId = 32
        appPerm1.value = "01020304"

        AppPermissionsType appPerm2 = new AppPermissionsType()
        appPerm2.psId = 99
        appPerm2.type = PermissionType.OPAQUE
        appPerm2.value = "02030405"

        AppPermissionsType appPerm3 = new AppPermissionsType()
        appPerm3.psId = 98
        appPerm3.type = PermissionType.BITMAP
        appPerm3.value = "03040506"
        return [appPerm1, appPerm2, appPerm3]
    }

    List<EnrolmentCredentialType> genECs(){
        EnrolmentCredentialType ec1 = new EnrolmentCredentialType()
        ec1.ecProfile = "SomeECProfile"
        ec1.eaName = "SomeEA"
        ec1.revocationDate = null
        ec1.type = "SomeType"
        ec1.status = ECStatusType.ACTIVE
        ec1.validFrom = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(5000L))
        ec1.expireDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(15000L))
        ec1.hashedId = "abcedef"
        ec1.data = "abc".getBytes()

        EnrolmentCredentialType ec2 = new EnrolmentCredentialType()
        ec2.ecProfile = "SomeECProfile"
        ec2.eaName = "SomeEA"
        ec2.revocationDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(10000L))
        ec2.type = "SomeType"
        ec2.status = ECStatusType.REVOKED
        ec2.validFrom = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(5000L))
        ec2.expireDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(15000L))
        ec2.hashedId = "abcedef"
        ec2.data = "abc".getBytes()

        return [ec1,ec2]
    }

    void verifyEnrolmentCredentials(def eCs){
        assert eCs.ec.size() == 2
        assert eCs.ec[0].ecProfile == "SomeECProfile"
        assert eCs.ec[0].eaName == "SomeEA"
        assert eCs.ec[0].type == "SomeType"
        assert eCs.ec[0].status == "ACTIVE"
        assert eCs.ec[0].validFrom == "1970-01-01T01:00:05.000+01:00"
        assert eCs.ec[0].expireDate == "1970-01-01T01:00:15.000+01:00"
        assert eCs.ec[0].hashedId == "abcedef"
        assert eCs.ec[0].data == "YWJj"

        assert eCs.ec[1].ecProfile == "SomeECProfile"
        assert eCs.ec[1].eaName == "SomeEA"
        assert eCs.ec[1].type == "SomeType"
        assert eCs.ec[1].status == "REVOKED"
        assert eCs.ec[1].revocationDate == "1970-01-01T01:00:10.000+01:00"
        assert eCs.ec[1].validFrom == "1970-01-01T01:00:05.000+01:00"
        assert eCs.ec[1].expireDate == "1970-01-01T01:00:15.000+01:00"
        assert eCs.ec[1].hashedId == "abcedef"
        assert eCs.ec[1].data == "YWJj"
    }


}
