/************************************************************************
 *                                                                       *
 *  Certificate Service - Messages                                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.messages.v2x

import org.apache.xml.security.Init
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import org.certificateservices.messages.csmessages.CSMessageParserManager
import org.certificateservices.messages.csmessages.CSMessageResponseData
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.csmessages.PayloadParserRegistry
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.v2x.jaxb.AppPermissionsType
import org.certificateservices.messages.v2x.jaxb.ITSStatusType
import org.certificateservices.messages.v2x.jaxb.InitECKeyType
import org.certificateservices.messages.v2x.jaxb.ObjectFactory
import org.certificateservices.messages.v2x.jaxb.PermissionType
import org.certificateservices.messages.v2x.jaxb.RegionsType
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
    ObjectFactory of = new ObjectFactory()
    org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()

    DefaultCSMessageParser csMessageParser

    KeyPair signKeys

    def setupSpec(){
        Security.addProvider(new BouncyCastleProvider())
        Init.init()

        // Use english - make test locale independent.
        Locale.setDefault(new Locale("en", "US"))
    }

    def setup(){
        setupRegisteredPayloadParser()
        csMessageParser = CSMessageParserManager.getCSMessageParser()
        pp = PayloadParserRegistry.getParser(V2XPayloadParser.NAMESPACE)

        KeyPairGenerator kf = KeyPairGenerator.getInstance("EC","BC")
        kf.initialize(ECNamedCurveTable.getParameterSpec("P-256"))
        signKeys = kf.generateKeyPair()
    }

    def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
        expect:
        pp.getJAXBPackage() == "org.certificateservices.messages.v2x.jaxb"
        pp.getNameSpace() == "http://certificateservices.org/xsd/v2x_2_0"
        pp.getSchemaAsInputStream("2.0") != null
        pp.getDefaultPayloadVersion() == "2.0"
        pp.getSupportedVersions() == ["2.0"] as String[]
    }

    def "Verify that generateRegisterITSRequest() generates a valid xml message and generateRegisterITSResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateRegisterITSRequest(TEST_ID, "SOMESOURCEID",  "someorg",
                "someEcuType", "SomeITSId", signKeys.public.encoded, "someECProfile", "someATProfile", genAppPermissions(),
                new Date(5000L), new Date(15000L), genRegions([1,2,3]),createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.RegisterITSRequest
        then:
        messageContainsPayload requestMessage, "v2x:RegisterITSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","RegisterITSRequest", createOriginatorCredential(), csMessageParser)

        payloadObject.itsId == "SomeITSId"
        payloadObject.ecInitPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        payloadObject.ecProfile == "someECProfile"
        payloadObject.atProfile == "someATProfile"
        payloadObject.itsValidFrom == "1970-01-01T01:00:05.000+01:00"
        payloadObject.itsValidTo == "1970-01-01T01:00:15.000+01:00"
        payloadObject.regions.identifiedRegions.countryOnly.size() == 3
        payloadObject.regions.identifiedRegions.countryOnly[0] == 1
        payloadObject.regions.identifiedRegions.countryOnly[1] == 2
        payloadObject.regions.identifiedRegions.countryOnly[2] == 3
        payloadObject.ecuType == "someEcuType"
        verifyAppPermissions(payloadObject.atPermissions)
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateRegisterITSResponse("SomeRelatedEndEntity", request,  "someEcuType",
                "SomeITSId", genEcKeyType(), "someECProfile", "someATProfile", genAppPermissions(),
                new Date(5000L), new Date(15000L), genRegions([1,2,3]),ITSStatusType.ACTIVE)
		printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.RegisterITSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:RegisterITSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "RegisterITSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","RegisterITSResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)
        verifyAppPermissions(payloadObject.atPermissions)
        verifyFullResponsePayload(payloadObject)

        expect:
        pp.parseMessage(rd.responseData)

    }

    def "Verify that generateRegisterITSRequest() generates a valid xml message with minimal required values and generateRegisterITSResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateRegisterITSRequest(TEST_ID, "SOMESOURCEID", "someorg",
                 "someEcuType", "SomeITSId", signKeys.public.encoded,
                 null, null, genAppPermissions(),null,
                null, null,null, null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.RegisterITSRequest
        then:
        messageContainsPayload requestMessage, "v2x:RegisterITSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","RegisterITSRequest", null, csMessageParser)

        payloadObject.itsId == "SomeITSId"
        payloadObject.ecInitPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        payloadObject.ecuType == "someEcuType"
        verifyAppPermissions(payloadObject.atPermissions)
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateRegisterITSResponse("SomeRelatedEndEntity", request,
                "someEcuType", "SomeITSId", genEcKeyType(), null, null,
                genAppPermissions(),null,null,null,ITSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.RegisterITSResponse
        then:
        messageContainsPayload rd.responseData, "v2x:RegisterITSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "RegisterITSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","RegisterITSResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)

    }

    def "Verify that generateUpdateITSRequest() generates a valid xml message and generateUpdateITSResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateUpdateITSRequest(TEST_ID, "SOMESOURCEID", "someorg",
                "SomeITSId", signKeys.public.encoded,  "someECProfile", "someATProfile", genAppPermissions(),
                new Date(5000L), new Date(15000L), genRegions([1,2,3]), createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.UpdateITSRequest
        then:
        messageContainsPayload requestMessage, "v2x:UpdateITSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","UpdateITSRequest", createOriginatorCredential(), csMessageParser)

        payloadObject.itsId == "SomeITSId"
        payloadObject.ecInitPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        payloadObject.ecProfile == "someECProfile"
        payloadObject.atProfile == "someATProfile"
        payloadObject.itsValidFrom == "1970-01-01T01:00:05.000+01:00"
        payloadObject.itsValidTo == "1970-01-01T01:00:15.000+01:00"
        payloadObject.regions.identifiedRegions.countryOnly.size() == 3
        payloadObject.regions.identifiedRegions.countryOnly[0] == 1
        payloadObject.regions.identifiedRegions.countryOnly[1] == 2
        payloadObject.regions.identifiedRegions.countryOnly[2] == 3
        verifyAppPermissions(payloadObject.atPermissions)
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateUpdateITSResponse("SomeRelatedEndEntity", request,
                 "someEcuType", "SomeITSId",
                genEcKeyType(), "someECProfile", "someATProfile", genAppPermissions(),
                new Date(5000L), new Date(15000L), genRegions([1,2,3]),ITSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.UpdateITSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:UpdateITSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "UpdateITSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","UpdateITSResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyFullResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)
        expect:
        pp.parseMessage(rd.responseData)

    }

    def "Verify that generateUpdateITSRequest() generates a valid xml message with minimal required values and generateUpdateITSResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateUpdateITSRequest(TEST_ID, "SOMESOURCEID", "someorg","SomeITSId", signKeys.public.encoded,
                null, null, null, null, null, null,null, null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.UpdateITSRequest
        then:
        messageContainsPayload requestMessage, "v2x:UpdateITSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","UpdateITSRequest", null, csMessageParser)

        payloadObject.itsId == "SomeITSId"
        payloadObject.ecInitPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateUpdateITSResponse("SomeRelatedEndEntity", request,
                 "someEcuType",
                "SomeITSId", genEcKeyType(), null, null,
                genAppPermissions(),null,null,null,ITSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.UpdateITSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:UpdateITSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "UpdateITSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","UpdateITSResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)

    }

    def "Verify that generateGetITSRequest() generates a valid xml message and generateGetITSResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateGetITSDataRequest(TEST_ID, "SOMESOURCEID", "someorg",  "SomeITSId", createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.GetITSDataRequest
        then:
        messageContainsPayload requestMessage, "v2x:GetITSDataRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID",
                "someorg","GetITSDataRequest", null, csMessageParser)

        payloadObject.itsId == "SomeITSId"
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateGetITSDataResponse("SomeRelatedEndEntity", request,
                 "someEcuType",
                "SomeITSId", genEcKeyType(), null, null,genAppPermissions(),
                null,null,null,ITSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.GetITSDataResponse

        then:
        messageContainsPayload rd.responseData, "v2x:GetITSDataResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "GetITSDataResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","GetITSDataResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)
    }

    def "Verify that generateDeactivateITSRequest() generates a valid xml message and generateDeactivateITSRequest() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateDeactivateITSRequest(TEST_ID, "SOMESOURCEID", "someorg",
                "SomeITSId", createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.DeactivateITSRequest
        then:
        messageContainsPayload requestMessage, "v2x:DeactivateITSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID",
                "someorg","DeactivateITSRequest", null, csMessageParser)

        payloadObject.itsId == "SomeITSId"
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateDeactivateITSResponse("SomeRelatedEndEntity", request,
                "someEcuType",
                "SomeITSId", genEcKeyType(), null, null,genAppPermissions(),
                null,null,null,ITSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.DeactivateITSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:DeactivateITSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "DeactivateITSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","DeactivateITSResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)
    }

    def "Verify that generateReactivateITSRequest() generates a valid xml message and generateReactivateITSRequest() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateReactivateITSRequest(TEST_ID, "SOMESOURCEID", "someorg",
                "SomeITSId", createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.ReactivateITSRequest
        then:
        messageContainsPayload requestMessage, "v2x:ReactivateITSRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID",
                "someorg","ReactivateITSRequest", null, csMessageParser)

        payloadObject.itsId == "SomeITSId"
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateReactivateITSResponse("SomeRelatedEndEntity", request,
                "someEcuType",
                "SomeITSId", genEcKeyType(), null, null,genAppPermissions(),
                null,null,null,ITSStatusType.ACTIVE)
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.ReactivateITSResponse

        then:
        messageContainsPayload rd.responseData, "v2x:ReactivateITSResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false,
                "ReactivateITSResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER",
                "someorg","ReactivateITSResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        verifyMinimalResponsePayload(payloadObject)
        verifyAppPermissions(payloadObject.atPermissions)

        expect:
        pp.parseMessage(rd.responseData)
    }


    RegionsType genRegions(List identifiedRegionsList){
        RegionsType.IdentifiedRegions identifiedRegions = of.createRegionsTypeIdentifiedRegions()
        identifiedRegions.countryOnly.addAll(identifiedRegionsList)
        RegionsType regionsType = of.createRegionsType()
        regionsType.setIdentifiedRegions(identifiedRegions)
        return regionsType
    }

    void verifyFullResponsePayload(def payloadObject){
        assert payloadObject.itsId == "SomeITSId"
        assert payloadObject.ecInitPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        assert payloadObject.ecProfile == "someECProfile"
        assert payloadObject.atProfile == "someATProfile"
        assert payloadObject.itsValidFrom == "1970-01-01T01:00:05.000+01:00"
        assert payloadObject.itsValidTo == "1970-01-01T01:00:15.000+01:00"
        assert payloadObject.regions.identifiedRegions.countryOnly.size() == 3
        assert payloadObject.regions.identifiedRegions.countryOnly[0] == 1
        assert payloadObject.regions.identifiedRegions.countryOnly[1] == 2
        assert payloadObject.regions.identifiedRegions.countryOnly[2] == 3
        assert payloadObject.ecInitPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        assert payloadObject.ecuType == "someEcuType"
        assert payloadObject.itsStatus == "ACTIVE"
    }

    void verifyMinimalResponsePayload(def payloadObject){
        assert payloadObject.itsId == "SomeITSId"
        assert payloadObject.ecInitPublicKey.publicVerificationKey == new String(Base64.encode(signKeys.public.encoded))
        assert payloadObject.itsStatus == "ACTIVE"
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

    InitECKeyType genEcKeyType(){
        InitECKeyType initECKey = of.createInitECKeyType()
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


}
