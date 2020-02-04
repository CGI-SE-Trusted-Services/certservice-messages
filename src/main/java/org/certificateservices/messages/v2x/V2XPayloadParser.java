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
package org.certificateservices.messages.v2x;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.BasePayloadParser;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.PayloadParser;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.v2x.jaxb.*;

import java.io.InputStream;
import java.security.PublicKey;
import java.util.List;
import java.util.Date;

/**
 * Payload Parser for generating V2X messages according to
 * v2x_schema2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class V2XPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/v2x_2_0";
	
	private static final String V2X_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/v2x_schema2_0.xsd";

	
	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_V2X_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_V2X_VERSION = "2.0";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.v2x.jaxb";
	}

	/**
	 * @see PayloadParser#getNameSpace()
	 */
	public String getNameSpace() {
		return NAMESPACE;
	}

	/**
	 * @see PayloadParser#getSchemaAsInputStream(String)
	 */
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
    	if(payLoadVersion.equals("2.0")){
    		return getClass().getResourceAsStream(V2X_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported SysConfig Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_V2X_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_V2X_VERSION;
	}
	
	
	/**
	 *
	 * Method generate a Register ITS Request Message.
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param user Defines a group the ITS station will belong to. This can for instance be the chassi number of the
	 *             vehicle in order to keep track of in which vehicle a specific ECU is located. (Required)
	 * @param userDisplayName A human readable form of the user entry. If not set is the user value used. (Required)
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level. (Required)
	 * @param itsId the canonical name of the ITS to register. Should be a unique identifier in hostname format. (Required)
	 * @param ecInitSignPubKey the initial ec sign public key as a COER encoded PublicVerificationKey from ETSI 103 097.
	 * @param ecInitEncPubKey the initial ec enc public key as a COER encoded PublicEncryptionKey from ETSI 103 097.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param itsValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itsValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateRegisterITSRequest(String requestId, String destinationId, String organisation, String user,
											 String userDisplayName, String ecuType, byte[] itsId,
											 byte[] ecInitSignPubKey, byte[] ecInitEncPubKey, String ecProfile,
											 String atProfile, Date itsValidFrom, Date itsValidTo, RegionsType regions,
											 Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		RegisterITSRequest payload = of.createRegisterITSRequest();
		payload.setUser(user);
		payload.setUserDisplayName(userDisplayName);
		payload.setEcuType(ecuType);

		payload.setEcInitPublicKey(createInitECKeyType(ecInitSignPubKey,ecInitEncPubKey));
		populateBaseRegisterRequestType(payload,itsId,ecProfile,atProfile,itsValidFrom,itsValidTo,regions);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(),
				payload, originator, assertions);
	}
	
	/**
	 * Method generate a Register ITS Response Message.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param user Defines a group the ITS station will belong to. This can for instance be the chassi number of the
	 *             vehicle in order to keep track of in which vehicle a specific ECU is located.
	 * @param userDisplayName A human readable form of the user entry. If not set is the user value used.
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level.
	 * @param itsId the canonical name of the ITS to register. Should be a unique identifier in hostname format.
	 * @param initECKey the initial ec public key type containing keys to update.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param itsValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itsValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param itsStatus the current status of the ITS Station.
	 * @return a generated and signed message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
    public CSMessageResponseData generateRegisterITSResponse(String relatedEndEntity, CSMessage request, String user,
															 String userDisplayName, String ecuType, byte[] itsId,
															 InitECKeyType initECKey,
															 String ecProfile, String atProfile, Date itsValidFrom,
															 Date itsValidTo, RegionsType regions, ITSStatusType itsStatus)
			throws MessageContentException, MessageProcessingException{
    	RegisterITSResponse payload = of.createRegisterITSResponse();

		populateBaseV2XResponseType(payload,user,userDisplayName,ecuType,itsId,initECKey,ecProfile,atProfile,itsValidFrom,itsValidTo,regions,itsStatus);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), payload);
	}

	/**
	 * Method generate a Update ITS Request Message. Fields that are null will not be updated.
	 *
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param user Defines a group the ITS station will belong to. This can for instance be the chassi number of the
	 *             vehicle in order to keep track of in which vehicle a specific ECU is located.
	 * @param userDisplayName A human readable form of the user entry. If not set is the user value used.
	 * @param itsId the canonical name of the ITS to register. Should be a unique identifier in hostname format. (Required)
	 * @param ecInitSignPubKey the initial ec sign public key as a COER encoded PublicVerificationKey from ETSI 103 097.
	 * @param ecInitEncPubKey the initial ec enc public key as a COER encoded PublicEncryptionKey from ETSI 103 097.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param itsValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itsValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param itsStatus to update the ITS status of the station.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateUpdateITSRequest(String requestId, String destinationId, String organisation, String user,
										   String userDisplayName,  byte[] itsId,
										   byte[] ecInitSignPubKey, byte[] ecInitEncPubKey, String ecProfile,
										   String atProfile, Date itsValidFrom, Date itsValidTo, RegionsType regions,
										   ITSStatusType itsStatus,
										   Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		UpdateITSRequest payload = of.createUpdateITSRequest();
		payload.setUser(user);
		payload.setUserDisplayName(userDisplayName);
		payload.setEcInitPublicKey(createInitECKeyType(ecInitSignPubKey,ecInitEncPubKey));
		payload.setItsStatus(itsStatus);
		populateBaseRegisterRequestType(payload,itsId,ecProfile,atProfile,itsValidFrom,itsValidTo,regions);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method generate a Update ITS Response Message.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param user Defines a group the ITS station will belong to. This can for instance be the chassi number of the
	 *             vehicle in order to keep track of in which vehicle a specific ECU is located.
	 * @param userDisplayName A human readable form of the user entry. If not set is the user value used.
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level.
	 * @param itsId the canonical name of the ITS to register. Should be a unique identifier in hostname format.
	 * @param initECKey the initial ec public key type containing keys to update.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param itsValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itsValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param itsStatus the current status of the ITS Station.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateUpdateITSResponse(String relatedEndEntity, CSMessage request, String user,
														   String userDisplayName, String ecuType, byte[] itsId,
														   InitECKeyType initECKey, String ecProfile,
														   String atProfile, Date itsValidFrom, Date itsValidTo,
														   RegionsType regions, ITSStatusType itsStatus)
			throws MessageContentException, MessageProcessingException{
		UpdateITSResponse payload = of.createUpdateITSResponse();
		populateBaseV2XResponseType(payload,user,userDisplayName,ecuType,itsId,initECKey,
				ecProfile,atProfile,itsValidFrom,itsValidTo,regions,itsStatus);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(),
				payload);
	}

	/**
	 * Method generate a Get ITS Data Request Message.
	 *
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param itsId the canonical name of the ITS to register. Should be a unique identifier in hostname format.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateGetITSDataRequest(String requestId, String destinationId, String organisation, byte[] itsId,
											Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		GetITSDataRequest payload = of.createGetITSDataRequest();
		payload.setItsId(itsId);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(),
				payload, originator, assertions);
	}

	/**
	 * Method generate a Get ITS Data Response Message.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param user Defines a group the ITS station will belong to. This can for instance be the chassi number of the
	 *             vehicle in order to keep track of in which vehicle a specific ECU is located.
	 * @param userDisplayName A human readable form of the user entry. If not set is the user value used.
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level.
	 * @param itsId the canonical name of the ITS to register. Should be a unique identifier in hostname format.
	 * @param initECKey the initial ec public key type containing keys to update.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param itsValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itsValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param itsStatus the current status of the ITS Station.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateGetITSDataResponse(String relatedEndEntity, CSMessage request, String user,
															String userDisplayName, String ecuType, byte[] itsId,
															InitECKeyType initECKey,
															String ecProfile, String atProfile, Date itsValidFrom,
															Date itsValidTo, RegionsType regions, ITSStatusType itsStatus)
			throws MessageContentException, MessageProcessingException{
		GetITSDataResponse payload = of.createGetITSDataResponse();

		populateBaseV2XResponseType(payload,user,userDisplayName,ecuType,itsId,initECKey,
				ecProfile,atProfile,itsValidFrom,itsValidTo,regions,itsStatus);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), payload);
	}

	/**
	 * Method generate a Deactivate ITS Request Message.
	 *
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param itsId the canonical name of the ITS to register. Should be a unique identifier in hostname format.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateDeactivateITSRequest(String requestId, String destinationId, String organisation, byte[] itsId,
											   Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		DeactivateITSRequest payload = of.createDeactivateITSRequest();
		payload.setItsId(itsId);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(),
				payload, originator, assertions);
	}

	/**
	 * Method generate a Deactivate ITS Response Message.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param user Defines a group the ITS station will belong to. This can for instance be the chassi number of the
	 *             vehicle in order to keep track of in which vehicle a specific ECU is located.
	 * @param userDisplayName A human readable form of the user entry. If not set is the user value used.
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level.
	 * @param itsId the canonical name of the ITS to register. Should be a unique identifier in hostname format.
	 * @param initECKey the initial ec public key type containing keys to update.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param itsValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itsValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param itsStatus the current status of the ITS Station.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateDeactivateITSResponse(String relatedEndEntity, CSMessage request, String user,
															   String userDisplayName, String ecuType, byte[] itsId,
															   InitECKeyType initECKey,
															   String ecProfile, String atProfile, Date itsValidFrom,
															   Date itsValidTo, RegionsType regions, ITSStatusType itsStatus)
			throws MessageContentException, MessageProcessingException{
		DeactivateITSResponse payload = of.createDeactivateITSResponse();

		populateBaseV2XResponseType(payload,user,userDisplayName,ecuType,itsId,initECKey,ecProfile,atProfile,itsValidFrom,itsValidTo,regions,itsStatus);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), payload);
	}


	private void populateBaseV2XResponseType(BaseV2XResponseType payload, String user, String userDisplayName,
											 String ecuType, byte[] itsId,
											 InitECKeyType initECKey, String ecProfile, String atProfile,
											 Date itsValidFrom, Date itsValidTo, RegionsType regions,
											 ITSStatusType itsStatus) throws MessageProcessingException {
		payload.setUser(user);
		payload.setUserDisplayName(userDisplayName);
		payload.setEcuType(ecuType);
		payload.setItsId(itsId);
		payload.setEcInitPublicKey(initECKey);
		payload.setEcProfile(ecProfile);
		payload.setAtProfile(atProfile);
		if(itsValidFrom != null) {
			payload.setItsValidFrom(MessageGenerateUtils.dateToXMLGregorianCalendar(itsValidFrom));
		}
		if(itsValidTo != null) {
			payload.setItsValidFrom(MessageGenerateUtils.dateToXMLGregorianCalendar(itsValidTo));
		}
		payload.setRegions(regions);
		payload.setItsStatus(itsStatus);
	}

	private void populateBaseRegisterRequestType(BaseRegisterRequestType payload, byte[] itsId,
												 String ecProfile, String atProfile, Date itsValidFrom, Date itsValidTo,
												 RegionsType regions) throws MessageProcessingException {
		payload.setItsId(itsId);
		payload.setEcProfile(ecProfile);
		payload.setAtProfile(atProfile);
		if(itsValidFrom != null) {
			payload.setItsValidFrom(MessageGenerateUtils.dateToXMLGregorianCalendar(itsValidFrom));
		}
		if(itsValidTo != null) {
			payload.setItsValidTo(MessageGenerateUtils.dateToXMLGregorianCalendar(itsValidTo));
		}
		payload.setRegions(regions);
	}


	private InitECKeyType createInitECKeyType(byte[] ecInitSignPubKey, byte[] ecInitEncPubKey){
		InitECKeyType initECKeyType = of.createInitECKeyType();
		InitECKeyType.PublicKeyInfos subjectPublicKeyInfos = of.createInitECKeyTypePublicKeyInfos();
		if(ecInitSignPubKey != null){
			subjectPublicKeyInfos.setPublicVerificationKey(ecInitSignPubKey);
		}
		if(ecInitEncPubKey != null){
			subjectPublicKeyInfos.setPublicEncryptionKey(ecInitEncPubKey);
		}
		initECKeyType.setPublicKeyInfos(subjectPublicKeyInfos);

		return initECKeyType;
	}



}
