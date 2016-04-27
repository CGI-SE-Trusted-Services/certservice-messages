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
package org.certificateservices.messages.credmanagement;


import java.io.InputStream;
import java.util.Date;
import java.util.List;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.credmanagement.jaxb.*;
import org.certificateservices.messages.credmanagement.jaxb.IssueTokenCredentialsRequest.FieldValues;
import org.certificateservices.messages.credmanagement.jaxb.IssueTokenCredentialsResponse.Credentials;
import org.certificateservices.messages.credmanagement.jaxb.IssueTokenCredentialsResponse.RevokedCredentials;
import org.certificateservices.messages.csmessages.BasePayloadParser;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.PayloadParser;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.CredentialStatusList;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Token;
import org.certificateservices.messages.csmessages.jaxb.TokenRequest;
import org.certificateservices.messages.csmessages.jaxb.User;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;
import org.certificateservices.messages.utils.MessageGenerateUtils;

/**
 * Payload Parser for generating Credential Management messages according to 
 * credmanagement_schema2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class CredManagementPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/credmanagement2_0";
	
	public static final String CREDMANAGEMENT_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/credmanagement_schema2_0.xsd";

	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_CREDMANAGEMENT_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_CREDMANAGEMENT_VERSION = "2.0";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.credmanagement.jaxb";
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
    		return getClass().getResourceAsStream(CREDMANAGEMENT_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported Credential Management Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_CREDMANAGEMENT_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_CREDMANAGEMENT_VERSION;
	}
	


	/**
	 * Method to a IssueTokenCredentialRequest message and populating it with the tokenRequest.
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param tokenRequest the tokenRequest to add to the CSRequest.
	 * @param fieldValues containing complementary input data to the request. Can be null if no complementary data is available.
	 * @param hardTokenData related hard token data to be stored in encrypted storage. Null if not applicable
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genIssueTokenCredentialsRequest(String requestId, String destinationId, String organisation, TokenRequest tokenRequest, List<FieldValue> fieldValues, HardTokenData hardTokenData, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IssueTokenCredentialsRequest payload = of.createIssueTokenCredentialsRequest();
		payload.setTokenRequest(tokenRequest);
		
		if(fieldValues != null && fieldValues.size() > 0){
			FieldValues values = new IssueTokenCredentialsRequest.FieldValues();
			values.getFieldValue().addAll(fieldValues);
			
			payload.setFieldValues(values);
		}

		if(hardTokenData != null){
			payload.setHardTokenData(hardTokenData);
		}
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to a IssueTokenCredentialResponse message and populating it with the tokenRequest and the
	 * generated responses.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param credentials the credentials to populate the response with.
	 * @param revokedCredentials credentials revoked in the operation or null, if no credentials where revoked.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genIssueTokenCredentialsResponse(String relatedEndEntity, CSMessage request, List<Credential> credentials, List<Credential> revokedCredentials, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IssueTokenCredentialsResponse response = of.createIssueTokenCredentialsResponse();
		if(request.getPayload().getAny() instanceof IssueTokenCredentialsRequest){
			IssueTokenCredentialsRequest requestPayLoad = (IssueTokenCredentialsRequest) request.getPayload().getAny();
			response.setTokenRequest(requestPayLoad.getTokenRequest());
		}else{
			throw new MessageContentException("Error generating IssueTokenCredentialsResponse, related request not a IssueTokenCredentialsResponse");
		}
		
		Credentials credentialsElement = new IssueTokenCredentialsResponse.Credentials();
		credentialsElement.getCredential().addAll(credentials);
		response.setCredentials(credentialsElement);
		
		if(revokedCredentials != null && revokedCredentials.size() > 0){
			RevokedCredentials revokedCredElements = new IssueTokenCredentialsResponse.RevokedCredentials();
			revokedCredElements.getCredential().addAll(revokedCredentials);
			response.setRevokedCredentials(revokedCredElements);
		}
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, true);
	}
	
	/**
	 * Method to generate a ChangeCredentialStatusRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param newCredentialStatus The new credential status to set.
	 * @param reasonInformation More detailed information about the revocation status
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genChangeCredentialStatusRequest(String requestId, String destinationId, String organisation, String issuerId, String serialNumber, int newCredentialStatus, String reasonInformation, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		ChangeCredentialStatusRequest payload = of.createChangeCredentialStatusRequest();
		payload.setIssuerId(issuerId);
		payload.setSerialNumber(serialNumber);
		payload.setNewCredentialStatus(newCredentialStatus);
		payload.setReasonInformation(reasonInformation);
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a ChangeCredentialStatusResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param credentialStatus the resulted credential status of the request
	 * @param reasonInformation More detailed information about the revocation status
	 * @param revocationDate the timestamp when the credential was revoked.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genChangeCredentialStatusResponse(String relatedEndEntity, CSMessage request, String issuerId, String serialNumber, int credentialStatus, String reasonInformation, Date revocationDate, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		ChangeCredentialStatusResponse response = of.createChangeCredentialStatusResponse();
		response.setCredentialStatus(credentialStatus);
		response.setIssuerId(issuerId);
		response.setSerialNumber(serialNumber);
		response.setReasonInformation(reasonInformation);
		response.setRevocationDate(MessageGenerateUtils.dateToXMLGregorianCalendar(revocationDate));
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, true);
	}
	
	/**
	 * Method to generate a GetCredentialRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param credentialSubType the credential sub type of the credential.
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetCredentialRequest(String requestId, String destinationId, String organisation, String credentialSubType, String issuerId, String serialNumber, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetCredentialRequest payload = of.createGetCredentialRequest();
		payload.setIssuerId(issuerId);
		payload.setCredentialSubType(credentialSubType);
		payload.setSerialNumber(serialNumber);
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a GetCredentialResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param credential the matching credential of the issued id and serial number
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetCredentialResponse(String relatedEndEntity, CSMessage request, Credential credential, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetCredentialResponse response = of.createGetCredentialResponse();
		response.setCredential(credential);
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a GetCredentialStatusListRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The number of the credential status list in the request (Optional)
	 * @param credentialStatusListType The type of status list to fetch
	 * @param originator the original requester of a message, null if not applicable.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetCredentialStatusListRequest(String requestId, String destinationId, String organisation, String issuerId, Long serialNumber, String credentialStatusListType, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetCredentialStatusListRequest payload = of.createGetCredentialStatusListRequest();
		payload.setIssuerId(issuerId);
		payload.setCredentialStatusListType(credentialStatusListType);
		payload.setSerialNumber(serialNumber);
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a GetCredentialStatusListResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param credentialStatusList the matching credential status list
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetCredentialStatusListResponse(String relatedEndEntity, CSMessage request, CredentialStatusList credentialStatusList, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetCredentialStatusListResponse response = of.createGetCredentialStatusListResponse();
		response.setCredentialStatusList(credentialStatusList);
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a GetIssuerCredentialsRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetIssuerCredentialsRequest(String requestId, String destinationId, String organisation, String issuerId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetIssuerCredentialsRequest payload = of.createGetIssuerCredentialsRequest();
		payload.setIssuerId(issuerId);
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a GetIssuerCredentialsResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param issuerCredential the issuers credential
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetIssuerCredentialsResponse(String relatedEndEntity, CSMessage request, Credential issuerCredential, List<Object> assertions)throws MessageContentException, MessageProcessingException{
		GetIssuerCredentialsResponse response = of.createGetIssuerCredentialsResponse();
		response.setCredential(issuerCredential);
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a IsIssuerRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genIsIssuerRequest(String requestId, String destinationId, String organisation, String issuerId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IsIssuerRequest payload = of.createIsIssuerRequest();
		payload.setIssuerId(issuerId);
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a IsIssuerResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param isIssuer indicating if current server is issuer or not
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genIsIssuerResponse(String relatedEndEntity, CSMessage request, boolean isIssuer, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IsIssuerResponse response = of.createIsIssuerResponse();
		response.setIsIssuer(isIssuer);
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a IssueCredentialStatusListRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The number of the credential status list in the request (Optional)
	 * @param credentialStatusListType The type of status list to fetch
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException
	 * @throws MessageProcessingException
	 */
	public byte[] genIssueCredentialStatusListRequest(String requestId, String destinationId, String organisation, String issuerId, String credentialStatusListType, Boolean force, Date requestedValidFromDate, Date requestedNotAfterDate, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IssueCredentialStatusListRequest payload = of.createIssueCredentialStatusListRequest();
		payload.setIssuerId(issuerId);
		payload.setCredentialStatusListType(credentialStatusListType);
		payload.setForce(force);
		payload.setRequestedValidFromDate(MessageGenerateUtils.dateToXMLGregorianCalendar(requestedValidFromDate));
		payload.setRequestedNotAfterDate(MessageGenerateUtils.dateToXMLGregorianCalendar(requestedNotAfterDate));
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a IssueCredentialStatusListResponse
	 * 
     * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param requestId the id of the request
	 * @param request the request to populate the response with
	 * @param credentialStatusList the new credential status list
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genIssueCredentialStatusListResponse(String relatedEndEntity,CSMessage request, CredentialStatusList credentialStatusList, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IssueCredentialStatusListResponse response = of.createIssueCredentialStatusListResponse();
		response.setCredentialStatusList(credentialStatusList);
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, true);
	}
	
	/**
	 * Method to generate a IssueCredentialStatusListResponse where there are no request, such 
	 * as scheduled CRL issuing.
     *
     * @param csMessageVersion the version of the CS Message Core protocol.
     * @param payLoadVersion the version of the credential management pay load protocol.
     * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param destinationId the destination of the response set in the CS message.
	 * @param requestName the name of the request message this response whould normally reply to.
	 * @param organisation the organisation set in the response message.
	 * @param credentialStatusList the new credential status list
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genIssueCredentialStatusListResponseWithoutRequest(String csMessageVersion, String payLoadVersion, String relatedEndEntity, String destinationId, String requestName, String organisation, CredentialStatusList credentialStatusList, Credential originator, List<Object> assertions)throws MessageContentException, MessageProcessingException{
		String responseId = MessageGenerateUtils.generateRandomUUID();
		
		IssueCredentialStatusListResponse response = of.createIssueCredentialStatusListResponse();
		response.setCredentialStatusList(credentialStatusList);
		response.setFailureMessage(null);
		response.setStatus(RequestStatus.SUCCESS);
		response.setInResponseTo(responseId);

		CSMessage csMessage = csMessageParser.genCSMessage(csMessageVersion, payLoadVersion,requestName,responseId, destinationId, organisation, originator, response, assertions);		
		byte[] responseData = csMessageParser.marshallAndSignCSMessage(csMessage);
		return new CSMessageResponseData(csMessage.getID(),csMessage.getName(), relatedEndEntity, csMessage.getDestinationId(),responseData, true);
		
	}
	
	/**
	 * Method to generate a RemoveCredentialRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genRemoveCredentialRequest(String requestId, String destinationId, String organisation, String issuerId, String serialNumber, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		RemoveCredentialRequest payload = of.createRemoveCredentialRequest();
		payload.setIssuerId(issuerId);
		payload.setSerialNumber(serialNumber);
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a RemoveCredentialResponse
	 *  
     * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genRemoveCredentialResponse(String relatedEndEntity, CSMessage request, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		RemoveCredentialResponse response = of.createRemoveCredentialResponse();
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, true);
	}
	
	/**
	 * Method to generate a FetchHardTokenDataRequest
	 * 
     * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param tokenSerial The unique serial number of the hard token within the organisation
	 * @param relatedCredentialSerialNumber The serial number of the most related credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param relatedCredentialIssuerId The unique id of the issuer of the related credential, usually the subject DN name of the issuer.
	 * @param adminCredential the credential of the requesting card administrator that need the hard token data. The response data is encrypted with this administrator as recipient.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genFetchHardTokenDataRequest(String requestId, String destinationId, String organisation, String tokenSerial, String relatedCredentialSerialNumber, String relatedCredentialIssuerId, Credential adminCredential, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		FetchHardTokenDataRequest payload = of.createFetchHardTokenDataRequest();
		payload.setTokenSerial(tokenSerial);
		payload.setRelatedCredentialSerialNumber(relatedCredentialSerialNumber);
		payload.setRelatedCredentialIssuerId(relatedCredentialIssuerId);
		payload.setAdminCredential(adminCredential);
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a FetchHardTokenDataResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param tokenSerial The unique serial number of the hard token within the organisation.
	 * @param encryptedData The token data encrypted with the token administrators credential sent in the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genFetchHardTokenDataResponse(String relatedEndEntity, CSMessage request, String tokenSerial, byte[] encryptedData, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		FetchHardTokenDataResponse response = of.createFetchHardTokenDataResponse();
		response.setTokenSerial(tokenSerial);
		response.setEncryptedData(encryptedData);
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a StoreHardTokenDataRequest
	 * 
     * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param tokenSerial The unique serial number of the hard token within the organisation
	 * @param relatedCredentialSerialNumber The serial number of the most related credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param relatedCredentialIssuerId The unique id of the issuer of the related credential, usually the subject DN name of the issuer.
	 * @param encryptedData The token data encrypted with a credential provided out-of-bands by the CS administrator to protect the data during transport.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genStoreHardTokenDataRequest(String requestId, String destinationId, String organisation, String tokenSerial, String relatedCredentialSerialNumber, String relatedCredentialIssuerId, byte[] encryptedData, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		StoreHardTokenDataRequest payload = of.createStoreHardTokenDataRequest();
		payload.setTokenSerial(tokenSerial);
		payload.setRelatedCredentialSerialNumber(relatedCredentialSerialNumber);
		payload.setRelatedCredentialIssuerId(relatedCredentialIssuerId);
		payload.setEncryptedData(encryptedData);
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	
	/**
	 * Method to generate a StoreHardTokenDataResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genStoreHardTokenDataResponse(String relatedEndEntity, CSMessage request, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		StoreHardTokenDataResponse response = of.createStoreHardTokenDataResponse();
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	

	/**
	 * Method to generate a GetTokensRequest
	 * 
     * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param serialNumber The unique serial number of the hard token within the organisation, complete or part of the serial number
	 * @param exactMatch If only exactly matching tokens should be fetched. 
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetTokensRequest(String requestId, String destinationId, String organisation, String serialNumber, boolean exactMatch,  Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetTokensRequest payload = of.createGetTokensRequest();
		payload.setSerialNumber(serialNumber);
		payload.setExactMatch(exactMatch);
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	
	/**
	 * Method to generate a GetTokensResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param tokens a list of matching tokens, never null.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetTokensResponse(String relatedEndEntity, CSMessage request, List<Token> tokens, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetTokensResponse response = of.createGetTokensResponse();
		GetTokensResponse.Tokens tokensElement = new GetTokensResponse.Tokens();
		for(Token t : tokens){
			tokensElement.getToken().add(t);
		}
		
		response.setTokens(tokensElement);
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a GetUsersRequest
	 * 
     * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param uniqueId The unique id of the user within the organisation, complete or part of the unique id to search for
	 * @param exactMatch If only exactly matching tokens should be fetched. 
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetUsersRequest(String requestId, String destinationId, String organisation, String uniqueId, boolean exactMatch,  Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetUsersRequest payload = of.createGetUsersRequest();
		payload.setUniqueId(uniqueId);
		payload.setExactMatch(exactMatch);
		
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	
	/**
	 * Method to generate a GetTokensResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param users a list of matching users, never null.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetUsersResponse(String relatedEndEntity, CSMessage request, List<User> users, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetUsersResponse response = of.createGetUsersResponse();
		GetUsersResponse.Users usersElement = new GetUsersResponse.Users();
		for(User u : users){
			usersElement.getUser().add(u);
		}
		
		response.setUsers(usersElement);
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}

}
