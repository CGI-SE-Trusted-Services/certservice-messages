/************************************************************************
*                                                                       *
*  Certificate Service - PKI Messages                                   *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages.pkimessages;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.pkimessages.jaxb.Credential;
import org.certificateservices.messages.pkimessages.jaxb.CredentialStatusList;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.RequestStatus;
import org.certificateservices.messages.pkimessages.jaxb.TokenRequest;

/**
 * PKIMessage Parser reading and writing all types of PKI messages.
 *  
 * @author Philip Vendil
 *
 */
public interface PKIMessageParser {
	
	/**
	 * Method that initializes the PKIMessage parser with a security provider and properties.
	 * 
	 * @param securityProvider the PKIMessage security provider to use.
	 * @param config the configuration of the parser.
	 * @throws MessageException if configuration contained bad configuration of security provider.
	 */
	void init(MessageSecurityProvider securityProvider, Properties config) throws MessageException;
	
	/**
	 * Method to parse the messageData into a PKI Message with validation according to the
	 * specification.
	 * 
	 * @param messageData the message data to parse
	 * @return a PKIMessage that is valid, never null.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessage parseMessage(byte[] messageData) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to a IssueTokenCredentialRequest message and populating it with the tokenRequest.
	 * 
	 * @param requestId the id of the request
	 * @param destination the destinationId used in the PKIMessage.
	 * @param organisation the related organisation
	 * @param tokenRequest the tokenRequest to add to the PKIRequest.
	 * @return generated and signed PKIMessage in byte[] format.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	byte[] genIssueTokenCredentialsRequest(String requestId, String destination, String organisation, TokenRequest tokenRequest) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to a IssueTokenCredentialResponse message and populating it with the tokenRequest and the
	 * generated responses.
	 * 
	 * @param request the request to populate the response with
	 * @param credentials the credentials to populate the response with.
	 * @param revokedCredentials credentials revoked in the operation or null, if no credentials where revoked.
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genIssueTokenCredentialsResponse(PKIMessage request, List<Credential> credentials, List<Credential> revokedCredentials) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a ChangeCredentialStatusRequest
	 * 
	 * @param requestId the id of the request
	 * @param destination the destinationId used in the PKIMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param newCredentialStatus The new credential status to set.
	 * @param reasonInformation More detailed information about the revocation status
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	byte[] genChangeCredentialStatusRequest(String requestId, String destination, String organisation, String issuerId, String serialNumber, int newCredentialStatus, String reasonInformation)  throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a ChangeCredentialStatusResponse
	 * 
	 * @param request the request to populate the response with
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param credentialStatus the resulted credential status of the request
	 * @param reasonInformation More detailed information about the revocation status
	 * @param revocationDate the timestamp when the credential was revoked.
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genChangeCredentialStatusResponse(PKIMessage request, String issuerId, String serialNumber, int credentialStatus, String reasonInformation, Date revocationDate)  throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a GetCredentialRequest
	 * 
	 * @param requestId the id of the request
	 * @param destination the destinationId used in the PKIMessage.
	 * @param organisation the related organisation
	 * @param credentialSubType the credential sub type of the credential.
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	byte[] genGetCredentialRequest(String requestId, String destination, String organisation, String credentialSubType, String issuerId, String serialNumber)  throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a GetCredentialResponse
	 * 
	 * @param request the request to populate the response with
	 * @param credential the matching credential of the issued id and serial number
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genGetCredentialResponse(PKIMessage request, Credential credential) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a GetCredentialStatusListRequest
	 * 
	 * @param requestId the id of the request
	 * @param destination the destinationId used in the PKIMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The number of the credential status list in the request (Optional)
	 * @param credentialStatusListType The type of status list to fetch
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	byte[] genGetCredentialStatusListRequest(String requestId, String destination, String organisation, String issuerId, Long serialNumber, String credentialStatusListType) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a GetCredentialStatusListResponse
	 * 
	 * @param request the request to populate the response with
	 * @param credentialStatusList the matching credential status list
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genGetCredentialStatusListResponse(PKIMessage request, CredentialStatusList credentialStatusList) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a GetIssuerCredentialsRequest
	 * 
	 * @param requestId the id of the request
	 * @param destination the destinationId used in the PKIMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	byte[] genGetIssuerCredentialsRequest(String requestId, String destination, String organisation, String issuerId) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a GetIssuerCredentialsResponse
	 * 
	 * @param request the request to populate the response with
	 * @param issuerCredential the issuers credential
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genGetIssuerCredentialsResponse(PKIMessage request, Credential issuerCredential) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a IsIssuerRequest
	 * 
	 * @param requestId the id of the request
	 * @param destination the destinationId used in the PKIMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	byte[] genIsIssuerRequest(String requestId, String destination, String organisation, String issuerId) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a IsIssuerResponse
	 * 
	 * @param request the request to populate the response with
	 * @param isIssuer indicating if current server is issuer or not
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genIsIssuerResponse(PKIMessage request, boolean isIssuer) throws IllegalArgumentException, MessageException;

	/**
	 * Method to generate a IssueCredentialStatusListRequest
	 * 
	 * @param requestId the id of the request
	 * @param destination the destinationId used in the PKIMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The number of the credential status list in the request (Optional)
	 * @param credentialStatusListType The type of status list to fetch
	 * @return a generated message.
	 * @throws IllegalArgumentException
	 * @throws MessageException
	 */
	byte[] genIssueCredentialStatusListRequest(String requestId, String destination, String organisation, String issuerId, String credentialStatusListType, Boolean force, Date requestedValidFromDate, Date requestedNotAfterDate) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a IssueCredentialStatusListResponse
	 * 
	 * @param requestId the id of the request
	 * @param request the request to populate the response with
	 * @param credentialStatusList the new credential status list
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genIssueCredentialStatusListResponse(PKIMessage request, CredentialStatusList credentialStatusList) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a RemoveCredentialRequest
	 * 
	 * @param requestId the id of the request
	 * @param destination the destinationId used in the PKIMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	byte[] genRemoveCredentialRequest(String requestId, String destination, String organisation, String issuerId, String serialNumber)  throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a RemoveCredentialResponse
	 *  
	 * @param request the request to populate the response with
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genRemoveCredentialResponse(PKIMessage request) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a FetchHardTokenDataRequest
	 * 
     * @param requestId the id of the request
	 * @param destination the destinationId used in the PKIMessage.
	 * @param organisation the related organisation
	 * @param tokenSerial The unique serial number of the hard token within the organisation
	 * @param relatedCredentialSerialNumber The serial number of the most related credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param relatedCredentialIssuerId The unique id of the issuer of the related credential, usually the subject DN name of the issuer.
	 * @param adminCredential the credential of the requesting card administrator that need the hard token data. The response data is encrypted with this administrator as recipient.
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	byte[] genFetchHardTokenDataRequest(String requestId, String destination, String organisation, String tokenSerial, String relatedCredentialSerialNumber, String relatedCredentialIssuerId, Credential adminCredential)  throws IllegalArgumentException, MessageException;
	
	
	/**
	 * Method to generate a FetchHardTokenDataResponse
	 * 
	 * @param destination the destinationId used in the PKIMessage.
	 * @param tokenSerial The unique serial number of the hard token within the organisation.
	 * @param encryptedData The token data encrypted with the token administrators credential sent in the request.
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genFetchHardTokenDataResponse(PKIMessage request, String tokenSerial, byte[] encryptedData)  throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a StoreHardTokenDataRequest
	 * 
     * @param requestId the id of the request
	 * @param destination the destinationId used in the PKIMessage.
	 * @param organisation the related organisation
	 * @param tokenSerial The unique serial number of the hard token within the organisation
	 * @param relatedCredentialSerialNumber The serial number of the most related credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param relatedCredentialIssuerId The unique id of the issuer of the related credential, usually the subject DN name of the issuer.
	 * @param encryptedData The token data encrypted with a credential provided out-of-bands by the PKI administrator to protect the data during transport.
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	byte[] genStoreHardTokenDataRequest(String requestId, String destination, String organisation, String tokenSerial, String relatedCredentialSerialNumber, String relatedCredentialIssuerId, byte[] encryptedData)  throws IllegalArgumentException, MessageException;
	
	
	/**
	 * Method to generate a StoreHardTokenDataResponse
	 * 
	 * @param destination the destinationId used in the PKIMessage.
	 * @return a generated message.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genStoreHardTokenDataResponse(PKIMessage request)  throws IllegalArgumentException, MessageException;
	
	
	/**
	 * Method to generate a basic PKI Response used when sending a message with status of ILLEGALARGUMENT or ERROR
	 * and a failureMessage.
	 * <p>
	 * This method is using the request sourceID as destinationID
	 * 
	 * @param request the PKI Request data to generate a response for.
	 * @param status the status to set in the request.
	 * @param failureMessage the failure message sent in the request.
	 * @return generated and signed PKIMessage in byte[] format.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genPKIResponse(byte[] request, RequestStatus status, String failureMessage) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a basic PKI Response used when sending a message with status of ILLEGALARGUMENT or ERROR
	 * and a failureMessage with a custom defined destinationId.
	 * 
	 * @param request the PKI Request data to generate a response for.
	 * @param status the status to set in the request.
	 * @param failureMessage the failure message sent in the request.
	 * @param destinationId the destinationId to use.
	 * @return generated and signed PKIMessage in byte[] format.
	 * @throws IllegalArgumentException if PKI message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the PKIMessage
	 */
	PKIMessageResponseData genPKIResponse(byte[] request, RequestStatus status, String failureMessage, String destinationId) throws IllegalArgumentException, MessageException;
	
	/**
	 * Fetches the signing certificate from the request.
	 * 
	 * @param request the request to parse the certificate from.
	 * @return the signer certificate of null if no certificate is required by the parser.
	 * @throws IllegalArgumentException, if no signer certificate was found and parser required it.
	 * @throws MessageException if internal error occurred parsing the certificate.
	 */
	X509Certificate getSigningCertificate(byte[] request) throws IllegalArgumentException, MessageException;

}
