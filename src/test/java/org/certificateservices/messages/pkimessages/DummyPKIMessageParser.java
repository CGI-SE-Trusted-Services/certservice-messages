package org.certificateservices.messages.pkimessages;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.pkimessages.PKIMessageParser;
import org.certificateservices.messages.pkimessages.PKIMessageResponseData;
import org.certificateservices.messages.pkimessages.jaxb.Credential;
import org.certificateservices.messages.pkimessages.jaxb.CredentialStatusList;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.RequestStatus;
import org.certificateservices.messages.pkimessages.jaxb.TokenRequest;

public class DummyPKIMessageParser  implements PKIMessageParser{

	public boolean initCalled = false;
	
	
	public void init(MessageSecurityProvider securityProvider,
			Properties config) throws MessageException {
		initCalled = true;
	}

	
	public PKIMessage parseMessage(byte[] messageData)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genIssueTokenCredentialsRequest(String requestId, String destination,String organisation,
			TokenRequest tokenRequest) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genIssueTokenCredentialsResponse(PKIMessage request,
			List<Credential> credentials, List<Credential> revokedCredentials) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genChangeCredentialStatusRequest(String requestId, String destination,String organisation,
			String issuerId, String serialNumber, int newCredentialStatus,
			String reasonInformation) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genChangeCredentialStatusResponse(PKIMessage request,
			String issuerId, String serialNumber, int credentialStatus,
			String reasonInformation, Date revocationDate)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genGetCredentialRequest(String requestId, String destination,String organisation,
			String credentialSubType, String issuerId, String serialNumber)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genGetCredentialResponse(PKIMessage request,
			Credential credential) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genGetCredentialStatusListRequest(String requestId, String destination,String organisation,
			String issuerId, Long serialNumber,
			String credentialStatusListType)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genGetCredentialStatusListResponse(PKIMessage request,
			CredentialStatusList credentialStatusList)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genGetIssuerCredentialsRequest(String requestId, String destination,String organisation,
			String issuerId) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genGetIssuerCredentialsResponse(PKIMessage request,
			Credential issuerCredential) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genIsIssuerRequest(String requestId, String destination, String organisation,String issuerId)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genIsIssuerResponse(PKIMessage request, boolean isIssuer)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genIssueCredentialStatusListRequest(String requestId, String destination,String organisation,
			String issuerId, String credentialStatusListType,
			Boolean force, Date requestedValidFromDate,
			Date requestedNotAfterDate) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genIssueCredentialStatusListResponse(PKIMessage request,
			CredentialStatusList credentialStatusList)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genRemoveCredentialRequest(String requestId, String destination,String organisation,
			String issuerId, String serialNumber)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genRemoveCredentialResponse(PKIMessage request)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genFetchHardTokenDataRequest(String requestId, String destination,String organisation,
			String tokenSerial, String relatedCredentialSerialNumber,
			String relatedCredentialIssuerId, Credential adminCredential)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genFetchHardTokenDataResponse(PKIMessage request,
			String tokenSerial, byte[] encryptedData)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genStoreHardTokenDataRequest(String requestId, String destination,String organisation,
			String tokenSerial, String relatedCredentialSerialNumber,
			String relatedCredentialIssuerId, byte[] encryptedData)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genStoreHardTokenDataResponse(PKIMessage request)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genPKIResponse(byte[] request, RequestStatus status,
			String failureMessage) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genPKIResponse(byte[] request, RequestStatus status,
			String failureMessage, String destinationId)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public X509Certificate getSigningCertificate(byte[] request)
			throws IllegalArgumentException, MessageException {
		return null;
	}


	public PKIMessageResponseData genIssueCredentialStatusListResponseWithoutRequest(
			String destination, String name, String organisation,
			CredentialStatusList credentialStatusList)
			throws IllegalArgumentException, MessageException {
		// Auto-generated method stub
		return null;
	}
	
}
