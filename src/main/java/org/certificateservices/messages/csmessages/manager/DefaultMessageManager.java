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
package org.certificateservices.messages.csmessages.manager;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser;
import org.certificateservices.messages.credmanagement.jaxb.IssueTokenCredentialsResponse;
import org.certificateservices.messages.csmessages.CSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.csmessages.constants.AvailableCredentialStatuses;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.CSResponse;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;
import org.certificateservices.messages.utils.MessageGenerateUtils;

/**
 * Message manager in charge of sending a request and waiting for the response for
 * a given time before a time out IOException is thrown.
 * <p>
 * If a IssueTokenRequest message is processed, but not returned in time is a 
 * revoke message sent back to the client.
 * 
 * @author Philip Vendil
 *
 */
public class DefaultMessageManager implements MessageManager, MessageResponseCallback{
	
	private static Logger log = Logger.getLogger(DefaultMessageManager.class);

	private  Map<String, RequestEntry> responseMap = new HashMap<String, RequestEntry>();
	  
	/**
	 * Setting indicating the time-out of a message in milli-seconds before IOException is thrown.
	 */
	public static final String SETTING_MESSAGE_TIMEOUT_MILLIS = "mq.message.timeout";
	public static final String DEFAULT_MESSAGE_TIMEOUT_MILLIS = "60000"; // 60 seconds 	
	
	/**
	 * Setting indicating the message handler to use to send and receive the messages.
	 */
	public static final String SETTING_MESSAGEHANDLER_CLASSPATH = "mq.messagehandler.impl";

	
	protected static String REVOKE_REASON_REASONINFORMATION_CESSATIONOFOPERATION = "5"; 
	
	protected static long SLEEP_INTERVAL_MILLIS = 100;
	protected CSMessageParser parser;
	protected CredManagementPayloadParser credManagementPayloadParser;
	protected String destination;
	protected MessageHandler messageHandler;
	protected long timeout;
	
	/** 
	 * Method that initializes the message manager
	 * 
	 * @see org.certificateservices.custom.vcc.vccpieclient.mq.MessageManager#init(Properties, PKIMessageParser, String, String)
	 */	
	public void init(Properties config, CSMessageParser parser, String destination) throws IllegalArgumentException,
			IOException, MessageProcessingException {
		this.destination = destination;
		this.parser = parser;
		
		timeout = getTimeOutInMillis(config);
		
		this.messageHandler = getMessageHandler(config, parser);
		
		credManagementPayloadParser = (CredManagementPayloadParser) PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE);
		
	}

	/**
	 * Main method signaling sending a request with given id and waits for a response
	 * for a given time before a time-out IO exception is thrown.
	 */
	public CSMessage sendMessage(String requestId, byte[] request) throws IllegalArgumentException,
			IOException, MessageProcessingException {
		CSMessage retval = null;
		
		registerWaitForRequestId(requestId);
		messageHandler.sendMessage(requestId, request);
				
		long waitTime = 0;
		while(waitTime < timeout){
			retval = checkIfResponseIsReady(requestId);
			if(retval != null){
				break;
			}
			try {
				Thread.sleep(SLEEP_INTERVAL_MILLIS);
			} catch (InterruptedException e) {
				log.error("waiting process interupted while waiting for MQ response: " + e.getMessage());
			}
			waitTime+= SLEEP_INTERVAL_MILLIS;
			
		}
		
		if(retval == null){
			cancelWaitForResponse(requestId);
			throw new IOException("Error: Timeout exception after waiting for message with request id: " + requestId);
		}
		
		return retval;
	}

	/**
	 * Method called by the MessageHandler when receiving a message intended for this
	 * message manager.
	 */
	public void responseReceived(CSMessage responseMessage){
		
		String requestId = findRequestId(responseMessage);
		if(requestId != null){
			boolean stillWaiting = populateResponseMapIfStillExist(requestId, responseMessage);
			if(!stillWaiting){
				if(responseMessage.getPayload().getAny() instanceof IssueTokenCredentialsResponse){
					IssueTokenCredentialsResponse itcr = (IssueTokenCredentialsResponse) responseMessage.getPayload().getAny();
					if(itcr.getStatus() == RequestStatus.SUCCESS){
						// Issuance was successful but request timed-out, sending revocation message.
						if( itcr.getCredentials() != null && itcr.getCredentials().getCredential() != null){
							for(Credential c : itcr.getCredentials().getCredential()){
								// Send revocation request
								try {
									String messageId = MessageGenerateUtils.generateRandomUUID();
									byte[] revokeMessage = credManagementPayloadParser.genChangeCredentialStatusRequest(messageId,destination, responseMessage.getOrganisation(), c.getIssuerId(), c.getSerialNumber(), AvailableCredentialStatuses.REVOKED, REVOKE_REASON_REASONINFORMATION_CESSATIONOFOPERATION, parser.getOriginatorFromRequest(responseMessage), null);
									messageHandler.sendMessage(messageId, revokeMessage);
								} catch (IOException e) {
									log.error("Error revoking timed-out certificate, io exception: " + e.getMessage());
								} catch (MessageProcessingException e) {
									log.error("Error revoking timed-out certificate, internal error: " + e.getMessage());
								} catch (MessageContentException e) {
									log.error("Error revoking timed-out certificate, illegal message: " + e.getMessage());
								} 															
							}
						}
					}
				}
			}
		}		
	}
	
	/**
	 * Signals that the current manager is listening for this message.
	 * 
	 * @param requestId  the id of the message to register
	 */
	protected synchronized void registerWaitForRequestId(String requestId){
		responseMap.put(requestId, new RequestEntry());
	}
	
	/**
	 * Method to check if a response have been sent to a request with the given id.
	 * @param requestId the id to check for 
	 * @return the PKIMessage response or null if no response have been recieved yet.
	 */
	protected synchronized CSMessage checkIfResponseIsReady(String requestId){
		CSMessage retval = null;
		RequestEntry entry = responseMap.get(requestId);
		if(entry != null && entry.getResponse() != null){
			retval = entry.getResponse();
			responseMap.remove(requestId);
		}
		
		return retval;
	}
	

	/**
	 * Method signaling that the waiting thread have stopped listening for
	 * a response to this request.
	 */
	protected synchronized void cancelWaitForResponse(String requestId){
		responseMap.remove(requestId);
	}
	
	/**
	 * Method that is called by the responseRecieved method that it received a message
	 * to this listener and should populate the response map.
	 */
	protected synchronized boolean populateResponseMapIfStillExist(String requestId, CSMessage responseMessage){
		boolean retval = false;
		RequestEntry entry = responseMap.get(requestId);
		if(entry != null){
			entry.setResponse(responseMessage);
			retval = true;
		}
		
		return retval;
	}

	/**
	 * Method that extracts the requestId from the responseMessage. Where
	 * IssueTokenCredentialsResponse and GetCredentialResponse and FailureResponse is supported.
	 *  
	 * @param responseMessage the message to parse request id from
	 * @return the request id or null if no valid request id was found in the response
	 */
	protected String findRequestId(CSMessage responseMessage) {
		String retval = null;
		CSResponse response = findResponsePayload(responseMessage);
		if(response != null){
			retval = response.getInResponseTo();
		}
		
		if(retval != null){
			retval = retval.trim();
		}
		
		return retval;
	}
	
	protected CSResponse findResponsePayload(CSMessage responseMessage){

		if(responseMessage.getPayload().getAny() instanceof CSResponse){
			return (CSResponse) responseMessage.getPayload().getAny();
		}
		
		return null;
	}


	/**
	 * Closes the underlying connection.
	 * 
	 * @see org.certificateservices.custom.vcc.vccpieclient.mq.MessageManager#close()
	 */
	public void close() throws IOException {
		messageHandler.close();
	}


	/**
	 * A request entry is used the the request map after a send message call i waiting
	 * for a response, contains a response PKI Message data.
	 * 
	 * @author Philip Vendil
	 *
	 */
	protected class RequestEntry{
		
		private CSMessage response;

		
		public CSMessage getResponse() {
			return response;
		}
		public void setResponse(CSMessage response) {
			this.response = response;
		}
	}
	
	/**
	 * Returns the message handler to use, if not configured is the default message handler created and returned.
	 */
	protected MessageHandler getMessageHandler(Properties config, CSMessageParser parser) throws MessageProcessingException, IllegalArgumentException, IOException{
		try{
			String classPath = config.getProperty(SETTING_MESSAGEHANDLER_CLASSPATH);
			if(classPath == null){
				throw new MessageProcessingException("Error no message handler configured with setting: " + SETTING_MESSAGEHANDLER_CLASSPATH);
			}			
			Class<?> c = Thread.currentThread().getContextClassLoader().loadClass(classPath);
			
			MessageHandler retval = (MessageHandler) c.newInstance();
			retval.init(config, parser, this);
			return retval;
		}catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			if(e instanceof IllegalArgumentException){
				throw (IllegalArgumentException) e;
			}
			if(e instanceof IOException){
				throw (IOException) e;
			}
			throw new MessageProcessingException("Error creating Message Handler: " + e.getMessage(),e);
		}
	}
	
	
	public static long getTimeOutInMillis(Properties config) throws MessageProcessingException{
		String timeout = config.getProperty(SETTING_MESSAGE_TIMEOUT_MILLIS, DEFAULT_MESSAGE_TIMEOUT_MILLIS);
		try{
			return Long.parseLong(timeout);
		}catch(Exception e){
			throw new MessageProcessingException("Invalid timout value in configuration, check setting: " + SETTING_MESSAGE_TIMEOUT_MILLIS);
		}
	}

	public Object getConnectionFactory() throws MessageProcessingException,
			IOException {
		return messageHandler.getConnectionFactory();		
	}

	public void connect() throws MessageProcessingException, IOException {
		messageHandler.connect();
		
	}

	public MessageHandler getMessageHandler() {
		return messageHandler;
	}

	public boolean isConnected() {
		return messageHandler.isConnected();
	}
}
