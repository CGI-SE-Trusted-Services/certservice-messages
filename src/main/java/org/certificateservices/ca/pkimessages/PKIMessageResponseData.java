/**
 * 
 */
package org.certificateservices.ca.pkimessages;

import java.util.Arrays;
import java.util.Set;

/**
 * Value class containing the result of a message processing call.
 * <p>
 * The information is mainly the response and PKI message destination.
 * 
 * @author Philip Vendil
 *
 */
public class PKIMessageResponseData {
	
	private String messageId;
	private String destination;
	private byte[] responseData;
	private boolean isForwardableResponse = false;
	
	
	/**
	 * Empty constructor
	 */
	public PKIMessageResponseData() {
		super();
	}

	/**
	 * Default constructor
	 * 
	 * @param messageId the related id of the message
	 * @param destination the PKI Message destination to send the message to.
	 * @param responseData the response data
	 */
	public PKIMessageResponseData(String messageId, String destination,
			byte[] responseData) {
		super();
		this.messageId = messageId;
		this.destination = destination;
		this.responseData = responseData;
	}
	
	/**
	 * Constructor where it's possible to set if the response is
	 * a failure response.
	 * 
	 * @param messageId the related id of the message
	 * @param destination the PKI Message destination to send the message to.
	 * @param responseData the response data
	 * @param isForwardableResponse true if response is forwardable.
	 */
	public PKIMessageResponseData(String messageId, String destination,
			byte[] responseData, boolean isForwardableResponse) {
		super();
		this.messageId = messageId;
		this.destination = destination;
		this.responseData = responseData;
		this.isForwardableResponse = isForwardableResponse;
	}
	
	/**
	 * Help method calculating if a method should be forwarded or not.
	 * <p>
	 * Does the following calculation:
	 * <li>Is PKI Message Destination not in exclude list
	 * <li>is not a failure response
	 * <li>if both are true is true returned
	 * @param excludedDestinations a set of excluded destinations.
	 * @return true if this message should be forwarded
	 */
	public boolean isForwardable(Set<String> excludedDestinations){
		boolean excluded = excludedDestinations.contains(destination.toUpperCase().trim());
		return isForwardableResponse && !excluded;
	}
	
	
	/**
	 * 
	 * @return the PKI Message destination to send the message to.
	 */
	public String getDestination() {
		return destination;
	}
	
	/**
	 * 
	 * @param destination the PKI Message destination to send the message to.
	 */
	public void setDestination(String destination) {
		this.destination = destination;
	}
	
	/**
	 * 
	 * @return the response data
	 */
	public byte[] getResponseData() {
		return responseData;
	}
	
	/**
	 * 
	 * @param responseData the response data
	 */
	public void setResponseData(byte[] responseData) {
		this.responseData = responseData;
	}
	
	/**
	 * 
	 * @return true if response is a forwardable or not.
	 */
	public boolean getIsForwardableResponse() {
		return isForwardableResponse;
	}

	/**
	 * 
	 * @param isFailureResponse true if response is a failure indication.
	 */
	public void setIsForwardableResponse(boolean isForwardableResponse) {
		this.isForwardableResponse = isForwardableResponse;
	}
	
	/**
	 * 
	 * @return the related id of the message
	 */
	public String getMessageId() {
		return messageId;
	}

	/**
	 * 
	 * @param messageId the related id of the message
	 */
	public void setMessageId(String messageId) {
		this.messageId = messageId;
	}

	@Override
	public String toString() {
		return "PKIMessageProcessResult [messageId=" + messageId
				+ ", destination=" + destination
				+ ", responseData=" + Arrays.toString(responseData)
				+ ", isForwardableResponse=" + isForwardableResponse + "]";
	}



}
