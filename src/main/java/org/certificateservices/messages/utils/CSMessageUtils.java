package org.certificateservices.messages.utils;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.GetApprovalRequest;

/**
 * Utility methods used when working with CS Messages
 * 
 * @author Philip Vendil
 *
 */
public class CSMessageUtils {

	/**
	 * Method to fetch the payload from a CSMessage
	 * @param csMessage the CSMessage to fetch payload from
	 * @return the related payload or null if no payload could be found.
	 */
	public static Object getPayload(CSMessage csMessage){
		if(csMessage == null){
			return null;
		}
		return csMessage.getPayload().getAny();
	}
	
	/**
	 * Method returning the name of the payload object. i.e the simple name of the payload class.
	 * @param csMessage
	 * @return
	 * @throws MessageContentException if no payload name could be found.
	 */
	public static String getPayloadName(CSMessage csMessage) throws MessageContentException{
		Object payload = getPayload(csMessage);
		if(payload == null){
			throw new MessageContentException("Error no payload name could be found in CS Message");
		}
		return payload.getClass().getSimpleName();
	}
	
	/**
	 * Method returning the related payload object in from a GetApprovalRequest.
	 * @param csMessage the CS message to fetch related payload object, must contain a GetApprovalRequest payload
	 * @return the related payload
	 * @throws MessageContentException if csMessage didn't contain any GetApprovalRequest
	 */
	public static Object getRelatedPayload(CSMessage csMessage) throws MessageContentException{
		Object payload = getPayload(csMessage);
		if(payload instanceof GetApprovalRequest){
			return ((GetApprovalRequest) payload).getRequestPayload().getAny();
		}
		throw new MessageContentException("Error fetching related payload object from CS Message, message didn't contain any GetApprovalRequest payload.");
	}
	
	/**
	 * Method returning the related payload name in from a GetApprovalRequest. i.e the simple name of the payload class.
	 * @param csMessage the CS message to fetch related payload name, must contain a GetApprovalRequest payload
	 * @return the related payload name, 
	 * @throws MessageContentException if csMessage didn't contain any GetApprovalRequest
	 */
	public static String getRelatedPayloadName(CSMessage csMessage) throws MessageContentException{
		Object payload = getPayload(csMessage);
		if(payload instanceof GetApprovalRequest){
			return ((GetApprovalRequest) payload).getRequestPayload().getAny().getClass().getSimpleName();
		}
		throw new MessageContentException("Error fetching related payload name from CS Message, message didn't contain any GetApprovalRequest payload.");
	}
	
}
