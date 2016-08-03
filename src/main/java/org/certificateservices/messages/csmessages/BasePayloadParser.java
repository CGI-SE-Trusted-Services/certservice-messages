/**
 * 
 */
package org.certificateservices.messages.csmessages;

import java.util.List;
import java.util.Properties;

import javax.xml.bind.JAXBElement;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.CSResponse;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.IsApprovedResponseType;
import org.certificateservices.messages.csmessages.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;

/**
 * Base implementation of a PayLoadParser that other implementations might inherit.
 * 
 * @author Philip Vendil
 *
 */
public abstract class BasePayloadParser implements PayloadParser {
	

	protected Properties config;
	protected MessageSecurityProvider secProv;
	
	protected ObjectFactory csMessageObjectFactory = new ObjectFactory();
	
	/**
	 * Default initializer setting the parser and config properties.
	 * 
	 * @see org.certificateservices.messages.csmessages.PayloadParser#init(java.util.Properties, MessageSecurityProvider)
	 */
	public void init(Properties config, MessageSecurityProvider secProv)
			throws MessageProcessingException {
		this.config = config;
		this.secProv = secProv;
	}

	protected CSMessageParser getCSMessageParser() throws MessageProcessingException {
		return CSMessageParserManager.getCSMessageParser();
	}

	/**
	 * Method to parse a message into a CSMessage and verify that it fulfills the registred schemas.
	 * <p>
	 * This method will parse all registered payloads and not only sys config payload messages.
	 * 
	 * @param messageData the data to parse into a CSMessage
	 * @return a parsed CS Message object.
	 * 
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
    public CSMessage parseMessage(byte[] messageData) throws MessageContentException, MessageProcessingException{
    	return getCSMessageParser().parseMessage(messageData);
    }
    
    /**
     * Help method to get the request status from a CS response message.
     * @param csMessage containing a CS response message.
     * @return the request status.
     * 
     * @throws MessageContentException if message content was illegal.
     */
    @SuppressWarnings("unchecked")
	public RequestStatus getResponseStatus(CSMessage csMessage) throws MessageContentException{
    	try{
    	Object responsePayload =  csMessage.getPayload().getAny();
    	if(responsePayload instanceof JAXBElement<?> && ((JAXBElement<?>) responsePayload).getValue() instanceof CSResponse){
    		return ((JAXBElement<CSResponse>) responsePayload).getValue().getStatus();
    	}
    	if(responsePayload instanceof CSResponse){
    		return ((CSResponse) responsePayload).getStatus();
    	}
    	}catch(Exception e){
    		throw new MessageContentException("Error parsing CSResponse status from message: " + e.getMessage(),e);
    	}
    	throw new MessageContentException("Error parsing CSResponse status from message, make sure it is a CSResponse.");
    }
    
    /**
     * Help method to get the payload of a message.
     * @param csMessage containing a CS message payload.
     * @return the payload object
     * 
     * @throws MessageContentException if message content was illegal.
     */
	public Object getPayload(CSMessage csMessage) throws MessageContentException{
    	try{
    		Object responsePayload =  csMessage.getPayload().getAny();
    		if(responsePayload instanceof JAXBElement<?>){
    			return ((JAXBElement<?>) csMessage.getPayload().getAny()).getValue();
    		}
    	    return responsePayload;
    	}catch(Exception e){
    		throw new MessageContentException("Error parsing payload from message: " + e.getMessage(),e);
    	}
    }
	
	/**
	 * Help method to retrieve the assertions from an approved IsApprovedResponseType payload
	 * 
	 * @param isApprovedResponse the payload if a IsApprovedResponse or GetApprovedResponse
	 * @return the list of assertions or null if no assertions could be found.
	 */
	public List<Object> getAssertions(IsApprovedResponseType isApprovedResponse){
		if(isApprovedResponse.getAssertions() != null && isApprovedResponse.getAssertions().size() > 0){
			return isApprovedResponse.getAssertions().get(0).getAny();
		}
		
		return null;
	}
	
	/**
	 * Method generate a Get Approval Request, 
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param requestMessage the request message to get approval for.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateGetApprovalRequest(String requestId, String destinationId, String organisation, byte[] requestMessage, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().generateGetApprovalRequest(requestId, destinationId, organisation, requestMessage, originator, assertions);
	}
	
	/**
	 * Method generate a Is Approved Request, 
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param approvalId the approval id to check.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateIsApprovedRequest(String requestId, String destinationId, String organisation, String approvalId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().generateIsApprovedRequest(requestId, destinationId, organisation, approvalId, originator, assertions);
	}
	
	
    /**
     * 
     * @return an array of version numbers of payload that is supported by this parser.
     */
	protected abstract String[] getSupportedVersions();
	
	/**
	 * 
	 * @return returns the payload version used by default when generating request messages.
	 */
	protected abstract String getDefaultPayloadVersion();
	
	/**
	 * Help method to determine if a payload version is supported by this parser.
	 * 
	 * @param payloadVersion the payload parser to check.
	 * @throws MessageContentException if unsupported version was found.
	 */
	protected void isPayloadVersionSupported(String payloadVersion) throws MessageContentException{
		for(String supportedVersion : getSupportedVersions()){
			if(supportedVersion.equals(payloadVersion)){
				return;
			}
		}
		throw new MessageContentException("Unsupported Payload version: " + payloadVersion + " for PayLoadParser " + this.getClass().getSimpleName());
	}
	
	


}
