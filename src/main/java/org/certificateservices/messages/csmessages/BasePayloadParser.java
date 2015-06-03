/**
 * 
 */
package org.certificateservices.messages.csmessages;

import java.util.Properties;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.ObjectFactory;

/**
 * Base implementation of a PayLoadParser that other implementations might inherit.
 * 
 * @author Philip Vendil
 *
 */
public abstract class BasePayloadParser implements PayloadParser {
	
	protected CSMessageParser csMessageParser;
	protected Properties config;
	
	protected ObjectFactory csMessageObjectFactory = new ObjectFactory();
	
	/**
	 * Default initializer setting the parser and config properties.
	 * 
	 * @see org.certificateservices.messages.csmessages.PayloadParser#init(java.util.Properties, org.certificateservices.messages.csmessages.CSMessageParser)
	 */
	@Override
	public void init(Properties config, CSMessageParser parser)
			throws MessageProcessingException {
		this.csMessageParser = parser;
		this.config = config;
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
    	return csMessageParser.parseMessage(messageData);
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
