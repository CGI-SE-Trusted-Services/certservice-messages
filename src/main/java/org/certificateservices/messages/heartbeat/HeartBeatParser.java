/**
 * 
 */
package org.certificateservices.messages.heartbeat;

import java.util.Properties;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.MessageSecurityProvider;

/**
 * Interface used for heart beat message parsers.
 * 
 * @author Philip Vendil
 *
 */
public interface HeartBeatParser {
	
	/**
	 * Method that initializes the heart beat parser with property set.
	 * 
	 * @param securityProvider the message security provider to use.
	 * @param config the configuration of the parser.
	 * @throws MessageException if configuration contained bad configuration of security provider.
	 */
	void init(MessageSecurityProvider securityProvider, Properties config) throws MessageException;
	
	/**
	 * Method to parse the messageData into a HeartBeatMessage with validation according to the
	 * specification.
	 * 
	 * @param messageData the message data to parse
	 * @return a heart beat message from the message data.
	 * @throws IllegalArgumentException if receipt message contained invalid data not conforming to the standard.
	 * @throws MessageException if internal state occurred when processing the message
	 */
	HeartBeatMessage parseMessage(byte[] messageData) throws IllegalArgumentException, MessageException;
	
	/**
	 * Method to generate a heart beat message from the supplied data.
	 * 
	 * @param heartBeatMessage the heart beat message data to transform into a message structure.
	 * @return a generated heart beat message, never null.
	 * @throws IllegalArgumentException if supplied arguments were invalid.
	 * @throws MessageException if internal problems occurred when generating the heart beat message.
	 */
	byte[] genHeartBeatMessage(String messageId, HeartBeatMessage heartBeatMessage)  throws IllegalArgumentException, MessageException;

}