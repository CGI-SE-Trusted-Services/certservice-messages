/**
 * 
 */
package org.certificateservices.ca.receipts;

import java.util.List;
import java.util.Properties;

/**
 * @author Philip Vendil
 *
 */
public interface ReceiptParser {
	
	/**
	 * Method that initializes the receipt parser with property set.
	 * 
	 * @param config the configuration of the parser.
	 * @throws ReceiptMessageException if configuration contained bad configuration of security provider.
	 */
	void init(Properties config) throws ReceiptMessageException;
	
	/**
	 * Method to parse the messageData into a ReceiptMessage with validation according to the
	 * specification.
	 * 
	 * @param messageData the message data to parse
	 * @return a list of ReceiptMessage that is valid, never null.
	 * @throws IllegalArgumentException if receipt message contained invalid data not conforming to the standard.
	 * @throws ReceiptMessageException if internal state occurred when processing the message
	 */
	List<ReceiptMessage> parseMessage(byte[] messageData) throws IllegalArgumentException, ReceiptMessageException;
	
	/**
	 * Method to generate a receipt message from the supplied data.
	 * 
	 * @param messageId the unique message id
	 * @param status the status of the receipt message
	 * @param errorDescription optional error description, null if not applicable
	 * @return a generated receipt message, never null.
	 * @throws IllegalArgumentException if supplied arguments were invalid.
	 * @throws ReceiptMessageException if internal problems occurred when generating the receipt message.
	 */
	byte[] genReceiptMessage(String messageId, ReceiptStatus status, String errorDescription)  throws IllegalArgumentException, ReceiptMessageException;

}
