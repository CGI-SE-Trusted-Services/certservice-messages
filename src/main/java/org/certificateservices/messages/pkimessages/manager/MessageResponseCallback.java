/**
 * 
 */
package org.certificateservices.messages.pkimessages.manager;

import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;

/**
 * Callback interface used to signal that a response targeted for this client (i.e destinationId = current sourceId)
 * <p>
 * Main method is responseRecieved
 * <p>
 * <b>Important</b> only messages with a destination matching this source id should be sent through
 * this callback.
 * 
 * @author Philip Vendil
 *
 */
public interface MessageResponseCallback {
	
	/**
	 * Method signaling that a response was recieved.
     * <p>
     * <b>Important</b> only messages with a destination matching this source id should be sent through
     * this callback.
	 * @param responseMessage the response message that was recieved.
	 */
	public void responseReceived(PKIMessage responseMessage);

}
