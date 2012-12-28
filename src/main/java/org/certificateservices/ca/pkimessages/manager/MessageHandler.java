package org.certificateservices.ca.pkimessages.manager;

import java.io.IOException;
import java.util.Properties;

import org.certificateservices.ca.pkimessages.PKIMessageException;
import org.certificateservices.ca.pkimessages.PKIMessageParser;


/**
 * Interface that a MQ message handler should implement in order to send and recieve messages
 * directly.
 * 
 * @author Philip Vendil
 *
 */
public interface MessageHandler {
	
	/**
	 * Method called after instantiation and should check configuration and prepare
	 * everything for connection with the message queue server.
	 * 
	 * @param config the configuration.
	 * @param parser the message parser configuration.
	 * @param callback the callback interface where response messages are sent.
	 * @throws PKIMessageException if configuration problems or other internal problems occurred.
	 */
	void init(Properties config, PKIMessageParser parser, MessageResponseCallback callback) throws PKIMessageException;
	
	/**
	 * Method returning the connection factory used to set-up the message queues. Used only
	 * for special purposes when not extending the implementing class.
	 * 
	 * Required method for extending classes to provide the connection factory
	 * to use when connecting to the message server.
	 * 
	 * @return a connection factory to use to set up the message processing environment, never null.
	 * @throws PKIMessageException if internal error or configuration problems occurred.
	 * @throws IOException if communication problems occurred with the message service.
	 */
	Object getConnectionFactory() throws PKIMessageException, IOException;
	
	/**
	 * Method called by service if the MessageHandler should connect to the MessageQueue server and start processing incoming calls.
	 * @throws PKIMessageException if configuration problems or other internal problems occurred connecting to the MQ server.
	 * @throws IOException if communication problems occurred connecting from the message server.
	 */
	void connect() throws PKIMessageException, IOException;	
	
	/**
	 * Method to send a message to the MQ server out queue.
	 * 
	 * @throws PKIMessageException if configuration problems or other internal problems occurred connecting to the MQ server.
	 * @throws IOException if communication problems occurred connecting and sending to the message server.
	 */
	void sendMessage(byte[] message)  throws PKIMessageException, IOException;	

	/**
	 * Method called by service if the MessageHandler should disconnect from the MessageQueue server.
	 * 
	 * @throws IOException if communication problems occurred disconnecting from the message server.
	 */
	void close() throws IOException;
}
