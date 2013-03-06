/************************************************************************
*                                                                       *
*  Certificate Service - Messages                                   *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages.heartbeat;

import java.io.IOException;
import java.util.Properties;

import org.certificateservices.messages.MessageException;

/**
 * Heart beat sender interface that is responsible for constructing messages and
 * sending them to monitoring systems.
 * <p>
 * Its main method is sendHeartBeat().
 * 
 * @author Philip Vendil
 *
 */
public interface HeartBeatSender {
	
	/**
	 * Initalization method that should be called directly after creating
	 * an instance of the interface.
	 * @param config configuration of the heart beats sender.
	 * @throws HeartBeatConfigurationException if configuration was insufficent to
	 * initialize the sender.
	 */
	void init(Properties config) throws HeartBeatConfigurationException;

	/**
	 * Main method in charge of generating a heartbeat message and sending to the receiving monitoring system.
	 * 
	 * @param heartBeatMessage the heartbeat message to send.
	 * @throws IllegalArgumentException if the given message contained faulty data.
	 * @throws IOException if communication problems occurred during sending of the message.
	 * @throws MessageException if internal error occurred generating and sending the message.
	 */
	void sendHeartBeat(HeartBeatMessage heartBeatMessage) throws IllegalArgumentException, IOException, MessageException;
	
	/**
	 * Method telling the underlying implementation to close it's connection and free resources if applicable.
	 * @throws IOException if communication problems occurred when closing the connection.
	 */
	void close() throws IOException;
}
