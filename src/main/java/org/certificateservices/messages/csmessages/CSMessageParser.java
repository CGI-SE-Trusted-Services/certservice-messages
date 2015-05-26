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

package org.certificateservices.messages.csmessages;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;

public interface CSMessageParser {
	

	
	/**
	 * Method that initializes the CSMessage parser with a security provider and properties.
	 * 
	 * @param securityProvider the CSMessage security provider to use.
	 * @param config the configuration of the parser.
	 * @throws MessageProcessingException if configuration contained bad configuration of security provider.
	 */
	void init(MessageSecurityProvider securityProvider, Properties config) throws MessageProcessingException;
	
	
	byte[] genMessage(String messageId, Object payLoad) throws MessageContentException, MessageProcessingException;

}
