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

import java.util.Properties;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.MessageSecurityProvider;

/**
 * Factory class in charge of creating and initializing a CS Message Parser from
 * a given configuration.
 * 
 * @author Philip Vendil
 *
 */
public class CSMessageParserFactory {
	
	/**
	 * Setting indicating which implementation of CS Message Parser that 
	 * should be used. By default is the Default Message Parser used.
	 */
	public static final String SETTING_CSMESSAGEPARSER_IMPL = "csmessage.parser.impl";
	
	private static final String DEFAULT_IMPLEMENTATION = DefaultCSMessageParser.class.getName();
	

	/**
	 * Method to generate a new CSMessageParser from the configuration, if setting "csmessage.parser.impl"
	 * isn't set will the default message parser be created.
	 * 
	 * @param securityProvider the security provider used for the message parser.
	 * @param config the configuration context.
	 * @return a newly created CS Message parser
	 * @throws MessageException if problems occurred creating a message parser.
	 */
	public static CSMessageParser genCSMessageParser(MessageSecurityProvider securityProvider, Properties config) throws MessageException{
		String cp = config.getProperty(SETTING_CSMESSAGEPARSER_IMPL, DEFAULT_IMPLEMENTATION);
		try{
			Class<?> c = CSMessageParserFactory.class.getClassLoader().loadClass(cp);
			CSMessageParser retval = (CSMessageParser) c.newInstance();
			retval.init(securityProvider, config);
			return retval;
		}catch(Exception e){
			if(e instanceof MessageException){
				throw (MessageException) e;
			}			
			throw new MessageException("Error creating CS Message Parser: " + e.getMessage(),e);			
		}
	}

}
