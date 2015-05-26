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

import java.lang.reflect.Method;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.CSResponse;

/**
 * Utility class containing help method used to process and parse CS Messages.
 * 
 * @author Philip Vendil
 *
 */
public class CSMessageUtils {

	/**
	 * Help method fetching the in response to value from a PKIMessage response.
	 * @param message the message to fetch in response to value (payload should contain a PKI Response message)
	 * @return the inResponse to from the payload or null if no value could be found.
	 * @throws MessageException if parsing problems occurred.
	 */
	public static String getInResponseTo(CSMessage message) throws MessageException{
		String retval = null;
		
		assert false; // TODO Test this method
		
		Object payLoad = message.getPayload();
		for(Method m : payLoad.getClass().getMethods()){
			if(m.getName().startsWith("get") && m.getName().endsWith("Response")){
				try {
					Object result = m.invoke(payLoad);
					if(result instanceof CSResponse){
						String value = ((CSResponse) result).getInResponseTo();
						if(value != null && !value.trim().equals("")){
							retval = value;
							break;
						}
					}
				} catch (Exception e) {
					throw new MessageException("Error parsing in response to from PKIMessage: " + e.getMessage(),e);
				}
			}
		}
		
		return retval;
	}
	
}
