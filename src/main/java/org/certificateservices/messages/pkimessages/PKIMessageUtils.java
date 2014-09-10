/**
 * 
 */
package org.certificateservices.messages.pkimessages;

import java.lang.reflect.Method;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.PKIResponse;

/**
 * Utility class containing help method used to process and parse PKI Messages.
 * 
 * @author Philip Vendil
 *
 */
public class PKIMessageUtils {

	/**
	 * Help method fetching the in response to value from a PKIMessage response.
	 * @param message the message to fetch in response to value (payload should contain a PKI Response message)
	 * @return the inResponse to from the payload or null if no value could be found.
	 * @throws MessageException if parsing problems occurred.
	 */
	public static String getInResponseTo(PKIMessage message) throws MessageException{
		String retval = null;
		
		Object payLoad = message.getPayload();
		for(Method m : payLoad.getClass().getMethods()){
			if(m.getName().startsWith("get") && m.getName().endsWith("Response")){
				try {
					Object result = m.invoke(payLoad);
					if(result instanceof PKIResponse){
						String value = ((PKIResponse) result).getInResponseTo();
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
