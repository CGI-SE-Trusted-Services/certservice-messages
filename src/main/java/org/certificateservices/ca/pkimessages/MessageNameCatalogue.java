package org.certificateservices.ca.pkimessages;

import java.util.Properties;

public interface MessageNameCatalogue {
	
	/**
	 * Default constructor
	 * @param properties the properties file of the PKI message parser.
	 * @throws PKIMessageException if 
	 */
	public void init(Properties config) throws PKIMessageException;

	/**
	 * Method that looks up the name for a specific setting used to populate the 'name' attribute
	 * in the header.
	 *   
	 * @param requestName the related request name if applicable, null if this is a request.
	 * @param payLoadObject the setting to look-up the name for. 
	 * @return the name of the message to use.
	 * @throws PKIMessageException if name lookup failed due to internal connection problems.
	 * @throws IllegalArgumentException if name lookup failed due to bad request data
	 */
	public String lookupName(String requestName, Object payLoadObject) throws PKIMessageException, IllegalArgumentException;
}