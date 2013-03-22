package org.certificateservices.messages.pkimessages;

import java.util.Properties;

import org.certificateservices.messages.MessageException;

public interface MessageNameCatalogue {
	
	/**
	 * Special request name that can be sent to the lookup method and indicates
	 * that the related message is a IssueCredentialStatusList that is automatically
	 * generated without any matching request.
	 */
	public static final String REQUESTNAME_CRLFORWARD = "CRLFORWARD";
	
	/**
	 * Default constructor
	 * @param properties the properties file of the PKI message parser.
	 * @throws MessageException if 
	 */
	public void init(Properties config) throws MessageException;

	/**
	 * Method that looks up the name for a specific setting used to populate the 'name' attribute
	 * in the header.
	 *   
	 * @param requestName the related request name if applicable, null if this is a request. 
	 * @param payLoadObject the setting to look-up the name for. 
	 * @return the name of the message to use.
	 * @throws MessageException if name lookup failed due to internal connection problems.
	 * @throws IllegalArgumentException if name lookup failed due to bad request data
	 */
	public String lookupName(String requestName, Object payLoadObject) throws MessageException, IllegalArgumentException;
}