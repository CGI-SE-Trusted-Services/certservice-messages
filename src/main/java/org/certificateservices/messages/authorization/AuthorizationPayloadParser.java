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
package org.certificateservices.messages.authorization;


import java.io.InputStream;
import java.util.List;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.authorization.jaxb.GetRequesterRolesRequest;
import org.certificateservices.messages.authorization.jaxb.GetRequesterRolesResponse;
import org.certificateservices.messages.authorization.jaxb.GetRolesType;
import org.certificateservices.messages.authorization.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.BasePayloadParser;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.PayloadParser;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;

/**
 * Payload Parser for generating Authorization messages according to 
 * authorization2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class AuthorizationPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/authorization2_0";
	
	public static final String AUTHORIZATION_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/authorization_schema2_0.xsd";

	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_AUTHORIZATION_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_AUTHORIZATION_VERSION = "2.0";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.authorization.jaxb";
	}

	/**
	 * @see PayloadParser#getNameSpace()
	 */
	public String getNameSpace() {
		return NAMESPACE;
	}

	/**
	 * @see PayloadParser#getSchemaAsInputStream(String)
	 */
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
    	if(payLoadVersion.equals("2.0")){
    		return getClass().getResourceAsStream(AUTHORIZATION_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported Credential Management Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_AUTHORIZATION_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_AUTHORIZATION_VERSION;
	}
	


	/**
	 * Method to create a GetRequesterRolesRequest message.
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetRequesterRolesRequest(String requestId, String destinationId, String organisation, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetRequesterRolesRequest payload = of.createGetRequesterRolesRequest();
	
		return csMessageParser.generateCSRequestMessage(requestId, destinationId, organisation, getDefaultPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to a GetRequesterRolesResponse message and populating it with the all requesters authorized roles.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param roles the authorized roles of the requester.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetRequesterRolesResponse(String relatedEndEntity, CSMessage request, List<String> roles, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetRequesterRolesResponse response = of.createGetRequesterRolesResponse();
		
		response.setRoles(new GetRolesType.Roles());
		for(String role : roles){
			response.getRoles().getRole().add(role);
		}
		
		return csMessageParser.generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, false);
	}
	
}