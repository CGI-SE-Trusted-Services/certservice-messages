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
package org.certificateservices.messages.sysconfig;

import java.io.InputStream;
import java.util.Properties;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.CSMessageParser;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParser;

/**
 * Payload Parser for generating SysConfig messages according to 
 * sysconfig_schema2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class SysConfigPayloadParser implements PayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/sysconfig2_0";
	
	private static final String SYSCONFIG_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/sysconfig_schema2_0.xsd";

	private CSMessageParser csMessageParser;
	
	@Override
	public void init(Properties config, CSMessageParser csMessageParser) throws MessageException {
		this.csMessageParser = csMessageParser;
	}
	
	@Override
	public String getJAXBPackage() {
		return "org.certificateservices.messages.sysconfig.jaxb";
	}


	@Override
	public String getNameSpace() {
		return NAMESPACE;
	}

	@Override
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
    	if(payLoadVersion.equals("2.0")){
    		return getClass().getResourceAsStream(SYSCONFIG_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported SysConfig Payload version: " + payLoadVersion);
	}


	
	// TODO figure out how to parse

}
