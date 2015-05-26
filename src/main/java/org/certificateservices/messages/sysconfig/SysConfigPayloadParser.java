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

import java.util.Properties;

import org.certificateservices.messages.MessageException;
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

	@Override
	public void init(Properties config) throws MessageException {

	}
	
	@Override
	public String getJAXBPackage() {
		return "org.certificateservices.messages.sysconfig.jaxb";
	}

	@Override
	public String getSchemaLocation(String payLoadVersion) throws  IllegalArgumentException {
    	if(payLoadVersion.equals("2.0")){
    		return SYSCONFIG_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
    	}
    	throw new IllegalArgumentException("");
	}

	@Override
	public String getNameSpace() {
		return NAMESPACE;
	}


	
	// TODO figure out how to parse

}
