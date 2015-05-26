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

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;

/**
 * Dummy implementation of a PayloadParser
 * 
 * @author Philip Vendil
 *
 */
public class DummyPayloadParser implements PayloadParser{
	
	public static String NAMESPACE = "http://dummynamespace";

	Properties config = null;
	boolean initCalled = false;


	@Override
	public void init(Properties config) throws MessageProcessingException {
		this.config = config;
		initCalled = true;
	}

	@Override
	public String getNameSpace() {
		return "http://testnamespace";
	}

	@Override
	public String getJAXBPackage() {
		return "some.package.name";
	}

	@Override
	public String getSchemaLocation(String payLoadVersion)
			throws MessageContentException {
		return "/somelocation.xsd";
	}
}
