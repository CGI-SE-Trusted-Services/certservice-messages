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
package org.certificateservices.messages.assertion;

import java.io.InputStream;
import java.util.Properties;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.CSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParser;

/**
 * 
 * TODO
 * @author Philip Vendil
 *
 */
public class AssertionPayloadParser implements PayloadParser {

	/* (non-Javadoc)
	 * @see org.certificateservices.messages.csmessages.PayloadParser#init(java.util.Properties)
	 */
	@Override
	public void init(Properties config, CSMessageParser parser) throws MessageProcessingException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getNameSpace()
	 */
	@Override
	public String getNameSpace() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getJAXBPackage()
	 */
	@Override
	public String getJAXBPackage() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getSchemaAsInputStream(java.lang.String)
	 */
	@Override
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
		// TODO Auto-generated method stub
		return null;
	}
	
	// Method to generate Each of the two Assertions
	
	// Method to parse an assertion
	
	// TODO main parser should verify
	
	// have a verify method
	
	

}
