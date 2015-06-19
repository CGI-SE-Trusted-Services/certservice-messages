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

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.assertion.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.BasePayloadParser;

/**
 * 
 * TODO
 * @author Philip Vendil
 *
 */
public class AssertionPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";
	
	private static final String ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/saml-schema-assertion-2.0.xsd";

	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_ASSERTION_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_ASSERTION_VERSION = "2.0";


	/**
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getNameSpace()
	 */
	@Override
	public String getNameSpace() {
		return NAMESPACE;
	}

	/**
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getJAXBPackage()
	 */
	@Override
	public String getJAXBPackage() {
		return "org.certificateservices.messages.assertion.jaxb";
	}

	/* (non-Javadoc)
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getSchemaAsInputStream(java.lang.String)
	 */
	@Override
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
    	if(payLoadVersion.equals("2.0")){
    		return getClass().getResourceAsStream(ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported Assertion version: " + payLoadVersion);
	}

	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_ASSERTION_VERSIONS;
	}

	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_ASSERTION_VERSION;
	}
	
	public byte[] genRoleAssertion() throws MessageContentException, MessageProcessingException{
		return null;
		
		// TODO Custom Sign
	}
	
	// Method to generate Each of the two Assertions
	
	// Method to parse an assertion
	
	// TODO main parser should verify
	
	// have a verify method
	
	

}
