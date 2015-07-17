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

/**
 * Defines available types of assertions.
 * 
 * @author Philip Vendil
 *
 */
public enum AssertionTypeEnum {

	AUTHORIZATION_TICKET("AUTHORIZATION_TICKET"),
	USER_DATA("USER_DATA"),
	APPROVAL_TICKET("APPROVAL_TICKET");

	private String attributeValue;
	private AssertionTypeEnum(String attributeValue){
		this.attributeValue = attributeValue;
	}
	
	/**
	 * @return the value of the AssertionType SAML Attribute
	 */
	public String getAttributeValue(){
		return attributeValue;
	}
}
