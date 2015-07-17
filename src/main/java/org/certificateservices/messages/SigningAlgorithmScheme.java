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
package org.certificateservices.messages;

/**
 * Definition of all supported Signature Algorithm by Message Security Providers.
 * 
 * @author Philip Vendil
 *
 */
public enum SigningAlgorithmScheme {
	
	RSAWithSHA256("http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
	
	String hashAlgorithmURI;
	String signatureAlgorithmURI;
	
	private SigningAlgorithmScheme(String hashAlgorithmURI, String signatureAlgorithmURI){
		this.hashAlgorithmURI = hashAlgorithmURI;
		this.signatureAlgorithmURI = signatureAlgorithmURI;
	}
	
	public String getHashAlgorithmURI(){
		return hashAlgorithmURI;
	}
	
	public String getSignatureAlgorithmURI(){
		return signatureAlgorithmURI;
	}
	
}
