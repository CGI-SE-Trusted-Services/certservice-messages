/************************************************************************
*                                                                       *
*  Certificate Service - PKI Messages                                   *
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

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;


/**
 * Dummy PKI Message Security Provider returning a self-signed certificate used
 * for testing.
 * 
 * @author Philip Vendil
 *
 */
public class DummyMessageSecurityProvider implements
		MessageSecurityProvider {

	private KeyStore dummyKS = null;
	
	private boolean validCallDone = false;
	private String organisationCalled = null;
	
	private KeyStore getDummyKeystore() throws MessageProcessingException{
		if(dummyKS == null){
			try {
				dummyKS = KeyStore.getInstance("JKS");
				dummyKS.load(this.getClass().getResourceAsStream("/dummykeystore.jks"), "tGidBq0Eep".toCharArray());
			} catch (Exception e) {
				throw new MessageProcessingException("Error loading dummy key store: " + e.getMessage(),e);
			}
			
		}
		return dummyKS;
	}
	
	/**
	 * Method fetching the signing key from the dummy keystore.
	 * 
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningKey()
	 */
	public PrivateKey getSigningKey() throws MessageProcessingException {
	
		try {
			return (PrivateKey) getDummyKeystore().getKey("test", "tGidBq0Eep".toCharArray());
		} catch (Exception e) {
			throw new MessageProcessingException("Error fetching dummy signing key: " + e.getMessage(),e);
		}
	}

	/**
	 * 
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningCertificate()
	 */
	public X509Certificate getSigningCertificate()
			throws IllegalArgumentException, MessageProcessingException {
		try {
			return (X509Certificate) getDummyKeystore().getCertificate("test");
		} catch (Exception e) {
			throw new MessageProcessingException("Error fetching dummy signing certificate: " + e.getMessage(),e);
		}
	}

	/**
	 * 
	 * @see org.certificateservices.messages.MessageSecurityProvider#isValidAndAuthorized(X509Certificate)
	 */
	public boolean isValidAndAuthorized(X509Certificate signCertificate, String organisation)
			throws IllegalArgumentException, MessageProcessingException {

		if(signCertificate == null){
			throw new IllegalArgumentException("Error sign certificate cannot be null when validating.");
		}
		
		boolean[] keyUsage = signCertificate.getKeyUsage();
		if (keyUsage[0] == false) {
			return false;
		}
		
		validCallDone = true;
		organisationCalled = organisation;
		
		return true;
	}
	
	public void resetCounters(){
		validCallDone = false;
		organisationCalled = null;
	}
	
	public boolean getValidCallDone(){
		return validCallDone;
	}
	
	public String getOrganisationCalled(){
		return organisationCalled;
	}

}
