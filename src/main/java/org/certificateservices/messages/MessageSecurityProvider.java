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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;


/**
 * PKI Message Security Provider used by the generator of messages to sign the PKI messages before 
 * they are sent.
 * 
 * @author Philip Vendil
 *
 */
public interface MessageSecurityProvider {
	

	/**
	 * Fetches the signing key used to create the digital signatures of the XML file.
	 * @return the signing key used.
	 * @throws MessageException if key isn't accessible or activated.
	 */
	PrivateKey getSigningKey() throws MessageProcessingException;
	
	/**
	 * Fetches the signing certificate used to create the digital signatures of the XML file.
	 * @return the signing certificate used.
	 * @throws MessageException if certificate isn't accessible.
	 */
	X509Certificate getSigningCertificate()  throws MessageProcessingException;
	

	/**
	 * Method in charge of validating a certificate used to sign a PKI message
	 * and also check if the certificate is authorized to generate messages.
	 * @param signCertificate the certificate used to sign the message.
	 * @param organisation the related organisation to the message
	 * @return true if the 
	 * @throws IllegalArgumentException if arguments were invalid.
	 * @throws MessageException if internal error occurred validating the certificate.
	 */
	boolean isValidAndAuthorized(X509Certificate signCertificate, String organisation) throws IllegalArgumentException, MessageProcessingException;
}
