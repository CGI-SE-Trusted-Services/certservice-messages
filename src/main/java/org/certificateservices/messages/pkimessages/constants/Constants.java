/**
 * 
 */
package org.certificateservices.messages.pkimessages.constants;

/**
 * Class containing general constants related to the PKI message protocol
 * 
 * @author Philip Vendil
 *
 */
public class Constants {
	
	/**
	 * Special value used when forwarding CRL automatically generated requests where the CA
	 * doesn't know which organisation the CRL belongs to and it's up the the receiver to figure this out.
	 */
	public static final String ORGANISATION_UNKNOWN = "UNKNOWN";

}
