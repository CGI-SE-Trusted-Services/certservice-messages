/**
 * 
 */
package org.certificateservices.messages.heartbeat;

/**
 * Exception thrown due to miss-configuration of a heart beat sender instance.
 * 
 * @author Philip Vendil
 *
 */
public class HeartBeatConfigurationException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Exception thrown due to miss-configuration of a heart beat sender instance.
	 */
	public HeartBeatConfigurationException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Exception thrown due to miss-configuration of a heart beat sender instance.
	 */
	public HeartBeatConfigurationException(String message) {
		super(message);
	}
	
	

}
