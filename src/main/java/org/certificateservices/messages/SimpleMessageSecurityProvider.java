/**
 * 
 */
package org.certificateservices.messages;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Properties;

import org.certificateservices.messages.utils.SettingsUtils;

/**
 * Simple PKI Message provider that is configured with two soft key stores.
 * One key store used as a client key store signing messages and
 * 
 * One trust store where accepted end entity certificates are stored.
 * 
 * @author Philip Vendil
 *
 */
public class SimpleMessageSecurityProvider implements
		MessageSecurityProvider {
	
	/**
	 * Setting indicating the path to the signing JKS key store (required) 
	 */
	public static final String SETTING_SIGNINGKEYSTORE_PATH = "simplesecurityprovider.signingkeystore.path";
	
	/**
	 * Setting indicating the password to the signing key store (required) 
	 */
	public static final String SETTING_SIGNINGKEYSTORE_PASSWORD = "simplesecurityprovider.signingkeystore.password";
	
	/**
	 * Setting indicating the alias of the certificate to use in the signing key store (required) 
	 */
	public static final String SETTING_SIGNINGKEYSTORE_ALIAS = "simplesecurityprovider.signingkeystore.alias";
	
	/**
	 * Setting indicating the path to the trust JKS key store (required) 
	 */
	public static final String SETTING_TRUSTKEYSTORE_PATH = "simplesecurityprovider.trustkeystore.path";
	
	/**
	 * Setting indicating the password to the trust JKS key store (required) 
	 */
	public static final String SETTING_TRUSTKEYSTORE_PASSWORD = "simplesecurityprovider.trustkeystore.password";
	
	
	private KeyStore trustStore = null;
	PrivateKey signPrivateKey = null;
	X509Certificate signCertificate = null;
	

	
	/**
	 * Configures and set's up the security provider.
	 * 
	 * @param config provider configuration.
	 * @throws MessageException if not all required settings were set correctly.
	 */
	public SimpleMessageSecurityProvider(Properties config) throws MessageException{
		String keyStorePath = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_PATH);
		
		InputStream keyStoreInputStream = this.getClass().getClassLoader().getResourceAsStream(keyStorePath);
		if(keyStoreInputStream == null){
			File keyStoreFile = new File(keyStorePath);
			if(!keyStoreFile.canRead() || !keyStoreFile.exists() || !keyStoreFile.isFile()){
				throw new MessageException("Error reading signing keystore: " + keyStorePath + ", make sure it exists and is readable");
			}else{
				try {
					keyStoreInputStream = new FileInputStream(keyStoreFile);
				} catch (FileNotFoundException e) {
					throw new MessageException("Error keystore file: " + keyStoreFile + " not found.");
				}
			}
		}
			
		
		String signKeystoreAlias = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_ALIAS);
		
		try{
			String signKeystorePassword = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_PASSWORD);
			
			KeyStore signKeystore = KeyStore.getInstance("JKS");
			signKeystore.load(keyStoreInputStream, signKeystorePassword.toCharArray());
			signCertificate = (X509Certificate) signKeystore.getCertificate(signKeystoreAlias);

			signPrivateKey = (PrivateKey) signKeystore.getKey(signKeystoreAlias, signKeystorePassword.toCharArray());

		}catch(Exception e){
			if(e instanceof MessageException){
				throw (MessageException) e;
			}
			throw new MessageException("Error loading signing keystore: " + e.getMessage(),e);
		}
		
		if(signCertificate == null || signPrivateKey == null){
			throw new MessageException("Error finding signing certificate and key for alias : " + signKeystoreAlias + ", in key store: " + keyStorePath);
		}
				
		String trustStorePath = SettingsUtils.getRequiredProperty(config, SETTING_TRUSTKEYSTORE_PATH);
		InputStream trustStoreInputStream = this.getClass().getClassLoader().getResourceAsStream(trustStorePath);
		if(trustStoreInputStream == null){
			File trustStoreFile = new File(trustStorePath);
			if(!trustStoreFile.canRead() || !trustStoreFile.exists() || !trustStoreFile.isFile()){
				throw new MessageException("Error reading signing truststore: " + trustStorePath + ", make sure it exists and is readable");
			}else{
				try {
					trustStoreInputStream = new FileInputStream(trustStorePath);
				} catch (FileNotFoundException e) {
					throw new MessageException("Error keystore file: " + trustStorePath + " not found.");
				}
			}
		}
		
		try{
			String truststorePassword = SettingsUtils.getRequiredProperty(config, SETTING_TRUSTKEYSTORE_PASSWORD);
			
			trustStore = KeyStore.getInstance("JKS");
			trustStore.load(trustStoreInputStream, truststorePassword.toCharArray());

		}catch(Exception e){
			if(e instanceof MessageException){
				throw (MessageException) e;
			}
			throw new MessageException("Error loading signing truststore: " + e.getMessage(),e);
		}
		
	}
	
	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningKey()
	 */
	public PrivateKey getSigningKey() throws MessageException {
		return signPrivateKey;
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningCertificate()
	 */
	public X509Certificate getSigningCertificate() throws MessageException {
		return signCertificate;
	}

	/**
	 * Method that checks if a sign certificate is in the trust store, the certificate itself have
	 * to be imported and not just the CA certificate.
	 * <p>
	 * The certificate also have to have key usage digital signature
	 * <p>
	 * Organisation name is ignored
	 * <p>
	 * @see org.certificateservices.messages.MessageSecurityProvider#isValidAndAuthorized(java.security.cert.X509Certificate, java.lang.String)
	 */
	public boolean isValidAndAuthorized(X509Certificate signCertificate,
			String organisation) throws IllegalArgumentException,
			MessageException {
		
		boolean[] keyUsage = signCertificate.getKeyUsage();
		if (keyUsage[0] == false) {
			return false;
		}
		
		
		boolean foundMatching = true;
		try{
			Enumeration<String> aliases = trustStore.aliases();
			while(aliases.hasMoreElements()){
				if(isTrusted(signCertificate, (X509Certificate) trustStore.getCertificate(aliases.nextElement()))){
					foundMatching = true;
					break;
				}
			}		  
		}catch(CertificateEncodingException e){
			throw new MessageException("Error reading certificates from truststore: " + e.getMessage());
		} catch (KeyStoreException e) {
			throw new MessageException("Error reading certificates from truststore: " + e.getMessage());
		}
		
		return foundMatching;
	}
	
	/**
	 * Checks that the two certificate is exactly the same.
	 * 
	 */
	private boolean isTrusted(X509Certificate signCertificate, X509Certificate trustedCertificate) throws CertificateEncodingException{
		return Arrays.equals(signCertificate.getEncoded(), trustedCertificate.getEncoded());
	}

}
