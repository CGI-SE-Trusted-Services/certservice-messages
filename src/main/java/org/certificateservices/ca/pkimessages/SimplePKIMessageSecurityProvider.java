/**
 * 
 */
package org.certificateservices.ca.pkimessages;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Properties;

import org.certificateservices.ca.pkimessages.utils.SettingsUtils;

/**
 * Simple PKI Message provider that is configured with two soft key stores.
 * One key store used as a client key store signing messages and
 * 
 * One trust store where accepted end entity certificates are stored.
 * 
 * @author Philip Vendil
 *
 */
public class SimplePKIMessageSecurityProvider implements
		PKIMessageSecurityProvider {
	
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
	 * @throws PKIMessageException if not all required settings were set correctly.
	 */
	public SimplePKIMessageSecurityProvider(Properties config) throws PKIMessageException{
		String keyStorePath = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_PATH);
		File keyStoreFile = new File(keyStorePath);
		if(!keyStoreFile.canRead() || !keyStoreFile.exists() || !keyStoreFile.isFile()){
			throw new PKIMessageException("Error reading signing keystore: " + keyStorePath + ", make sure it exists and is readable");
		}
		
		String signKeystoreAlias = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_ALIAS);
		
		try{
			String signKeystorePassword = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_PASSWORD);
			
			KeyStore signKeystore = KeyStore.getInstance("JKS");
			signKeystore.load(new FileInputStream(keyStoreFile), signKeystorePassword.toCharArray());
			signCertificate = (X509Certificate) signKeystore.getCertificate(signKeystoreAlias);

			signPrivateKey = (PrivateKey) signKeystore.getKey(signKeystoreAlias, signKeystorePassword.toCharArray());

		}catch(Exception e){
			if(e instanceof PKIMessageException){
				throw (PKIMessageException) e;
			}
			throw new PKIMessageException("Error loading signing keystore: " + e.getMessage(),e);
		}
		
		if(signCertificate == null || signPrivateKey == null){
			throw new PKIMessageException("Error finding signing certificate and key for alias : " + signKeystoreAlias + ", in key store: " + keyStorePath);
		}
		
		String trustStorePath = SettingsUtils.getRequiredProperty(config, SETTING_TRUSTKEYSTORE_PATH);
		File trustStoreFile = new File(trustStorePath);
		if(!trustStoreFile.canRead() || !trustStoreFile.exists() || !trustStoreFile.isFile()){
			throw new PKIMessageException("Error reading signing truststore: " + trustStorePath + ", make sure it exists and is readable");
		}
		
		try{
			String truststorePassword = SettingsUtils.getRequiredProperty(config, SETTING_TRUSTKEYSTORE_PASSWORD);
			
			trustStore = KeyStore.getInstance("JKS");
			trustStore.load(new FileInputStream(trustStoreFile), truststorePassword.toCharArray());

		}catch(Exception e){
			if(e instanceof PKIMessageException){
				throw (PKIMessageException) e;
			}
			throw new PKIMessageException("Error loading signing keystore: " + e.getMessage(),e);
		}
		
	}
	
	/**
	 * @see org.certificateservices.ca.pkimessages.PKIMessageSecurityProvider#getSigningKey()
	 */
	public PrivateKey getSigningKey() throws PKIMessageException {
		return signPrivateKey;
	}

	/**
	 * @see org.certificateservices.ca.pkimessages.PKIMessageSecurityProvider#getSigningCertificate()
	 */
	public X509Certificate getSigningCertificate() throws PKIMessageException {
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
	 * @see org.certificateservices.ca.pkimessages.PKIMessageSecurityProvider#isValidAndAuthorized(java.security.cert.X509Certificate, java.lang.String)
	 */
	public boolean isValidAndAuthorized(X509Certificate signCertificate,
			String organisation) throws IllegalArgumentException,
			PKIMessageException {
		
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
			throw new PKIMessageException("Error reading certificates from truststore: " + e.getMessage());
		} catch (KeyStoreException e) {
			throw new PKIMessageException("Error reading certificates from truststore: " + e.getMessage());
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
