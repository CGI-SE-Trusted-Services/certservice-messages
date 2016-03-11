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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;
import org.certificateservices.messages.utils.DefaultSystemTime;
import org.certificateservices.messages.utils.SettingsUtils;
import org.certificateservices.messages.utils.SystemTime;
import org.certificateservices.messages.utils.XMLEncrypter;

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
	
	Logger log = Logger.getLogger(SimpleMessageSecurityProvider.class);
	
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
	 * Setting indicating the path to the decrypt JKS key store (optional, if not set is signing keystore used for both signing and encryption) 
	 */
	public static final String SETTING_DECRYPTKEYSTORE_PATH = "simplesecurityprovider.decryptkeystore.path";
	
	/**
	 * Setting indicating the password to the decrypt key store (required, if encrypt key store is specified.) 
	 */
	public static final String SETTING_DECRYPTKEYSTORE_PASSWORD = "simplesecurityprovider.decryptkeystore.password";
	
	/**
	 *  Setting indicating the alias of the decryption key to use if no specific key is known. (optional, if not set is same as signing keystore alias used.) 
	 */
	public static final String SETTING_DECRYPTKEYSTORE_DEFAULTKEY_ALIAS = "simplesecurityprovider.decryptkeystore.defaultkey.alias";
	
	/**
	 * Setting indicating the path to the trust JKS key store (required) 
	 */
	public static final String SETTING_TRUSTKEYSTORE_PATH = "simplesecurityprovider.trustkeystore.path";
	
	/**
	 * Setting indicating the password to the trust JKS key store (required) 
	 */
	public static final String SETTING_TRUSTKEYSTORE_PASSWORD = "simplesecurityprovider.trustkeystore.password";
	
	
	/**
	 * Setting indicating the Signature algorithm scheme to use, possible values are:
	 * <li>RSAWithSHA256 (Default if not set).
	 */
	public static final String SETTING_SIGNATURE_ALGORITHM_SCHEME = "simplesecurityprovider.signature.algorithm";
	public static final SigningAlgorithmScheme DEFAULT_SIGNATURE_ALGORITHM_SCHEME = SigningAlgorithmScheme.RSAWithSHA256;
	
	/**
	 * Setting indicating the Encryption algorithm scheme to use, possible values are:
	 * <li>RSA_OAEP_WITH_AES256 (Default if not set).
	 * <li>RSA_PKCS1_5_WITH_AES256
	 */
	public static final String SETTING_ENCRYPTION_ALGORITHM_SCHEME = "simplesecurityprovider.encryption.algorithm";
	public static final EncryptionAlgorithmScheme DEFAULT_ENCRYPTION_ALGORITHM_SCHEME = EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256;
	
	private KeyStore trustStore = null;
	PrivateKey signPrivateKey = null;
	X509Certificate signCertificate = null;
	
	Map<String, PrivateKey> decryptionKeys = new HashMap<String, PrivateKey>();
	Map<String, X509Certificate[]> decryptionCertificates = new HashMap<String, X509Certificate[]>();
	String defaultDecryptionKeyId = null;
	
	private SigningAlgorithmScheme signingAlgorithmScheme;
	private EncryptionAlgorithmScheme encryptionAlgorithmScheme;
	SystemTime systemTime = new DefaultSystemTime();

	
	/**
	 * Configures and set's up the security provider.
	 * 
	 * @param config provider configuration.
	 * @throws MessageException if not all required settings were set correctly.
	 */
	public SimpleMessageSecurityProvider(Properties config) throws MessageProcessingException{
			
		String signKeystorePath = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_PATH);
		String signKeystoreAlias = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_ALIAS);
		
		try{
			String signKeystorePassword = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_PASSWORD);
			KeyStore signKeystore = getSigningKeyStore(config);
			signCertificate = (X509Certificate) signKeystore.getCertificate(signKeystoreAlias);
			signPrivateKey = (PrivateKey) signKeystore.getKey(signKeystoreAlias, signKeystorePassword.toCharArray());

		}catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Error loading signing keystore: " + e.getMessage(),e);
		}
		
		if(signCertificate == null || signPrivateKey == null){
			throw new MessageProcessingException("Error finding signing certificate and key for alias : " + signKeystoreAlias + ", in key store: " + signKeystorePath);
		}
				
		trustStore = getKeyStore(config, SETTING_TRUSTKEYSTORE_PATH, SETTING_TRUSTKEYSTORE_PASSWORD);

		String decKeystorePath = SettingsUtils.getRequiredProperty(config, SETTING_DECRYPTKEYSTORE_PATH, SETTING_SIGNINGKEYSTORE_PATH);
		KeyStore decKS = getDecryptionKeyStore(config);
		String defaultDecryptionAlias = getDefaultDecryptionAlias(config);
		char[] decKeyStorePassword = getDecryptionKeyStorePassword(config);
		
		try{
		  Enumeration<String> aliases = decKS.aliases();
		  while(aliases.hasMoreElements()){
			  String alias = aliases.nextElement();
			  Key key = decKS.getKey(alias, decKeyStorePassword);
			  Certificate[] certChain = decKS.getCertificateChain(alias);
			  if(key != null && key instanceof PrivateKey && certChain != null && certChain.length > 0){
				  X509Certificate[] x509CertChain =  (X509Certificate[]) Arrays.copyOf(certChain,certChain.length, X509Certificate[].class);
				  String keyId = XMLEncrypter.generateKeyId(x509CertChain[0].getPublicKey());
				  decryptionKeys.put(keyId, (PrivateKey) key);
				  decryptionCertificates.put(keyId, x509CertChain);
			  }
		  }
		  
		  Certificate defaultDecryptCert = decKS.getCertificate(defaultDecryptionAlias);
		  if(defaultDecryptCert != null){
			  defaultDecryptionKeyId = XMLEncrypter.generateKeyId(defaultDecryptCert.getPublicKey());
		  }
		
		}catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Error reading decryption keys and certificates from keystore: " + e.getMessage(),e);
		}
		
		
		if(decryptionKeys.size() == 0){
			throw new MessageProcessingException("Error no decryption keys found in decryption keystore: " + decKeystorePath);
		}
		
		if(decryptionKeys.get(defaultDecryptionKeyId) == null){
			throw new MessageProcessingException("Error no default decryption key with id (alias) :" + defaultDecryptionAlias + " found in decryption keystore: " + decKeystorePath);
		}
		
		signingAlgorithmScheme = (SigningAlgorithmScheme) findAlgorithm(SigningAlgorithmScheme.values(), config, SETTING_SIGNATURE_ALGORITHM_SCHEME, DEFAULT_SIGNATURE_ALGORITHM_SCHEME);
		encryptionAlgorithmScheme = (EncryptionAlgorithmScheme) findAlgorithm(EncryptionAlgorithmScheme.values(), config, SETTING_ENCRYPTION_ALGORITHM_SCHEME, DEFAULT_ENCRYPTION_ALGORITHM_SCHEME);

	}
	

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningKey()
	 */
	public PrivateKey getSigningKey() throws MessageProcessingException {
		return signPrivateKey;
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningCertificate()
	 */
	public X509Certificate getSigningCertificate() throws MessageProcessingException {
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
			MessageProcessingException {
		
		boolean[] keyUsage = signCertificate.getKeyUsage();
		if (keyUsage[0] == false) {
			return false;
		}
		
		Date currentTime = systemTime.getSystemTime();
		if(currentTime.after(signCertificate.getNotAfter())){
			log.error("Error processing Certificate Services message signing certificate expired: " + signCertificate.getNotAfter());
			return false;
		}
		if(currentTime.before(signCertificate.getNotBefore())){
			log.error("Error processing Certificate Services message signing certificate not yet valid: " + signCertificate.getNotBefore());
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
			throw new MessageProcessingException("Error reading certificates from truststore: " + e.getMessage());
		} catch (KeyStoreException e) {
			throw new MessageProcessingException("Error reading certificates from truststore: " + e.getMessage());
		}
		
		return foundMatching;
	}
	
	/**
	 * Checks that the two certificate is exactly the same.
	 * 
	 */
	protected boolean isTrusted(X509Certificate signCertificate, X509Certificate trustedCertificate) throws CertificateEncodingException{
		return Arrays.equals(signCertificate.getEncoded(), trustedCertificate.getEncoded());
	}
	

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getDecryptionKey(String)
	 */
	public PrivateKey getDecryptionKey(String keyId)
			throws MessageProcessingException {
		return decryptionKeys.get((keyId == null ? defaultDecryptionKeyId : keyId));
	}


	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getDecryptionCertificate(String)
	 */
	public X509Certificate getDecryptionCertificate(String keyId)
			throws MessageProcessingException {
		return decryptionCertificates.get((keyId == null ? defaultDecryptionKeyId : keyId))[0];
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getDecryptionCertificateChain(String)
	 */
	public X509Certificate[] getDecryptionCertificateChain(String keyId)
			throws MessageProcessingException {
		return decryptionCertificates.get((keyId == null ? defaultDecryptionKeyId : keyId));
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getDecryptionKeyIds()
	 */
	public Set<String> getDecryptionKeyIds() throws MessageProcessingException {
		return decryptionKeys.keySet();
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getEncryptionAlgorithmScheme()
	 */
	public EncryptionAlgorithmScheme getEncryptionAlgorithmScheme()
			throws MessageProcessingException {
		return encryptionAlgorithmScheme;
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningAlgorithmScheme()
	 */
	public SigningAlgorithmScheme getSigningAlgorithmScheme()
			throws MessageProcessingException {
		return signingAlgorithmScheme;
	}

	/**
	 * Method that that reads in the configured signing keystore.
	 * 
	 * @param config the provider configuration
	 * @return the specified keystore from configuration.
	 * @throws MessageProcessingException if configuration of security provider was faulty.
	 */
	protected KeyStore getSigningKeyStore(Properties config) throws MessageProcessingException {
		return getKeyStore(config, SETTING_SIGNINGKEYSTORE_PATH, SETTING_SIGNINGKEYSTORE_PASSWORD);
	}

	/**
	 * Method that that reads in the configured decryption keystore and if no specific decryption keystore
	 * is exists uses the singing keystore.
	 * 
	 * @param config the provider configuration
	 * @return the specified keystore from configuration.
	 * @throws MessageProcessingException if configuration of security provider was faulty.
	 */
	protected KeyStore getDecryptionKeyStore(Properties config) throws MessageProcessingException {
		String encryptPath = config.getProperty(SETTING_DECRYPTKEYSTORE_PATH);
		if(encryptPath == null || encryptPath.trim().equals("")){
			return getSigningKeyStore(config);
		}
		return getKeyStore(config, SETTING_DECRYPTKEYSTORE_PATH, SETTING_DECRYPTKEYSTORE_PASSWORD);
	}

	
	/**
	 * Method that that reads in the configured decryption keystore and if no specific decryption keystore
	 * is exists uses the singing keystore.
	 * 
	 * @param config the provider configuration
	 * @return the specified keystore from configuration.
	 * @throws MessageProcessingException if configuration of security provider was faulty.
	 */
	protected char[] getDecryptionKeyStorePassword(Properties config) throws MessageProcessingException {
		String encryptPath = config.getProperty(SETTING_DECRYPTKEYSTORE_PATH);
		if(encryptPath == null || encryptPath.trim().equals("")){
			return SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_PASSWORD).toCharArray();
		}
		return SettingsUtils.getRequiredProperty(config, SETTING_DECRYPTKEYSTORE_PASSWORD).toCharArray();
	}
	
	/**
	 * Help method that reads default key alias and failbacks on signature keystore alias.
	 */
	protected String getDefaultDecryptionAlias(Properties config) throws MessageProcessingException {
		return SettingsUtils.getRequiredProperty(config, SETTING_DECRYPTKEYSTORE_DEFAULTKEY_ALIAS, SETTING_SIGNINGKEYSTORE_ALIAS);
	}
	
	/**
	 * Help method reading a JKS keystore from configuration and specified settings.
	 */
	protected KeyStore getKeyStore(Properties config, String pathSetting, String passwordSetting) throws MessageProcessingException {
		String keyStorePath = SettingsUtils.getRequiredProperty(config, pathSetting);
		
		InputStream keyStoreInputStream = this.getClass().getClassLoader().getResourceAsStream(keyStorePath);
		if(keyStoreInputStream == null){
			File keyStoreFile = new File(keyStorePath);
			if(!keyStoreFile.canRead() || !keyStoreFile.exists() || !keyStoreFile.isFile()){
				throw new MessageProcessingException("Error reading keystore: " + keyStorePath + ", make sure it exists and is readable");
			}else{
				try {
					keyStoreInputStream = new FileInputStream(keyStoreFile);
				} catch (FileNotFoundException e) {
					throw new MessageProcessingException("Error keystore file: " + keyStoreFile + " not found.");
				}
			}
		}
		
		String keystorePassword = SettingsUtils.getRequiredProperty(config, passwordSetting);
		try{
		  KeyStore keyStore = KeyStore.getInstance("JKS");
		  keyStore.load(keyStoreInputStream, keystorePassword.toCharArray());
		  return keyStore;
		}catch(Exception e){
			throw new MessageProcessingException("Error reading keystore " + keyStorePath + ", make sure it is a JKS file and password is correct.");
		}
		
	}

	
	protected Object findAlgorithm(Enum<?>[] algorithms, Properties config, String setting, Object defaultValue) throws MessageProcessingException{
		String settingValue = config.getProperty(setting);
		if(settingValue == null || settingValue.trim().equals("")){
			return defaultValue;
		}
		
		settingValue = settingValue.trim();
		
		for(Enum<?> next : algorithms){
			if(next.name().equalsIgnoreCase(settingValue)){
				return next;
			}
		}
		
		throw new MessageProcessingException("Error finding supported cryptographic algorithm, check setting: " + setting + ", unsupported value is: " + settingValue);
	}



}
