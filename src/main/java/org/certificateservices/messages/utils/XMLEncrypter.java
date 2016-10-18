/**
 * 
 */
package org.certificateservices.messages.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.InvalidPropertiesFormatException;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyName;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.EncryptionConstants;
import org.certificateservices.messages.EncryptionAlgorithmScheme;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.NoDecryptionKeyFoundException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Helper methods to perform XML Encryption and Decryption tasks on JAXB Elements.
 * 
 * @author Philip Vendil
 *
 */
public class XMLEncrypter {
	
	private static String XMLDSIG_NAMESPACE = XMLSigner.XMLDSIG_NAMESPACE;
	
	private MessageSecurityProvider securityProvider;
	private DocumentBuilder documentBuilder;
	private Marshaller marshaller;
	private Unmarshaller unmarshaller;
	
	private XMLCipher encKeyXMLCipher;
	private XMLCipher encDataXMLCipher;
	private XMLCipher decChiper;
	
	private CertificateFactory cf;
	private KeyGenerator dataKeyGenerator;
	
	private Set<String> supportedEncryptionChipers = new HashSet<String>();
	
	/**
	 * Contructor of a xml XML Encrypter
	 * @param securityProvider the used message security provider
	 * @param documentBuilder the DOM Document Builder used for related messages.
	 * @param marshaller the JAXB Marshaller used for related messages.
	 * @param unmarshaller the JAXB Unmarshaller used for related messages.
	 * @throws MessageProcessingException if problems occurred initializing this helper class.
	 */
	public XMLEncrypter(MessageSecurityProvider securityProvider, 
			            DocumentBuilder documentBuilder, 
			            Marshaller marshaller,
			            Unmarshaller unmarshaller) throws MessageProcessingException{
		this.securityProvider = securityProvider;
		this.documentBuilder = documentBuilder;
		this.marshaller = marshaller;
		this.unmarshaller = unmarshaller;
		
		try {
			this.encKeyXMLCipher = XMLCipher.getInstance(securityProvider.getEncryptionAlgorithmScheme().getKeyEncryptionAlgorithmURI());
			this.encDataXMLCipher = XMLCipher.getInstance(securityProvider.getEncryptionAlgorithmScheme().getDataEncryptionAlgorithmURI());
			this.decChiper = XMLCipher.getInstance();

			cf = CertificateFactory.getInstance("X.509");
			
			switch(securityProvider.getEncryptionAlgorithmScheme()){
			case RSA_OAEP_WITH_AES256:
			case RSA_PKCS1_5_WITH_AES256:
				dataKeyGenerator = KeyGenerator.getInstance("AES");
				dataKeyGenerator.init(256);
				break;
				default:
					throw new MessageProcessingException("Unsupported Encryption scheme " + securityProvider.getEncryptionAlgorithmScheme());
			}
			
			for(EncryptionAlgorithmScheme scheme : EncryptionAlgorithmScheme.values()){
				supportedEncryptionChipers.add(scheme.getDataEncryptionAlgorithmURI());
				supportedEncryptionChipers.add(scheme.getKeyEncryptionAlgorithmURI());
			}
			
		} catch (Exception e) {
			throw new MessageProcessingException("Error instanciating XML chipers: " + e.getMessage(),e);
		}

	}
	
	/**
	 * Method to create a encrypted DOM structure containing a EncryptedData element of the related JAXB Element.
	 * 
	 * @param element the JAXB element to decrypt.
	 * @param receipients a list of reciepiets of the message.
	 * @param useKeyId if in key info should be included the shorter KeyName tag instead of X509Certificate
	 * @return a new DOM Document the encrypted data.
	 * @throws MessageProcessingException if internal problems occurred generating the data.
	 */
	public  Document encryptElement(JAXBElement<?> element, List<X509Certificate> receipients, boolean useKeyId) throws MessageProcessingException{
		try{
			Document doc = documentBuilder.newDocument();

			marshaller.marshal(element, doc);

			return encryptElement(doc, receipients, useKeyId);

		}catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when encrypting XML: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to create a encrypted DOM structure containing a EncryptedData element of the related JAXB Element.
	 * 
	 * @param doc the document to encrypt.
	 * @param receipients a list of reciepiets of the message.
	 * @param useKeyId if in key info should be included the shorter KeyName tag instead of X509Certificate
	 * @return a new DOM Document the encrypted data.
	 * @throws MessageProcessingException if internal problems occurred generating the data.
	 */
	public  Document encryptElement(Document doc, List<X509Certificate> receipients, boolean useKeyId) throws MessageProcessingException{
		try{
			
			Key dataKey = dataKeyGenerator.generateKey();

			encDataXMLCipher.init(XMLCipher.ENCRYPT_MODE, dataKey);
			EncryptedData encData = encDataXMLCipher.getEncryptedData();
			KeyInfo keyInfo = new KeyInfo(doc);
			for(X509Certificate receipient: receipients){
				keyInfo.add(addReceipient(doc, dataKey, receipient, useKeyId));
			}
			encData.setKeyInfo(keyInfo);
			Element documentElement = doc.getDocumentElement();
			doc = encDataXMLCipher.doFinal(doc, documentElement, false);
			return doc;

		}catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when encrypting XML: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to decrypt all encrypted structures in the related message.
	 * 
	 * <b>Important: If multiple EncryptedData exists it must be encrypted with the same data key and receipients.</b>
	 * @param doc the document containing encrypted data.
	 * @return a JAXB version of the document where all encrypted attributes are decrypted.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of message was invalid
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found with the message.
	 */
	public Object decryptDocument(Document doc) throws MessageProcessingException, MessageContentException, NoDecryptionKeyFoundException{
		return decryptDocument(doc, null);
	}
	
	/**
	 * Method to decrypt all encrypted structures in the related message.
	 * 
	 * <b>Important: If multiple EncryptedData exists it must be encrypted with the same data key and receipients.</b>
	 * @param doc the document containing encrypted data.
	 * @param converter the post decryption xml converter to manipulate the result to fullfill schema, null to disable manipulation.
	 * @return a JAXB version of the document where all encrypted attributes are decrypted.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of message was invalid
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found with the message.
	 */
	public Object decryptDocument(Document doc, DecryptedXMLConverter converter) throws MessageProcessingException, MessageContentException, NoDecryptionKeyFoundException{
		try{			
			return unmarshaller.unmarshal(decryptDoc(doc,converter));
		}catch(Exception e){
			if(e instanceof NoDecryptionKeyFoundException){
				throw (NoDecryptionKeyFoundException) e;
			}
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when decrypting XML: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to decrypt all encrypted structures in the related message.
	 * 
	 * <b>Important: If multiple EncryptedData exists it must be encrypted with the same data key and receipients.</b>
	 * @param doc the document containing encrypted data.
	 * @param converter the post decryption xml converter to manipulate the result to fullfill schema, null to disable manipulation.
	 * @return a new Document with decrypted content.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of message was invalid
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found with the message.
	 */
	public Document decryptDoc(Document doc, DecryptedXMLConverter converter) throws MessageProcessingException, MessageContentException, NoDecryptionKeyFoundException{
		try{
			NodeList nodeList = doc.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA);
			while(nodeList.getLength() > 0){
				Element encryptedElement = (Element) nodeList.item(0);
				verifyCiphers(encryptedElement);
				decChiper.init(XMLCipher.DECRYPT_MODE,null);
				decChiper.setKEK(findKEK(encryptedElement));
				doc = decChiper.doFinal(doc, encryptedElement);
				nodeList = doc.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA);
			}

			if(converter != null){
				doc = converter.convert(doc);
			}
			
			return doc;
		}catch(Exception e){
			if(e instanceof NoDecryptionKeyFoundException){
				throw (NoDecryptionKeyFoundException) e;
			}
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when decrypting XML: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to encrypt java.util.Properties in XML-format
	 * @param properties properties to encrypt
	 * @param receipients a list of recipients of the properties.
	 * @param useKeyId if in key info should be included the shorter KeyName tag instead of X509Certificate
	 * @return a new DOM Document with the encrypted properties.
	 * @throws MessageProcessingException if internal problems occurred encrypting the message.
	 */
	public Document encryptProperties(Properties properties, List<X509Certificate> receipients, boolean useKeyId) throws MessageProcessingException {
		Document encDocument = null, document = null;
		try {
			ByteArrayOutputStream os = new ByteArrayOutputStream();		
			properties.storeToXML(os, null, "UTF-8");			
			InputStream is = new ByteArrayInputStream(os.toByteArray());
			document = documentBuilder.parse(is);
			encDocument = encryptElement(document, receipients, useKeyId);
		} catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when encrypting properties: " + e.getMessage(), e);
		}

		return encDocument;
	}
	
	/**
	 * Method to decrypt document containing properties in XML-format.
	 * @param encDocument the document containing encrypted data.
	 * @return decrypted properties
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of document was invalid
	 */
	public Properties decryptProperties(Document encDocument) throws NoDecryptionKeyFoundException, MessageProcessingException, MessageContentException {
		Properties properties = null;
		
		try {
			Document document = decryptDoc(encDocument, null);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();		
			Source src = new DOMSource(document);
			Result res = new StreamResult(baos);
			Transformer trf = TransformerFactory.newInstance().newTransformer();
			trf.setOutputProperty(OutputKeys.DOCTYPE_SYSTEM, "http://java.sun.com/dtd/properties.dtd");
			trf.transform(src, res);
			InputStream is = new ByteArrayInputStream(baos.toByteArray());
			properties = new Properties();
			properties.loadFromXML(is);
		} catch(Exception e){
			if(e instanceof NoDecryptionKeyFoundException){
				throw (NoDecryptionKeyFoundException) e;
			}
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when decrypting properties: " + e.getMessage(), e);
		}
		
		return properties;
	}
	
	/**
	 * Method to verify that data was encrypted with supported chiphers only.
	 * @param encryptedElement the encrypted element to verify.
	 * @throws MessageContentException if unsupported ciphers was used.
	 */
	private void verifyCiphers(Element encryptedElement) throws MessageContentException{
		NodeList nodeList = encryptedElement.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTIONMETHOD);
		for(int i=0; i<nodeList.getLength();i++){
			Element encryptionMetod = (Element) nodeList.item(0);
			String alg = encryptionMetod.getAttribute(EncryptionConstants._ATT_ALGORITHM);
			if(!supportedEncryptionChipers.contains(alg)){
		       throw new MessageContentException("Error unsupported encryption algorithm " + alg + " for encrypted XML data");		
			}
		}
		
	}
	
	/**
	 * Help method that looks through all key info and tries to find all Key Info elements of type KeyName or X509Certificate
	 * that is used to check if message security provider has relevant decryption key.
	 * 
	 * @param encryptedElement the encrypted element to extract key info from
	 * @return a related Private Key used to decrypt the data key with.
	 * @throws MessageContentException if no valid decryption key could be found in the key info.
	 */
	private Key findKEK(Element encryptedElement) throws NoDecryptionKeyFoundException {
		try{
			Set<String> availableKeyIds = securityProvider.getDecryptionKeyIds();
			
			NodeList keyNameList = encryptedElement.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "KeyName");
			for(int i=0; i<keyNameList.getLength();i++){
				Node keyName = keyNameList.item(i);
				String keyId = keyName.getFirstChild().getNodeValue();
				if(keyId != null){
					keyId = keyId.trim();
					if(availableKeyIds.contains(keyId)){
						return securityProvider.getDecryptionKey(keyId);
					}
				}			
			}

			NodeList certList = encryptedElement.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "X509Certificate");
			for(int i=0; i<certList.getLength();i++){
				Node certNode = certList.item(i);
				String certData = certNode.getFirstChild().getNodeValue();
				if(certData != null){
					X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certData)));
					String keyId = generateKeyId(cert.getPublicKey());
					if(availableKeyIds.contains(keyId)){
						return securityProvider.getDecryptionKey(keyId);
					}			
				}
			}

		}catch(Exception e){
			throw new NoDecryptionKeyFoundException("Error finding encryption public key in XML message: " + e.getMessage(), e);
		}

		throw new NoDecryptionKeyFoundException("Error couldn't find any matching decryption key to decrypt XML message");

	}


	private static MessageDigest generateKeyDigest;
	/**
	 * Help method to generate a key id from a public key by calculating its SHA-256 Hash value and Base64 encoding it.
	 */
	public static String generateKeyId(PublicKey publicKey) throws MessageProcessingException{
		try{
			if(generateKeyDigest == null){
				generateKeyDigest = MessageDigest.getInstance("SHA-256");
			}
			generateKeyDigest.update(publicKey.getEncoded());
			return new String(Base64.encode(generateKeyDigest.digest()));
		}catch(Exception e){
			throw new MessageProcessingException(e.getMessage(),e);
		}
	}
	
	/**
	 * Help method to add a receipient to a message.
	 */
	private EncryptedKey addReceipient(Document doc, Key dataKey, X509Certificate receipient, boolean useKeyId) throws XMLEncryptionException, CertificateEncodingException, MessageProcessingException{
		encKeyXMLCipher.init(XMLCipher.WRAP_MODE,receipient.getPublicKey());
		KeyInfo keyInfo = new KeyInfo(doc);
		EncryptedKey retval = encKeyXMLCipher.encryptKey(doc, dataKey);
		if(useKeyId){
			KeyName keyName = new KeyName(doc, generateKeyId(receipient.getPublicKey()));
			keyInfo.add(keyName);
		}else{
			X509Data x509Data = new X509Data(doc);
		    x509Data.addCertificate(receipient.getEncoded());
		    keyInfo.add(x509Data);
		}
		retval.setKeyInfo(keyInfo);
		return retval;
	}
	
	/**
	 * Interface to do post decryption manipulation to the DOM to have the decrypted document to fullfill it schema.
	 * 
	 * @author Philip Vendil
	 */
	public interface DecryptedXMLConverter{
		
		/**
		 * Method to manipulate a encrypted document structure.
		 * @param doc the decrypted document
		 * @return a converted document that satisfies schema.
		 * @throws MessageContentException if decrypted document contain faulty schema.
		 */
		Document convert(Document doc) throws MessageContentException;
	}
	

}
