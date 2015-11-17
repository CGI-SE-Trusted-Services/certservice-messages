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
package org.certificateservices.messages.utils;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.utils.Base64;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.SigningAlgorithmScheme;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Class containing help methods for digital XML signatures
 * 
 * @author Philip Vendil
 *
 */
public class XMLSigner {
	
	public static String XMLDSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";
	
	private static String ENVELOPE_TRANSFORM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
	
	private DocumentBuilder documentBuilder;
	private CertificateFactory cf;
	private String organisationElementLocalName;
	private String organisationElementNS;
	
	private String signedElementLocalName;
	private String signedElementNS;
	private String signedElementIDAttr;
	private Set<String> supportedDigestsAlgorithm;
	private Set<String> supportedSignatureAlgorithm;
	private MessageSecurityProvider messageSecurityProvider;
	private Transformer transformer;
	private boolean signMessages;
	
	public XMLSigner(MessageSecurityProvider messageSecurityProvider,
			DocumentBuilder documentBuilder, 
			boolean signMessages,
			String signedElementLocalName, 
			String signedElementNS, 
			String signedElementIDAttr,
			String organisationElementLocalName,
			String organisationElementNS) throws MessageProcessingException{
		this.messageSecurityProvider = messageSecurityProvider;
		this.organisationElementLocalName = organisationElementLocalName;
		this.organisationElementNS = organisationElementNS;
		this.documentBuilder = documentBuilder;
		this.signMessages = signMessages;
		
		this.signedElementLocalName = signedElementLocalName;
		this.signedElementNS = signedElementNS;
		this.signedElementIDAttr = signedElementIDAttr;
		
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new MessageProcessingException("Error instanciating CertificateFactory for XMLSigner: " + e.getMessage(),e);
		}
		
		supportedDigestsAlgorithm = new HashSet<String>();
		supportedSignatureAlgorithm = new HashSet<String>();
		for(SigningAlgorithmScheme scheme : SigningAlgorithmScheme.values()){
			supportedDigestsAlgorithm.add(scheme.getHashAlgorithmURI());
			supportedSignatureAlgorithm.add(scheme.getSignatureAlgorithmURI());
		}
		
		TransformerFactory tf = TransformerFactory.newInstance();
		try {
			transformer = tf.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new MessageProcessingException("Error instanciating Transformer for XMLSigner: " + e.getMessage(),e);
		}
		
	}
	
	
	/**
	 * Help method to verify a signed enveloped message and performs the following checks.
	 * 
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 * <p>
	 * This method does not perform and authorization call towards message security provider.
	 * 
	 * @param message the message to verify signature of.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occurred verifying the signature.
	 */
	public void verifyEnvelopedSignature(byte[] message) throws MessageContentException, MessageProcessingException{
		  verifyEnvelopedSignature(message, false);
	}
	
	/**
	 * Help method to verify a signed enveloped message and performs the following checks.
	 * 
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 * 
	 * @param message the message to verify signature of.
	 * @param authorizeAgainstOrganisation true if the message security provider should perform
	 * any authorization to the related organisation, that must exist in the message of true.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	public void verifyEnvelopedSignature(byte[] message, boolean authorizeAgainstOrganisation) throws MessageContentException, MessageProcessingException{
		Document doc;
		try{
			doc = documentBuilder.parse(new ByteArrayInputStream(message));		
		}catch(Exception e){
			throw new MessageContentException("Error validating signature of message: " + e.getMessage(),e);
		}
		verifyEnvelopedSignature(doc, authorizeAgainstOrganisation);
	}
	
	/**
	 * Help method to verify a signed enveloped message and performs the following checks.
	 * 
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 * 
	 * @param message the message to verify signature of.
	 * @param authorizeAgainstOrganisation true if the message security provider should perform
	 * any authorization to the related organisation, that must exist in the message of true.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	public void verifyEnvelopedSignature(Document doc, boolean authorizeAgainstOrganisation) throws MessageContentException, MessageProcessingException{
		
		try{
			NodeList signedObjects = doc.getElementsByTagNameNS(signedElementNS, signedElementLocalName);
			if(signedObjects.getLength() == 0){
				throw new MessageContentException("Error verifying signature, no Element "+ signedElementLocalName + " found in message.");
			}
			if(signedObjects.getLength() > 1){
				throw new MessageContentException("Error verifying signature, Only one signed Element "+ signedElementLocalName + " is each message is supported.");
			}
			Element signedElement = (Element) signedObjects.item(0);
			Element signature = findSignatureElementInObject(signedElement);
			
			checkValidSignatureURI(signature);
			checkValidDigestURI(signature);
			checkValidTransform(signature);
			checkValidReferenceURI(signedElement, signature);
			

			X509Certificate signerCert = null;
			NodeList certList = signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "X509Certificate");
			if(certList.getLength() > 0){
				String certData = certList.item(0).getFirstChild().getNodeValue();
				if(certData != null){
					signerCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certData)));
				}
			}

		
			if(signerCert == null){
				throw new MessageContentException("Invalid signature, no related certificate found.");
			}


			DOMValidateContext validationContext = new DOMValidateContext(signerCert.getPublicKey(), signature);
			validationContext.setIdAttributeNS(signedElement, null, signedElementIDAttr);
			XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
			XMLSignature sig =  signatureFactory.unmarshalXMLSignature(validationContext);
			if(!sig.validate(validationContext)){
				throw new MessageContentException("Error, signed message didn't pass validation.");
			}

			if(authorizeAgainstOrganisation){
				if(!messageSecurityProvider.isValidAndAuthorized(signerCert, findOrganisation(doc))){
					throw new MessageContentException("A certificate with DN " + signerCert.getSubjectDN().toString() + " signing a message wasn't authorized or valid.");
				}
			}
			
		}catch(Exception e){
			if(e instanceof MessageContentException ){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageContentException("Error validating signature of message: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to find first certificate found in signature element.
	 * @param message the message to extract certificate of.
	 * @return the certificate in signature.
	 * 
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occurred parsing the certificate.
	 */
	public X509Certificate findSignerCertificate(byte[] message)  throws MessageContentException, MessageProcessingException{
		try{
			Document doc = documentBuilder.parse(new ByteArrayInputStream(message));
			
			NodeList signedObjects = doc.getElementsByTagNameNS(signedElementNS, signedElementLocalName);
			if(signedObjects.getLength() == 0){
				throw new MessageContentException("Error verifying signature, no Element "+ signedElementLocalName + " found in message.");
			}
			if(signedObjects.getLength() > 1){
				throw new MessageContentException("Error verifying signature, Only one signed Element "+ signedElementLocalName + " is each message is supported.");
			}
			Element signedElement = (Element) signedObjects.item(0);
			Element signature = findSignatureElementInObject(signedElement);

			X509Certificate signerCert = null;
			NodeList certList = signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "X509Certificate");
			if(certList.getLength() > 0){
				String certData = certList.item(0).getFirstChild().getNodeValue();
				if(certData != null){
					signerCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certData)));
				}
			}
		
			if(signerCert == null){
				throw new MessageContentException("Invalid signature, no related certificate found.");
			}
			
			return signerCert;
			
		}catch(Exception e){
			if(e instanceof MessageContentException ){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageContentException("Error  parsing the certificate from siganture in message: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Help method to marshall and sign an Assertion, either standalone or inside a SAMLP Response
	 * 
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param message a Assertion or Response (SAMLP) structure.
	 * @return a marshalled and signed message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
	 */
	public byte[] marshallAndSignAssertion(Document doc, String messageID,  SignatureLocationFinder signatureLocationFinder, String afterSiblingLocalName, String afterSiblingNS) throws MessageProcessingException, MessageContentException{


		try {
			
			if(signMessages){
				XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
				DigestMethod digestMethod = fac.newDigestMethod 
						(messageSecurityProvider.getSigningAlgorithmScheme().getHashAlgorithmURI(), null);

				List<Transform> transFormList = new ArrayList<Transform>();
				transFormList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));				
				Reference ref = fac.newReference("#" + messageID,digestMethod, transFormList, null, null);

				ArrayList<Reference> refList = new ArrayList<Reference>();
				refList.add(ref);
				CanonicalizationMethod cm =  fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,(C14NMethodParameterSpec) null);
				SignatureMethod sm = fac.newSignatureMethod(messageSecurityProvider.getSigningAlgorithmScheme().getSignatureAlgorithmURI(),null);
				SignedInfo signedInfo =fac.newSignedInfo(cm,sm,refList);
				DOMSignContext signContext = null;


				Element signatureLocation = signatureLocationFinder.getSignatureLocation(doc);
				if(afterSiblingLocalName != null){
					Node issuerNode = doc.getElementsByTagNameNS(afterSiblingNS, afterSiblingLocalName).item(0);
					signContext = new DOMSignContext(messageSecurityProvider.getSigningKey(),signatureLocation,issuerNode.getNextSibling());
				}else{
					signContext = new DOMSignContext(messageSecurityProvider.getSigningKey(),signatureLocation);	
				}
				signContext.setIdAttributeNS(signatureLocation, null, signedElementIDAttr);
				signContext.putNamespacePrefix("http://www.w3.org/2000/09/xmldsig#", "ds");

				KeyInfoFactory kif = KeyInfoFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
				List<X509Certificate> certs = new ArrayList<X509Certificate>();
				X509Certificate cert = messageSecurityProvider.getSigningCertificate();
				certs.add(cert);
				X509Data x509Data = kif.newX509Data(certs);
				KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509Data)); 

				XMLSignature signature = fac.newXMLSignature(signedInfo,ki);
				signature.sign(signContext);
			}

			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			String output = writer.getBuffer().toString();	
			return output.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new MessageProcessingException("Error marshalling Assertion, " + e.getMessage(),e);
		} catch (TransformerException e) {
			throw new MessageProcessingException("Error marshalling Assertion, " + e.getMessage(),e);
		} catch (NoSuchAlgorithmException e) {
			throw new MessageProcessingException("Error signing the Assertion, " + e.getMessage(),e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new MessageProcessingException("Error signing the Assertion, " + e.getMessage(),e);
		} catch (MarshalException e) {
			throw new MessageProcessingException("Error signing the Assertion, " + e.getMessage(),e);
		} catch (XMLSignatureException e) {
			throw new MessageProcessingException("Error signing the Assertion, " + e.getMessage(),e);
		}
	}
	
	/**
	 * Help method to find ds:Signature element among direct childs to this element.
	 */
	private Element findSignatureElementInObject(Element signedElement) throws MessageContentException{
		NodeList childs = signedElement.getChildNodes();
		for(int i = 0; i < childs.getLength(); i++){
			Element next = (Element) childs.item(i);
			if(next.getLocalName().equals("Signature") && next.getNamespaceURI().equals(XMLDSIG_NAMESPACE)){
				return next;
			}
		}
		
		throw new MessageContentException("Required digital signature not found in message.");
	}
	
	private String findOrganisation(Document doc) throws MessageContentException{
		NodeList organsiationElements = doc.getElementsByTagNameNS(organisationElementNS, organisationElementLocalName);
		if(organsiationElements.getLength() == 0){
			throw new MessageContentException("Error verifying signature, no element "+ organisationElementLocalName + " found in message.");
		}
		if(organsiationElements.getLength() > 1){
			throw new MessageContentException("Error verifying signature, Only one organisation element "+ organisationElementLocalName + " is each message is supported.");
		}
		try{
			Element orgElement = (Element) organsiationElements.item(0);
			return orgElement.getFirstChild().getNodeValue();
		}catch(Exception e){
			throw new MessageContentException("Error extracting organisation element " + organisationElementLocalName + " from message: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method that checks the referenced URI actually is the same as ID of the enveloped signed object otherwise MessageContentException
	 */
	private void checkValidReferenceURI(Element signedElement, Element signature) throws MessageContentException{
		try{
			String objectID = signedElement.getAttribute(signedElementIDAttr);
			Element transform = (Element) signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "Reference").item(0);
			String referenceID = transform.getAttribute("URI");
			if(!referenceID.equals("#" + objectID)){
				throw new MessageContentException("Error checking reference URI of digital signature it doesn't match the id of the signed element.");
			}
		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			throw new MessageContentException("Error checking Reference URI with the signed object: " + e.getMessage(),e);
		}
	}

	/**
	 * Method that check that the transform is set to enveloped otherwise MessageContentException
	 */
	private void checkValidTransform(Element signature) throws MessageContentException {
		try{
			Element transform = (Element) signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "Transform").item(0);
			String algorithm = transform.getAttribute("Algorithm");
			if(!algorithm.equals(ENVELOPE_TRANSFORM)){
				throw new MessageContentException("Error unsupported transform in digital sigature: " + algorithm + " only enveloped signatures are supported.");
			}
		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			throw new MessageContentException("Error extracting transform from digital sigature: " + e.getMessage(),e);
		}
	}

	/**
	 * Method that checks supported digestURI from available SigningAlgorithmScheme otherwise MessageContentException
	 */
	private void checkValidDigestURI(Element signature) throws MessageContentException{
		try{
			Element transform = (Element) signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "DigestMethod").item(0);
			String algorithm = transform.getAttribute("Algorithm");
			
			if(!supportedDigestsAlgorithm.contains(algorithm)){
				throw new MessageContentException("Error unsupported digest algorithm in digital sigature: " + algorithm + ".");
			}
		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			throw new MessageContentException("Error extracting digest algorithm from digital sigature: " + e.getMessage(),e);
		}
	}

	/**
	 * Method that checks supported signature algorithm from available SigningAlgorithmScheme otherwise MessageContentException
	 */
	private void checkValidSignatureURI(Element signature) throws MessageContentException{
		try{
			Element transform = (Element) signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "SignatureMethod").item(0);
			String algorithm = transform.getAttribute("Algorithm");
			
			if(!supportedSignatureAlgorithm.contains(algorithm)){
				throw new MessageContentException("Error unsupported digest algorithm in digital sigature: " + algorithm + ".");
			}
		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			throw new MessageContentException("Error extracting digest algorithm from digital sigature: " + e.getMessage(),e);
		}
		
	}
	
	/**
	 * Interface used to find the location and ID of a signed object.
	 * 
	 * @author Philip Vendil
	 *
	 */
	public interface SignatureLocationFinder{
		
		/**
		 * Return the element inside a document that should be signed.
		 */
		Element getSignatureLocation(Document doc) throws MessageProcessingException;
		
	}
	
}
