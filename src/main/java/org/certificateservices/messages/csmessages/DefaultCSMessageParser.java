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
package org.certificateservices.messages.csmessages;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.JAXBIntrospector;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.util.JAXBSource;
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
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.csmessages.PayloadParserRegistry.ConfigurationCallback;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.jaxb.Originator;
import org.certificateservices.messages.csmessages.jaxb.Payload;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.utils.SettingsUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * 
 * 
 * 
 * @author Philip Vendil
 *
 */
public class DefaultCSMessageParser implements CSMessageParser {

	public static final String SETTING_SOURCEID = "csmessage.sourceid";
	public static final String OLD_SETTING_SOURCEID = "pkimessage.sourceid";
	
	public static final String SETTING_SIGN = "csmessage.sign";
	public static final String OLD_SETTING_SIGN = "pkimessage.sign";
	
	public static final String SETTING_REQUIRESIGNATURE = "csmessage.requiresignature";
	public static final String OLD_SETTING_REQUIRESIGNATURE = "pkimessage.requiresignature";
	
	public static final String SETTING_MESSAGE_NAME_CATALOGUE_IMPL = "pkimessage.messagenamecatalogue.impl";
	public static final String OLD_SETTING_MESSAGE_NAME_CATALOGUE_IMPL = "pkimessage.messagenamecatalogue.impl";
	public static final String DEFAULT_MESSAGE_NAME_CATALOGUE_IMPL = DefaultMessageNameCatalogue.class.getName();

	private static final String CSMESSAGE_VERSION_2_0 = "2.0";
	
	private static final String CSMESSAGE_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/csmessages_schema2_0.xsd";
	
	private static final String CSMESSAGE_XSD_SCHEMA_2_0_URI = "http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd";	
	
	private static final Map<String,String> csMessageSchemaMap = new HashMap<String,String>();
	static{
		csMessageSchemaMap.put(CSMESSAGE_VERSION_2_0, CSMESSAGE_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
	}
	
	private static final Map<String,String> csMessageSchemaUriMap = new HashMap<String,String>();
	static{
		csMessageSchemaUriMap.put(CSMESSAGE_VERSION_2_0, CSMESSAGE_XSD_SCHEMA_2_0_URI);
	}
	
	private static final String XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION = "/xmldsig-core-schema.xsd";
	

	private static final String[] SUPPORTED_CSMESSAGE_VERSIONS = {"2.0"};
	


	
	private ObjectFactory objectFactory = new ObjectFactory();
	
	private Properties properties = null;
	private MessageSecurityProvider securityProvider = null;
	private MessageNameCatalogue messageNameCatalogue = null;
	private JAXBRelatedData jaxbData = new JAXBRelatedData();
	
	private String sourceId = null;
	
	private String defaultVersion = CSMESSAGE_VERSION_2_0;
	
	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#init(org.certificateservices.messages.MessageSecurityProvider, java.util.Properties)
	 */
	@Override
	public void init(MessageSecurityProvider securityProvider, Properties config)
			throws MessageProcessingException {
		this.properties = config;
		this.securityProvider = securityProvider;
		this.messageNameCatalogue = getMessageNameCatalogue(config);
		
		// Register
		
		PayloadParserRegistry.configure(new ConfigurationCallback() {
			
			@Override
			public void updateContext() throws MessageProcessingException {
				jaxbData.clearAllJAXBData();
			}
			
			/**
			 * There is never any need for reinitialization since auto reloading of current version
			 * of CSMessageParser isn't supported.
			 */
			@Override
			public boolean needReinitialization(String namespace)
					throws MessageProcessingException {
				return false;
			}
			
			/**
			 * Initialize the pay load parser with same configuration.
			 */
			@Override
			public void configurePayloadParser(String namespace,
					PayloadParser payloadParser) throws MessageProcessingException {
				payloadParser.init(properties);
				
			}
		}, true);
		
		
		// Initialize all PayloadParsers
		try {
			jaxbData.getJAXBContext();
		} catch (JAXBException e) {
			throw new MessageProcessingException("Error occurred initializing JAXBContext: " + e.getMessage(),e);
		}

        // Initialize all marshallers for all supported version.
		for(String version : SUPPORTED_CSMESSAGE_VERSIONS){
			try{
				jaxbData.getCSMessageMarshaller(version);
				jaxbData.getCSMessageUnmarshaller(version);
			}catch(MessageContentException e){
				throw new MessageProcessingException("Unsupported CS Message version: " + version + " detected");
			}
		}

		sourceId = SettingsUtils.getProperty(config, SETTING_SOURCEID, OLD_SETTING_SOURCEID);
		if(sourceId == null || sourceId.trim().equals("")){
			throw new MessageProcessingException("Error setting " + SETTING_SOURCEID + " must be set.");
		}
	}

	@Override
	public byte[] genMessage(String messageId, Object payLoad) throws MessageContentException, MessageProcessingException {

		CSMessage message = genCSMessage(defaultVersion, messageId, "somedest", "someorg", null, payLoad);		
		return marshallAndSignCSMessage( message);
	}
	
	
	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#parseMessage(byte[])
	 */
	
	public synchronized CSMessage parseMessage(byte[] messageData)
			throws MessageContentException, MessageProcessingException {
		try{
			
			CSMessageVersion version = getVersionFromMessage(messageData);
			verifyCSMessageVersion(version.getMessageVersion());
		
			Object object = jaxbData.getCSMessageUnmarshaller(version.getMessageVersion()).unmarshal(new ByteArrayInputStream(messageData));
			validateCSMessage(version, object, new String(messageData,"UTF-8"));
			return (CSMessage) object;
		}catch(JAXBException e){
			throw new MessageContentException("Error parsing PKI Message: " + e.getMessage(),e);
		} catch (UnsupportedEncodingException e) {
			throw new MessageContentException("Error parsing PKI Message: " + e.getMessage(),e);
		}
		
	}
	
	// Unmarshall
	
	
	/**
	 * Verifies that the given version is supported.
	 * @param version the version to check.
	 * @throws MessageContentException if version is unsupported.
	 */
	private void verifyCSMessageVersion(String version) throws MessageContentException{
		boolean foundVersion = false;
		for(String supportedVersion : SUPPORTED_CSMESSAGE_VERSIONS){
			if(supportedVersion.equals(version)){
				foundVersion=true;
				break;
			}
		}
		if(!foundVersion){
			throw new MessageContentException("Error unsupported protocol version " + version);
		}
	}
	
	/**
	 * Method that validates the fields of the message that isn't already validated by the schema
	 * and the digital signature of the message.
	 * 
	 * @param object the message to validate.
	 * @param message string representation of the message data.
	 * @throws MessageContentException if the message contained bad format.
	 * @throws MessageProcessingException if internal problems occurred validating the message.
	 */
	private void validateCSMessage(CSMessageVersion version, Object object, String message) throws MessageContentException, MessageProcessingException {
		
		if(!(object instanceof CSMessage)){
			throw new MessageContentException("Error: parsed object not a CS Message.");
		}
		CSMessage csMessage = (CSMessage) object;
		validateCSMessageHeader(csMessage, message);
		
		validatePayload(version, csMessage);
	}
	
	/**
	 * Method that validates the "header" parts of the cs message.
	 * 
	 * @param csMessage the cs message to validate, never null
	 * @param message string representation of the message data.
	 * @throws MessageContentException if the header contained illegal arguments.
	 */
	private void validateCSMessageHeader(CSMessage pkiMessage, String message) throws MessageContentException, MessageProcessingException{
		
		
		validateSignature(message);
		
		
	}

	private void validatePayload(CSMessageVersion version, CSMessage pkiMessage) throws MessageProcessingException, MessageContentException {

		Object payLoadObject = pkiMessage.getPayload().getAny();
		String payLoadNamespace = jaxbData.getNamespace(payLoadObject);
		Validator validator = jaxbData.getPayLoadValidatorFromCache(payLoadNamespace, version.getPayLoadVersion());
		try {
			validator.validate(new JAXBSource(jaxbData.getJAXBContext(), payLoadObject));
		} catch (Exception e) {
			// tODO HERE
		}
		
		
	}

	private void validateSignature(String message) throws MessageContentException, MessageProcessingException {
		if(requireSignature()){
			try{
				DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
				factory.setNamespaceAware(true);
				DocumentBuilder builder = factory.newDocumentBuilder();
				Document doc = builder.parse(new InputSource(new StringReader(message)));

				Node signature = doc.getElementsByTagName("ds:Signature").item(0);

				if(signature == null){
					throw new MessageContentException("Required digital signature not found in message.");
				}

				DOMValidateContext validationContext = new DOMValidateContext(new X509DataOnlyKeySelector(securityProvider), signature);
				validationContext.setIdAttributeNS(doc.getDocumentElement(), null, "ID");
				XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
				XMLSignature sig =  signatureFactory.unmarshalXMLSignature(validationContext);
				if(!sig.validate(validationContext)){
					throw new MessageContentException("Error, signed message didn't pass validation.");
				}
				//sig.getKeyInfo().getContent().g
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
	}
	

	private DocumentBuilder documentBuilder = null;
	private DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
		if(documentBuilder == null){
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);

			documentBuilder = dbf.newDocumentBuilder();
		}

		return documentBuilder;
	}
	
	/**
	 * Method that generates a configured message name catalogue or uses the default
	 * one if not configured
	 * @param config the configuration.
	 * @return a newly generated MessageNameCatalogue
	 * @throws MessageProcessingException if problems occurred generating a MessageNameCatalogue
	 */
    private MessageNameCatalogue getMessageNameCatalogue(Properties config) throws MessageProcessingException{
    	try{
    		MessageNameCatalogue retval =  (MessageNameCatalogue) this.getClass().getClassLoader().loadClass(config.getProperty(SETTING_MESSAGE_NAME_CATALOGUE_IMPL, DEFAULT_MESSAGE_NAME_CATALOGUE_IMPL)).newInstance();
    		retval.init(config);
    		return retval;
    	}catch(Exception e){
    		throw new MessageProcessingException("Error creating creating name catalogue " + e.getClass().getName() + ": " + e.getMessage());
    	}
    }
	
    /**
     * Method that tries to parse the xml version from a message
     * @param messageData the messageData to extract version from.
     * @return the version in the version and payLoadVersion attributes of the message.
     * @throws MessageContentException didn't contains a valid version attribute.
     * @throws MessageProcessingException if internal problems occurred.
     */
    private CSMessageVersion getVersionFromMessage(byte[] messageData) throws MessageContentException, MessageProcessingException{
    	String messageVersion = null;
    	String payLoadVersion = null;
    	try{
    		Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(messageData));
    		
    		Node csMessage = doc.getFirstChild();
    		if(csMessage != null){
    			Node versionNode = csMessage.getAttributes().getNamedItem("version");
    			if(versionNode != null){
    				messageVersion = versionNode.getNodeValue();
    			}
    			Node payLoadVersionNode = csMessage.getAttributes().getNamedItem("payLoadVersion");
    			if(payLoadVersionNode != null){
    				payLoadVersion = payLoadVersionNode.getNodeValue();
    			}
    		}    		

    	}catch(Exception e){
    		throw new MessageContentException("Error parsing XML data: " + e.getMessage(),e);
    	}

    	if(messageVersion == null || messageVersion.trim().equals("")){
    	  throw new MessageContentException("Error no version attribute found in PKI Message.");
    	}
    	if(payLoadVersion == null || payLoadVersion.trim().equals("")){
      	  throw new MessageContentException("Error no payload version attribute found in PKI Message.");
      	}
    	return new CSMessageVersion(messageVersion, payLoadVersion);
    }
	

	
	
	/**
	 * Method that populates all fields except the signature of a CS message
	 * @param messageId the id of the message, if null is a random id generated.
	 * @param destinationID the destination Id to use.
	 * @param organisation the related organisation
	 * @param originator the originator of the message if applicable.
	 * @param payload the payload object to set in the object
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	private CSMessage genCSMessage(String version, String messageId, String destinationID, String organisation, Credential originator, Object payload) throws MessageContentException, MessageProcessingException{
		return genCSMessage(version,null, messageId, destinationID, organisation, originator, payload);
	}
	
	/**
	 * Method that populates all fields except the signature of a CS message.
	 * 
	 * @param requestName the name in the request, or null if no related request exists
	 * @param messageId the id of the message, if null is a random id generated.
	 * @param destinationID the destination Id to use.
	 * @param organisation the related organisation
	 * @param originator the originator of the message if applicable.
	 * @param payload the payload object to set in the object
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	private CSMessage genCSMessage(String version, String requestName, String messageId, String destinationID, String organisation, Credential originator, Object payload) throws MessageContentException, MessageProcessingException{
		CSMessage retval = objectFactory.createCSMessage();
		retval.setVersion(version);
		if(messageId == null){
		  retval.setID(MessageGenerateUtils.generateRandomUUID());
		}else{
		  retval.setID(messageId);
		}
		retval.setTimeStamp(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date()));
		//retval.setName(messageNameCatalogue.lookupName(requestName, payload)); // TODO
		retval.setName("testname");
		retval.setDestinationId(destinationID);
		retval.setSourceId(sourceId);
		retval.setOrganisation(organisation);
		if(originator != null){
			Originator originatorElement = objectFactory.createOriginator();
			originatorElement.setCredential(originator);
		    retval.setOriginator(originatorElement);
		}
		Payload payLoadElem = objectFactory.createPayload();
		payLoadElem.setAny(payload);
		retval.setPayload(payLoadElem);
			
		return retval;
	}

	/**
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param csMessage the PKIMessage to sign and marshall, never null.
	 * @return a marshalled and signed message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
	 */
	public synchronized byte[] marshallAndSignCSMessage(CSMessage csMessage) throws MessageProcessingException, MessageContentException{
		if(csMessage == null){
			throw new MessageProcessingException("Error marshalling CS Message, message cannot be null.");
		}

		try {
			Document doc = getDocumentBuilder().newDocument();		
			String version = csMessage.getVersion();
			jaxbData.getCSMessageMarshaller(version).marshal(csMessage, doc);
			if(signMessages()){
	
				XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
				DigestMethod digestMethod = fac.newDigestMethod 
						("http://www.w3.org/2001/04/xmlenc#sha256", null);

				List<Transform> transFormList = new ArrayList<Transform>();
				transFormList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));				
				Reference ref = fac.newReference("#" + csMessage.getID(),digestMethod, transFormList, null, null);

				ArrayList<Reference> refList = new ArrayList<Reference>();
				refList.add(ref);
				CanonicalizationMethod cm =  fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,(C14NMethodParameterSpec) null);
				SignatureMethod sm = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",null);
				SignedInfo signedInfo =fac.newSignedInfo(cm,sm,refList);
				DOMSignContext signContext = null;
				signContext = new DOMSignContext(securityProvider.getSigningKey(),doc.getDocumentElement());

				signContext.setIdAttributeNS(doc.getDocumentElement(), null, "ID");
				
				KeyInfoFactory kif = KeyInfoFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
				List<X509Certificate> certs = new ArrayList<X509Certificate>();
				X509Certificate cert = securityProvider.getSigningCertificate();
				certs.add(cert);
				X509Data x509Data = kif.newX509Data(certs);
				KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509Data)); 

				XMLSignature signature = fac.newXMLSignature(signedInfo,ki);
				signature.sign(signContext);

				org.w3c.dom.Node signatureElement = doc.getElementsByTagName("Signature").item(0);
				signatureElement.setPrefix("ds");
			}
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			String output = writer.getBuffer().toString();	
			return output.getBytes("UTF-8");
		} catch (JAXBException e) {
			throw new MessageProcessingException("Error marshalling CS Message, " + e.getMessage(),e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Error marshalling CS Message, " + e.getMessage(),e);
		} catch (UnsupportedEncodingException e) {
			throw new MessageProcessingException("Error marshalling CS Message, " + e.getMessage(),e);
		} catch (TransformerException e) {
			throw new MessageProcessingException("Error marshalling CS Message, " + e.getMessage(),e);
		} catch (NoSuchAlgorithmException e) {
			throw new MessageProcessingException("Error signing the CS Message, " + e.getMessage(),e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new MessageProcessingException("Error signing the CS Message, " + e.getMessage(),e);
		} catch (MarshalException e) {
			throw new MessageProcessingException("Error signing the CS Message, " + e.getMessage(),e);
		} catch (XMLSignatureException e) {
			throw new MessageProcessingException("Error signing the CS Message, " + e.getMessage(),e);
		}
	}
	
	
	private Boolean signMessages;
	private boolean signMessages() throws MessageProcessingException{
		if(signMessages == null){
			signMessages = SettingsUtils.parseBooleanWithDefault(properties, SETTING_SIGN, OLD_SETTING_SIGN, true);
		}
		return signMessages;
	}
	
	private Boolean requireSignature;
	private boolean requireSignature() throws MessageProcessingException{
		if(requireSignature == null){
			requireSignature = SettingsUtils.parseBooleanWithDefault(properties, SETTING_REQUIRESIGNATURE, OLD_SETTING_REQUIRESIGNATURE,true);
		}
		return requireSignature;
	}
	
	private class JAXBRelatedData{
		
		private JAXBContext jaxbContext = null;
		HashMap<String, Validator> payLoadValidatorCache = new HashMap<String, Validator>();
	    private JAXBIntrospector jaxbIntrospector = null;
		private Map<String,Marshaller> csMessageMarshallers = new HashMap<String, Marshaller>();
		private Map<String,Unmarshaller> csMessageUnmarshallers = new HashMap<String, Unmarshaller>();
		
		void clearAllJAXBData(){
			jaxbContext = null;
			payLoadValidatorCache.clear();
			jaxbIntrospector = null;
		}
	    /**
	     * Help method maintaining the PKI Message JAXB Context.
	     */
	    JAXBContext getJAXBContext() throws JAXBException, MessageProcessingException{
	    	if(jaxbContext== null){
	    		String payloadClassPath = "";
	    			    		
	    		for(String namespace : PayloadParserRegistry.getRegistredNamespaces()){
	    			payloadClassPath = ":" + PayloadParserRegistry.getParser(namespace).getJAXBPackage();
	    		}
	    		
	    		jaxbContext = JAXBContext.newInstance("org.certificateservices.messages.csmessages.jaxb" +payloadClassPath);
	    		
	    	}
	    	return jaxbContext;
	    }
	    
		
		Validator getPayLoadValidatorFromCache(String payLoadNamespace, String payLoadVersion) throws MessageProcessingException, MessageContentException{
			String key = payLoadNamespace + ";" + payLoadVersion;
			Validator retval = payLoadValidatorCache.get(key);
			if(retval == null){
				PayloadParser pp = PayloadParserRegistry.getParser(payLoadNamespace);
				String schemaLocation = pp.getSchemaLocation(payLoadVersion);
				try {
					Schema s = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(new StreamSource(getClass().getResourceAsStream(schemaLocation)));
					retval = s.newValidator();
				} catch (SAXException e) {
					throw new MessageProcessingException("Problems occurred generating pay load schema for " + payLoadNamespace + ", version " + payLoadVersion + ", error: " + e.getMessage(),e);
				}
				payLoadValidatorCache.put(key, retval);
			}
			
			return retval;
		}
		
	    JAXBIntrospector getJAXBIntrospector() throws JAXBException, MessageProcessingException{
	    	if(jaxbIntrospector== null){
	    		jaxbIntrospector = getJAXBContext().createJAXBIntrospector();
	    	}
	    	return jaxbIntrospector;
	    }
		
		Marshaller createMarshaller(String schemaLocation) throws JAXBException{
			Marshaller retval = jaxbContext.createMarshaller();
			
			retval.setProperty(Marshaller.JAXB_SCHEMA_LOCATION, schemaLocation);
			retval.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
			return retval;
		}
		
	    /**
	     * Help method to fetch the name space of a given jaxb object.
	     *  
	     * @param jaxbObject the jaxbObject to lookup
	     * 
	     * @return the related name space of the object or null of object didn't have any related name space.
	     * @throws MessageProcessingException If problems occurred generating JAXB Context.
	     * @throws JAXBException of internal JAXB problems occurred when looking up the name space.
	     */
	    private String getNamespace(Object jaxbObject) throws MessageProcessingException {
	    	QName qname = null;
			try {
				qname = getJAXBIntrospector().getElementName(jaxbObject);
			} catch (JAXBException e) {
				throw new MessageProcessingException("Problems occured generating JAXB Context ( Introspector ) : " + e.getMessage(), e);
			}
	    	if(qname != null){
	    	  return qname.getNamespaceURI();
	    	}
	    	return null;
	    }
	    
	    /**
	     * Method that returns a marshaller for a given version,
	     * @param version the version of the CS Message protocol to fetch.
	     * @return related marshaller
	     * @throws MessageProcessingException if problems occurred creating the CS Message Marshaller for the given version.
	     * @throws MessageContentException if requested version was unsupported.
	     */
	    Marshaller getCSMessageMarshaller(String version) throws MessageProcessingException, MessageContentException{
	    	if(version == null){
	    		throw new MessageContentException("Invalid CS Message, version is missing.");
	    	}
	    	
	    	Marshaller retval = csMessageMarshallers.get(version);
	    	if(retval == null){
	    		String schemaURL = csMessageSchemaUriMap.get(version);
	    		try{
	    			retval = createMarshaller(schemaURL);
	    			retval.setSchema(generateCSMessageSchema(version)); 
	    			csMessageMarshallers.put(version, retval);
	    		}catch(Exception e){
	    			throw new MessageProcessingException("Error creating XML Marshaller for PKI Message version: " + version);
	    		}
	    	}
	    	return retval;
	    	
	    }
		
	    /**
	     * Method that returns a unmarshaller for a given version,
	     * @param version the version of the PKI Message protocol to fetch.
	     * @return related unmarshaller
	     * @throws MessageProcessingException if problems occurred creating the PKI Message Marshaller for the given version.
	     * @throws MessageContentException   if requested version was unsupported.
	     */
	    Unmarshaller getCSMessageUnmarshaller(String version) throws MessageProcessingException, MessageContentException{
	    	if(version == null){
	    		throw new MessageContentException("Invalid CS Message, version is missing.");
	    	}
	    	
	    	Unmarshaller retval = csMessageUnmarshallers.get(version);
	    	if(retval == null){
	    		try{
	    			retval = getJAXBContext().createUnmarshaller();
	    			retval.setSchema(generateCSMessageSchema(version));
	    			csMessageUnmarshallers.put(version, retval);
	    		}catch(Exception e){
	    			throw new MessageProcessingException("Error creating XML Unmarshaller for CS Message version: " + version);
	    		}
	    	}
	    	return retval;
	    	
	    }

	    
	    /**
	     * Help method to generate a  CSMessage Schema for a given version.
	     * @param version the version to look up.
	     * @return the generated Schema
	     * @throws MessageContentException
	     * @throws SAXException
	     * @throws MessageProcessingException
	     */
	    Schema generateCSMessageSchema(String version) throws MessageContentException, SAXException, MessageProcessingException{
	    	String schemaLocation = csMessageSchemaMap.get(version);
			SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			
	        Source[] sources = new Source[2];
	        sources[0] = new StreamSource(getClass().getResourceAsStream(schemaLocation));
	        sources[1] = new StreamSource(getClass().getResourceAsStream(XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
	        
	        Schema schema = schemaFactory.newSchema(sources);       
	        
	        return schema;
	    }
	}
}
