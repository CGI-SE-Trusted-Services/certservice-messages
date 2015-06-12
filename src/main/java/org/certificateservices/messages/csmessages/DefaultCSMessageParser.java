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
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
import javax.xml.bind.JAXBElement;
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
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.csmessages.PayloadParserRegistry.ConfigurationCallback;
import org.certificateservices.messages.csmessages.jaxb.ApprovalStatus;
import org.certificateservices.messages.csmessages.jaxb.Assertions;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.CSRequest;
import org.certificateservices.messages.csmessages.jaxb.CSResponse;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.GetApprovalRequest;
import org.certificateservices.messages.csmessages.jaxb.IsApprovedRequest;
import org.certificateservices.messages.csmessages.jaxb.IsApprovedResponseType;
import org.certificateservices.messages.csmessages.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.jaxb.Originator;
import org.certificateservices.messages.csmessages.jaxb.Payload;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.utils.SettingsUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * 
 * Default implementation of CS Message Parser.
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

	public static final String CSMESSAGE_NAMESPACE = "http://certificateservices.org/xsd/csmessages2_0";
	
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
	
	static final String XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION = "/xmldsig-core-schema.xsd";
	static final String XMLENC_XSD_SCHEMA_RESOURCE_LOCATION = "/xenc-schema.xsd";
	

	private static final String[] SUPPORTED_CSMESSAGE_VERSIONS = {"2.0"};
	


	
	private ObjectFactory objectFactory = new ObjectFactory();
	
	private Properties properties = null;
	private MessageSecurityProvider securityProvider = null;
	private MessageNameCatalogue messageNameCatalogue = null;
	private JAXBRelatedData jaxbData = new JAXBRelatedData();
	
	private String sourceId = null;
	
	private final String defaultVersion = CSMESSAGE_VERSION_2_0;
	
	
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
		final CSMessageParser thisParser = this;
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
				payloadParser.init(properties, thisParser);
				
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


	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#parseMessage(byte[])
	 */
	@Override
	public synchronized CSMessage parseMessage(byte[] messageData)
			throws MessageContentException, MessageProcessingException {
		try{
			
			CSMessageVersion version = getVersionFromMessage(messageData);
			verifyCSMessageVersion(version.getMessageVersion());
		
			Object object = jaxbData.getCSMessageUnmarshaller(version.getMessageVersion()).unmarshal(new ByteArrayInputStream(messageData));
			validateCSMessage(version, object, messageData);
			return (CSMessage) object;
		}catch(JAXBException e){
			throw new MessageContentException("Error parsing CS Message: " + e.getMessage(),e);
		} 
		
	}
	

	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#generateCSRequestMessage(String, String, String, String, Object, List)
	 * 
	 */
	public byte[] generateCSRequestMessage(String requestId, String destinationId, String organisation, String payLoadVersion, Object payload, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		return generateCSRequestMessage(requestId, destinationId, organisation, payLoadVersion, payload, null, assertions);
	}

	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#generateCSRequestMessage(String, String, String, String, Object, Credential, List)
	 * 
	 */
	public byte[] generateCSRequestMessage(String requestId, String destinationId, String organisation, String payLoadVersion, Object payload, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		CSMessage message = genCSMessage(defaultVersion, payLoadVersion,null, requestId, destinationId, organisation, originator, payload,  assertions);
		return marshallAndSignCSMessage( message);
	}

	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#generateCSResponseMessage(String, CSMessage, String, CSResponse)
	 * 
	 */
	public CSMessageResponseData generateCSResponseMessage(String relatedEndEntity, CSMessage request, String payLoadVersion, Object payload) throws MessageContentException, MessageProcessingException{
		return generateCSResponseMessage(relatedEndEntity, request, payLoadVersion, payload, false);
	}
	

	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#generateCSResponseMessage(String, CSMessage, String, CSResponse)
	 * 
	 */
	public CSMessageResponseData generateCSResponseMessage(String relatedEndEntity, CSMessage request, String payLoadVersion, Object payload, boolean isForwardableResponse) throws MessageContentException, MessageProcessingException{
		populateSuccessfulResponse(payload, request);
		CSMessage message = genCSMessage(request.getVersion(), payLoadVersion, request.getName(), null, request.getSourceId(), request.getOrganisation(),  getOriginatorFromRequest(request), payload,  null);
		byte[] responseData = marshallAndSignCSMessage( message);
		return new CSMessageResponseData(message.getID(),message.getName(), relatedEndEntity, message.getDestinationId(),responseData, isForwardableResponse);
	}

	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#generateGetApprovalRequest(String, String, String, CSRequest, String Credential, List)
	 * 
	 */
	@Override
	public byte[] generateGetApprovalRequest(String requestId, String destinationId, String organisation, CSRequest request, String requestPayloadVersion, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetApprovalRequest payload = objectFactory.createGetApprovalRequest();
		Payload requestedPayload = objectFactory.createPayload();
		requestedPayload.setAny(request);
		payload.setRequestPayload(requestedPayload);
		
		return generateCSRequestMessage(requestId, destinationId, organisation, requestPayloadVersion, payload, originator, assertions);
	}
	
	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#generateIsApprovedRequest(String, String, String, String, Credential, List)
	 * 
	 */
	@Override
	public byte[] generateIsApprovedRequest(String requestId, String destinationId, String organisation, String approvalId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IsApprovedRequest payload = objectFactory.createIsApprovedRequest();
		payload.setApprovalId(approvalId);
		
		return generateCSRequestMessage(requestId, destinationId, organisation, defaultVersion, payload, originator, assertions);
	}
	
	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#generateIsApprovedResponse(String, CSMessage, ApprovalStatus, Credential, List) 
	 * 
	 */
	@Override
	public CSMessageResponseData generateIsApprovedResponse(String relatedEndEntity, CSMessage request, ApprovalStatus approvalStatus, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IsApprovedResponseType responseType = objectFactory.createIsApprovedResponseType();
		if(request.getPayload().getAny() instanceof IsApprovedRequest){
			responseType.setApprovalId(((IsApprovedRequest) request.getPayload().getAny()).getApprovalId());
		}else{
			throw new MessageContentException("Error generating IsApprovedResponse, no IsApprovedRequest found in request payload");
		}
		responseType.setApprovalStatus(approvalStatus);
		
		return generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), objectFactory.createIsApprovedResponse(responseType));
	}
	
	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#generateGetApprovalResponse(String, CSMessage, String, ApprovalStatus, Credential, List)
	 */
	@Override
	public CSMessageResponseData generateGetApprovalResponse(String relatedEndEntity, CSMessage request, String approvalId, ApprovalStatus approvalStatus, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IsApprovedResponseType responseType = objectFactory.createIsApprovedResponseType();
		responseType.setApprovalId(approvalId);
		responseType.setApprovalStatus(approvalStatus);

		
		
		return generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), objectFactory.createGetApprovalResponse(responseType));
	}
	

	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#genCSFailureResponse(String, byte[], RequestStatus, String, String, Credential)
	 */
	@Override
	public CSMessageResponseData genCSFailureResponse(String relatedEndEntity,byte[] request, RequestStatus status,
			String failureMessage, String destinationID, Credential originator) throws MessageContentException,
			MessageProcessingException {
		try {
			DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
			domFactory.setNamespaceAware(true);
			DocumentBuilder builder = domFactory.newDocumentBuilder();
			Document doc = builder.parse(new ByteArrayInputStream(request));
			
    		Node pkiMessageNode = doc.getFirstChild();
    		String version=null;
    		if(pkiMessageNode != null){
    			Node versionNode = pkiMessageNode.getAttributes().getNamedItem("version");
    			if(versionNode != null){
    				version = versionNode.getNodeValue();
    			}
    		}  
    		if(version == null || version.trim().equals("")){
    			throw new MessageContentException("Error unsupported protocol version when generating CSResponse, version: " + version);
    		}

			XPathFactory factory = XPathFactory.newInstance();
			XPath xpath = factory.newXPath();
			if(destinationID == null){
				XPathExpression expr = xpath.compile("//*[local-name()='sourceId']/text()");
				String result = (String) expr.evaluate(doc, XPathConstants.STRING);
				if(result != null){
				  destinationID = result;
				}
			}

			XPathExpression expr = xpath.compile("//*[local-name()='CSMessage']/@ID");
			Object result = expr.evaluate(doc, XPathConstants.STRING);			   
			String responseToRequestID = (String) result;

			expr = xpath.compile("//*[local-name()='organisation']/text()");
			result = expr.evaluate(doc, XPathConstants.STRING);;
			String organisation = (String) result;
			
			expr = xpath.compile("//*[local-name()='name']/text()");
			result = expr.evaluate(doc, XPathConstants.STRING);;
			String requestName = (String) result;
			
			if(organisation == null || responseToRequestID == null || destinationID == null || requestName==null){
				throw new MessageContentException("Error generating CS Message Response from request, due to missing fields organisation, sourceId, name or ID in request.");
			}
			
			CSResponse csResponse = objectFactory.createCSResponse();
			csResponse.setStatus(status);
			csResponse.setFailureMessage(failureMessage);
			csResponse.setInResponseTo(responseToRequestID);

			CSMessage csMessage = genCSMessage(version,version,requestName, null,destinationID, organisation, originator, objectFactory.createFailureResponse(csResponse), null);

			byte[] responseData = marshallAndSignCSMessage(csMessage);
			return new CSMessageResponseData(csMessage.getID(), csMessage.getName(), relatedEndEntity, csMessage.getDestinationId(),responseData, false );
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Error configuring the XML SAX Parser : " + e.getMessage());
		} catch (SAXException e) {
			throw new MessageContentException("Error parsing request XML message: " + e.getMessage());
		} catch (IOException e) {
			throw new MessageProcessingException("Error reading the XML request data : " + e.getMessage());
		} catch (XPathExpressionException e) {
			throw new MessageProcessingException("Error constructing XPath expression when generating PKI Message responses : " + e.getMessage());
		}
	}
	

	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#getSigningCertificate(byte[])	 
	 */	
	@Override
	public X509Certificate getSigningCertificate(byte[] request)
			throws MessageContentException, MessageProcessingException {
		X509Certificate retval = null;
		if(requireSignature()){
			try{
				DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
				domFactory.setNamespaceAware(true);
				DocumentBuilder builder = domFactory.newDocumentBuilder();
				Document doc = builder.parse(new ByteArrayInputStream(request));

				XPathFactory factory = XPathFactory.newInstance();
				XPath xpath = factory.newXPath();

				XPathExpression expr = xpath.compile("//*[local-name()='KeyInfo']/*[local-name()='X509Data']/*[local-name()='X509Certificate']/text()");
				String result = (String) expr.evaluate(doc, XPathConstants.STRING);
				if(result != null && !result.equals("")){
					CertificateFactory cf = 
							CertificateFactory.getInstance("X.509");
					retval = (X509Certificate) 
							cf.generateCertificate(new ByteArrayInputStream(Base64.decode(result.getBytes())));					
				}

			}catch(CertificateException e){
			} catch (ParserConfigurationException e) {
				throw new MessageProcessingException("Error building XPath Expression when fetching signing certificate: " + e.getMessage(),e);
			} catch (SAXException e) {
				throw new MessageContentException("Error reading signing certificate found in CS Message request: " + e.getMessage(),e);
			} catch (IOException e) {
				throw new MessageContentException("Error reading signing certificate found in CS Message request: " + e.getMessage(),e);
			} catch (XPathExpressionException e) {
				throw new MessageProcessingException("Error building XPath Expression when fetching signing certificate: " + e.getMessage(),e);
			} catch (Base64DecodingException e) {
				throw new MessageContentException("Error reading signing certificate base 64 decoding exception: " + e.getMessage(),e);
			}


			if(retval == null){
				throw new MessageContentException("Error, no signing certificate found in CS Message request.");
			}			
		}
		return retval;
	}
	
	/**
	 * @see org.certificateservices.messages.csmessages.CSMessageParser#genCSMessage(String, String, String, String, String, String, Credential, Object, List)	 
	 */
	public CSMessage genCSMessage(String version, String payLoadVersion, String requestName, String messageId, String destinationID, String organisation, Credential originator, Object payload, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		CSMessage retval = objectFactory.createCSMessage();
		retval.setVersion(version);
		retval.setPayLoadVersion(payLoadVersion);
		if(messageId == null){
		  retval.setID(MessageGenerateUtils.generateRandomUUID());
		}else{
		  retval.setID(messageId);
		}
		retval.setTimeStamp(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date()));
		retval.setName(messageNameCatalogue.lookupName(requestName, payload));
		retval.setDestinationId(destinationID);
		retval.setSourceId(sourceId);
		retval.setOrganisation(organisation);
		if(originator != null){
			Originator originatorElement = objectFactory.createOriginator();
			originatorElement.setCredential(originator);
		    retval.setOriginator(originatorElement);
		}
		
		if(assertions != null && assertions.size() > 0){
			Assertions assertionsElem = objectFactory.createAssertions();
			for(Object assertion : assertions){
			  assertionsElem.getAny().add(assertion);
			}
		}
		
		Payload payLoadElem = objectFactory.createPayload();
		payLoadElem.setAny(payload);
		retval.setPayload(payLoadElem);
			
		return retval;
	}

	/**
	 * Help method that sets status to success and the in response to ID.
	 * @param response the response object to populate
	 * @param request the related request.
	 * 
	 * @throws MessageProcessingException  if problem occurred parsing the CSResponse from the respone object.
	 */
	private void populateSuccessfulResponse(
			Object response, CSMessage request) throws MessageProcessingException {
		
		CSResponse csresp = null;
		if(response instanceof CSResponse ){
			csresp = (CSResponse) response;
		}
		if(response instanceof JAXBElement<?> ){
			if(((JAXBElement<?>) response).getValue() instanceof CSResponse){
		  	  csresp = (CSResponse) ((JAXBElement<?>) response).getValue();
			}
		}
		if(csresp == null){
			throw new MessageProcessingException("Error populating CS response, response object is not a CSResponse");
		}
		
		csresp.setFailureMessage(null);
		csresp.setStatus(RequestStatus.SUCCESS);
		csresp.setInResponseTo(request.getID());		
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
	
	
    /**
     * Method that tries to parse the xml version from a message
     * @param messageData the messageData to extract version from.
     * @return the version in the version and payLoadVersion attributes of the message.
     * @throws MessageContentException didn't contains a valid version attribute.
     * @throws MessageProcessingException if internal problems occurred.
     */
	@Override
    public CSMessageVersion getVersionFromMessage(byte[] messageData) throws MessageContentException, MessageProcessingException{
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
    	  throw new MessageContentException("Error no version attribute found in CS Message.");
    	}
    	if(payLoadVersion == null || payLoadVersion.trim().equals("")){
      	  throw new MessageContentException("Error no payload version attribute found in CS Message.");
      	}
    	return new CSMessageVersion(messageVersion, payLoadVersion);
    }

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
	private void validateCSMessage(CSMessageVersion version, Object object, byte[] message) throws MessageContentException, MessageProcessingException {
		
		if(!(object instanceof CSMessage)){
			throw new MessageContentException("Error: parsed object not a CS Message.");
		}
		CSMessage csMessage = (CSMessage) object;
		validateCSMessageHeader(csMessage, message);
		
		validatePayloadObject(version, csMessage.getPayload().getAny());
	}
	
	/**
	 * Method that validates the "header" parts of the cs message.
	 * 
	 * @param csMessage the cs message to validate, never null
	 * @param message string representation of the message data.
	 * @throws MessageContentException if the header contained illegal arguments.
	 */
	private void validateCSMessageHeader(CSMessage pkiMessage, byte[] message) throws MessageContentException, MessageProcessingException{
		validateSignature(message);
	}

	
	/**
	 * Method to validate a payload object separately, used for special cases such when validating GetApprovalRequest requestData etc.
	 * 
	 * @param version the versions of a CS message.
	 * @param payLoadObject the pay load object to validate schema for.
	 * 
	 * @throws MessageProcessingException
	 * @throws MessageContentException if the message contained invalid XML.
	 */
	@Override
    public void validatePayloadObject(CSMessageVersion version, Object payLoadObject) throws MessageContentException {
		try {
			String payLoadNamespace = jaxbData.getNamespace(payLoadObject);
			if(!payLoadNamespace.equals(CSMESSAGE_NAMESPACE)){
			  Validator validator = jaxbData.getPayLoadValidatorFromCache(payLoadNamespace, version.getMessageVersion(), version.getPayLoadVersion());
			  validator.validate(new JAXBSource(jaxbData.getJAXBContext(), payLoadObject));
			}else{
				if(payLoadObject instanceof GetApprovalRequest){
					GetApprovalRequest getApprovalRequest = (GetApprovalRequest) payLoadObject;
					Object requestedPayload = getApprovalRequest.getRequestPayload().getAny();
					String requestedPayLoadNamespace = jaxbData.getNamespace(requestedPayload);
					Validator validator = jaxbData.getPayLoadValidatorFromCache(requestedPayLoadNamespace, version.getMessageVersion(), version.getPayLoadVersion());
					validator.validate(new JAXBSource(jaxbData.getJAXBContext(), requestedPayload));
				}
			}
		} catch (Exception e) {
			throw new MessageContentException("Error parsing payload of CS Message: " + e.getMessage(), e);
		}   	
    }
	


	/**
	 * Help method to verify a messag signature.
	 */
	private void validateSignature(byte[] message) throws MessageContentException, MessageProcessingException {
		if(requireSignature()){
			try{
				DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
				factory.setNamespaceAware(true);
				DocumentBuilder builder = factory.newDocumentBuilder();
				Document doc = builder.parse(new InputSource(new ByteArrayInputStream(message)));

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
	 * one if not configured.
	 * 
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
	
	public Credential getOriginatorFromRequest(CSMessage request) {
		Credential retval = null;
		if(request!= null && request.getOriginator() != null){
			retval = request.getOriginator().getCredential();
		}
		return retval;
	}
	
	/**
	 * Helper class to group JAXB Related data, and make it easy to re-init if new payload parser is registered.
	 *  
	 * @author Philip Vendil
	 *
	 */
	private class JAXBRelatedData{
		
		private JAXBContext jaxbContext = null;
		private HashMap<String, Validator> payLoadValidatorCache = new HashMap<String, Validator>();
	    private JAXBIntrospector jaxbIntrospector = null;
		private Map<String,Marshaller> csMessageMarshallers = new HashMap<String, Marshaller>();
		private Map<String,Unmarshaller> csMessageUnmarshallers = new HashMap<String, Unmarshaller>();
		private String jaxbClassPath = "";
		
		void clearAllJAXBData(){
			jaxbClassPath = "";
			jaxbContext = null;
			payLoadValidatorCache.clear();
			csMessageMarshallers.clear();
			csMessageUnmarshallers.clear();
			jaxbIntrospector = null;
		}
		
	    /**
	     * Help method maintaining the PKI Message JAXB Context.
	     */
	    JAXBContext getJAXBContext() throws JAXBException, MessageProcessingException{
	    	if(jaxbContext== null){
	    		jaxbClassPath = "org.certificateservices.messages.csmessages.jaxb";
	    			    		
	    		for(String namespace : PayloadParserRegistry.getRegistredNamespaces()){
	    			jaxbClassPath += ":" + PayloadParserRegistry.getParser(namespace).getJAXBPackage();
	    		}
	    		
	    		jaxbContext = JAXBContext.newInstance(jaxbClassPath);
	    		
	    	}
	    	return jaxbContext;
	    }
	    
		
		Validator getPayLoadValidatorFromCache(String payLoadNamespace, String version, String payLoadVersion) throws MessageProcessingException, MessageContentException{
			String key = payLoadNamespace + ";" + version + ";" + payLoadVersion;
			Validator retval = payLoadValidatorCache.get(key);
			if(retval == null){
				PayloadParser pp = PayloadParserRegistry.getParser(payLoadNamespace);
				InputStream payLoadSchemaStream = pp.getSchemaAsInputStream(payLoadVersion);
		    	String csMessageSchemaLocation = csMessageSchemaMap.get(version);
				
		        Source[] sources = new Source[4];
		        sources[0] = new StreamSource(getClass().getResourceAsStream(XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
		        sources[1] = new StreamSource(getClass().getResourceAsStream(XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
		        sources[2] = new StreamSource(getClass().getResourceAsStream(csMessageSchemaLocation));
		        sources[3] = new StreamSource(payLoadSchemaStream);
		        
				try {
					Schema s = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(sources);
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
	    			throw new MessageProcessingException("Error creating XML Marshaller for CS Message version: " + version);
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
			
	        Source[] sources = new Source[3];
	        sources[0] = new StreamSource(getClass().getResourceAsStream(XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
	        sources[1] = new StreamSource(getClass().getResourceAsStream(XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
	        sources[2] = new StreamSource(getClass().getResourceAsStream(schemaLocation));
	        
	        Schema schema = schemaFactory.newSchema(sources);       
	        
	        return schema;
	    }
	}

}
