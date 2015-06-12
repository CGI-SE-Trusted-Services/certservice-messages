package org.certificateservices.messages.csmessages.manager

import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser
import org.certificateservices.messages.credmanagement.jaxb.GetCredentialResponse;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.CSResponse;
import org.certificateservices.messages.csmessages.jaxb.CredentialRequest;
import org.certificateservices.messages.csmessages.jaxb.IsApprovedResponseType;
import org.certificateservices.messages.csmessages.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.jaxb.TokenRequest;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.junit.BeforeClass
import org.junit.Ignore;
import org.junit.Test

import spock.lang.IgnoreRest;
import spock.lang.Shared
import spock.lang.Specification


class DefaultMessageManagerSpec extends Specification{

	@Shared DefaultMessageManager mm = new DefaultMessageManager()
		
	@Shared ObjectFactory of = new ObjectFactory()
	@Shared org.certificateservices.messages.credmanagement.jaxb.ObjectFactory credOf = new org.certificateservices.messages.credmanagement.jaxb.ObjectFactory()
	
	@Shared DefaultCSMessageParser parser = new DefaultCSMessageParser()
	@Shared CredManagementPayloadParser credManagementPayloadParser;
	
	@Shared Properties config
	
	private static final String TEST_ID = "12345678-1234-4444-8000-123456789012"

	def setupSpec(){
        config = new Properties();
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "somesourceId");		
		config.setProperty(DefaultMessageManager.SETTING_MESSAGEHANDLER_CLASSPATH, DummyMessageHandler.class.getName());		
		config.setProperty(DummyMessageHandler.SETTING_WAITTIME, "100");
		
		parser.init(new DummyMessageSecurityProvider(), config);
		mm.init(config,parser, "SomeDestination");
		
		credManagementPayloadParser = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE)
	}
	
	// TODO repeat the same request messages
	

	def "Test to send a simple get credential request message and expect a get credential response"(){
		setup:
		byte[] request = credManagementPayloadParser.genGetCredentialRequest(TEST_ID, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null,null)
		when:
		CSMessage response = mm.sendMessage(TEST_ID, request)
		then:
		assert response != null;
		assert response.getPayload().getAny() instanceof GetCredentialResponse
	}
	

	def "Test to 200 concurrent request and verify all responses are ok"(){
		final int numberOfConcurrentRequests = 200
		when:
		System.out.println("Generating " + numberOfConcurrentRequests + " concurrent request with a responsetime between 100 and 4100 millis");
		
		for(int i=0;i<numberOfConcurrentRequests;i++){
			String requestId = MessageGenerateUtils.generateRandomUUID();
			byte[] request = credManagementPayloadParser.genGetCredentialRequest(requestId, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null,null)
			new Thread(new SendRandomRequest(mm,requestId,request, 100,4000)).start()
		}
		
		
		
		while(SendRandomRequest.numberOfCompletedRequests < numberOfConcurrentRequests){
			System.out.println("number of completed : " + SendRandomRequest.numberOfCompletedRequests);
			Thread.sleep(1000);			
		}
		System.out.println("number of completed : " + SendRandomRequest.numberOfCompletedRequests);
		
		then:
		assert true;
	}
	

	def "Check that time out expeption is thrown when message takes longer time than set timeout."(){
		setup:
		((DummyMessageHandler) mm.messageHandler).waitTime = 10000
		mm.timeout = 200
		byte[] request = credManagementPayloadParser.genGetCredentialRequest(TEST_ID, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null,null)
		when:
		mm.sendMessage(TEST_ID, request)
		then:
		thrown(IOException)
		cleanup:
		((DummyMessageHandler) mm.messageHandler).waitTime = 100
		mm.timeout = 10000
	}

	def "Check that revoce message is sent for issue token request responses where wait thread has timed out."(){
		setup:
		((DummyMessageHandler) mm.messageHandler).waitTime = 1000
		mm.timeout = 200
		byte[] request = credManagementPayloadParser.genIssueTokenCredentialsRequest(TEST_ID, "somedestination", "someorg", createDummyTokenRequest(),null,null,null)
		when:
		mm.sendMessage(TEST_ID, request)
		then:
		thrown(IOException)
		when:
		
		while(!((DummyMessageHandler) mm.messageHandler).revokeMessageRecieved){
			System.out.println("Waiting for revoce message to be sent ...");
			Thread.sleep(1000);
		}
		System.out.println("Waiting sent successfully");
		then:
		assert ((DummyMessageHandler) mm.messageHandler).revokeMessageRecieved
		cleanup:
		((DummyMessageHandler) mm.messageHandler).waitTime = 100
		mm.timeout = 10000
	}
	

	def "Check findRequestId returns the correct request id from the message"(){
		when:
		CSResponse response = of.createCSResponse();
		response.setInResponseTo(TEST_ID);		
		CSMessage csMessage = parser.genCSMessage(DefaultCSMessageParser.CSMESSAGE_VERSION_2_0,"2.0",null, null, "somedest", "someorg", null,response,null)
		then:
		assert mm.findRequestId(csMessage) == TEST_ID
		when:
		response = credOf.createIssueTokenCredentialsResponse();
		response.setInResponseTo(TEST_ID);
		csMessage = parser.genCSMessage(DefaultCSMessageParser.CSMESSAGE_VERSION_2_0,"2.0",null,null, "somedest", "someorg", null,response,null)
		then:
		assert mm.findRequestId(csMessage) == TEST_ID
		when:
		response = credOf.createGetCredentialResponse();
		response.setInResponseTo(TEST_ID);
		csMessage = parser.genCSMessage(DefaultCSMessageParser.CSMESSAGE_VERSION_2_0,"2.0",null,null, "somedest", "someorg", null,response,null)
		then:
		assert mm.findRequestId(csMessage) == TEST_ID
		when:
		response = credOf.createIsIssuerResponse();
		response.setInResponseTo(TEST_ID);
		csMessage = parser.genCSMessage(DefaultCSMessageParser.CSMESSAGE_VERSION_2_0,"2.0",null,null, "somedest", "someorg", null,response,null)
		then:
		assert mm.findRequestId(csMessage) == TEST_ID
		when:
		csMessage = parser.genCSMessage(DefaultCSMessageParser.CSMESSAGE_VERSION_2_0,"2.0",null,null, "somedest", "someorg", null,credOf.createIsIssuerRequest(),null)
		then:
		assert mm.findRequestId(csMessage) == null


	}
	


	def "Check getTimeOutInMillis verifies the responses properly"(){
		when:
		Properties config = new Properties();
		config.setProperty(DefaultMessageManager.SETTING_MESSAGE_TIMEOUT_MILLIS, "123")
		then:
		assert mm.getTimeOutInMillis(config) == 123
		when:
		config.setProperty(DefaultMessageManager.SETTING_MESSAGE_TIMEOUT_MILLIS, "abc")
		mm.getTimeOutInMillis(config)
		then:
		thrown (MessageProcessingException)
		when:
		config = new Properties();		
		then:
		assert mm.getTimeOutInMillis(config) == 60000L

	}
	
	
	
	private class SendRandomRequest implements Runnable{
	
		private static Random random = new Random();
			
		public static int numberOfCompletedRequests = 0;
		
		private String requestId
		private byte[] requestData
		private MessageManager mm
		
		int minTime
		int randomTime
		
		private SendRandomRequest(MessageManager mm, String requestId, byte[] requestData, int minTime, int maxTime){
			this.requestId = requestId
			this.requestData = requestData;
			this.minTime = minTime;
			this.randomTime =  maxTime- minTime;
			this.mm = mm;
		}

		@Override
		public void run() {
			long waitTime = minTime;
			if(randomTime > 0){
				waitTime += random.nextInt(randomTime)
			}
			Thread.sleep(waitTime);
			
			def result = mm.sendMessage(requestId, requestData)
			assert result != null;	
			
			synchronized (numberOfCompletedRequests) {
				numberOfCompletedRequests++;
				
			}		
		}
		
	}

	private TokenRequest createDummyTokenRequest(){
		TokenRequest retval = of.createTokenRequest();
		retval.user = "someuser";
		retval.tokenContainer = "SomeTokenContainer"
		retval.tokenType = "SomeTokenType"
		retval.tokenClass = "SomeTokenClass"
		
		CredentialRequest cr = of.createCredentialRequest();
		cr.credentialRequestId = 123
		cr.credentialType = "SomeCredentialType"
		cr.credentialSubType = "SomeCredentialSubType"
		cr.x509RequestType = "SomeX509RequestType"
		cr.credentialRequestData = "12345ABC"
		
		retval.setCredentialRequests(new TokenRequest.CredentialRequests())
		retval.getCredentialRequests().getCredentialRequest().add(cr)

		return retval
	}

}
