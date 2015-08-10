package org.certificateservices.messages;

import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;

import groovy.xml.XmlUtil;

public class TestUtils {
	
	public static XmlSlurper xmlSlurper = new XmlSlurper()
	
	public static def slurpXml(byte[] data){
		return xmlSlurper.parse(new ByteArrayInputStream(data))
	}
	
	public static def slurpXml(String msg){
		return xmlSlurper.parse(new ByteArrayInputStream(msg.getBytes()))
	}
	
	public static String prettyPrintXML(byte[] data){
		return prettyPrintXML(new String(data,"UTF-8"))
	}

	public static String prettyPrintXML(String msg){
	    return XmlUtil.serialize(msg);
    }
	
	public static void printXML(byte[] data){
		println prettyPrintXML(data);
	}
	
	public static void printXML(String msg){
		println prettyPrintXML(msg);
    }
	
	public static void messageContainsPayload(byte[] data, String payloadName){
		String msg = new  String(data, "UTF-8")
		assert msg =~ payloadName
	}
	
	public static void verifyCSMessageResponseData(CSMessageResponseData rd, String expectedDest, String notExpectedMessageId, boolean isForwardable, String expectedMessageName, String expectedRelatedEndEntity){
		assert rd.destination == expectedDest
		assert rd.messageId != notExpectedMessageId && rd.messageId != null
		assert rd.isForwardableResponse == isForwardable
		assert rd.messageName == expectedMessageName
		assert rd.relatedEndEntity == expectedRelatedEndEntity
		assert rd.messageProperties != null
	}
	
	public static void setupRegisteredPayloadParser(){
		DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
		Properties config = new Properties();
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID");
		DefaultCSMessageParser mp = new DefaultCSMessageParser();
		mp.init(secprov, config)
	}
}
