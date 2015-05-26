package org.certificateservices.messages.csmessages;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;

import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.sysconfig.jaxb.GetActiveConfigurationRequest;
import org.certificateservices.messages.sysconfig.jaxb.Property;

import spock.lang.Specification;

public class DefaultCSMessageParserSpec extends Specification{
	
	
	org.certificateservices.messages.sysconfig.jaxb.ObjectFactory sysConfigOf = new org.certificateservices.messages.sysconfig.jaxb.ObjectFactory()
	DefaultCSMessageParser mp = new DefaultCSMessageParser()
	DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
	
	static final String TEST_ID = "12345678-1234-4444-8000-123456789012"
	
	def setup(){
		Properties config = new Properties();
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID");
		mp.init(secprov, config)
	}
	
	def "initial test"(){
		when:
		
		GetActiveConfigurationRequest payLoad = sysConfigOf.createGetActiveConfigurationRequest()
		payLoad.application = "asdf"
		payLoad.organisationShortName = "SomeOrg"
		
	    byte[] data = mp.genMessage(TEST_ID, payLoad)
		String s = new String(data, "UTF-8")
		println s
		
		CSMessage csmsg = mp.parseMessage(s.getBytes())
		GetActiveConfigurationRequest cr = csmsg.getPayload().getAny() 
		
		then:
		csmsg != null
		cr.organisationShortName == "SomeOrg"
	}

}
