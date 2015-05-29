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

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;

import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.sysconfig.jaxb.GetActiveConfigurationRequest;
import org.certificateservices.messages.sysconfig.jaxb.Property;

import spock.lang.Specification;

public class CSMessageParserFactorySpec extends Specification{
	
	Properties config = new Properties();
	DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
	
	
	def "Verify that with no configuration is DefaultCSMessageParser returned and initialized."(){
		setup:
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID")

		when:
		def mp = CSMessageParserFactory.genCSMessageParser(secprov, config)
		
		then:
		mp instanceof DefaultCSMessageParser
		mp.securityProvider == secprov
		mp.sourceId == "SOMESOURCEID"
		
	}
	
	def "Verify that custom CSMessageParser is returned if configured"(){
		setup:
		config.setProperty(CSMessageParserFactory.SETTING_CSMESSAGEPARSER_IMPL, TestCSMessageParser.class.getName())
		
		when:
		def mp = CSMessageParserFactory.genCSMessageParser(secprov, config)
		
		then:
		mp instanceof TestCSMessageParser
	}

	def "Verify that MessageProcessingException is thrown if invalid class path was given"(){
		setup:
		config.setProperty(CSMessageParserFactory.SETTING_CSMESSAGEPARSER_IMPL, Integer.class.getName())
		
		when:
		CSMessageParserFactory.genCSMessageParser(secprov, config)
		then:
		thrown MessageProcessingException
		
		when:
		config.setProperty(CSMessageParserFactory.SETTING_CSMESSAGEPARSER_IMPL, "notvalid.Invalid")
		CSMessageParserFactory.genCSMessageParser(secprov, config)
		then:
		thrown MessageProcessingException
	}

}
