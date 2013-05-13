package org.certificateservices.messages.utils

import java.io.File;

import javax.xml.datatype.XMLGregorianCalendar;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.utils.SettingsUtils;
import org.junit.Test;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

class DefaultSystemTimeSpec extends Specification{
		


	 @Test
	 def "Test default system time works"(){
		 expect:
		 (new DefaultSystemTime()).getSystemTimeMS() != 0
	 }
	 
	 

}
