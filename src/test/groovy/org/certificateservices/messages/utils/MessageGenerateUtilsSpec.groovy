package org.certificateservices.messages.utils

import java.io.File;

import javax.xml.datatype.XMLGregorianCalendar;


import org.junit.Test;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

class MessageGenerateUtilsSpec extends Specification{
		

	 @Test
	 def "Test that generateRandomUUID generates UUID that matches the pattern."(){

		 when:
         String uuid = MessageGenerateUtils.generateRandomUUID()
		 
		 then:		 
		 assert uuid.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[8-9a-bA-B][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");
	 }
	 
	 @Test
	 def "Generate 1000 UUIDs and check that they all are unique."(){
		 setup:
		 HashSet<String> generated = [];
		 when:
		 for(int i=0; i<1000;i++){
		   String uuid = MessageGenerateUtils.generateRandomUUID()		   
		   assert uuid.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[8-9a-bA-B][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");
		   assert !generated.contains(uuid);
		   generated.add(uuid);
		 }
		 then:
		 assert true;
	 }
	
	 @Test
	 def "Test dateToXMLGregorianCalendar method converts date correctly"(){
		 when: " date is null should result be null"
		 XMLGregorianCalendar result = MessageGenerateUtils.dateToXMLGregorianCalendar(null);
		 then:
		 result == null
		 when: " date is set should a XML gregorian calendar be returned."
		 result = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(0L));
		 then:
		 result.toString().startsWith("1970")
	 }
	 
	 @Test
	 def "Test xMLGregorianCalendarToDate method converts date correctly"(){
		 when: " calendarDate is null should result be null"
		 Date result = MessageGenerateUtils.xMLGregorianCalendarToDate(null);
		 then:
		 result == null
		 when: " calendarDate should generate a date if XMLGregorianCalendarToDate is valid."
		 result = MessageGenerateUtils.xMLGregorianCalendarToDate(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(0L)))
		 then:
		 result.getTime() == 0L
	 }

}