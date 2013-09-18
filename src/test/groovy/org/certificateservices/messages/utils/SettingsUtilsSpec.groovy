package org.certificateservices.messages.utils

import static org.junit.Assert.*;

import java.io.File;

import javax.xml.datatype.XMLGregorianCalendar;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.utils.SettingsUtils;
import org.junit.Test;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

class SettingsUtilsSpec extends Specification{
		


	 @Test
	 @Unroll
	 def "Test that parseBoolean returns #expected for setting #value when not required."(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
         Boolean result =SettingsUtils.parseBoolean(config,"somekey", false)
		 
		 then:		 
		 assert result == expected
		 
		 where:
		 value     | expected
		 "true"    | true
		 "tRue"    | true
		 "FALSE"   | false
		 "false"   | false
		 ""        | null
		 null      | null
	 }
	 
	 @Test
	 @Unroll
	 def "Test that parseBoolean throws exception for invalid setting value #value and required."(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
		 Boolean result =SettingsUtils.parseBoolean(config,"somekey", true)
		 
		then:
		  thrown(MessageException)
		 
		 where:
		 value     << ["untrue","maybe","", null]

	 }
	 
	 @Test
	 @Unroll
	 def "Test that parseBooleanWithDefault returns #expected for setting #value with default value #defaultVal"(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
		 Boolean result =SettingsUtils.parseBooleanWithDefault(config,"somekey", defaultVal)
		 
		 then:
		 assert result == expected
		 
		 where:
		 value     | expected | defaultVal
		 "true"    | true     | false
		 "tRue"    | true     | false
		 "FALSE"   | false    | true
		 "false"   | false    | true
		 ""        | true     | true
		 null      | false    | false
	 }
	 
	 @Test
	 @Unroll
	 def "Test that parseStringArray returns #expected for setting #value with default value #defaultVal and delimiter #delimiter"(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
		 String[] result =SettingsUtils.parseStringArray(config,"somekey", delimiter, defaultVal)
		 
		 then:
		 assert Arrays.equals(result, expected)
		 
		 where:
		 value                | expected                       | defaultVal             | delimiter
		 "someval"            | (String[]) ["someval"]         | (String[]) []          | ","
		 "someval , other  "  | (String[]) ["someval","other"] | (String[]) []          | ","
		 null                 | (String[]) ["someval"]         | (String[]) ["someval"] | ","
		"someval , other  "   | (String[]) ["someval , other"] | (String[]) []          | ";"		 
		 
	 }
	 
	 @Test
	 @Unroll
	 def "Test that parseStringArray returns #expected for setting #value and required  #required and delimiter #delimiter"(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
		 String[] result =SettingsUtils.parseStringArray(config,"somekey", delimiter, required)
		 
		then:
         assert Arrays.equals(result, expected)
			
		 
		 where:
		 value                | expected                       | required | delimiter
		 "someval"            | (String[]) ["someval"]         | true     | ","
		 "someval , other  "  | (String[]) ["someval","other"] | true     | ","		
		 "someval , other  "  | (String[]) ["someval , other"] | true     | ";"
		 null                 | (String[]) []                  | false    | ";"
		 
	 }
	 
	 @Test
	 def "Test that parseStringArray throws and exception when required value isn't set"(){
		setup:
		Properties config = new Properties()

		when:
		String[] result =SettingsUtils.parseStringArray(config,"somekey", ",", true)

		then:
		thrown(MessageException)
				 
	 }
	 
	 @Test
	 def "Test that getRequiredProperty throws and exception when required value isn't set"(){
		setup:
		Properties config = new Properties()

		when:
		SettingsUtils.getRequiredProperty(config,"somekey")

		then:
		thrown(MessageException)
		
		when:
		config.setProperty("somekey"," ")
		SettingsUtils.getRequiredProperty(config,"somekey")

		then:
		thrown(MessageException)
				 
	 }
	 
	 @Test
	 def "Test that getRequiredProperty fetches value as expected"(){
		setup:
		Properties config = new Properties()
		config.setProperty("somekey","somevalue")
		when:
		String value = SettingsUtils.getRequiredProperty(config,"somekey")

		then:
		assert value == "somevalue"
				 
	 }
	 
	 

	

}
