package org.certificateservices.messages.assertion

import spock.lang.Specification
import spock.lang.Unroll;
import static org.certificateservices.messages.assertion.AssertionTypeEnum.*

class AssertionTypeEnumSpec extends Specification {
	
	@Unroll
	def "verify that AssertionTypeEnum #type has assertion value #value"(){
		expect:
		type.attributeValue == value
		where:
		type                  | value
		APPROVAL_TICKET       | "APPROVAL_TICKET"
		USER_DATA             | "USER_DATA"
		AUTHORIZATION_TICKET  | "AUTHORIZATION_TICKET"
	}

}
