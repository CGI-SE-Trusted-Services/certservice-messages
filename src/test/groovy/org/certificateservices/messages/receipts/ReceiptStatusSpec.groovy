/************************************************************************
*                                                                       *
*  Certificate Service - EJBCA Components                               *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages.receipts;

import org.certificateservices.messages.receipts.ReceiptStatus;
import org.junit.Test

import spock.lang.Specification
import spock.lang.Unroll

public class ReceiptStatusSpec extends Specification{



	
	@Test
	@Unroll
	def "Test findById return returns correct status #expectedStatus for id #id"(){
		when:
		ReceiptStatus s = ReceiptStatus.findById(id)
		
	
		then:
		assert s == expectedStatus
		
		where:
		id  | expectedStatus
		-3  | ReceiptStatus.RECIEVED_WITH_BAD_SIGNATURE
		-2  | ReceiptStatus.RECIEVED_WITH_PAYLOAD_ERROR
		-1  | ReceiptStatus.RECIEVED_WITH_HEADER_ERROR
		0   | ReceiptStatus.SENT
		1   | ReceiptStatus.RECIEVED_OK
		2   | null
	}
	
}
