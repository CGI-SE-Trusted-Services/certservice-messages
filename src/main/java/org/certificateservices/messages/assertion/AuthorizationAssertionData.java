/**
 * 
 */
package org.certificateservices.messages.assertion;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.assertion.jaxb.AssertionType;
import org.certificateservices.messages.assertion.jaxb.AttributeStatementType;
import org.certificateservices.messages.assertion.jaxb.AttributeType;

/**
 * Value object containing information about and Authorization Ticketr Assertion.
 * 
 * @author Philip Vendil
 *
 */
public class AuthorizationAssertionData extends AssertionData {

	private List<String> roles;

	/**
	 * Main Constructor
	 */
	public AuthorizationAssertionData(AssertionPayloadParser assertionPayloadParser){
		super(assertionPayloadParser);
	}
	
	/**
	 * Main parser called by AssertionPayloadParser after decryption.
	 */
	@Override
	public void parse(JAXBElement<AssertionType> assertion)
			throws MessageContentException, MessageProcessingException {
		parseCommonData(assertion);
		
		try{
			for(Object nextStatement : assertion.getValue().getStatementOrAuthnStatementOrAuthzDecisionStatement()){
				if(nextStatement instanceof AttributeStatementType){
					for(Object attr : ((AttributeStatementType) nextStatement).getAttributeOrEncryptedAttribute()){
						if(attr instanceof AttributeType){

							if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_ROLES)){
								roles = new ArrayList<String>();
								for(Object next : ((AttributeType) attr).getAttributeValue()){
									if(next instanceof String){
										roles.add((String) next);
									}
								}						
							}
						}
					}
				}
			}
		}catch(Exception e){
			throw new MessageContentException("Error parsing Authorization Assertion: " + e.getMessage(), e);
		}	
	}

	/**
	 * @return roles a list of roles the user has.
	 */
	public List<String> getRoles() {
		return roles;
	}

	@Override
	public String toString() {
		return "AuthorizationAssertionData [roles=" + roles
				+ ", id="
				+ getId() + ", notBefore=" + getNotBefore()
				+ ", notOnOrAfter=" + getNotOnOrAfter()
				+ ", subjectId=" + getSubjectId()
				+ ", signCertificate=" + getSignCertificate().toString() + "]";
	}

	
	
}
