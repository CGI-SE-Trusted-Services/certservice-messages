package org.certificateservices.messages.saml2.assertion;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.saml2.BaseSAMLMessageParser;
import org.certificateservices.messages.saml2.assertion.jaxb.*;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.utils.XMLSigner;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.transform.dom.DOMResult;
import java.util.Date;
import java.util.List;

/**
 * MessageParser for generating generate SAML 2.0 Assertions. This should be used when generating SAML Assertions
 * that is not connected to CSMessages. For CSMessage related assertions use AssertionPayloadParser.
 *
 * Created by philip on 02/01/17.
 */
public class SAMLAssertionMessageParser extends BaseSAMLMessageParser{

    private static final String BASE_JAXB_CONTEXT = "org.certificateservices.messages.saml2.assertion.jaxb:org.certificateservices.messages.saml2.protocol.jaxb:org.certificateservices.messages.xenc.jaxb:org.certificateservices.messages.xmldsig.jaxb";
    @Override
    public String getNameSpace() {
        return ASSERTION_NAMESPACE;
    }

    @Override
    public String getJAXBPackages() {
        return BASE_JAXB_CONTEXT;
    }

    @Override
    public String[] getDefaultSchemaLocations() throws SAXException {
        return new String[] {DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION,
                DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION,
                ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION,
                SAMLP_XSD_SCHEMA_2_0_RESOURCE_LOCATION};
    }

    @Override
    public XMLSigner.SignatureLocationFinder getSignatureLocationFinder(){
        return assertionSignatureLocationFinder;
    }

    @Override
    public XMLSigner.OrganisationLookup getOrganisationLookup(){
        return null;
    }

    /**
     * Method for generating a simple assertion data structure.
     * @param issuer the name if the issuer, set as NameIDType
     * @param notBefore the not before date
     * @param notOnOrAfter the expiration date
     * @param subjectId the name of the subject the assertion is related to.
     * @param attributes a list of attributes or encrypted attributes to add to the assertion.
     * @return a simply assertion.
     * @throws MessageProcessingException if internal problems occurred generating the assertion.
     */
    public JAXBElement<AssertionType> generateSimpleAssertion(String issuer, Date notBefore, Date notOnOrAfter, String subjectId, List<Object> attributes) throws MessageProcessingException{
        AttributeStatementType attributeStatementType = null;
        if(attributes != null) {
            attributeStatementType = of.createAttributeStatementType();
            for (Object attribute : attributes) {
                attributeStatementType.getAttributeOrEncryptedAttribute().add(attribute);
            }
        }

        NameIDType issuerNameType = of.createNameIDType();
        issuerNameType.setValue(issuer);


        NameIDType subjectNameType = of.createNameIDType();
        subjectNameType.setValue(subjectId);

        SubjectType subjectType = of.createSubjectType();
        subjectType.getContent().add(of.createNameID(subjectNameType));

        ConditionsType conditionsType = of.createConditionsType();
        conditionsType.setNotBefore(MessageGenerateUtils.dateToXMLGregorianCalendar(notBefore));
        conditionsType.setNotOnOrAfter(MessageGenerateUtils.dateToXMLGregorianCalendar(notOnOrAfter));

        AssertionType assertionType = of.createAssertionType();
        assertionType.setID("_" + MessageGenerateUtils.generateRandomUUID());
        assertionType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendar(systemTime.getSystemTime()));
        assertionType.setVersion(DEFAULT_SAML_VERSION);
        assertionType.setIssuer(issuerNameType);
        assertionType.setSubject(subjectType);
        assertionType.setConditions(conditionsType);
        if(attributeStatementType != null) {
            assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(attributeStatementType);
        }
        return of.createAssertion(assertionType);
    }

    /**
     * Method to verify a signature of an assertion in a parsed SAML message.
     * @param assertion the assertion to verify.
     * @throws MessageContentException
     * @throws MessageProcessingException
     */
    public  void verifyAssertionSignature(JAXBElement<AssertionType> assertion) throws MessageContentException, MessageProcessingException {
        DOMResult res = new DOMResult();
        try {
            getMarshaller().marshal(assertion, res);
        } catch (JAXBException e) {
            throw new MessageContentException("Error marshalling assertion: " + e.getMessage(),e);
        }

        xmlSigner.verifyEnvelopedSignature((Document) res.getNode(),getSignatureLocationFinder(),getOrganisationLookup());
    }


}
