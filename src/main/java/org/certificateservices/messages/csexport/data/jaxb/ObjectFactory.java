//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.02.15 at 11:42:53 AM CET 
//


package org.certificateservices.messages.csexport.data.jaxb;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;
import org.certificateservices.messages.xmldsig.jaxb.SignatureType;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the org.certificateservices.messages.csexport.data.jaxb package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _Signature_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "Signature");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: org.certificateservices.messages.csexport.data.jaxb
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link CSExport }
     * 
     */
    public CSExport createCSExport() {
        return new CSExport();
    }

    /**
     * Create an instance of {@link FieldConstraint }
     * 
     */
    public FieldConstraint createFieldConstraint() {
        return new FieldConstraint();
    }

    /**
     * Create an instance of {@link ConditionalList }
     * 
     */
    public ConditionalList createConditionalList() {
        return new ConditionalList();
    }

    /**
     * Create an instance of {@link TokenTypeLifeCycleRule }
     * 
     */
    public TokenTypeLifeCycleRule createTokenTypeLifeCycleRule() {
        return new TokenTypeLifeCycleRule();
    }

    /**
     * Create an instance of {@link Department }
     * 
     */
    public Department createDepartment() {
        return new Department();
    }

    /**
     * Create an instance of {@link TokenType }
     * 
     */
    public TokenType createTokenType() {
        return new TokenType();
    }

    /**
     * Create an instance of {@link Organisation }
     * 
     */
    public Organisation createOrganisation() {
        return new Organisation();
    }

    /**
     * Create an instance of {@link CSExport.Organisations }
     * 
     */
    public CSExport.Organisations createCSExportOrganisations() {
        return new CSExport.Organisations();
    }

    /**
     * Create an instance of {@link CSExport.TokenTypes }
     * 
     */
    public CSExport.TokenTypes createCSExportTokenTypes() {
        return new CSExport.TokenTypes();
    }

    /**
     * Create an instance of {@link TokenTypeOrganisation }
     * 
     */
    public TokenTypeOrganisation createTokenTypeOrganisation() {
        return new TokenTypeOrganisation();
    }

    /**
     * Create an instance of {@link DomainNameRestriction }
     * 
     */
    public DomainNameRestriction createDomainNameRestriction() {
        return new DomainNameRestriction();
    }

    /**
     * Create an instance of {@link DepartmentAttribute }
     * 
     */
    public DepartmentAttribute createDepartmentAttribute() {
        return new DepartmentAttribute();
    }

    /**
     * Create an instance of {@link CredentialConstraint }
     * 
     */
    public CredentialConstraint createCredentialConstraint() {
        return new CredentialConstraint();
    }

    /**
     * Create an instance of {@link TokenContainerInfoEx }
     * 
     */
    public TokenContainerInfoEx createTokenContainerInfoEx() {
        return new TokenContainerInfoEx();
    }

    /**
     * Create an instance of {@link ValidityRestriction }
     * 
     */
    public ValidityRestriction createValidityRestriction() {
        return new ValidityRestriction();
    }

    /**
     * Create an instance of {@link ConditionalListAvailableList }
     * 
     */
    public ConditionalListAvailableList createConditionalListAvailableList() {
        return new ConditionalListAvailableList();
    }

    /**
     * Create an instance of {@link ConditionalListInListMapping }
     * 
     */
    public ConditionalListInListMapping createConditionalListInListMapping() {
        return new ConditionalListInListMapping();
    }

    /**
     * Create an instance of {@link RelatedTokenAttribute }
     * 
     */
    public RelatedTokenAttribute createRelatedTokenAttribute() {
        return new RelatedTokenAttribute();
    }

    /**
     * Create an instance of {@link FieldConstraint.AvailableValues }
     * 
     */
    public FieldConstraint.AvailableValues createFieldConstraintAvailableValues() {
        return new FieldConstraint.AvailableValues();
    }

    /**
     * Create an instance of {@link FieldConstraint.DomainNameRestrictions }
     * 
     */
    public FieldConstraint.DomainNameRestrictions createFieldConstraintDomainNameRestrictions() {
        return new FieldConstraint.DomainNameRestrictions();
    }

    /**
     * Create an instance of {@link FieldConstraint.RelatedTokenAttributes }
     * 
     */
    public FieldConstraint.RelatedTokenAttributes createFieldConstraintRelatedTokenAttributes() {
        return new FieldConstraint.RelatedTokenAttributes();
    }

    /**
     * Create an instance of {@link ConditionalList.AvailableLists }
     * 
     */
    public ConditionalList.AvailableLists createConditionalListAvailableLists() {
        return new ConditionalList.AvailableLists();
    }

    /**
     * Create an instance of {@link ConditionalList.InListMappings }
     * 
     */
    public ConditionalList.InListMappings createConditionalListInListMappings() {
        return new ConditionalList.InListMappings();
    }

    /**
     * Create an instance of {@link TokenTypeLifeCycleRule.TokenClasses }
     * 
     */
    public TokenTypeLifeCycleRule.TokenClasses createTokenTypeLifeCycleRuleTokenClasses() {
        return new TokenTypeLifeCycleRule.TokenClasses();
    }

    /**
     * Create an instance of {@link TokenTypeLifeCycleRule.CredentialSubTypes }
     * 
     */
    public TokenTypeLifeCycleRule.CredentialSubTypes createTokenTypeLifeCycleRuleCredentialSubTypes() {
        return new TokenTypeLifeCycleRule.CredentialSubTypes();
    }

    /**
     * Create an instance of {@link Department.Attributes }
     * 
     */
    public Department.Attributes createDepartmentAttributes() {
        return new Department.Attributes();
    }

    /**
     * Create an instance of {@link TokenType.Organisations }
     * 
     */
    public TokenType.Organisations createTokenTypeOrganisations() {
        return new TokenType.Organisations();
    }

    /**
     * Create an instance of {@link TokenType.FieldConstraints }
     * 
     */
    public TokenType.FieldConstraints createTokenTypeFieldConstraints() {
        return new TokenType.FieldConstraints();
    }

    /**
     * Create an instance of {@link TokenType.CredentialConstraints }
     * 
     */
    public TokenType.CredentialConstraints createTokenTypeCredentialConstraints() {
        return new TokenType.CredentialConstraints();
    }

    /**
     * Create an instance of {@link TokenType.KeySpecConstraints }
     * 
     */
    public TokenType.KeySpecConstraints createTokenTypeKeySpecConstraints() {
        return new TokenType.KeySpecConstraints();
    }

    /**
     * Create an instance of {@link TokenType.TokenContainerConstraints }
     * 
     */
    public TokenType.TokenContainerConstraints createTokenTypeTokenContainerConstraints() {
        return new TokenType.TokenContainerConstraints();
    }

    /**
     * Create an instance of {@link TokenType.KeystoreTypes }
     * 
     */
    public TokenType.KeystoreTypes createTokenTypeKeystoreTypes() {
        return new TokenType.KeystoreTypes();
    }

    /**
     * Create an instance of {@link TokenType.TokenTypeLifeCycleRules }
     * 
     */
    public TokenType.TokenTypeLifeCycleRules createTokenTypeTokenTypeLifeCycleRules() {
        return new TokenType.TokenTypeLifeCycleRules();
    }

    /**
     * Create an instance of {@link TokenType.ValidityRestrictions }
     * 
     */
    public TokenType.ValidityRestrictions createTokenTypeValidityRestrictions() {
        return new TokenType.ValidityRestrictions();
    }

    /**
     * Create an instance of {@link Organisation.Departments }
     * 
     */
    public Organisation.Departments createOrganisationDepartments() {
        return new Organisation.Departments();
    }


}