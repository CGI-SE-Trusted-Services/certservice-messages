//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.01.10 at 07:01:27 AM MSK 
//


package org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;
import org.certificateservices.messages.saml2.assertion.jaxb.AttributeStatementType;
import org.certificateservices.messages.saml2.assertion.jaxb.ConditionsType;
import org.certificateservices.messages.saml2.assertion.jaxb.NameIDType;


/**
 * <p>Java class for SignRequestExtensionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SignRequestExtensionType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}RequestTime"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}Conditions"/>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}Signer" minOccurs="0"/>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}IdentityProvider"/>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}SignRequester"/>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}SignService"/>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}RequestedSignatureAlgorithm" minOccurs="0"/>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}CertRequestProperties" minOccurs="0"/>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}SignMessage" minOccurs="0"/>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}OtherRequestInfo" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Version" type="{http://www.w3.org/2001/XMLSchema}string" default="1.1" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SignRequestExtensionType", propOrder = {
    "requestTime",
    "conditions",
    "signer",
    "identityProvider",
    "signRequester",
    "signService",
    "requestedSignatureAlgorithm",
    "certRequestProperties",
    "signMessage",
    "otherRequestInfo"
})
public class SignRequestExtensionType {

    @XmlElement(name = "RequestTime", required = true)
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar requestTime;
    @XmlElement(name = "Conditions", namespace = "urn:oasis:names:tc:SAML:2.0:assertion", required = true)
    protected ConditionsType conditions;
    @XmlElement(name = "Signer")
    protected AttributeStatementType signer;
    @XmlElement(name = "IdentityProvider", required = true)
    protected NameIDType identityProvider;
    @XmlElement(name = "SignRequester", required = true)
    protected NameIDType signRequester;
    @XmlElement(name = "SignService", required = true)
    protected NameIDType signService;
    @XmlElement(name = "RequestedSignatureAlgorithm")
    @XmlSchemaType(name = "anyURI")
    protected String requestedSignatureAlgorithm;
    @XmlElement(name = "CertRequestProperties")
    protected CertRequestPropertiesType certRequestProperties;
    @XmlElement(name = "SignMessage")
    protected SignMessageType signMessage;
    @XmlElement(name = "OtherRequestInfo")
    protected AnyType otherRequestInfo;
    @XmlAttribute(name = "Version")
    protected String version;

    /**
     * Gets the value of the requestTime property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getRequestTime() {
        return requestTime;
    }

    /**
     * Sets the value of the requestTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setRequestTime(XMLGregorianCalendar value) {
        this.requestTime = value;
    }

    /**
     * Conditions that MUST be evaluated when
     *                         assessing the validity of and/or
     *                         when using the Sign Request. See Section 2.5 of [SAML2.0]for additional
     *                         information on how to evaluate condition
     *                         s.
     *                         This element MUST include the attributes NotBefore and NotOnOrAfter and
     *                         MUST include the element saml:AudienceRestriction which in turn MUST
     *                         contain one saml:Audience element, specifying the return URL for any
     *                         resulting Sign Response message.
     *                     
     * 
     * @return
     *     possible object is
     *     {@link ConditionsType }
     *     
     */
    public ConditionsType getConditions() {
        return conditions;
    }

    /**
     * Sets the value of the conditions property.
     * 
     * @param value
     *     allowed object is
     *     {@link ConditionsType }
     *     
     */
    public void setConditions(ConditionsType value) {
        this.conditions = value;
    }

    /**
     * Gets the value of the signer property.
     * 
     * @return
     *     possible object is
     *     {@link AttributeStatementType }
     *     
     */
    public AttributeStatementType getSigner() {
        return signer;
    }

    /**
     * Sets the value of the signer property.
     * 
     * @param value
     *     allowed object is
     *     {@link AttributeStatementType }
     *     
     */
    public void setSigner(AttributeStatementType value) {
        this.signer = value;
    }

    /**
     * Gets the value of the identityProvider property.
     * 
     * @return
     *     possible object is
     *     {@link NameIDType }
     *     
     */
    public NameIDType getIdentityProvider() {
        return identityProvider;
    }

    /**
     * Sets the value of the identityProvider property.
     * 
     * @param value
     *     allowed object is
     *     {@link NameIDType }
     *     
     */
    public void setIdentityProvider(NameIDType value) {
        this.identityProvider = value;
    }

    /**
     * Gets the value of the signRequester property.
     * 
     * @return
     *     possible object is
     *     {@link NameIDType }
     *     
     */
    public NameIDType getSignRequester() {
        return signRequester;
    }

    /**
     * Sets the value of the signRequester property.
     * 
     * @param value
     *     allowed object is
     *     {@link NameIDType }
     *     
     */
    public void setSignRequester(NameIDType value) {
        this.signRequester = value;
    }

    /**
     * Gets the value of the signService property.
     * 
     * @return
     *     possible object is
     *     {@link NameIDType }
     *     
     */
    public NameIDType getSignService() {
        return signService;
    }

    /**
     * Sets the value of the signService property.
     * 
     * @param value
     *     allowed object is
     *     {@link NameIDType }
     *     
     */
    public void setSignService(NameIDType value) {
        this.signService = value;
    }

    /**
     * Gets the value of the requestedSignatureAlgorithm property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRequestedSignatureAlgorithm() {
        return requestedSignatureAlgorithm;
    }

    /**
     * Sets the value of the requestedSignatureAlgorithm property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRequestedSignatureAlgorithm(String value) {
        this.requestedSignatureAlgorithm = value;
    }

    /**
     * Gets the value of the certRequestProperties property.
     * 
     * @return
     *     possible object is
     *     {@link CertRequestPropertiesType }
     *     
     */
    public CertRequestPropertiesType getCertRequestProperties() {
        return certRequestProperties;
    }

    /**
     * Sets the value of the certRequestProperties property.
     * 
     * @param value
     *     allowed object is
     *     {@link CertRequestPropertiesType }
     *     
     */
    public void setCertRequestProperties(CertRequestPropertiesType value) {
        this.certRequestProperties = value;
    }

    /**
     * Gets the value of the signMessage property.
     * 
     * @return
     *     possible object is
     *     {@link SignMessageType }
     *     
     */
    public SignMessageType getSignMessage() {
        return signMessage;
    }

    /**
     * Sets the value of the signMessage property.
     * 
     * @param value
     *     allowed object is
     *     {@link SignMessageType }
     *     
     */
    public void setSignMessage(SignMessageType value) {
        this.signMessage = value;
    }

    /**
     * Gets the value of the otherRequestInfo property.
     * 
     * @return
     *     possible object is
     *     {@link AnyType }
     *     
     */
    public AnyType getOtherRequestInfo() {
        return otherRequestInfo;
    }

    /**
     * Sets the value of the otherRequestInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link AnyType }
     *     
     */
    public void setOtherRequestInfo(AnyType value) {
        this.otherRequestInfo = value;
    }

    /**
     * Gets the value of the version property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getVersion() {
        if (version == null) {
            return "1.1";
        } else {
            return version;
        }
    }

    /**
     * Sets the value of the version property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setVersion(String value) {
        this.version = value;
    }

}