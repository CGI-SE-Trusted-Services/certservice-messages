//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.05.30 at 07:57:06 AM CEST 
//


package org.certificateservices.messages.v2x.registration.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;
import org.certificateservices.messages.csmessages.jaxb.CSResponse;


/**
 * <p>Java class for BaseV2XResponseType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="BaseV2XResponseType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/csmessages2_0}CSResponse">
 *       &lt;sequence>
 *         &lt;element name="canonicalId" type="{http://certificateservices.org/xsd/v2x_registration_2_0}CanonicalIdType"/>
 *         &lt;element name="ecuType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="canonicalPublicKey" type="{http://certificateservices.org/xsd/v2x_registration_2_0}CanonicalKeyType"/>
 *         &lt;element name="eaName" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ProfileNameType"/>
 *         &lt;element name="ecProfile" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ProfileNameType" minOccurs="0"/>
 *         &lt;element name="atProfile" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ProfileNameType" minOccurs="0"/>
 *         &lt;element name="atPermissions" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ATAppPermissionsType"/>
 *         &lt;element name="itssValidFrom" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="itssValidTo" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="regions" type="{http://certificateservices.org/xsd/v2x_registration_2_0}RegionsType" minOccurs="0"/>
 *         &lt;element name="itssStatus" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ITSSStatusType"/>
 *         &lt;element name="enrolmentCredentials" type="{http://certificateservices.org/xsd/v2x_registration_2_0}EnrolmentCredentialsType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BaseV2XResponseType", propOrder = {
    "canonicalId",
    "ecuType",
    "canonicalPublicKey",
    "eaName",
    "ecProfile",
    "atProfile",
    "atPermissions",
    "itssValidFrom",
    "itssValidTo",
    "regions",
    "itssStatus",
    "enrolmentCredentials"
})
@XmlSeeAlso({
    DeactivateITSSResponse.class,
    ReactivateITSSResponse.class,
    GetITSSDataResponse.class,
    RegisterITSSResponse.class,
    UpdateITSSResponse.class
})
public class BaseV2XResponseType
    extends CSResponse
{

    @XmlElement(required = true)
    protected String canonicalId;
    @XmlElement(required = true)
    protected String ecuType;
    @XmlElement(required = true)
    protected CanonicalKeyType canonicalPublicKey;
    @XmlElement(required = true)
    protected String eaName;
    protected String ecProfile;
    protected String atProfile;
    @XmlElement(required = true)
    protected ATAppPermissionsType atPermissions;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar itssValidFrom;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar itssValidTo;
    protected RegionsType regions;
    @XmlElement(required = true)
    @XmlSchemaType(name = "string")
    protected ITSSStatusType itssStatus;
    protected EnrolmentCredentialsType enrolmentCredentials;

    /**
     * Gets the value of the canonicalId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCanonicalId() {
        return canonicalId;
    }

    /**
     * Sets the value of the canonicalId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCanonicalId(String value) {
        this.canonicalId = value;
    }

    /**
     * Gets the value of the ecuType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEcuType() {
        return ecuType;
    }

    /**
     * Sets the value of the ecuType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEcuType(String value) {
        this.ecuType = value;
    }

    /**
     * Gets the value of the canonicalPublicKey property.
     * 
     * @return
     *     possible object is
     *     {@link CanonicalKeyType }
     *     
     */
    public CanonicalKeyType getCanonicalPublicKey() {
        return canonicalPublicKey;
    }

    /**
     * Sets the value of the canonicalPublicKey property.
     * 
     * @param value
     *     allowed object is
     *     {@link CanonicalKeyType }
     *     
     */
    public void setCanonicalPublicKey(CanonicalKeyType value) {
        this.canonicalPublicKey = value;
    }

    /**
     * Gets the value of the eaName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEaName() {
        return eaName;
    }

    /**
     * Sets the value of the eaName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEaName(String value) {
        this.eaName = value;
    }

    /**
     * Gets the value of the ecProfile property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEcProfile() {
        return ecProfile;
    }

    /**
     * Sets the value of the ecProfile property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEcProfile(String value) {
        this.ecProfile = value;
    }

    /**
     * Gets the value of the atProfile property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAtProfile() {
        return atProfile;
    }

    /**
     * Sets the value of the atProfile property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAtProfile(String value) {
        this.atProfile = value;
    }

    /**
     * Gets the value of the atPermissions property.
     * 
     * @return
     *     possible object is
     *     {@link ATAppPermissionsType }
     *     
     */
    public ATAppPermissionsType getAtPermissions() {
        return atPermissions;
    }

    /**
     * Sets the value of the atPermissions property.
     * 
     * @param value
     *     allowed object is
     *     {@link ATAppPermissionsType }
     *     
     */
    public void setAtPermissions(ATAppPermissionsType value) {
        this.atPermissions = value;
    }

    /**
     * Gets the value of the itssValidFrom property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getItssValidFrom() {
        return itssValidFrom;
    }

    /**
     * Sets the value of the itssValidFrom property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setItssValidFrom(XMLGregorianCalendar value) {
        this.itssValidFrom = value;
    }

    /**
     * Gets the value of the itssValidTo property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getItssValidTo() {
        return itssValidTo;
    }

    /**
     * Sets the value of the itssValidTo property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setItssValidTo(XMLGregorianCalendar value) {
        this.itssValidTo = value;
    }

    /**
     * Gets the value of the regions property.
     * 
     * @return
     *     possible object is
     *     {@link RegionsType }
     *     
     */
    public RegionsType getRegions() {
        return regions;
    }

    /**
     * Sets the value of the regions property.
     * 
     * @param value
     *     allowed object is
     *     {@link RegionsType }
     *     
     */
    public void setRegions(RegionsType value) {
        this.regions = value;
    }

    /**
     * Gets the value of the itssStatus property.
     * 
     * @return
     *     possible object is
     *     {@link ITSSStatusType }
     *     
     */
    public ITSSStatusType getItssStatus() {
        return itssStatus;
    }

    /**
     * Sets the value of the itssStatus property.
     * 
     * @param value
     *     allowed object is
     *     {@link ITSSStatusType }
     *     
     */
    public void setItssStatus(ITSSStatusType value) {
        this.itssStatus = value;
    }

    /**
     * Gets the value of the enrolmentCredentials property.
     * 
     * @return
     *     possible object is
     *     {@link EnrolmentCredentialsType }
     *     
     */
    public EnrolmentCredentialsType getEnrolmentCredentials() {
        return enrolmentCredentials;
    }

    /**
     * Sets the value of the enrolmentCredentials property.
     * 
     * @param value
     *     allowed object is
     *     {@link EnrolmentCredentialsType }
     *     
     */
    public void setEnrolmentCredentials(EnrolmentCredentialsType value) {
        this.enrolmentCredentials = value;
    }

}