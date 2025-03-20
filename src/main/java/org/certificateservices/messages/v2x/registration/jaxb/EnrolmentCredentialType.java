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
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Java class for EnrolmentCredentialType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="EnrolmentCredentialType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="type" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ProfileNameType"/>
 *         &lt;element name="hashedId" type="{http://certificateservices.org/xsd/v2x_registration_2_0}HashedIdType"/>
 *         &lt;element name="ecProfile" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ProfileNameType"/>
 *         &lt;element name="eaName" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ProfileNameType"/>
 *         &lt;element name="data" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *         &lt;element name="validFrom" type="{http://www.w3.org/2001/XMLSchema}dateTime"/>
 *         &lt;element name="expireDate" type="{http://www.w3.org/2001/XMLSchema}dateTime"/>
 *         &lt;element name="revocationDate" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="status" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ECStatusType"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "EnrolmentCredentialType", propOrder = {
    "type",
    "hashedId",
    "ecProfile",
    "eaName",
    "data",
    "validFrom",
    "expireDate",
    "revocationDate",
    "status"
})
public class EnrolmentCredentialType {

    @XmlElement(required = true)
    protected String type;
    @XmlElement(required = true)
    protected String hashedId;
    @XmlElement(required = true)
    protected String ecProfile;
    @XmlElement(required = true)
    protected String eaName;
    @XmlElement(required = true)
    protected byte[] data;
    @XmlElement(required = true)
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar validFrom;
    @XmlElement(required = true)
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar expireDate;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar revocationDate;
    @XmlElement(required = true)
    @XmlSchemaType(name = "string")
    protected ECStatusType status;

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setType(String value) {
        this.type = value;
    }

    /**
     * Gets the value of the hashedId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getHashedId() {
        return hashedId;
    }

    /**
     * Sets the value of the hashedId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setHashedId(String value) {
        this.hashedId = value;
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
     * Gets the value of the data property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Sets the value of the data property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setData(byte[] value) {
        this.data = value;
    }

    /**
     * Gets the value of the validFrom property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getValidFrom() {
        return validFrom;
    }

    /**
     * Sets the value of the validFrom property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setValidFrom(XMLGregorianCalendar value) {
        this.validFrom = value;
    }

    /**
     * Gets the value of the expireDate property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getExpireDate() {
        return expireDate;
    }

    /**
     * Sets the value of the expireDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setExpireDate(XMLGregorianCalendar value) {
        this.expireDate = value;
    }

    /**
     * Gets the value of the revocationDate property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getRevocationDate() {
        return revocationDate;
    }

    /**
     * Sets the value of the revocationDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setRevocationDate(XMLGregorianCalendar value) {
        this.revocationDate = value;
    }

    /**
     * Gets the value of the status property.
     * 
     * @return
     *     possible object is
     *     {@link ECStatusType }
     *     
     */
    public ECStatusType getStatus() {
        return status;
    }

    /**
     * Sets the value of the status property.
     * 
     * @param value
     *     allowed object is
     *     {@link ECStatusType }
     *     
     */
    public void setStatus(ECStatusType value) {
        this.status = value;
    }

}
