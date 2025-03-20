//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2018.02.02 at 11:17:20 AM CET 
//


package org.certificateservices.messages.credmanagement.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.certificateservices.messages.csmessages.jaxb.CSRequest;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/csmessages2_0}CSRequest">
 *       &lt;sequence>
 *         &lt;element name="issuerId" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="serialNumber" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="locale" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "issuerId",
    "serialNumber",
    "locale"
})
@XmlRootElement(name = "GetCredentialAvailableActionsRequest")
public class GetCredentialAvailableActionsRequest
    extends CSRequest
{

    @XmlElement(required = true)
    protected String issuerId;
    @XmlElement(required = true)
    protected String serialNumber;
    @XmlElement(defaultValue = "en")
    protected String locale;


    /**
     * Gets the value of the issuerId property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getIssuerId() {
        return issuerId;
    }

    /**
     * Sets the value of the issuerId property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setIssuerId(String value) {
        this.issuerId = value;
    }

    /**
     * Gets the value of the serialNumber property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * Sets the value of the serialNumber property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setSerialNumber(String value) {
        this.serialNumber = value;
    }

    /**
     * Gets the value of the locale property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLocale() {
        return locale;
    }

    /**
     * Sets the value of the locale property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLocale(String value) {
        this.locale = value;
    }

}
