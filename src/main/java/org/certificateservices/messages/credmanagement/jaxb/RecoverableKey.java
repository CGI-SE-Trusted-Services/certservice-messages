//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.03.07 at 08:36:38 AM CET 
//


package org.certificateservices.messages.credmanagement.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RecoverableKey complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RecoverableKey">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="relatedCredentialRequestId" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="encryptedData" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RecoverableKey", propOrder = {
    "relatedCredentialRequestId",
    "encryptedData"
})
public class RecoverableKey {

    protected int relatedCredentialRequestId;
    @XmlElement(required = true)
    protected byte[] encryptedData;

    /**
     * Gets the value of the relatedCredentialRequestId property.
     * 
     */
    public int getRelatedCredentialRequestId() {
        return relatedCredentialRequestId;
    }

    /**
     * Sets the value of the relatedCredentialRequestId property.
     * 
     */
    public void setRelatedCredentialRequestId(int value) {
        this.relatedCredentialRequestId = value;
    }

    /**
     * Gets the value of the encryptedData property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getEncryptedData() {
        return encryptedData;
    }

    /**
     * Sets the value of the encryptedData property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setEncryptedData(byte[] value) {
        this.encryptedData = value;
    }

}
