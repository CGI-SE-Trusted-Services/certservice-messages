//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.03.01 at 08:01:08 PM CET 
//


package org.certificateservices.messages.sensitivekeys.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for AsymmetricKey complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AsymmetricKey">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="publicKey" type="{http://certificateservices.org/xsd/sensitivekeys}EncodedKey"/>
 *         &lt;element name="privateKey" type="{http://certificateservices.org/xsd/sensitivekeys}EncodedKey"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AsymmetricKey", propOrder = {
    "publicKey",
    "privateKey"
})
public class AsymmetricKey {

    @XmlElement(required = true)
    protected EncodedKey publicKey;
    @XmlElement(required = true)
    protected EncodedKey privateKey;

    /**
     * Gets the value of the publicKey property.
     * 
     * @return
     *     possible object is
     *     {@link EncodedKey }
     *     
     */
    public EncodedKey getPublicKey() {
        return publicKey;
    }

    /**
     * Sets the value of the publicKey property.
     * 
     * @param value
     *     allowed object is
     *     {@link EncodedKey }
     *     
     */
    public void setPublicKey(EncodedKey value) {
        this.publicKey = value;
    }

    /**
     * Gets the value of the privateKey property.
     * 
     * @return
     *     possible object is
     *     {@link EncodedKey }
     *     
     */
    public EncodedKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Sets the value of the privateKey property.
     * 
     * @param value
     *     allowed object is
     *     {@link EncodedKey }
     *     
     */
    public void setPrivateKey(EncodedKey value) {
        this.privateKey = value;
    }

}
