//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2012.09.23 at 02:26:35 PM CEST 
//


package org.certificateservices.messages.pkimessages.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for StoreHardTokenDataRequest complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="StoreHardTokenDataRequest">
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/pkimessages1_0}PKIRequest">
 *       &lt;sequence>
 *         &lt;element name="tokenSerial" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="relatedCredentialSerialNumber" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="relatedCredentialIssuerId" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="encryptedData" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "StoreHardTokenDataRequest", propOrder = {
    "tokenSerial",
    "relatedCredentialSerialNumber",
    "relatedCredentialIssuerId",
    "encryptedData"
})
public class StoreHardTokenDataRequest
    extends PKIRequest
{

    @XmlElement(required = true)
    protected String tokenSerial;
    @XmlElement(required = true)
    protected String relatedCredentialSerialNumber;
    @XmlElement(required = true)
    protected String relatedCredentialIssuerId;
    @XmlElement(required = true)
    protected byte[] encryptedData;

    /**
     * Gets the value of the tokenSerial property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTokenSerial() {
        return tokenSerial;
    }

    /**
     * Sets the value of the tokenSerial property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTokenSerial(String value) {
        this.tokenSerial = value;
    }

    /**
     * Gets the value of the relatedCredentialSerialNumber property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRelatedCredentialSerialNumber() {
        return relatedCredentialSerialNumber;
    }

    /**
     * Sets the value of the relatedCredentialSerialNumber property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRelatedCredentialSerialNumber(String value) {
        this.relatedCredentialSerialNumber = value;
    }

    /**
     * Gets the value of the relatedCredentialIssuerId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRelatedCredentialIssuerId() {
        return relatedCredentialIssuerId;
    }

    /**
     * Sets the value of the relatedCredentialIssuerId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRelatedCredentialIssuerId(String value) {
        this.relatedCredentialIssuerId = value;
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