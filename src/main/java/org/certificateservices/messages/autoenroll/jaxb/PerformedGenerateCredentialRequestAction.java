//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.03.02 at 11:08:13 AM CET 
//


package org.certificateservices.messages.autoenroll.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.certificateservices.messages.csmessages.jaxb.CredentialRequest;


/**
 * <p>Java class for PerformedGenerateCredentialRequestAction complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PerformedGenerateCredentialRequestAction">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="credentialRequest" type="{http://certificateservices.org/xsd/csmessages2_0}CredentialRequest"/>
 *         &lt;element name="encryptedKey" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PerformedGenerateCredentialRequestAction", propOrder = {
    "credentialRequest",
    "encryptedKey"
})
public class PerformedGenerateCredentialRequestAction {

    @XmlElement(required = true)
    protected CredentialRequest credentialRequest;
    protected byte[] encryptedKey;

    /**
     * Gets the value of the credentialRequest property.
     * 
     * @return
     *     possible object is
     *     {@link CredentialRequest }
     *     
     */
    public CredentialRequest getCredentialRequest() {
        return credentialRequest;
    }

    /**
     * Sets the value of the credentialRequest property.
     * 
     * @param value
     *     allowed object is
     *     {@link CredentialRequest }
     *     
     */
    public void setCredentialRequest(CredentialRequest value) {
        this.credentialRequest = value;
    }

    /**
     * Gets the value of the encryptedKey property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    /**
     * Sets the value of the encryptedKey property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setEncryptedKey(byte[] value) {
        this.encryptedKey = value;
    }

}
