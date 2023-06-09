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
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/v2x_registration_2_0}BaseRegisterRequestType">
 *       &lt;sequence>
 *         &lt;element name="ecuType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="canonicalPublicKey" type="{http://certificateservices.org/xsd/v2x_registration_2_0}CanonicalKeyType"/>
 *         &lt;element name="eaName" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ProfileNameType"/>
 *         &lt;element name="atPermissions" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ATAppPermissionsType"/>
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
    "ecuType",
    "canonicalPublicKey",
    "eaName",
    "atPermissions"
})
@XmlRootElement(name = "RegisterITSSRequest")
public class RegisterITSSRequest
    extends BaseRegisterRequestType
{

    @XmlElement(required = true)
    protected String ecuType;
    @XmlElement(required = true)
    protected CanonicalKeyType canonicalPublicKey;
    @XmlElement(required = true)
    protected String eaName;
    @XmlElement(required = true)
    protected ATAppPermissionsType atPermissions;

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

}
