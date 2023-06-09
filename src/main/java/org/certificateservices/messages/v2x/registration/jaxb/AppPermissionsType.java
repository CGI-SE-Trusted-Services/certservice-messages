//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.05.30 at 07:57:06 AM CEST 
//


package org.certificateservices.messages.v2x.registration.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;


/**
 * <p>Java class for AppPermissionsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AppPermissionsType">
 *   &lt;simpleContent>
 *     &lt;extension base="&lt;http://certificateservices.org/xsd/v2x_registration_2_0>PermissionDataType">
 *       &lt;attribute name="psId" use="required" type="{http://www.w3.org/2001/XMLSchema}int" />
 *       &lt;attribute name="type" type="{http://certificateservices.org/xsd/v2x_registration_2_0}PermissionType" default="bitmap" />
 *     &lt;/extension>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AppPermissionsType", propOrder = {
    "value"
})
public class AppPermissionsType {

    @XmlValue
    protected String value;
    @XmlAttribute(name = "psId", required = true)
    protected int psId;
    @XmlAttribute(name = "type")
    protected PermissionType type;

    /**
     * Gets the value of the value property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getValue() {
        return value;
    }

    /**
     * Sets the value of the value property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setValue(String value) {
        this.value = value;
    }

    /**
     * Gets the value of the psId property.
     * 
     */
    public int getPsId() {
        return psId;
    }

    /**
     * Sets the value of the psId property.
     * 
     */
    public void setPsId(int value) {
        this.psId = value;
    }

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link PermissionType }
     *     
     */
    public PermissionType getType() {
        if (type == null) {
            return PermissionType.BITMAP;
        } else {
            return type;
        }
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link PermissionType }
     *     
     */
    public void setType(PermissionType value) {
        this.type = value;
    }

}
