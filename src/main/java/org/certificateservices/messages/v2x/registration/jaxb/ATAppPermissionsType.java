//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.05.30 at 07:57:06 AM CEST 
//


package org.certificateservices.messages.v2x.registration.jaxb;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ATAppPermissionsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ATAppPermissionsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="appPermission" type="{http://certificateservices.org/xsd/v2x_registration_2_0}AppPermissionsType" maxOccurs="256"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ATAppPermissionsType", propOrder = {
    "appPermission"
})
public class ATAppPermissionsType {

    @XmlElement(required = true)
    protected List<AppPermissionsType> appPermission;

    /**
     * Gets the value of the appPermission property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the appPermission property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAppPermission().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link AppPermissionsType }
     * 
     * 
     */
    public List<AppPermissionsType> getAppPermission() {
        if (appPermission == null) {
            appPermission = new ArrayList<AppPermissionsType>();
        }
        return this.appPermission;
    }

}
