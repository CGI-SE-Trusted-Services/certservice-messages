//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.01.10 at 07:01:27 AM MSK 
//


package org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.certificateservices.messages.saml2.assertion.jaxb.NameIDType;


/**
 * <p>Java class for MappedAttributeType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="MappedAttributeType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="AttributeAuthority" type="{urn:oasis:names:tc:SAML:2.0:assertion}NameIDType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="SamlAttributeName" type="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}PreferredSAMLAttributeNameType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="CertAttributeRef" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="CertNameType" default="rdn">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *             &lt;enumeration value="rdn"/>
 *             &lt;enumeration value="san"/>
 *             &lt;enumeration value="sda"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;attribute name="FriendlyName" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="DefaultValue" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="Required" type="{http://www.w3.org/2001/XMLSchema}boolean" default="false" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "MappedAttributeType", propOrder = {
    "attributeAuthority",
    "samlAttributeName"
})
public class MappedAttributeType {

    @XmlElement(name = "AttributeAuthority")
    protected List<NameIDType> attributeAuthority;
    @XmlElement(name = "SamlAttributeName")
    protected List<PreferredSAMLAttributeNameType> samlAttributeName;
    @XmlAttribute(name = "CertAttributeRef")
    protected String certAttributeRef;
    @XmlAttribute(name = "CertNameType")
    protected String certNameType;
    @XmlAttribute(name = "FriendlyName")
    protected String friendlyName;
    @XmlAttribute(name = "DefaultValue")
    protected String defaultValue;
    @XmlAttribute(name = "Required")
    protected Boolean required;

    /**
     * Gets the value of the attributeAuthority property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the attributeAuthority property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAttributeAuthority().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link NameIDType }
     * 
     * 
     */
    public List<NameIDType> getAttributeAuthority() {
        if (attributeAuthority == null) {
            attributeAuthority = new ArrayList<NameIDType>();
        }
        return this.attributeAuthority;
    }

    /**
     * Gets the value of the samlAttributeName property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the samlAttributeName property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSamlAttributeName().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link PreferredSAMLAttributeNameType }
     * 
     * 
     */
    public List<PreferredSAMLAttributeNameType> getSamlAttributeName() {
        if (samlAttributeName == null) {
            samlAttributeName = new ArrayList<PreferredSAMLAttributeNameType>();
        }
        return this.samlAttributeName;
    }

    /**
     * Gets the value of the certAttributeRef property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCertAttributeRef() {
        return certAttributeRef;
    }

    /**
     * Sets the value of the certAttributeRef property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCertAttributeRef(String value) {
        this.certAttributeRef = value;
    }

    /**
     * Gets the value of the certNameType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCertNameType() {
        if (certNameType == null) {
            return "rdn";
        } else {
            return certNameType;
        }
    }

    /**
     * Sets the value of the certNameType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCertNameType(String value) {
        this.certNameType = value;
    }

    /**
     * Gets the value of the friendlyName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getFriendlyName() {
        return friendlyName;
    }

    /**
     * Sets the value of the friendlyName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setFriendlyName(String value) {
        this.friendlyName = value;
    }

    /**
     * Gets the value of the defaultValue property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDefaultValue() {
        return defaultValue;
    }

    /**
     * Sets the value of the defaultValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDefaultValue(String value) {
        this.defaultValue = value;
    }

    /**
     * Gets the value of the required property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isRequired() {
        if (required == null) {
            return false;
        } else {
            return required;
        }
    }

    /**
     * Sets the value of the required property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setRequired(Boolean value) {
        this.required = value;
    }

}
