//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.02.15 at 11:42:53 AM CET 
//


package org.certificateservices.messages.csexport.data.jaxb;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for FieldConstraint complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="FieldConstraint">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="key">
 *           &lt;simpleType>
 *             &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *               &lt;pattern value="[a-z0-9_\-\.]+"/>
 *             &lt;/restriction>
 *           &lt;/simpleType>
 *         &lt;/element>
 *         &lt;element name="displayName" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="description" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="type" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="required" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="minLength" type="{http://www.w3.org/2001/XMLSchema}integer"/>
 *         &lt;element name="maxLength" type="{http://www.w3.org/2001/XMLSchema}integer"/>
 *         &lt;element name="minNumberOfFields" type="{http://www.w3.org/2001/XMLSchema}integer"/>
 *         &lt;element name="maxNumberOfFields" type="{http://www.w3.org/2001/XMLSchema}integer"/>
 *         &lt;element name="availableValues" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="availableValue" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="domainNameRestrictions" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="domainNameRestriction" type="{http://certificateservices.org/xsd/csexport_data_1_0}DomainNameRestriction" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="customRegexp" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="customLabel" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="customHelpText" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="isCustomTextResourceKey" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="relatedTokenAttributes">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="relatedTokenAttribute" type="{http://certificateservices.org/xsd/csexport_data_1_0}RelatedTokenAttribute" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="allowOnlyTrustedData" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="relatedField" type="{http://certificateservices.org/xsd/csexport_data_1_0}notemptystring" minOccurs="0"/>
 *         &lt;element name="availableConditionalList" type="{http://certificateservices.org/xsd/csexport_data_1_0}ConditionalList" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "FieldConstraint", propOrder = {
    "key",
    "displayName",
    "description",
    "type",
    "required",
    "minLength",
    "maxLength",
    "minNumberOfFields",
    "maxNumberOfFields",
    "availableValues",
    "domainNameRestrictions",
    "customRegexp",
    "customLabel",
    "customHelpText",
    "isCustomTextResourceKey",
    "relatedTokenAttributes",
    "allowOnlyTrustedData",
    "relatedField",
    "availableConditionalList"
})
public class FieldConstraint {

    @XmlElement(required = true)
    protected String key;
    protected String displayName;
    protected String description;
    @XmlElement(required = true)
    protected String type;
    @XmlElement(defaultValue = "false")
    protected Boolean required;
    @XmlElement(required = true)
    protected BigInteger minLength;
    @XmlElement(required = true)
    protected BigInteger maxLength;
    @XmlElement(required = true)
    protected BigInteger minNumberOfFields;
    @XmlElement(required = true)
    protected BigInteger maxNumberOfFields;
    protected FieldConstraint.AvailableValues availableValues;
    protected FieldConstraint.DomainNameRestrictions domainNameRestrictions;
    protected String customRegexp;
    protected String customLabel;
    protected String customHelpText;
    @XmlElement(defaultValue = "false")
    protected Boolean isCustomTextResourceKey;
    @XmlElement(required = true)
    protected FieldConstraint.RelatedTokenAttributes relatedTokenAttributes;
    @XmlElement(defaultValue = "false")
    protected Boolean allowOnlyTrustedData;
    protected String relatedField;
    protected ConditionalList availableConditionalList;

    /**
     * Gets the value of the key property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getKey() {
        return key;
    }

    /**
     * Sets the value of the key property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setKey(String value) {
        this.key = value;
    }

    /**
     * Gets the value of the displayName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Sets the value of the displayName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDisplayName(String value) {
        this.displayName = value;
    }

    /**
     * Gets the value of the description property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the value of the description property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDescription(String value) {
        this.description = value;
    }

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
     * Gets the value of the required property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isRequired() {
        return required;
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

    /**
     * Gets the value of the minLength property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getMinLength() {
        return minLength;
    }

    /**
     * Sets the value of the minLength property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setMinLength(BigInteger value) {
        this.minLength = value;
    }

    /**
     * Gets the value of the maxLength property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getMaxLength() {
        return maxLength;
    }

    /**
     * Sets the value of the maxLength property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setMaxLength(BigInteger value) {
        this.maxLength = value;
    }

    /**
     * Gets the value of the minNumberOfFields property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getMinNumberOfFields() {
        return minNumberOfFields;
    }

    /**
     * Sets the value of the minNumberOfFields property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setMinNumberOfFields(BigInteger value) {
        this.minNumberOfFields = value;
    }

    /**
     * Gets the value of the maxNumberOfFields property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getMaxNumberOfFields() {
        return maxNumberOfFields;
    }

    /**
     * Sets the value of the maxNumberOfFields property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setMaxNumberOfFields(BigInteger value) {
        this.maxNumberOfFields = value;
    }

    /**
     * Gets the value of the availableValues property.
     * 
     * @return
     *     possible object is
     *     {@link FieldConstraint.AvailableValues }
     *     
     */
    public FieldConstraint.AvailableValues getAvailableValues() {
        return availableValues;
    }

    /**
     * Sets the value of the availableValues property.
     * 
     * @param value
     *     allowed object is
     *     {@link FieldConstraint.AvailableValues }
     *     
     */
    public void setAvailableValues(FieldConstraint.AvailableValues value) {
        this.availableValues = value;
    }

    /**
     * Gets the value of the domainNameRestrictions property.
     * 
     * @return
     *     possible object is
     *     {@link FieldConstraint.DomainNameRestrictions }
     *     
     */
    public FieldConstraint.DomainNameRestrictions getDomainNameRestrictions() {
        return domainNameRestrictions;
    }

    /**
     * Sets the value of the domainNameRestrictions property.
     * 
     * @param value
     *     allowed object is
     *     {@link FieldConstraint.DomainNameRestrictions }
     *     
     */
    public void setDomainNameRestrictions(FieldConstraint.DomainNameRestrictions value) {
        this.domainNameRestrictions = value;
    }

    /**
     * Gets the value of the customRegexp property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCustomRegexp() {
        return customRegexp;
    }

    /**
     * Sets the value of the customRegexp property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCustomRegexp(String value) {
        this.customRegexp = value;
    }

    /**
     * Gets the value of the customLabel property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCustomLabel() {
        return customLabel;
    }

    /**
     * Sets the value of the customLabel property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCustomLabel(String value) {
        this.customLabel = value;
    }

    /**
     * Gets the value of the customHelpText property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCustomHelpText() {
        return customHelpText;
    }

    /**
     * Sets the value of the customHelpText property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCustomHelpText(String value) {
        this.customHelpText = value;
    }

    /**
     * Gets the value of the isCustomTextResourceKey property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsCustomTextResourceKey() {
        return isCustomTextResourceKey;
    }

    /**
     * Sets the value of the isCustomTextResourceKey property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsCustomTextResourceKey(Boolean value) {
        this.isCustomTextResourceKey = value;
    }

    /**
     * Gets the value of the relatedTokenAttributes property.
     * 
     * @return
     *     possible object is
     *     {@link FieldConstraint.RelatedTokenAttributes }
     *     
     */
    public FieldConstraint.RelatedTokenAttributes getRelatedTokenAttributes() {
        return relatedTokenAttributes;
    }

    /**
     * Sets the value of the relatedTokenAttributes property.
     * 
     * @param value
     *     allowed object is
     *     {@link FieldConstraint.RelatedTokenAttributes }
     *     
     */
    public void setRelatedTokenAttributes(FieldConstraint.RelatedTokenAttributes value) {
        this.relatedTokenAttributes = value;
    }

    /**
     * Gets the value of the allowOnlyTrustedData property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isAllowOnlyTrustedData() {
        return allowOnlyTrustedData;
    }

    /**
     * Sets the value of the allowOnlyTrustedData property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setAllowOnlyTrustedData(Boolean value) {
        this.allowOnlyTrustedData = value;
    }

    /**
     * Gets the value of the relatedField property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRelatedField() {
        return relatedField;
    }

    /**
     * Sets the value of the relatedField property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRelatedField(String value) {
        this.relatedField = value;
    }

    /**
     * Gets the value of the availableConditionalList property.
     * 
     * @return
     *     possible object is
     *     {@link ConditionalList }
     *     
     */
    public ConditionalList getAvailableConditionalList() {
        return availableConditionalList;
    }

    /**
     * Sets the value of the availableConditionalList property.
     * 
     * @param value
     *     allowed object is
     *     {@link ConditionalList }
     *     
     */
    public void setAvailableConditionalList(ConditionalList value) {
        this.availableConditionalList = value;
    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType>
     *   &lt;complexContent>
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *       &lt;sequence>
     *         &lt;element name="availableValue" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/>
     *       &lt;/sequence>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "availableValue"
    })
    public static class AvailableValues {

        protected List<String> availableValue;

        /**
         * Gets the value of the availableValue property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the availableValue property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getAvailableValue().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link String }
         * 
         * 
         */
        public List<String> getAvailableValue() {
            if (availableValue == null) {
                availableValue = new ArrayList<String>();
            }
            return this.availableValue;
        }

    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType>
     *   &lt;complexContent>
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *       &lt;sequence>
     *         &lt;element name="domainNameRestriction" type="{http://certificateservices.org/xsd/csexport_data_1_0}DomainNameRestriction" maxOccurs="unbounded" minOccurs="0"/>
     *       &lt;/sequence>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "domainNameRestriction"
    })
    public static class DomainNameRestrictions {

        protected List<DomainNameRestriction> domainNameRestriction;

        /**
         * Gets the value of the domainNameRestriction property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the domainNameRestriction property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getDomainNameRestriction().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link DomainNameRestriction }
         * 
         * 
         */
        public List<DomainNameRestriction> getDomainNameRestriction() {
            if (domainNameRestriction == null) {
                domainNameRestriction = new ArrayList<DomainNameRestriction>();
            }
            return this.domainNameRestriction;
        }

    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType>
     *   &lt;complexContent>
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *       &lt;sequence>
     *         &lt;element name="relatedTokenAttribute" type="{http://certificateservices.org/xsd/csexport_data_1_0}RelatedTokenAttribute" maxOccurs="unbounded" minOccurs="0"/>
     *       &lt;/sequence>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "relatedTokenAttribute"
    })
    public static class RelatedTokenAttributes {

        protected List<RelatedTokenAttribute> relatedTokenAttribute;

        /**
         * Gets the value of the relatedTokenAttribute property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the relatedTokenAttribute property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getRelatedTokenAttribute().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link RelatedTokenAttribute }
         * 
         * 
         */
        public List<RelatedTokenAttribute> getRelatedTokenAttribute() {
            if (relatedTokenAttribute == null) {
                relatedTokenAttribute = new ArrayList<RelatedTokenAttribute>();
            }
            return this.relatedTokenAttribute;
        }

    }

}