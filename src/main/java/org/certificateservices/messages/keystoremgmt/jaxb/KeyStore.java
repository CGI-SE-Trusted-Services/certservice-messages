//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.06.02 at 10:40:08 AM CEST 
//


package org.certificateservices.messages.keystoremgmt.jaxb;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

import org.certificateservices.messages.csmessages.jaxb.Organisation;


/**
 * <p>Java class for KeyStore complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="KeyStore">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="providerName" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="status" type="{http://certificateservices.org/xsd/keystoremgmt2_0}KeyStoreStatus"/>
 *         &lt;element name="relatedOrganisations" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="organisation" type="{http://certificateservices.org/xsd/csmessages2_0}Organisation" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="keyInfos">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="keyInfo" type="{http://certificateservices.org/xsd/keystoremgmt2_0}KeyInfo" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KeyStore", namespace = "http://certificateservices.org/xsd/keystoremgmt2_0", propOrder = {
    "providerName",
    "status",
    "relatedOrganisations",
    "keyInfos"
})
public class KeyStore {

    @XmlElement(required = true)
    protected String providerName;
    @XmlElement(required = true)
    protected KeyStoreStatus status;
    protected KeyStore.RelatedOrganisations relatedOrganisations;
    @XmlElement(required = true)
    protected KeyStore.KeyInfos keyInfos;

    /**
     * Gets the value of the providerName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getProviderName() {
        return providerName;
    }

    /**
     * Sets the value of the providerName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setProviderName(String value) {
        this.providerName = value;
    }

    /**
     * Gets the value of the status property.
     * 
     * @return
     *     possible object is
     *     {@link KeyStoreStatus }
     *     
     */
    public KeyStoreStatus getStatus() {
        return status;
    }

    /**
     * Sets the value of the status property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyStoreStatus }
     *     
     */
    public void setStatus(KeyStoreStatus value) {
        this.status = value;
    }

    /**
     * Gets the value of the relatedOrganisations property.
     * 
     * @return
     *     possible object is
     *     {@link KeyStore.RelatedOrganisations }
     *     
     */
    public KeyStore.RelatedOrganisations getRelatedOrganisations() {
        return relatedOrganisations;
    }

    /**
     * Sets the value of the relatedOrganisations property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyStore.RelatedOrganisations }
     *     
     */
    public void setRelatedOrganisations(KeyStore.RelatedOrganisations value) {
        this.relatedOrganisations = value;
    }

    /**
     * Gets the value of the keyInfos property.
     * 
     * @return
     *     possible object is
     *     {@link KeyStore.KeyInfos }
     *     
     */
    public KeyStore.KeyInfos getKeyInfos() {
        return keyInfos;
    }

    /**
     * Sets the value of the keyInfos property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyStore.KeyInfos }
     *     
     */
    public void setKeyInfos(KeyStore.KeyInfos value) {
        this.keyInfos = value;
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
     *         &lt;element name="keyInfo" type="{http://certificateservices.org/xsd/keystoremgmt2_0}KeyInfo" maxOccurs="unbounded" minOccurs="0"/>
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
        "keyInfo"
    })
    public static class KeyInfos {

        @XmlElement(namespace = "http://certificateservices.org/xsd/keystoremgmt2_0")
        protected List<KeyInfo> keyInfo;

        /**
         * Gets the value of the keyInfo property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the keyInfo property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getKeyInfo().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link KeyInfo }
         * 
         * 
         */
        public List<KeyInfo> getKeyInfo() {
            if (keyInfo == null) {
                keyInfo = new ArrayList<KeyInfo>();
            }
            return this.keyInfo;
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
     *         &lt;element name="organisation" type="{http://certificateservices.org/xsd/csmessages2_0}Organisation" maxOccurs="unbounded" minOccurs="0"/>
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
        "organisation"
    })
    public static class RelatedOrganisations {

        @XmlElement(namespace = "http://certificateservices.org/xsd/keystoremgmt2_0")
        protected List<Organisation> organisation;

        /**
         * Gets the value of the organisation property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the organisation property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getOrganisation().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link Organisation }
         * 
         * 
         */
        public List<Organisation> getOrganisation() {
            if (organisation == null) {
                organisation = new ArrayList<Organisation>();
            }
            return this.organisation;
        }

    }

}
