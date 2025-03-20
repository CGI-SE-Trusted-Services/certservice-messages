//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2018.01.04 at 04:35:43 PM MSK 
//


package org.certificateservices.messages.csagent.jaxb;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;
import org.certificateservices.messages.csmessages.jaxb.CSRequest;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/csmessages2_0}CSRequest">
 *       &lt;sequence>
 *         &lt;element name="agentId" type="{http://certificateservices.org/xsd/csmessages2_0}between1and250string"/>
 *         &lt;element name="scanId" type="{http://certificateservices.org/xsd/csmessages2_0}uuid"/>
 *         &lt;element name="scanTimeStamp" type="{http://www.w3.org/2001/XMLSchema}dateTime"/>
 *         &lt;element name="discoveredCredentialData" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="dcd" type="{http://certificateservices.org/xsd/cs_agent_protocol2_0}DiscoveredCredentialData" maxOccurs="100"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
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
    "agentId",
    "scanId",
    "scanTimeStamp",
    "discoveredCredentialData"
})
@XmlRootElement(name = "DiscoveredCredentialDataRequest")
public class DiscoveredCredentialDataRequest
    extends CSRequest
{

    @XmlElement(required = true)
    protected String agentId;
    @XmlElement(required = true)
    protected String scanId;
    @XmlElement(required = true)
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar scanTimeStamp;
    protected DiscoveredCredentialDataRequest.DiscoveredCredentialData discoveredCredentialData;

    /**
     * Gets the value of the agentId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAgentId() {
        return agentId;
    }

    /**
     * Sets the value of the agentId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAgentId(String value) {
        this.agentId = value;
    }

    /**
     * Gets the value of the scanId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getScanId() {
        return scanId;
    }

    /**
     * Sets the value of the scanId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setScanId(String value) {
        this.scanId = value;
    }

    /**
     * Gets the value of the scanTimeStamp property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getScanTimeStamp() {
        return scanTimeStamp;
    }

    /**
     * Sets the value of the scanTimeStamp property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setScanTimeStamp(XMLGregorianCalendar value) {
        this.scanTimeStamp = value;
    }

    /**
     * Gets the value of the discoveredCredentialData property.
     * 
     * @return
     *     possible object is
     *     {@link DiscoveredCredentialDataRequest.DiscoveredCredentialData }
     *     
     */
    public DiscoveredCredentialDataRequest.DiscoveredCredentialData getDiscoveredCredentialData() {
        return discoveredCredentialData;
    }

    /**
     * Sets the value of the discoveredCredentialData property.
     * 
     * @param value
     *     allowed object is
     *     {@link DiscoveredCredentialDataRequest.DiscoveredCredentialData }
     *     
     */
    public void setDiscoveredCredentialData(DiscoveredCredentialDataRequest.DiscoveredCredentialData value) {
        this.discoveredCredentialData = value;
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
     *         &lt;element name="dcd" type="{http://certificateservices.org/xsd/cs_agent_protocol2_0}DiscoveredCredentialData" maxOccurs="100"/>
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
        "dcd"
    })
    public static class DiscoveredCredentialData {

        @XmlElement(required = true)
        protected List<org.certificateservices.messages.csagent.jaxb.DiscoveredCredentialData> dcd;

        /**
         * Gets the value of the dcd property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the dcd property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getDcd().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link org.certificateservices.messages.csagent.jaxb.DiscoveredCredentialData }
         * 
         * 
         */
        public List<org.certificateservices.messages.csagent.jaxb.DiscoveredCredentialData> getDcd() {
            if (dcd == null) {
                dcd = new ArrayList<org.certificateservices.messages.csagent.jaxb.DiscoveredCredentialData>();
            }
            return this.dcd;
        }

    }

}
