//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2012.09.23 at 02:26:35 PM CEST 
//


package org.certificateservices.messages.pkimessages.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


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
 *         &lt;element name="name" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="sourceId" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="destinationId" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="organisation" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="payload">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;choice>
 *                   &lt;element name="issueTokenCredentialsRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}IssueTokenCredentialsRequest"/>
 *                   &lt;element name="issueTokenCredentialsResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}IssueTokenCredentialsResponse"/>
 *                   &lt;element name="changeCredentialStatusRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}ChangeCredentialStatusRequest"/>
 *                   &lt;element name="changeCredentialStatusResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}ChangeCredentialStatusResponse"/>
 *                   &lt;element name="getCredentialRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}GetCredentialRequest"/>
 *                   &lt;element name="getCredentialResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}GetCredentialResponse"/>
 *                   &lt;element name="getCredentialStatusListRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}GetCredentialStatusListRequest"/>
 *                   &lt;element name="getCredentialStatusListResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}GetCredentialStatusListResponse"/>
 *                   &lt;element name="getIssuerCredentialsRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}GetIssuerCredentialsRequest"/>
 *                   &lt;element name="getIssuerCredentialsResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}GetIssuerCredentialsResponse"/>
 *                   &lt;element name="isIssuerRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}IsIssuerRequest"/>
 *                   &lt;element name="isIssuerResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}IsIssuerResponse"/>
 *                   &lt;element name="issueCredentialStatusListRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}IssueCredentialStatusListRequest"/>
 *                   &lt;element name="issueCredentialStatusListResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}IssueCredentialStatusListResponse"/>
 *                   &lt;element name="removeCredentialRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}RemoveCredentialRequest"/>
 *                   &lt;element name="removeCredentialResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}RemoveCredentialResponse"/>
 *                   &lt;element name="fetchHardTokenDataRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}FetchHardTokenDataRequest"/>
 *                   &lt;element name="fetchHardTokenDatarResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}FetchHardTokenDataResponse"/>
 *                   &lt;element name="storeHardTokenDataRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}StoreHardTokenDataRequest"/>
 *                   &lt;element name="storeHardTokenDataResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}StoreHardTokenDataResponse"/>
 *                   &lt;element name="failureResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}PKIResponse"/>
 *                 &lt;/choice>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element ref="{http://www.w3.org/2000/09/xmldsig#}Signature" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="version" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="ID" use="required" type="{http://certificateservices.org/xsd/pkimessages1_0}uuid" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "name",
    "sourceId",
    "destinationId",
    "organisation",
    "originator",
    "payload",
    "signature"
})
@XmlRootElement(name = "PKIMessage")
public class PKIMessage {

    @XmlElement(required = true)
    protected String name;
    @XmlElement(required = true)
    protected String sourceId;
    @XmlElement(required = true)
    protected String destinationId;
    @XmlElement(required = true)
    protected String organisation;
    protected Originator originator;
    @XmlElement(required = true)
    protected PKIMessage.Payload payload;
    @XmlElement(name = "Signature", namespace = "http://www.w3.org/2000/09/xmldsig#")
    protected Object signature;
    @XmlAttribute(name = "version", required = true)
    protected String version;
    @XmlAttribute(name = "ID", required = true)
    protected String id;
    @XmlAttribute(name = "timeStamp")
	private XMLGregorianCalendar timeStamp;

    /**
     * Gets the value of the name property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the value of the name property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setName(String value) {
        this.name = value;
    }

    /**
     * Gets the value of the sourceId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSourceId() {
        return sourceId;
    }

    /**
     * Sets the value of the sourceId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSourceId(String value) {
        this.sourceId = value;
    }

    /**
     * Gets the value of the destinationId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDestinationId() {
        return destinationId;
    }

    /**
     * Sets the value of the destinationId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDestinationId(String value) {
        this.destinationId = value;
    }
    
    /**
     * Gets the value of the Organisation property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getOrganisation() {
        return organisation;
    }

    /**
     * Sets the value of the Organisation property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOrganisation(String value) {
        this.organisation = value;
    }
    
    /**
     * Gets the value of the Originator property.
     * 
     * @return
     *     possible object is
     *     {@link Originator }
     *     
     */
    public Originator getOriginator() {
        return originator;
    }

    /**
     * Sets the value of the Originator property.
     * 
     * @param value
     *     allowed object is
     *     {@link Originator }
     *     
     */
    public void setOriginator(Originator originator) {
        this.originator = originator;
    }

    /**
     * Gets the value of the payload property.
     * 
     * @return
     *     possible object is
     *     {@link PKIMessage.Payload }
     *     
     */
    public PKIMessage.Payload getPayload() {
        return payload;
    }

    /**
     * Sets the value of the payload property.
     * 
     * @param value
     *     allowed object is
     *     {@link PKIMessage.Payload }
     *     
     */
    public void setPayload(PKIMessage.Payload value) {
        this.payload = value;
    }

    /**
     * Gets the value of the signature property.
     * 
     * @return
     *     possible object is
     *     {@link SignatureType }
     *     
     */
    public Object getSignature() {
        return signature;
    }

    /**
     * Sets the value of the signature property.
     * 
     * @param value
     *     allowed object is
     *     {@link SignatureType }
     *     
     */
    public void setSignature(Object value) {
        this.signature = value;
    }

    /**
     * Gets the value of the version property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getVersion() {
        return version;
    }

    /**
     * Sets the value of the version property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setVersion(String value) {
        this.version = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getID() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setID(String value) {
        this.id = value;
    }

    /**
     * Gets the value of the timeStamp property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getTimeStamp() {
		return timeStamp;
	}

    /**
     * Sets the value of the timeStamp property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
	public void setTimeStamp(XMLGregorianCalendar timeStamp) {
		this.timeStamp = timeStamp;
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
     *       &lt;choice>
     *         &lt;element name="issueTokenCredentialsRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}IssueTokenCredentialsRequest"/>
     *         &lt;element name="issueTokenCredentialsResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}IssueTokenCredentialsResponse"/>
     *         &lt;element name="changeCredentialStatusRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}ChangeCredentialStatusRequest"/>
     *         &lt;element name="changeCredentialStatusResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}ChangeCredentialStatusResponse"/>
     *         &lt;element name="getCredentialRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}GetCredentialRequest"/>
     *         &lt;element name="getCredentialResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}GetCredentialResponse"/>
     *         &lt;element name="getCredentialStatusListRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}GetCredentialStatusListRequest"/>
     *         &lt;element name="getCredentialStatusListResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}GetCredentialStatusListResponse"/>
     *         &lt;element name="getIssuerCredentialsRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}GetIssuerCredentialsRequest"/>
     *         &lt;element name="getIssuerCredentialsResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}GetIssuerCredentialsResponse"/>
     *         &lt;element name="isIssuerRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}IsIssuerRequest"/>
     *         &lt;element name="isIssuerResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}IsIssuerResponse"/>
     *         &lt;element name="issueCredentialStatusListRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}IssueCredentialStatusListRequest"/>
     *         &lt;element name="issueCredentialStatusListResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}IssueCredentialStatusListResponse"/>
     *         &lt;element name="removeCredentialRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}RemoveCredentialRequest"/>
     *         &lt;element name="removeCredentialResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}RemoveCredentialResponse"/>
     *         &lt;element name="fetchHardTokenDataRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}FetchHardTokenDataRequest"/>
     *         &lt;element name="fetchHardTokenDatarResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}FetchHardTokenDataResponse"/>
     *         &lt;element name="storeHardTokenDataRequest" type="{http://certificateservices.org/xsd/pkimessages1_0}StoreHardTokenDataRequest"/>
     *         &lt;element name="storeHardTokenDataResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}StoreHardTokenDataResponse"/>
     *         &lt;element name="failureResponse" type="{http://certificateservices.org/xsd/pkimessages1_0}PKIResponse"/>
     *       &lt;/choice>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "issueTokenCredentialsRequest",
        "issueTokenCredentialsResponse",
        "changeCredentialStatusRequest",
        "changeCredentialStatusResponse",
        "getCredentialRequest",
        "getCredentialResponse",
        "getCredentialStatusListRequest",
        "getCredentialStatusListResponse",
        "getIssuerCredentialsRequest",
        "getIssuerCredentialsResponse",
        "isIssuerRequest",
        "isIssuerResponse",
        "issueCredentialStatusListRequest",
        "issueCredentialStatusListResponse",
        "removeCredentialRequest",
        "removeCredentialResponse",
        "fetchHardTokenDataRequest",
        "fetchHardTokenDataResponse",
        "storeHardTokenDataRequest",
        "storeHardTokenDataResponse",
        "failureResponse"
    })
    public static class Payload {

        protected IssueTokenCredentialsRequest issueTokenCredentialsRequest;
        protected IssueTokenCredentialsResponse issueTokenCredentialsResponse;
        protected ChangeCredentialStatusRequest changeCredentialStatusRequest;
        protected ChangeCredentialStatusResponse changeCredentialStatusResponse;
        protected GetCredentialRequest getCredentialRequest;
        protected GetCredentialResponse getCredentialResponse;
        protected GetCredentialStatusListRequest getCredentialStatusListRequest;
        protected GetCredentialStatusListResponse getCredentialStatusListResponse;
        protected GetIssuerCredentialsRequest getIssuerCredentialsRequest;
        protected GetIssuerCredentialsResponse getIssuerCredentialsResponse;
        protected IsIssuerRequest isIssuerRequest;
        protected IsIssuerResponse isIssuerResponse;
        protected IssueCredentialStatusListRequest issueCredentialStatusListRequest;
        protected IssueCredentialStatusListResponse issueCredentialStatusListResponse;
        protected RemoveCredentialRequest removeCredentialRequest;
        protected RemoveCredentialResponse removeCredentialResponse;
        protected FetchHardTokenDataRequest fetchHardTokenDataRequest;
        protected FetchHardTokenDataResponse fetchHardTokenDataResponse;
        protected StoreHardTokenDataRequest storeHardTokenDataRequest;
        protected StoreHardTokenDataResponse storeHardTokenDataResponse;
        protected PKIResponse failureResponse;

        /**
         * Gets the value of the issueTokenCredentialsRequest property.
         * 
         * @return
         *     possible object is
         *     {@link IssueTokenCredentialsRequest }
         *     
         */
        public IssueTokenCredentialsRequest getIssueTokenCredentialsRequest() {
            return issueTokenCredentialsRequest;
        }

        /**
         * Sets the value of the issueTokenCredentialsRequest property.
         * 
         * @param value
         *     allowed object is
         *     {@link IssueTokenCredentialsRequest }
         *     
         */
        public void setIssueTokenCredentialsRequest(IssueTokenCredentialsRequest value) {
            this.issueTokenCredentialsRequest = value;
        }

        /**
         * Gets the value of the issueTokenCredentialsResponse property.
         * 
         * @return
         *     possible object is
         *     {@link IssueTokenCredentialsResponse }
         *     
         */
        public IssueTokenCredentialsResponse getIssueTokenCredentialsResponse() {
            return issueTokenCredentialsResponse;
        }

        /**
         * Sets the value of the issueTokenCredentialsResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link IssueTokenCredentialsResponse }
         *     
         */
        public void setIssueTokenCredentialsResponse(IssueTokenCredentialsResponse value) {
            this.issueTokenCredentialsResponse = value;
        }

        /**
         * Gets the value of the changeCredentialStatusRequest property.
         * 
         * @return
         *     possible object is
         *     {@link ChangeCredentialStatusRequest }
         *     
         */
        public ChangeCredentialStatusRequest getChangeCredentialStatusRequest() {
            return changeCredentialStatusRequest;
        }

        /**
         * Sets the value of the changeCredentialStatusRequest property.
         * 
         * @param value
         *     allowed object is
         *     {@link ChangeCredentialStatusRequest }
         *     
         */
        public void setChangeCredentialStatusRequest(ChangeCredentialStatusRequest value) {
            this.changeCredentialStatusRequest = value;
        }

        /**
         * Gets the value of the changeCredentialStatusResponse property.
         * 
         * @return
         *     possible object is
         *     {@link ChangeCredentialStatusResponse }
         *     
         */
        public ChangeCredentialStatusResponse getChangeCredentialStatusResponse() {
            return changeCredentialStatusResponse;
        }

        /**
         * Sets the value of the changeCredentialStatusResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link ChangeCredentialStatusResponse }
         *     
         */
        public void setChangeCredentialStatusResponse(ChangeCredentialStatusResponse value) {
            this.changeCredentialStatusResponse = value;
        }

        /**
         * Gets the value of the getCredentialRequest property.
         * 
         * @return
         *     possible object is
         *     {@link GetCredentialRequest }
         *     
         */
        public GetCredentialRequest getGetCredentialRequest() {
            return getCredentialRequest;
        }

        /**
         * Sets the value of the getCredentialRequest property.
         * 
         * @param value
         *     allowed object is
         *     {@link GetCredentialRequest }
         *     
         */
        public void setGetCredentialRequest(GetCredentialRequest value) {
            this.getCredentialRequest = value;
        }

        /**
         * Gets the value of the getCredentialResponse property.
         * 
         * @return
         *     possible object is
         *     {@link GetCredentialResponse }
         *     
         */
        public GetCredentialResponse getGetCredentialResponse() {
            return getCredentialResponse;
        }

        /**
         * Sets the value of the getCredentialResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link GetCredentialResponse }
         *     
         */
        public void setGetCredentialResponse(GetCredentialResponse value) {
            this.getCredentialResponse = value;
        }

        /**
         * Gets the value of the getCredentialStatusListRequest property.
         * 
         * @return
         *     possible object is
         *     {@link GetCredentialStatusListRequest }
         *     
         */
        public GetCredentialStatusListRequest getGetCredentialStatusListRequest() {
            return getCredentialStatusListRequest;
        }

        /**
         * Sets the value of the getCredentialStatusListRequest property.
         * 
         * @param value
         *     allowed object is
         *     {@link GetCredentialStatusListRequest }
         *     
         */
        public void setGetCredentialStatusListRequest(GetCredentialStatusListRequest value) {
            this.getCredentialStatusListRequest = value;
        }

        /**
         * Gets the value of the getCredentialStatusListResponse property.
         * 
         * @return
         *     possible object is
         *     {@link GetCredentialStatusListResponse }
         *     
         */
        public GetCredentialStatusListResponse getGetCredentialStatusListResponse() {
            return getCredentialStatusListResponse;
        }

        /**
         * Sets the value of the getCredentialStatusListResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link GetCredentialStatusListResponse }
         *     
         */
        public void setGetCredentialStatusListResponse(GetCredentialStatusListResponse value) {
            this.getCredentialStatusListResponse = value;
        }

        /**
         * Gets the value of the getIssuerCredentialsRequest property.
         * 
         * @return
         *     possible object is
         *     {@link GetIssuerCredentialsRequest }
         *     
         */
        public GetIssuerCredentialsRequest getGetIssuerCredentialsRequest() {
            return getIssuerCredentialsRequest;
        }

        /**
         * Sets the value of the getIssuerCredentialsRequest property.
         * 
         * @param value
         *     allowed object is
         *     {@link GetIssuerCredentialsRequest }
         *     
         */
        public void setGetIssuerCredentialsRequest(GetIssuerCredentialsRequest value) {
            this.getIssuerCredentialsRequest = value;
        }

        /**
         * Gets the value of the getIssuerCredentialsResponse property.
         * 
         * @return
         *     possible object is
         *     {@link GetIssuerCredentialsResponse }
         *     
         */
        public GetIssuerCredentialsResponse getGetIssuerCredentialsResponse() {
            return getIssuerCredentialsResponse;
        }

        /**
         * Sets the value of the getIssuerCredentialsResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link GetIssuerCredentialsResponse }
         *     
         */
        public void setGetIssuerCredentialsResponse(GetIssuerCredentialsResponse value) {
            this.getIssuerCredentialsResponse = value;
        }

        /**
         * Gets the value of the isIssuerRequest property.
         * 
         * @return
         *     possible object is
         *     {@link IsIssuerRequest }
         *     
         */
        public IsIssuerRequest getIsIssuerRequest() {
            return isIssuerRequest;
        }

        /**
         * Sets the value of the isIssuerRequest property.
         * 
         * @param value
         *     allowed object is
         *     {@link IsIssuerRequest }
         *     
         */
        public void setIsIssuerRequest(IsIssuerRequest value) {
            this.isIssuerRequest = value;
        }

        /**
         * Gets the value of the isIssuerResponse property.
         * 
         * @return
         *     possible object is
         *     {@link IsIssuerResponse }
         *     
         */
        public IsIssuerResponse getIsIssuerResponse() {
            return isIssuerResponse;
        }

        /**
         * Sets the value of the isIssuerResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link IsIssuerResponse }
         *     
         */
        public void setIsIssuerResponse(IsIssuerResponse value) {
            this.isIssuerResponse = value;
        }

        /**
         * Gets the value of the issueCredentialStatusListRequest property.
         * 
         * @return
         *     possible object is
         *     {@link IssueCredentialStatusListRequest }
         *     
         */
        public IssueCredentialStatusListRequest getIssueCredentialStatusListRequest() {
            return issueCredentialStatusListRequest;
        }

        /**
         * Sets the value of the issueCredentialStatusListRequest property.
         * 
         * @param value
         *     allowed object is
         *     {@link IssueCredentialStatusListRequest }
         *     
         */
        public void setIssueCredentialStatusListRequest(IssueCredentialStatusListRequest value) {
            this.issueCredentialStatusListRequest = value;
        }

        /**
         * Gets the value of the issueCredentialStatusListResponse property.
         * 
         * @return
         *     possible object is
         *     {@link IssueCredentialStatusListResponse }
         *     
         */
        public IssueCredentialStatusListResponse getIssueCredentialStatusListResponse() {
            return issueCredentialStatusListResponse;
        }

        /**
         * Sets the value of the issueCredentialStatusListResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link IssueCredentialStatusListResponse }
         *     
         */
        public void setIssueCredentialStatusListResponse(IssueCredentialStatusListResponse value) {
            this.issueCredentialStatusListResponse = value;
        }

        /**
         * Gets the value of the removeCredentialRequest property.
         * 
         * @return
         *     possible object is
         *     {@link RemoveCredentialRequest }
         *     
         */
        public RemoveCredentialRequest getRemoveCredentialRequest() {
            return removeCredentialRequest;
        }

        /**
         * Sets the value of the removeCredentialRequest property.
         * 
         * @param value
         *     allowed object is
         *     {@link RemoveCredentialRequest }
         *     
         */
        public void setRemoveCredentialRequest(RemoveCredentialRequest value) {
            this.removeCredentialRequest = value;
        }

        /**
         * Gets the value of the removeCredentialResponse property.
         * 
         * @return
         *     possible object is
         *     {@link RemoveCredentialResponse }
         *     
         */
        public RemoveCredentialResponse getRemoveCredentialResponse() {
            return removeCredentialResponse;
        }

        /**
         * Sets the value of the removeCredentialResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link RemoveCredentialResponse }
         *     
         */
        public void setRemoveCredentialResponse(RemoveCredentialResponse value) {
            this.removeCredentialResponse = value;
        }

        /**
         * Gets the value of the fetchHardTokenDataRequest property.
         * 
         * @return
         *     possible object is
         *     {@link FetchHardTokenDataRequest }
         *     
         */
        public FetchHardTokenDataRequest getFetchHardTokenDataRequest() {
            return fetchHardTokenDataRequest;
        }

        /**
         * Sets the value of the fetchHardTokenDataRequest property.
         * 
         * @param value
         *     allowed object is
         *     {@link FetchHardTokenDataRequest }
         *     
         */
        public void setFetchHardTokenDataRequest(FetchHardTokenDataRequest value) {
            this.fetchHardTokenDataRequest = value;
        }

        /**
         * Gets the value of the fetchHardTokenDatarResponse property.
         * 
         * @return
         *     possible object is
         *     {@link FetchHardTokenDataResponse }
         *     
         */
        public FetchHardTokenDataResponse getFetchHardTokenDataResponse() {
            return fetchHardTokenDataResponse;
        }

        /**
         * Sets the value of the fetchHardTokenDatarResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link FetchHardTokenDataResponse }
         *     
         */
        public void setFetchHardTokenDataResponse(FetchHardTokenDataResponse value) {
            this.fetchHardTokenDataResponse = value;
        }

        /**
         * Gets the value of the storeHardTokenDataRequest property.
         * 
         * @return
         *     possible object is
         *     {@link StoreHardTokenDataRequest }
         *     
         */
        public StoreHardTokenDataRequest getStoreHardTokenDataRequest() {
            return storeHardTokenDataRequest;
        }

        /**
         * Sets the value of the storeHardTokenDataRequest property.
         * 
         * @param value
         *     allowed object is
         *     {@link StoreHardTokenDataRequest }
         *     
         */
        public void setStoreHardTokenDataRequest(StoreHardTokenDataRequest value) {
            this.storeHardTokenDataRequest = value;
        }

        /**
         * Gets the value of the storeHardTokenDataResponse property.
         * 
         * @return
         *     possible object is
         *     {@link StoreHardTokenDataResponse }
         *     
         */
        public StoreHardTokenDataResponse getStoreHardTokenDataResponse() {
            return storeHardTokenDataResponse;
        }

        /**
         * Sets the value of the storeHardTokenDataResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link StoreHardTokenDataResponse }
         *     
         */
        public void setStoreHardTokenDataResponse(StoreHardTokenDataResponse value) {
            this.storeHardTokenDataResponse = value;
        }

        /**
         * Gets the value of the failureResponse property.
         * 
         * @return
         *     possible object is
         *     {@link PKIResponse }
         *     
         */
        public PKIResponse getFailureResponse() {
            return failureResponse;
        }

        /**
         * Sets the value of the failureResponse property.
         * 
         * @param value
         *     allowed object is
         *     {@link PKIResponse }
         *     
         */
        public void setFailureResponse(PKIResponse value) {
            this.failureResponse = value;
        }

    }

}
