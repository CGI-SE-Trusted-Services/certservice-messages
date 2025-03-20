//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.03.01 at 08:01:08 PM CET 
//


package org.certificateservices.messages.sensitivekeys.jaxb;

import javax.xml.bind.annotation.XmlRegistry;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the org.certificateservices.messages.sensitivekeys.jaxb package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {


    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: org.certificateservices.messages.sensitivekeys.jaxb
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link KeyData }
     * 
     */
    public KeyData createKeyData() {
        return new KeyData();
    }

    /**
     * Create an instance of {@link KeyDataType }
     * 
     */
    public KeyDataType createKeyDataType() {
        return new KeyDataType();
    }

    /**
     * Create an instance of {@link EncodedKey }
     * 
     */
    public EncodedKey createEncodedKey() {
        return new EncodedKey();
    }

    /**
     * Create an instance of {@link AsymmetricKey }
     * 
     */
    public AsymmetricKey createAsymmetricKey() {
        return new AsymmetricKey();
    }

}
