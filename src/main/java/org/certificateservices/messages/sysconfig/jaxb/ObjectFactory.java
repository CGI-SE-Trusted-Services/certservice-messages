//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.05.22 at 12:49:39 PM CEST 
//


package org.certificateservices.messages.sysconfig.jaxb;

import javax.xml.bind.annotation.XmlRegistry;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the org.certificateservices.messages.sysconfig.jaxb package. 
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
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: org.certificateservices.messages.sysconfig.jaxb
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link PublishConfigurationResponse }
     * 
     */
    public PublishConfigurationResponse createPublishConfigurationResponse() {
        return new PublishConfigurationResponse();
    }


    /**
     * Create an instance of {@link GetActiveConfigurationResponse }
     * 
     */
    public GetActiveConfigurationResponse createGetActiveConfigurationResponse() {
        return new GetActiveConfigurationResponse();
    }

    /**
     * Create an instance of {@link SystemConfiguration }
     * 
     */
    public SystemConfiguration createSystemConfiguration() {
        return new SystemConfiguration();
    }

    /**
     * Create an instance of {@link PublishConfigurationRequest }
     * 
     */
    public PublishConfigurationRequest createPublishConfigurationRequest() {
        return new PublishConfigurationRequest();
    }

    /**
     * Create an instance of {@link GetActiveConfigurationRequest }
     * 
     */
    public GetActiveConfigurationRequest createGetActiveConfigurationRequest() {
        return new GetActiveConfigurationRequest();
    }

    /**
     * Create an instance of {@link ConfigurationData }
     * 
     */
    public ConfigurationData createConfigurationData() {
        return new ConfigurationData();
    }

    /**
     * Create an instance of {@link Property }
     * 
     */
    public Property createProperty() {
        return new Property();
    }


}
