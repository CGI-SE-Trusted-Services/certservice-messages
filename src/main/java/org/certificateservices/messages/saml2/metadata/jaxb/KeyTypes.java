//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.01.02 at 04:39:08 PM MSK 
//


package org.certificateservices.messages.saml2.metadata.jaxb;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for KeyTypes.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="KeyTypes">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="encryption"/>
 *     &lt;enumeration value="signing"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "KeyTypes")
@XmlEnum
public enum KeyTypes {

    @XmlEnumValue("encryption")
    ENCRYPTION("encryption"),
    @XmlEnumValue("signing")
    SIGNING("signing");
    private final String value;

    KeyTypes(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static KeyTypes fromValue(String v) {
        for (KeyTypes c: KeyTypes.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}