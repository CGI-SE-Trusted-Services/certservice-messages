package org.certificateservices.messages

import spock.lang.Specification

import org.certificateservices.messages.ContextMessageSecurityProvider.Context
/**
 * Created by philip on 22/02/17.
 */
class ContextMessageSecurityProviderSpec extends Specification {

    def "Verify Context class constructor and getter and setters"(){
        when:
        Context c = new Context("SomeUsage")
        then:
        c.getUsage() == "SomeUsage"
        when:
        c.setUsage("OtherUsage")
        then:
        c.getUsage() == "OtherUsage"
        when:
        c= new Context("SomeUsage1","SomeOrg")
        then:
        c.getUsage() == "SomeUsage1"
        c.getRelatedOrganisation() == "SomeOrg"
        when:
        c.setRelatedOrganisation("SomeOrg2")
        then:
        c.getRelatedOrganisation() == "SomeOrg2"
        when:
        c= new Context("SomeUsage1","SomeOrg",[key1:"value1"])
        then:
        c.getUsage() == "SomeUsage1"
        c.getRelatedOrganisation() == "SomeOrg"
        c.getProperties()["key1"] == "value1"
        when:
        c.setProperties([key2:"value2"])
        then:
        c.getProperties()["key2"] == "value2"
    }

    def "Verify hasCode and equals returns correct values"(){
        setup:
        def c1 = new Context("SomeUsage1")
        def c2 = new Context("SomeUsage1","SomeOrg")
        def c3 = new Context("SomeUsage1","SomeOrg",[key1:"value1"])
        def c4 = new Context("SomeUsage1","SomeOrg",[key1:"value1"])

        expect:
        c1 != c2
        c1 != c3
        c3 == c4
        c1.hashCode() != c2.hashCode()
        c1.hashCode() != c3.hashCode()
        c3.hashCode() == c4.hashCode()
    }

    def "Verify that toString returns correct values"(){
        setup:
        def c1 = new Context("SomeUsage1")
        def c2 = new Context("SomeUsage1","SomeOrg")
        def c3 = new Context("SomeUsage1","SomeOrg",[key1:"value1"])
        expect:
        c1.toString() == "Context{usage='SomeUsage1', relatedOrganisation='null', properties=null}"
        c2.toString() == "Context{usage='SomeUsage1', relatedOrganisation='SomeOrg', properties=null}"
        c3.toString() == "Context{usage='SomeUsage1', relatedOrganisation='SomeOrg', properties={key1=value1}}"
    }
}