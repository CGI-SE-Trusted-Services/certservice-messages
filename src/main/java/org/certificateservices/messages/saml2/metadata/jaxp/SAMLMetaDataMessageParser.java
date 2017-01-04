package org.certificateservices.messages.saml2.metadata.jaxp;

import org.certificateservices.messages.saml2.BaseSAMLMessageParser;
import org.certificateservices.messages.utils.XMLSigner;
import org.xml.sax.SAXException;

/**
 * Created by philip on 02/01/17.
 */
public class SAMLMetaDataMessageParser extends BaseSAMLMessageParser {

    @Override
    public String getNameSpace() {
        return null;
    }

    @Override
    public String getJAXBPackages() {
        return null;
    }

    @Override
    public String[] getDefaultSchemaLocations() throws SAXException {
        return new String[0];
    }

    @Override
    public XMLSigner.SignatureLocationFinder getSignatureLocationFinder() {
        return null;
    }

    @Override
    public XMLSigner.OrganisationLookup getOrganisationLookup() {
        return null;
    }
}
