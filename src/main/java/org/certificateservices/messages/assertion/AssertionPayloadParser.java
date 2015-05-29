/**
 * 
 */
package org.certificateservices.messages.assertion;

import java.io.InputStream;
import java.security.cert.CertStoreParameters;
import java.util.Properties;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.CSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParser;

/**
 * 
 * TODO
 * @author philip
 *
 */
public class AssertionPayloadParser implements PayloadParser {

	/* (non-Javadoc)
	 * @see org.certificateservices.messages.csmessages.PayloadParser#init(java.util.Properties)
	 */
	@Override
	public void init(Properties config, CSMessageParser parser) throws MessageProcessingException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getNameSpace()
	 */
	@Override
	public String getNameSpace() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getJAXBPackage()
	 */
	@Override
	public String getJAXBPackage() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getSchemaAsInputStream(java.lang.String)
	 */
	@Override
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
		// TODO Auto-generated method stub
		return null;
	}

}
