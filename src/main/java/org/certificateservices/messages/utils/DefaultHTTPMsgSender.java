package org.certificateservices.messages.utils;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.SpamProtectionException;
import org.certificateservices.messages.TimeoutException;

import java.io.IOException;
import java.net.MalformedURLException;

/**
 * DefaultHTTPMsgSender sending a byte[] array to a given URL.
 * <p>
 * Created by Philip Vendil on 16/06/16.
 */
public class DefaultHTTPMsgSender extends BaseHTTPSender implements MsgSender {

    static final String DEFAULT_CONTENT_TYPE = "text/xml; charset=utf-8";

    /**
     * Main constructor for POST requests
     *
     * @param url the URL to connect to.
     * @throws MalformedURLException if URL was malformed.
     */
    public DefaultHTTPMsgSender(String url) throws MalformedURLException {
        super(url, "POST", DEFAULT_CONTENT_TYPE);
    }

    /**
     * Main constructor where it is possible to specify request type.
     *
     * @param url         the URL to connect to.
     * @param requestType the HTTP request type in upper case (For example POST, GET)
     * @throws MalformedURLException if URL was malformed.
     */
    public DefaultHTTPMsgSender(String url, String requestType) throws MalformedURLException {
        super(url, requestType, DEFAULT_CONTENT_TYPE);
    }

    @Override
    public byte[] sendMsg(byte[] request) throws MessageContentException, MessageProcessingException, IOException, SpamProtectionException {
        return super.sendMsg(request);
    }

    @Override
    public void sendMsg(byte[] request, MsgCallback callback) {
        super.sendMsg(request, callback);
    }
}
