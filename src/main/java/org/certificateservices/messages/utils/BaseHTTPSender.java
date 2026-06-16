package org.certificateservices.messages.utils;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.SpamProtectionException;
import org.certificateservices.messages.TimeoutException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Abstract base class for a component that can send messages over HTTP.
 *
 * @author Philip Vendil, 23/06/16
 */
public abstract class BaseHTTPSender {

    protected final URL baseURL;
    protected final String requestType;
    protected final String outputContentType;

    /**
     * Main constructor where it is possible to specify request type.
     *
     * @param url               the URL to connect to.
     * @param requestType       the HTTP request type in upper case (For example POST, GET)
     * @param outputContentType the content type on the output data.
     * @throws MalformedURLException if URL was malformed.
     */
    public BaseHTTPSender(String url, String requestType, String outputContentType) throws MalformedURLException {
        try {
            this.baseURL = new URL(url);
        } catch (MalformedURLException e) {
            throw new MalformedURLException("Invalid URL provided:" + url);
        }
        this.requestType = requestType;
        this.outputContentType = outputContentType;
    }

    /**
     * Synchronous call to test connection to the given url.
     *
     * @return true if connection is working, otherwise false.
     */
    public boolean testConnection() {
        HttpURLConnection con = null;
        try {
            con = (HttpURLConnection) baseURL.openConnection();
            con.connect();
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }
    }

    /**
     * Synchronous call for sending HTTP request sending data in the HTTP request body (usually using POST)
     *
     * @param request the data to send.
     * @return the response data.
     * @throws MessageContentException    if request contained illegal content.
     * @throws MessageProcessingException if internal problems occurred processing the request at the server.
     * @throws IOException                if communication problems occurred.
     * @throws SpamProtectionException    if server side regarded call as a SPAM request and denied it.
     * @throws TimeoutException           if timeout was detected when calling service.
     */
    protected byte[] sendMsg(byte[] request) throws MessageContentException, MessageProcessingException, IOException, SpamProtectionException, TimeoutException {
        SynchronousCallback callback = new SynchronousCallback();
        new SendMsgRunnable(request, callback).run();

        Exception error = callback.error;
        if (error != null) {
            if (error instanceof MessageContentException) {
                throw (MessageContentException) error;
            } else if (error instanceof TimeoutException) {
                throw (TimeoutException) error;
            } else if (error instanceof MessageProcessingException) {
                throw (MessageProcessingException) error;
            } else if (error instanceof IOException) {
                throw (IOException) error;
            } else if (error instanceof SpamProtectionException) {
                throw (SpamProtectionException) error;
            }
            throw new MessageProcessingException("Error sending message to " + baseURL + " : " + error.getMessage(), error);
        }
        return callback.responseData;
    }

    /**
     * Asynchronous call for sending HTTP request sending data in the HTTP request body (usually using POST)
     *
     * @param request  the data to send.
     * @param callback the callback to signal the result to.
     */
    protected void sendMsg(byte[] request, MsgSender.MsgCallback callback) {
        new Thread(new BaseHTTPSender.SendMsgRunnable(request,callback)).start();
    }

    /**
     * Asynchronous call for sending HTTP request with parameters in URL string (usually using GET)
     *
     * @param parameters the parameter string to send (without ?)
     * @param callback   the callback to signal the result to.
     */
    protected void sendMsg(String parameters, MsgSender.MsgCallback callback) throws MessageContentException {
        new Thread(new BaseHTTPSender.SendMsgRunnable(parameters,callback)).start();
    }

    /**
     * Synchronous call for sending HTTP request with parameters in URL string (usually using GET)
     *
     * @param parameters the parameter string to send (without ?)
     * @return the response data.
     * @throws MessageContentException    if request contained illegal content.
     * @throws MessageProcessingException if internal problems occurred processing the request at the server.
     * @throws IOException                if communication problems occurred.
     * @throws SpamProtectionException    if server side regarded call as a SPAM request and denied it.
     */
    protected byte[] sendMsg(String parameters) throws MessageContentException, MessageProcessingException, IOException, SpamProtectionException {
        SynchronousCallback callback = new SynchronousCallback();
        new SendMsgRunnable(parameters, callback).run();

        Exception error = callback.error;
        if (error != null) {
            if (error instanceof MessageContentException) {
                throw (MessageContentException) error;
            } else if (error instanceof TimeoutException) {
                throw (TimeoutException) error;
            } else if (error instanceof MessageProcessingException) {
                throw (MessageProcessingException) error;
            } else if (error instanceof IOException) {
                throw (IOException) error;
            } else if (error instanceof SpamProtectionException) {
                throw (SpamProtectionException) error;
            }
            throw new MessageProcessingException("Error sending message to " + baseURL + " : " + error.getMessage(), error);
        }
        return callback.responseData;
    }

    /**
     * Runnable that sends a HTTP call and wait for the response.
     */
    protected class SendMsgRunnable implements Runnable {
        byte[] request;
        String parameters = null;
        MsgSender.MsgCallback callback;
        boolean doOutput = false;
        URL url;

        /**
         * Constructor when sending a byte array output (Usually using POST)
         *
         * @param request  the request data to send.
         * @param callback the callback to signal result to.
         */
        protected SendMsgRunnable(byte[] request, MsgSender.MsgCallback callback) {
            this.request = request;
            this.callback = callback;
            this.doOutput = true;
            url = baseURL;
        }

        /**
         * Constructor when sending data as parameters in the URL (Usually using GET)
         *
         * @param parameters the parameters (excluding ?) to use in the request.
         * @param callback   the callback to signal result to.
         */
        protected SendMsgRunnable(String parameters, MsgSender.MsgCallback callback) throws MessageContentException {
            this.parameters = parameters;
            this.callback = callback;
            try {
                url = new URL(baseURL.toString() + "?" + parameters);
            } catch (MalformedURLException e) {
                throw new MessageContentException("Error building GET request to server, invalid URL parameters: " + parameters, e);
            }
        }

        @Override
        public void run() {
            try {
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setRequestMethod(requestType);
                con.setRequestProperty("content-type", outputContentType);
                if (doOutput && request != null) {
                    con.setDoOutput(true);
                    try (OutputStream os = con.getOutputStream()) {
                        os.write(request);
                    }
                }

                int responseCode = con.getResponseCode();

                if (responseCode >= 200 && responseCode < 300) {
                    try (InputStream inputStream = con.getInputStream()) {
                        byte[] responseData = toByteArray(inputStream);
                        callback.responseReceived(responseData);
                    }
                } else {
                    String errorMessage;
                    InputStream errorStream = con.getErrorStream();
                    if (errorStream != null) {
                        try (InputStream es = errorStream) {
                            byte[] errorData = toByteArray(es);
                            errorMessage = new String(errorData, StandardCharsets.UTF_8);
                        }
                    } else {
                        errorMessage = con.getResponseMessage();
                    }

                    if (responseCode == 429) {
                        callback.errorOccurred(new SpamProtectionException("Error sending message to " + url + ", got response code: " + responseCode + " message: " + errorMessage));
                    } else if (responseCode == 503) {
                        callback.errorOccurred(new TimeoutException("Timeout sending message to " + url + ", got response code: " + responseCode + " message: " + errorMessage));
                    } else if (responseCode >= 400 && responseCode < 500) {
                        callback.errorOccurred(new MessageContentException("Error sending message to " + url + ", got response code: " + responseCode + " message: " + errorMessage));
                    } else {
                        callback.errorOccurred(new MessageProcessingException("Error sending message to " + url + ", got response code: " + responseCode + " message: " + errorMessage));
                    }
                }
            } catch (ProtocolException e) {
                callback.errorOccurred(new MessageProcessingException("Error sending message to " + baseURL + ": " + e.getMessage(), e));
            } catch (IOException e) {
                callback.errorOccurred(e);
            }
        }
    }

    public static byte[] toByteArray(final InputStream inputStream) throws IOException {
        if (inputStream == null) {
            return new byte[0];
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[4096];
        int nRead;
        while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }

    /**
     * Special case callback used for synchronous request calls.
     */
    protected static class SynchronousCallback implements MsgSender.MsgCallback {
        byte[] responseData;
        Exception error;

        @Override
        public void responseReceived(byte[] responseData) {
            this.responseData = responseData;
        }

        @Override
        public void errorOccurred(Exception e) {
            this.error = e;
        }
    }
}
