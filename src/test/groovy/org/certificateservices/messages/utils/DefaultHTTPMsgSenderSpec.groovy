package org.certificateservices.messages.utils

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.certificateservices.messages.MessageContentException

import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import org.eclipse.jetty.server.Request
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.handler.AbstractHandler
import org.eclipse.jetty.server.handler.ContextHandler



class DefaultHTTPMsgSenderSpec extends Specification{


    DefaultHTTPMsgSender msgSender;
    @Shared Server jettyServer;
    @Shared int defaultJettyHTTPPort = 8089;

    def setupSpec(){

        // Here start a test jetty server at some given port (not 8080) and add handlers that
        // verify it's a POST and the contenttype is text/xml and returns some byte data.

        String responseData = "Response data"
        jettyServer = new Server(defaultJettyHTTPPort)

        ContextHandler context = new ContextHandler()
        context.setContextPath("/messageprocessor")

        def defaultHandler = [handle:{String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response ->

            byte[] requestBodyInput =  request.getInputStream().getBytes()
            if(request.getMethod() != "POST"){
                response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Only supporting POST request method.")
            }else if(request.getContentType() != "text/xml; charset=UTF-8"){
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Only supporting content type text/xml.")
            }else if(!requestBodyInput){
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid message")
            }else{
                response.setContentType("text/xml")
                response.setStatus(HttpServletResponse.SC_OK)
                baseRequest.setHandled(true)
                response.getOutputStream().write(responseData.bytes)
            }

        }] as AbstractHandler

        jettyServer.setHandler(defaultHandler)
        jettyServer.start()

    }

    def setup(){
        // create msgSender poiting to the port of the jetty server.
        msgSender = new DefaultHTTPMsgSender("http://localhost:8089/messageprocessor")
    }


    def "Verify that synchronous msg sending works."(){
        when:
        def resp = msgSender.sendMsg("RequestData".getBytes())

        then:
        assert new String(resp, "UTF-8") == "Response data"
    }

    def "Verify that asynchronous msg sending works."(){
        setup:
        def asyncCallBack = new TestMsgCallback()

        when:
        msgSender.sendMsg("RequestData".getBytes(), asyncCallBack)
        while(!asyncCallBack.responseData){
            if(asyncCallBack.responseData){
                break;
            }
        }
        then:
        assert new String(asyncCallBack.responseData, "UTF-8") == "Response data"
    }

    @Unroll
    def "Verify that correct exception #exception is throws for error HTTP code #errocode "(){
        setup:
        def e
        when:
        // Verify that returning a specific error code results in an exception.
        if(errocode == "4"){
            msgSender = new DefaultHTTPMsgSender("http://localhost:8089/messageprocessors", "POST")
        }else{
            msgSender = new DefaultHTTPMsgSender("http://localhost:8099/messageprocessors", "POST")
        }
        def resp = msgSender.sendMsg("".getBytes())
        then:
        e = thrown (Exception)
        if(exception == "MessageContentException"){
            assert e instanceof MessageContentException
            assert e.message.startsWith("Error sending message to ")
        }else{
            assert e instanceof IOException
        }
        where:
        errocode | exception 					| description
        "4"		 | "MessageContentException"	| "wrong request is sent."
        "5"		 | "IOException"				| "wrong port is accessed."
    }

    def cleanupSpec(){
        if(jettyServer!=null && jettyServer.isRunning()){
            jettyServer.stop()
            jettyServer = null

        }
    }

    class TestMsgCallback implements MsgSender.MsgCallback {

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