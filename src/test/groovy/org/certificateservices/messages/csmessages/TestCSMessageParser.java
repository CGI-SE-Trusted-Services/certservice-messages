/************************************************************************
*                                                                       *
*  Certificate Service - Messages                                       *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages.csmessages;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.csmessages.jaxb.ApprovalStatus;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.CSRequest;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;

public class TestCSMessageParser implements CSMessageParser {

	@Override
	public void init(MessageSecurityProvider securityProvider, Properties config)
			throws MessageProcessingException {

	}

	@Override
	public byte[] generateCSRequestMessage(String requestId,
			String destinationId, String organisation, String payLoadVersion,
			Object payload, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	@Override
	public byte[] generateCSRequestMessage(String requestId,
			String destinationId, String organisation, String payLoadVersion,
			Object payload, Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	@Override
	public CSMessageResponseData generateCSResponseMessage(
			String relatedEndEntity, CSMessage request, String payLoadVersion,
			Object payload) throws MessageContentException,
			MessageProcessingException {

		return null;
	}

	@Override
	public CSMessageResponseData generateCSResponseMessage(
			String relatedEndEntity, CSMessage request, String payLoadVersion,
			Object payload, boolean isForwarable)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	@Override
	public byte[] generateGetApprovalRequest(String requestId,
			String destinationId, String organisation, CSRequest request,String requestPayloadVersion,
			Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	@Override
	public byte[] generateIsApprovedRequest(String requestId,
			String destinationId, String organisation, String approvalId,
			Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	@Override
	public CSMessageResponseData generateIsApprovedResponse(
			String relatedEndEntity, CSMessage request,
			ApprovalStatus approvalStatus, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	@Override
	public CSMessageResponseData generateGetApprovalResponse(
			String relatedEndEntity, CSMessage request, String approvalId,
			ApprovalStatus approvalStatus, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	@Override
	public CSMessageResponseData genCSFailureResponse(String relatedEndEntity,
			byte[] request, RequestStatus status, String failureMessage,
			String destinationID, Credential originator)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	@Override
	public X509Certificate getSigningCertificate(byte[] request)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	@Override
	public byte[] marshallAndSignCSMessage(CSMessage csMessage)
			throws MessageProcessingException, MessageContentException {

		return null;
	}

	@Override
	public void validatePayloadObject(CSMessageVersion version,
			Object payLoadObject) throws MessageContentException {

	}

	@Override
	public CSMessageVersion getVersionFromMessage(byte[] messageData)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

}
