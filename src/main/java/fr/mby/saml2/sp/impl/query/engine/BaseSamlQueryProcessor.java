/**
 * Copyright (C) 2012 RECIA http://www.recia.fr
 * @Author (C) 2012 Maxime Bossard <mxbossard@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * 
 */
package fr.mby.saml2.sp.impl.query.engine;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import fr.mby.saml2.sp.api.core.ISaml20SpProcessor;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.SamlSecurityException;
import fr.mby.saml2.sp.api.exception.SamlValidationException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.api.om.IRequestWaitingForResponse;
import fr.mby.saml2.sp.api.query.IQuery;
import fr.mby.saml2.sp.api.query.engine.IQueryProcessor;
import fr.mby.saml2.sp.impl.helper.SamlHelper;
import fr.mby.saml2.sp.impl.om.SamlIncomingMessage;

/**
 * Base implementation of Query Processor.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public abstract class BaseSamlQueryProcessor<T extends IQuery> implements IQueryProcessor {

	/** Logger. */
	private final Logger logger = LoggerFactory.getLogger(BaseSamlQueryProcessor.class);

	/** The incoming HTTP request. */
	private HttpServletRequest httpRequest;

	/** SAML message in plain XML text. */
	private String samlMessage;

	/** SP Processor. */
	private ISaml20SpProcessor spProcessor;

	/** Endpoint location to validate incoming message. */
	private String endpointLocation;

	/**
	 * Unique constructor protected.
	 * Construction delegated to QueryProcessorFactory.
	 */
	protected BaseSamlQueryProcessor() {
		super();
	}

	/**
	 * Initialize the query processor.
	 * 
	 * @param pHttpRequest
	 * @param spProcessor
	 */
	public void initialize(final HttpServletRequest pHttpRequest, final ISaml20SpProcessor pSpProcessor) {
		this.httpRequest = pHttpRequest;
		this.spProcessor = pSpProcessor;
	}

	@Override
	public IIncomingSaml processIncomingSamlMessage()
			throws SamlProcessingException, UnsupportedSamlOperation {
		IIncomingSaml incomingSamlObj = null;

		this.checkInitialization();

		try {
			this.samlMessage = this.marshallSamlMessage();

			boolean validRequetType = this.validateRequestType();
			if (!validRequetType) {
				throw new SamlProcessingException("Bad SAML Query Processor in use for incoming request !");
			}

			this.preProcess();

			this.checkSecurity();

			this.validateConditions();

			this.process();

			incomingSamlObj = this.buildIncomingSamlObject();

		} catch (SamlValidationException e) {
			final String validationMessage = "Validation problem while processing incoming SAML message !";
			this.logger.warn(validationMessage, e);
			throw new SamlProcessingException(validationMessage, e);
		} catch (SamlSecurityException e) {
			SamlHelper.logSecurityProblem(e, this.samlMessage);
		}

		return incomingSamlObj;
	}

	/** Check the query processor initialization. */
	protected void checkInitialization() {
		Assert.notNull(this.spProcessor, "SP Processor wasn't provided !");
		Assert.notNull(this.httpRequest, "HTTP request was not provided !");
	}

	/**
	 * Marshall the SAML message.
	 * 
	 * @param httpRequest the HTTP request
	 * @param binding the binding used
	 * @return the SAML message in plain XML text
	 * @throws SamlProcessingException if unable to initialize the processor
	 * @throws SamlSecurityException if security problem
	 */
	protected abstract String marshallSamlMessage()
			throws SamlProcessingException, SamlSecurityException;

	/**
	 * Validate the Incoming SAML request type.
	 * This processor should process only one type of SAML request.
	 * 
	 * @return false if this processor cannot process this SAML request type
	 * @throws SamlProcessingException if unable to validate the request type
	 */
	protected boolean validateRequestType() throws SamlProcessingException {
		// Validate endpoint location
		final String endpointUri = this.getHttpRequest().getRequestURI();

		return StringUtils.hasText(this.endpointLocation) && endpointUri.startsWith(this.endpointLocation);
	}

	/**
	 * Allow to do pre processing after ensuring the good request type but before checking SAML validity.
	 * 
	 * @throws SamlProcessingException if processing problem
	 * @throws UnsupportedSamlOperation if operation not supported by this processor
	 */
	protected void preProcess() throws SamlProcessingException, UnsupportedSamlOperation {
		// Nothing to do by default
	}

	/**
	 * Check the security of the SAML Request.
	 * 
	 * @throws SamlSecurityException if security problem
	 */
	protected abstract void checkSecurity() throws SamlSecurityException;

	/**
	 * Validate the conditions of the request.
	 * 
	 * @throws SamlValidationException if valdiation problem
	 */
	protected abstract void validateConditions() throws SamlValidationException;

	/**
	 * Do the processing this request require.
	 * 
	 * @throws SamlProcessingException if processing problem
	 * @throws SamlSecurityException if security problem
	 * @throws UnsupportedSamlOperation if operation not supported by this processor
	 */
	protected abstract void process() throws SamlProcessingException, SamlSecurityException, UnsupportedSamlOperation;

	/**
	 * Build the SAML Query.
	 * 
	 * @return the SAML Query
	 * @throws SamlProcessingException
	 */
	protected abstract T buildSamlQuery() throws SamlProcessingException, SamlSecurityException;

	/**
	 * Check if the response anwser to a previously created request.
	 * 
	 * @param inResponseToId the original request Id
	 * @return the Response
	 * @throws SamlProcessingException if no request found in cache (may have expired)
	 * @throws SamlSecurityException if request not of expected type
	 */
	@SuppressWarnings("unchecked")
	protected <X extends IRequestWaitingForResponse> X checkResponseLegitimacy(final String inResponseToId,
			final Class<X> expectedRequestType) throws SamlProcessingException, SamlSecurityException {
		Assert.hasText(inResponseToId, "No inResponseToId provided ! !");
		Assert.notNull(expectedRequestType, "No expected request type provided !");

		// Try to retrieve original request
		IRequestWaitingForResponse originalRequest =
				this.getSpProcessor().getSaml20Storage().findRequestWaitingForResponse(inResponseToId);

		// Original request cannot be null
		if (originalRequest == null) {
			throw new SamlProcessingException(
					"No original AuthnRequest found matching the AuthnResponse (Request may have expired) !");
		}

		// Original request must be of expected type
		if (!expectedRequestType.isAssignableFrom(originalRequest.getClass())) {
			throw new SamlSecurityException(
					"The orginal request type doesn't match the response type !");
		}

		return (X) originalRequest;
	}

	/**
	 * Build the IIncomingSaml object to return by processIncomingHttpRequest().
	 * 
	 * @return the IIncomingSaml object
	 * @throws SamlProcessingException
	 * @throws SamlSecurityException
	 */
	protected IIncomingSaml buildIncomingSamlObject()
			throws SamlProcessingException, SamlSecurityException {
		Assert.notNull(this.httpRequest, "HTTP request is null !");

		// SamlMessage
		final String samlMessage = this.getSamlMessage();
		Assert.hasText(samlMessage, "SAML message was not built yet !");

		// Endpoint URL
		final String endpointUrl = this.httpRequest.getRequestURL().toString();

		// RelayState
		final String relayState = SamlHelper.getRelayState(this.httpRequest);

		// SAML Query
		final IQuery samlQuery = this.buildSamlQuery();

		final SamlIncomingMessage samlIncMessage = new SamlIncomingMessage();
		samlIncMessage.setSamlMessage(samlMessage);
		samlIncMessage.setEndpointUrl(endpointUrl);
		samlIncMessage.setRelayState(relayState);
		samlIncMessage.setSamlQuery(samlQuery);

		return samlIncMessage;
	}

	/**
	 * The SP Processor.
	 * 
	 * @return the HTTP request
	 */
	protected ISaml20SpProcessor getSpProcessor() {
		Assert.notNull(this.spProcessor, "SP Processor cannot be null !");
		return this.spProcessor;
	}

	/**
	 * The incoming HTTP request.
	 * 
	 * @return the HTTP request
	 */
	protected HttpServletRequest getHttpRequest() {
		return this.httpRequest;
	}

	/**
	 * SAML message in plain XML text.
	 * @return the SAML message
	 */
	protected String getSamlMessage() {
		return this.samlMessage;
	}

	public String getEndpointLocation() {
		return this.endpointLocation;
	}

	public void setEndpointLocation(final String endpointLocation) {
		this.endpointLocation = endpointLocation;
	}

}
