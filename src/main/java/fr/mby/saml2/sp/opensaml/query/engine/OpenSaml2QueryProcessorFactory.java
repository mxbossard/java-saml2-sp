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

package fr.mby.saml2.sp.opensaml.query.engine;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.Validate;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.security.MessageReplayRule;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.ReplayCache;
import org.opensaml.util.storage.ReplayCacheEntry;
import org.opensaml.util.storage.StorageService;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import fr.mby.saml2.sp.api.core.ISaml20SpProcessor;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.SamlSecurityException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.api.query.engine.IQueryProcessor;
import fr.mby.saml2.sp.api.query.engine.IQueryProcessorFactory;
import fr.mby.saml2.sp.impl.helper.SamlHelper;

/**
 * OpenSaml 2 implementation of QueryProcessorFactory. This factory build the OpenSaml tree object representing the SAML
 * message. The XML element name of the SAML message is used to determine which query processor to build. The factory is
 * based on Spring Bean Factory
 * 
 * @see BeanFactoryAware.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 * 
 */
public class OpenSaml2QueryProcessorFactory implements IQueryProcessorFactory, InitializingBean, BeanFactoryAware {

	/** Logger. */
	private final Logger logger = LoggerFactory.getLogger(OpenSaml2QueryProcessorFactory.class);

	/** Security logger. */
	private final Logger securityLogger = LoggerFactory.getLogger(SamlHelper.SECURITY_LOGGER_NAME);

	private int replayMinutes;

	private MessageReplayRule rule;

	/** SAML Message Decoder (Base64, inflater, ...). */
	private Map<SamlBindingEnum, SAMLMessageDecoder> samlMessageDecoders;

	/** Switch to disable SecurityException thrown while decoding. */
	private boolean allowDecodingSecurityException = true;

	/** Signature validator. */
	private Validator<Signature> signatureValidator;

	/** Acceptable clock skew. */
	private int clockSkewSeconds;

	/** Factory configuration. */
	private Map<String, String> processorConfiguration;

	/** Factory configuration. */
	private Map<String, SamlBindingEnum> bindingConfiguration;

	/** Spring bean factory. */
	private BeanFactory beanFactory;

	@Override
	public IQueryProcessor buildQueryProcessor(final ISaml20SpProcessor spProcessor, final HttpServletRequest request)
			throws UnsupportedSamlOperation, SamlProcessingException {
		Assert.notNull(request, "HTTP request is null !");

		BaseOpenSaml2QueryProcessor<?, ?> newInstance = null;

		// Use OpenSaml to build OpenSaml representation of the message
		final SamlBindingEnum bindingUsed = this.extractBindingFromRequest(request);
		SAMLObject openSamlObject = null;
		try {
			openSamlObject = this.extractOpenSamlObjectFromRequest(request, bindingUsed);
		} catch (final SamlSecurityException e) {
			SamlHelper.logSecurityProblem(e, null);
		}

		final String localElementName = openSamlObject.getElementQName().getLocalPart();

		final String queryProcessorId = this.processorConfiguration.get(localElementName);

		if (queryProcessorId == null) {
			final String message = String.format(
					"OpenSaml element [%1$s] is not associated to a QueryProcessor in config !", localElementName);
			throw new UnsupportedSamlOperation(message);
		}

		try {
			newInstance = (BaseOpenSaml2QueryProcessor<?, ?>) this.beanFactory.getBean(queryProcessorId);
		} catch (final Exception e) {
			throw new SamlProcessingException("Unable to build new instance of OpenSaml Query Processor !", e);
		}

		newInstance.initialize(this, openSamlObject, request, spProcessor);

		this.logger.debug("Built a new QueryProcessor: [{}] for OpenSaml element: [{}] with binding: [{}]",
				new Object[]{newInstance.getClass().getName(), localElementName, bindingUsed});

		return newInstance;
	}

	@Override
	public void setBeanFactory(final BeanFactory pBeanFactory) throws BeansException {
		this.beanFactory = pBeanFactory;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notEmpty(this.processorConfiguration, "Query Processors not configured !");
		Assert.notEmpty(this.bindingConfiguration, "Bindings not configured !");
		Assert.notNull(this.samlMessageDecoders, "No SAML message decoders configured !");
		Assert.notNull(this.signatureValidator, "No signature validator configured !");

		// TODO MBD: what to do with this ?
		final StorageService<String, ReplayCacheEntry> storageEngine = new MapBasedStorageService<String, ReplayCacheEntry>();
		final ReplayCache replayCache = new ReplayCache(storageEngine, 60 * 1000 * this.replayMinutes);
		this.rule = new MessageReplayRule(replayCache);

		Assert.notNull(this.samlMessageDecoders, "No SAML message decoders provided for this IdP connector !");
		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
			Assert.notNull(this.samlMessageDecoders.get(binding),
					String.format("No SAML message decoder provided for the binding [%s] !", binding.getDescription()));
		}

	}

	protected SamlBindingEnum extractBindingFromRequest(final HttpServletRequest request)
			throws UnsupportedSamlOperation {
		SamlBindingEnum binding = null;

		final String endpointUri = request.getRequestURI();
		final String bindingPart = StringUtils.getFilename(endpointUri);

		binding = this.bindingConfiguration.get(bindingPart);

		if (binding == null) {
			final String message = String.format("The endpoint URI [%1$s] with binding part "
					+ "[%2$s] is not attached to a supported binding !", endpointUri, bindingPart);
			throw new UnsupportedSamlOperation(message);
		}

		return binding;
	}

	/**
	 * Extract SAML Object from request.
	 * 
	 * @param binding
	 * 
	 * @param messageContext
	 *            the message context
	 * @return the SAML Authn Response. It can't be null !
	 * @throws SamlProcessingException
	 * @throws SamlSecurityException
	 */
	protected SAMLObject extractOpenSamlObjectFromRequest(final HttpServletRequest request,
			final SamlBindingEnum binding) throws SamlProcessingException, SamlSecurityException {
		SAMLObject samlObject = null;
		MessageContext messageContext = null;

		try {
			messageContext = this.buildMessageContext(request, binding);
		} catch (final SecurityException e) {
			final String encodedSamlMessage = SamlHelper.getEncodedSamlMesage(request);
			final String securityMessage = String.format("Security problem while decoding SAML message: [%1$s] !",
					encodedSamlMessage);
			throw new SamlSecurityException(securityMessage, e);
		} catch (final MessageDecodingException e) {
			throw new SamlProcessingException("Unable to decode SAML message !", e);
		}

		Assert.notNull(messageContext, "MessageContext must be supplied !");

		final XMLObject inboundMessage = messageContext.getInboundMessage();
		if ((inboundMessage != null) && SAMLObject.class.isAssignableFrom(inboundMessage.getClass())) {
			samlObject = (SAMLObject) inboundMessage;
		} else {
			throw new SamlProcessingException("Unable to find a SAML Object in HTTP request !");
		}

		return samlObject;
	}

	/**
	 * Build the SAML message context from a HttpServletRequest.
	 * 
	 * @param request
	 *            the HttpServletRequest
	 * @param binding
	 * @return the SAML message context
	 * @throws SecurityException
	 *             in case of Security problem
	 * @throws MessageDecodingException
	 *             in case of decoding problem
	 */
	@SuppressWarnings("rawtypes")
	protected MessageContext buildMessageContext(final HttpServletRequest request, final SamlBindingEnum binding)
			throws SecurityException, MessageDecodingException {
		Validate.notNull(request, "Request must be supplied !");

		final MessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));

		try {
			final SAMLMessageDecoder decoder = this.getSamlMessageDecoder(binding);
			decoder.decode(messageContext);
		} catch (final SecurityException e) {
			// Decoder throw SecurityException that we can skip
			this.securityLogger.debug("Security problem while decoding incoming SAML message !", e);
			if (this.isAllowDecodingSecurityException()) {
				throw e;
			}
		}

		this.validateMessageContext(messageContext);

		return messageContext;
	}

	/**
	 * Retrieve the SAML message decoder attached to the binding.
	 * 
	 * @param binding
	 *            the binding
	 * @return the right SAML message decoder
	 */
	protected SAMLMessageDecoder getSamlMessageDecoder(final SamlBindingEnum binding) {
		final Map<SamlBindingEnum, SAMLMessageDecoder> samlMessageDecoders = this.getSamlMessageDecoders();
		final SAMLMessageDecoder decoder = samlMessageDecoders.get(binding);
		if (decoder == null) {
			throw new IllegalStateException(String.format("No decoder configured for binding [%1$s] !", binding));
		}
		return samlMessageDecoders.get(binding);
	}

	/**
	 * Validate the message context if MessageReplayRule was provided.
	 * 
	 * @param messageContext
	 *            the message context
	 * @throws SecurityPolicyException
	 *             in case of rule requirements problem.
	 */
	protected void validateMessageContext(final MessageContext messageContext) throws SecurityPolicyException {
		final MessageReplayRule rules = this.getRule();
		if ((rules != null) && (messageContext != null)) {
			rules.evaluate(messageContext);
		}
	}

	public void setBindingConfiguration(final Map<String, SamlBindingEnum> bindingConfiguration) {
		this.bindingConfiguration = bindingConfiguration;
	}

	public void setProcessorConfiguration(final Map<String, String> processorConfiguration) {
		this.processorConfiguration = processorConfiguration;
	}

	public int getReplayMinutes() {
		return this.replayMinutes;
	}

	public void setReplayMinutes(final int replayMinutes) {
		this.replayMinutes = replayMinutes;
	}

	public MessageReplayRule getRule() {
		return this.rule;
	}

	public void setRule(final MessageReplayRule rule) {
		this.rule = rule;
	}

	public Map<SamlBindingEnum, SAMLMessageDecoder> getSamlMessageDecoders() {
		return this.samlMessageDecoders;
	}

	public void setSamlMessageDecoders(final Map<SamlBindingEnum, SAMLMessageDecoder> samlMessageDecoders) {
		this.samlMessageDecoders = samlMessageDecoders;
	}

	public boolean isAllowDecodingSecurityException() {
		return this.allowDecodingSecurityException;
	}

	public void setAllowDecodingSecurityException(final boolean allowDecodingSecurityException) {
		this.allowDecodingSecurityException = allowDecodingSecurityException;
	}

	public Validator<Signature> getSignatureValidator() {
		return this.signatureValidator;
	}

	public void setSignatureValidator(final Validator<Signature> signatureValidator) {
		this.signatureValidator = signatureValidator;
	}

	public int getClockSkewSeconds() {
		return this.clockSkewSeconds;
	}

	public void setClockSkewSeconds(final int clockSkewSeconds) {
		this.clockSkewSeconds = clockSkewSeconds;
	}

}
