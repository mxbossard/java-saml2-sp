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

import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;
import org.springframework.util.Assert;

import fr.mby.saml2.sp.api.core.ISaml20IdpConnector;
import fr.mby.saml2.sp.api.core.ISaml20SpProcessor;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.exception.NotSignedException;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.SamlSecurityException;
import fr.mby.saml2.sp.api.exception.SamlValidationException;
import fr.mby.saml2.sp.api.query.IQuery;
import fr.mby.saml2.sp.impl.helper.SamlValidationHelper;
import fr.mby.saml2.sp.impl.query.engine.BaseSamlQueryProcessor;
import fr.mby.saml2.sp.opensaml.helper.OpenSamlHelper;

/**
 * Base implementation of Query Processor with OpenSaml 2 library.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public abstract class BaseOpenSaml2QueryProcessor<T extends IQuery, V extends SAMLObject>
extends BaseSamlQueryProcessor<T> {

	/** Factory of the object. */
	private OpenSaml2QueryProcessorFactory factory;

	/** Binding used for the message.*/
	private SamlBindingEnum binding;

	/** OpenSaml representation of SAML message. */
	private V openSamlObject;

	/**
	 * Initialize the OpenSaml 2 query processor.
	 * 
	 * @param pFactory
	 * @param samlObject
	 * @param pHttpRequest
	 * @param pSpProcessor
	 */
	@SuppressWarnings("unchecked")
	public void initialize(final OpenSaml2QueryProcessorFactory pFactory, final SAMLObject samlObject,
			final HttpServletRequest pHttpRequest, final ISaml20SpProcessor pSpProcessor) {

		super.initialize(pHttpRequest, pSpProcessor);
		this.factory = pFactory;
		this.openSamlObject = (V) samlObject;
	}

	@Override
	protected String marshallSamlMessage()
			throws SamlProcessingException, SamlSecurityException {
		String samlMessage = null;

		try {
			samlMessage = OpenSamlHelper.marshallXmlObject(this.openSamlObject);
		} catch (MarshallingException e) {
			throw new SamlProcessingException("OpenSaml object marshalling problem !", e);
		}

		return samlMessage;
	}

	@Override
	protected void checkInitialization() {
		Assert.notNull(this.factory, "Factory wasn't provided !");
		Assert.notNull(this.openSamlObject, "OpenSaml object is null !");
	}

	/**
	 * Validate a Saml2 signature if a signature profile validator was provided.
	 * Verify a Saml2 signature with IdP Metadata.
	 * 
	 * @param signableObject the Saml 2.0 Response to validate and verify.
	 * @param issuer issuer of the message
	 * @throws NotSignedException if no signature present
	 * @throws SamlSecurityException if saml security problem
	 */
	protected void validateSignatureTrust(final SignableSAMLObject signableObject, final Issuer issuer,
			final ISaml20IdpConnector idpConnector) throws NotSignedException, SamlSecurityException {
		Assert.notNull(issuer, "No Issuer provided to check the signature !");
		Assert.notNull(idpConnector, "No IdP Connector provided to check the signature !");

		if (signableObject != null) {
			final CriteriaSet criteriaSet = new CriteriaSet();
			criteriaSet.add(new EntityIDCriteria(issuer.getValue()));

			Signature signature = signableObject.getSignature();
			if ((signature == null) || signature.isNil()) {
				throw new NotSignedException("The signature is missing !");
			}

			final Validator<Signature> signatureValidator = this.factory.getSignatureValidator();
			if (signatureValidator != null) {
				try {
					signatureValidator.validate(signature);
				} catch (ValidationException e) {
					throw new SamlSecurityException("Signature is not a valid XML element !", e);
				}
			}

			// On test mode only if security keys are provided
			criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
			criteriaSet.add(new UsageCriteria(UsageType.SIGNING));

			final SignatureTrustEngine signatureTrustEngine = idpConnector.getIdpConfig().getSignatureTrustEngine();
			boolean isSignatureTrusted = false;
			try {
				isSignatureTrusted = signatureTrustEngine.validate(signature, criteriaSet);
			} catch (SecurityException e) {
				throw new SamlSecurityException("Unable to validate signature trust !", e);
			}
			if (!isSignatureTrusted) {
				throw new SamlSecurityException("Signature is not valid or emitted by an untrusted party !");
			}
		}
	}

	/**
	 * Validate assertion conditions.
	 * 
	 * @param assertion
	 *            the assertion to validate
	 * @throws ValidationException
	 *             in case of validation problem
	 */
	protected void validateConditions(final Assertion assertion) throws SamlValidationException {
		if (assertion != null) {
			Conditions conditions = assertion.getConditions();
			int clockSkew = this.getFactory().getClockSkewSeconds();
			SamlValidationHelper.validateTimes(clockSkew,
					conditions.getNotBefore(), conditions.getNotOnOrAfter());
		}
	}

	/**
	 * Find the IdP Connector to use to process the message.
	 * 
	 * @param issuer the issuer of the SAML message
	 * @return the IdP connector (cannot be null)
	 * @throws SamlSecurityException if no IdP connector found
	 */
	protected ISaml20IdpConnector findIdpConnector(final Issuer issuer) throws SamlSecurityException {
		Assert.notNull(issuer, "No issuer provided !");
		ISaml20IdpConnector connector = this.getSpProcessor().findSaml20IdpConnectorToUse(issuer.getValue());

		if (connector == null) {
			throw new SamlSecurityException("IdP Connector not found !");
		}

		return connector;
	}

	/**
	 * Get the OpenSaml object representing the SAML message.
	 * 
	 * @return OpenSaml object
	 */
	protected V getOpenSamlObject() {
		Assert.notNull(this.openSamlObject, "Typed OpenSaml object wasn't build yet !");
		return this.openSamlObject;
	}

	/**
	 * The binding use to transport the request.
	 * 
	 * @return the binding
	 */
	protected SamlBindingEnum getBinding() {
		return this.binding;
	}

	/**
	 * The Abstract Factory which built the query processor.
	 * 
	 * @return the binding
	 */
	protected OpenSaml2QueryProcessorFactory getFactory() {
		return this.factory;
	}

}
