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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.EncryptedAttribute;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import fr.mby.saml2.sp.api.core.ISaml20IdpConnector;
import fr.mby.saml2.sp.api.core.ISaml20SpProcessor;
import fr.mby.saml2.sp.api.exception.NotSignedException;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.SamlSecurityException;
import fr.mby.saml2.sp.api.exception.SamlValidationException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.api.om.IAuthentication;
import fr.mby.saml2.sp.impl.helper.SamlValidationHelper;
import fr.mby.saml2.sp.impl.om.BasicSamlAuthentication;
import fr.mby.saml2.sp.impl.query.QueryAuthnRequest;
import fr.mby.saml2.sp.impl.query.QueryAuthnResponse;
import fr.mby.saml2.sp.opensaml.helper.OpenSamlHelper;

/**
 * OpenSaml 2 implementation of QueryProcessor for incoming AuthnResponse.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 * 
 */
public class AuthnResponseQueryProcessor extends BaseOpenSaml2QueryProcessor<QueryAuthnResponse, Response> {

	/** Logger. */
	private final Logger logger = LoggerFactory.getLogger(AuthnResponseQueryProcessor.class);

	/** Assertions in AuthnResponse. */
	private List<Assertion> assertions;

	/** Authentications resulting of processing. */
	private List<IAuthentication> authentications;

	@Override
	protected void preProcess() throws SamlProcessingException, UnsupportedSamlOperation {
		// Extract Assertions
		final Response authnResponse = this.getOpenSamlObject();
		try {
			this.assertions = this.retrieveAllAssertions(authnResponse);
		} catch (final DecryptionException e) {
			throw new SamlProcessingException("Decryption problem encoutered", e);
		}

		if (CollectionUtils.isEmpty(this.assertions)) {
			throw new SamlProcessingException("No Assertions found in AuthnResponse !");
		}
	}

	@Override
	protected void checkSecurity() throws SamlSecurityException {
		final Response authnResponse = this.getOpenSamlObject();

		final ISaml20IdpConnector idpConnector = this.findIdpConnector(authnResponse.getIssuer());

		// Validate Response signature
		boolean responseSigned = false;

		try {
			this.validateSignatureTrust(authnResponse, authnResponse.getIssuer(), idpConnector);
			responseSigned = true;
		} catch (final NotSignedException e) {
			// If the response signature is absent, try to check assertions signature...
			this.logger.debug("Unable to validate AuthnResponse signature trust ! "
					+ "We will try to validate the assertions signatures ...", e);
		}

		// Validate Assertions signature
		for (final Assertion assertion : this.assertions) {
			try {
				this.validateSignatureTrust(assertion, assertion.getIssuer(), idpConnector);
			} catch (final NotSignedException e) {
				// If the response signature and assertion signature is missing => Security problem !
				if (!responseSigned) {
					throw new SamlSecurityException(
							"The Authn Response cannot be trusted, some signatures are missing !");
				}
			}
		}

	}

	@Override
	protected void validateConditions() throws SamlValidationException {
		// Validate Assertions conditions
		for (final Assertion assertion : this.assertions) {
			this.validateConditions(assertion);
		}
	}

	@Override
	protected void process() throws SamlProcessingException, SamlSecurityException, UnsupportedSamlOperation {
		final Response authnResponse = this.getOpenSamlObject();
		this.authentications = this.extractSamlAuthentications(authnResponse);

		if (CollectionUtils.isEmpty(this.authentications)) {
			throw new SamlProcessingException("No Authentication statement found in AuthnResponse !");
		}
	}

	@Override
	protected QueryAuthnResponse buildSamlQuery() throws SamlProcessingException, SamlSecurityException {
		final Response authnResponse = this.getOpenSamlObject();
		Assert.notNull(this.authentications, "Authentications list wasn't build yet !");

		final String inResponseToId = authnResponse.getInResponseTo();
		final QueryAuthnRequest originalRequest = this.checkResponseLegitimacy(inResponseToId, QueryAuthnRequest.class);

		final QueryAuthnResponse query = new QueryAuthnResponse(authnResponse.getID());
		query.setInResponseToId(inResponseToId);
		query.setOriginalRequest(originalRequest);
		query.setSamlAuthentications(this.authentications);

		return query;
	}

	/**
	 * Retrieve all assertions, normal ones and encrypted ones if a private key was provided.
	 * 
	 * @param samlResponse
	 *            the saml response containing the assertions.
	 * @return the list of all assertions.
	 * @throws DecryptionException
	 *             in case of decryption problem.
	 * @throws UnsupportedSamlOperation
	 */
	protected List<Assertion> retrieveAllAssertions(final Response samlResponse) throws DecryptionException,
			UnsupportedSamlOperation {
		final List<Assertion> allAssertions = new ArrayList<Assertion>();

		if (samlResponse != null) {
			// Normal Assertions
			final List<Assertion> normalAssertions = samlResponse.getAssertions();
			if (!CollectionUtils.isEmpty(normalAssertions)) {
				allAssertions.addAll(normalAssertions);
			}

			// Encrypted Assertions
			final List<EncryptedAssertion> encAssertions = samlResponse.getEncryptedAssertions();
			if (!CollectionUtils.isEmpty(encAssertions)) {
				for (final EncryptedAssertion encAssertion : samlResponse.getEncryptedAssertions()) {
					final Assertion assertion = this.decryptAssertion(encAssertion);

					allAssertions.add(assertion);
				}
			}
		}

		return allAssertions;
	}

	/**
	 * Decrypt an encrypted assertion.
	 * 
	 * @param encAssertion
	 * @throws DecryptionException
	 * @throws UnsupportedSamlOperation
	 */
	private Assertion decryptAssertion(final EncryptedAssertion encAssertion) throws DecryptionException,
			UnsupportedSamlOperation {
		Assertion assertion = null;

		if (encAssertion != null) {
			final ISaml20SpProcessor spProcessor = this.getSpProcessor();
			final Decrypter decrypter = spProcessor.getDecrypter();

			assertion = (Assertion) decrypter.decryptData(encAssertion.getEncryptedData(), true);

			if (this.logger.isDebugEnabled()) {
				try {
					this.logger.debug("Decrypted Assertion: [{}]", OpenSamlHelper.marshallXmlObject(assertion));
				} catch (final MarshallingException e) {
					this.logger.error("Unable to marshall decrypted Assertion for debugging purpose !");
				}
			}
		}

		return assertion;
	}

	/**
	 * Decrypt Assertion Identifier and add it in the Subject.
	 * 
	 * @param assertion
	 * @throws DecryptionException
	 * @throws UnsupportedSamlOperation
	 */
	private void decryptIdentifier(final Assertion assertion) throws DecryptionException, UnsupportedSamlOperation {
		if (assertion != null) {
			final Subject subject = assertion.getSubject();

			final EncryptedID encryptedId = subject.getEncryptedID();
			if (encryptedId != null) {
				final ISaml20SpProcessor spProcessor = this.getSpProcessor();
				final Decrypter decrypter = spProcessor.getDecrypter();
				final SAMLObject identifier = decrypter.decrypt(encryptedId);
				if ((identifier == null) || !NameID.class.isAssignableFrom(identifier.getClass())) {
					// Encrypted ID not a NameID !
					final String message = String.format("Encrypted ID type not supported: [%1$s] ! "
							+ "Only NameID is currently supported !", identifier.getClass());
					throw new UnsupportedSamlOperation(message);
				}

				// Inject the NameID in the assertion
				final NameID nameId = (NameID) identifier;
				subject.setNameID(nameId);

				this.logger.debug("Decrypted Indentifier: [{}]", nameId.getValue());
			}
		}
	}

	/**
	 * Decrypt assertion attributes and add it in clear attributes.
	 * 
	 * @param assertion
	 * @throws DecryptionException
	 */
	private void decryptAttributes(final Assertion assertion) throws DecryptionException {
		if (assertion != null) {
			final ISaml20SpProcessor spProcessor = this.getSpProcessor();
			final Decrypter decrypter = spProcessor.getDecrypter();

			final List<AttributeStatement> attributeStmts = assertion.getAttributeStatements();
			if (!CollectionUtils.isEmpty(attributeStmts)) {
				for (final AttributeStatement attributeStmt : attributeStmts) {
					final Iterator<EncryptedAttribute> encryptAttrIt = attributeStmt.getEncryptedAttributes()
							.iterator();

					while (encryptAttrIt.hasNext()) {
						final EncryptedAttribute encryptedAttribute = encryptAttrIt.next();
						// For every encrypted attribute
						final Attribute attribute = decrypter.decrypt(encryptedAttribute);

						// Inject the Attribute in the assertion
						attributeStmt.getAttributes().add(attribute);

						this.logger.debug("Decrypted Attribute name: [{}]", attribute.getName());
					}
				}
			}

		}
	}

	/**
	 * Extract the authentications informations from opensaml Authn Response.
	 * 
	 * @param authnResponse
	 * @param idpConnector
	 * @param responseSigned
	 * @return a list of authentications embeded in the Authn Response
	 * @throws UnsupportedSamlOperation
	 * @throws SamlSecurityException
	 * @throws SamlProcessingException
	 */
	protected List<IAuthentication> extractSamlAuthentications(final Response authnResponse)
			throws SamlSecurityException, UnsupportedSamlOperation, SamlProcessingException {
		final List<IAuthentication> authentications = new ArrayList<IAuthentication>();

		Assert.notEmpty(this.assertions, "Assertions not already processed !");

		try {
			// Our Authn Response could carry multiple assertions, we are interressed only by an AuthnStatement
			// Assertion.
			for (final Assertion assertion : this.assertions) {
				// We look for an AuthnStatement Assertion !
				final List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
				if (authnStatements != null) {
					for (final AuthnStatement authnStatement : authnStatements) {
						// MBD FIX 2013-04-30 : Loop on all AuthnStatement
						final Subject subject = this.validateAndRetrieveSubject(assertion);
						final NameID nameId = subject.getNameID();
						if (nameId == null) {
							throw new UnsupportedSamlOperation(
									"Subject NameID missing other ID types are not supported !");
						}

						final BasicSamlAuthentication authn = new BasicSamlAuthentication();
						authn.setAuthenticationInstant(authnStatement.getAuthnInstant());
						authn.setSubjectId(nameId.getValue());
						authn.setSessionIndex(authnStatement.getSessionIndex());

						this.processAuthnAttributes(assertion, authn);

						// Add the authentication to the list
						authn.lock();
						authentications.add(authn);
					}
				}
			}
		} catch (final SamlValidationException e) {
			throw new SamlProcessingException("Validation of Assertion Subjet failed !", e);
		} catch (final DecryptionException e) {
			throw new SamlProcessingException("Decryption of SAML Assertions failed !", e);
		}

		return authentications;
	}

	/**
	 * Retrieve a unique AuthnStatement in an assertion.
	 * 
	 * @param assertionsession
	 *            assertion
	 * @return the AuthnStatement of this assertion (can be null)
	 * @throws UnsupportedSamlOperation
	 *             if multiple AuthnStatement found
	 */
	protected AuthnStatement retrieveAuthnStatement(final Assertion assertion) throws UnsupportedSamlOperation {
		AuthnStatement authnStatement = null;

		if (assertion != null) {
			final List<AuthnStatement> authnStatements = assertion.getAuthnStatements();

			if (authnStatements.size() > 1) {
				throw new UnsupportedSamlOperation(
						"This SP does not support multiple AuthnStatement in one assertion !");
			} else if (authnStatements.size() == 1) {
				authnStatement = authnStatements.iterator().next();
			}
		}

		return authnStatement;
	}

	/**
	 * Validate an assertion subject.
	 * 
	 * @param assertion
	 *            the assertion containing the subject
	 * @return the validated subject. It can be null !
	 * @throws ValidationException
	 *             in case of validation problem
	 * @throws DecryptionException
	 * @throws UnsupportedSamlOperation
	 */
	protected Subject validateAndRetrieveSubject(final Assertion assertion) throws SamlValidationException,
			DecryptionException, UnsupportedSamlOperation {
		Subject subject = null;
		if (assertion != null) {
			subject = assertion.getSubject();
			List<SubjectConfirmation> subjectConfirmations = null;

			SubjectConfirmationData scData = null;

			if (subject == null) {
				throw new SamlValidationException("The assertion doesn't contain a subject !");
			}

			// Check subject confirmations
			subjectConfirmations = subject.getSubjectConfirmations();
			if (!CollectionUtils.isEmpty(subjectConfirmations)) {
				for (final SubjectConfirmation subjectConfirmation : subjectConfirmations) {
					if (subjectConfirmation != null) {
						scData = subjectConfirmation.getSubjectConfirmationData();
						final int clockSkew = this.getFactory().getClockSkewSeconds();
						SamlValidationHelper.validateTimes(clockSkew, scData.getNotBefore(), scData.getNotOnOrAfter());
					}
				}
			}

			this.decryptIdentifier(assertion);
		}

		return subject;
	}

	/**
	 * Add each assertion attributes and its values in the authentication data object.
	 * 
	 * @param assertion
	 *            the assertion
	 * @param authn
	 *            the authentication data object
	 * @throws DecryptionException
	 * @throws SamlSecurityException
	 */
	protected void processAuthnAttributes(final Assertion assertion, final IAuthentication authn)
			throws SamlSecurityException, DecryptionException {
		final List<Attribute> attributes = this.retrieveAttributes(assertion);
		if (!CollectionUtils.isEmpty(attributes)) {
			for (final Attribute attr : attributes) {
				if (attr != null) {
					final List<String> values = new ArrayList<String>();
					for (final XMLObject value : attr.getAttributeValues()) {
						if (value != null) {
							final String textContent = value.getDOM().getTextContent();
							if (StringUtils.hasText(textContent)) {
								values.add(textContent);
							}
						}
					}

					final String attrName = attr.getName();
					if (!CollectionUtils.isEmpty(values)) {
						authn.addAttribute(attrName, values);
					}
				}
			}
		}
	}

	/**
	 * Retrieve assertion attributes.
	 * 
	 * @param assertion
	 *            the assertion containing the attributes
	 * @return the list of all attributes.
	 * @throws DecryptionException
	 */
	protected List<Attribute> retrieveAttributes(final Assertion assertion) throws DecryptionException {
		final List<Attribute> attributes = new ArrayList<Attribute>();

		this.decryptAttributes(assertion);

		if (assertion != null) {
			final List<AttributeStatement> statements = assertion.getAttributeStatements();
			if (!CollectionUtils.isEmpty(statements)) {
				for (final AttributeStatement statement : statements) {
					// Get all attributes from statement
					final List<Attribute> attrs = statement.getAttributes();
					if (!CollectionUtils.isEmpty(attrs)) {
						attributes.addAll(attrs);
					}
				}
			}
		}

		this.logger.info("[{}] attribute(s) found in SAML assertion.", attributes.size());

		return attributes;
	}

}
