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

import java.io.IOException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.SamlSecurityException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.api.om.IAuthentication;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.api.om.IRequestWaitingForResponse;
import fr.mby.saml2.sp.api.query.IQuery;
import fr.mby.saml2.sp.impl.helper.SamlHelper;
import fr.mby.saml2.sp.impl.helper.SamlTestResourcesHelper;
import fr.mby.saml2.sp.impl.query.QueryAuthnRequest;
import fr.mby.saml2.sp.impl.query.QueryAuthnResponse;
import fr.mby.saml2.sp.opensaml.core.OpenSaml20IdpConnector;
import fr.mby.saml2.sp.opensaml.core.OpenSaml20SpProcessor;
import fr.mby.saml2.sp.opensaml.query.engine.AuthnResponseQueryProcessor;
import fr.mby.saml2.sp.opensaml.query.engine.OpenSaml2QueryProcessorFactory;

/**
 * Integration Test of AuthnResponse Query Processor with opensaml2 library.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 * 
 */
@RunWith(value = SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:openSaml20SpProcessorContext.xml")
public class AuthnResponseQueryProcessorTest {

	@Autowired
	private OpenSaml20SpProcessor spProcessor;

	@Autowired
	private OpenSaml20IdpConnector idpConnector;

	@Autowired
	private OpenSaml2QueryProcessorFactory factory;

	@Autowired
	private AuthnResponseQueryProcessor processor;

	private static final String SAML_ATTRIBUTE_KEY_SCENARIO_1 = "ctemail";

	private static final Object SAML_ATTRIBUTE_VALUE_SCENARIO_1 = "testValue";

	@javax.annotation.Resource(name = "authnRequest")
	private ClassPathResource authnRequest;

	@javax.annotation.Resource(name = "responseAssertSigned")
	private ClassPathResource responseAssertSigned;

	@javax.annotation.Resource(name = "responseSimpleSigned")
	private ClassPathResource responseSimpleSigned;

	@javax.annotation.Resource(name = "responseFullSigned")
	private ClassPathResource responseFullSigned;

	@javax.annotation.Resource(name = "responseAttacked2")
	private ClassPathResource responseAttacked2;

	@javax.annotation.Resource(name = "responseAttacked3")
	private ClassPathResource responseAttacked3;

	@javax.annotation.Resource(name = "responseAttacked4")
	private ClassPathResource responseAttacked4;

	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	/**
	 * Initialize the Caches
	 * 
	 * @throws Exception
	 */
	@Before
	public void initCaches() throws Exception {
		this.spProcessor.getSaml20Storage().clear();

		final AuthnRequest openSamlAuthnRequest = (AuthnRequest) SamlTestResourcesHelper
				.buildOpenSamlXmlObjectFromResource(this.authnRequest);
		final String id = openSamlAuthnRequest.getID();
		final Map<String, String[]> parametersMap = new HashMap<String, String[]>();
		final IRequestWaitingForResponse requestData = new QueryAuthnRequest(id, this.idpConnector, parametersMap);
		this.spProcessor.getSaml20Storage().storeRequestWaitingForResponse(requestData);
	}

	/**
	 * Test a valid AuthnResponse with assertions signed on all bindings.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testAssertSignedAuthnResponseProcessing() throws Exception {
		this.testAuthnResponseProcessingScenario1(this.responseAssertSigned);
	}

	/**
	 * Test a valid AuthnResponse with embedding Response signed on all bindings.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSimpleSignedAuthnResponseProcessing() throws Exception {
		this.testAuthnResponseProcessingScenario1(this.responseSimpleSigned);
	}

	/**
	 * Test a valid AuthnResponse with assertions and embedding Response signed on all bindings.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFullSignedAuthnResponseProcessing() throws Exception {
		this.testAuthnResponseProcessingScenario1(this.responseFullSigned);
	}

	/**
	 * Test Attack 2 of AuthnResponse with all bindings. Attack 2 : Add an unsigned assertion in an unsigned response
	 * 
	 * @throws Exception
	 */
	@Test(expected = SamlProcessingException.class)
	public void testAuthnResponseAttacked2() throws Exception {
		this.testAuthnResponseProcessingScenario1(this.responseAttacked2);
	}

	/**
	 * Test Attack 3 of AuthnResponse with all bindings. Attack 3 : Attack XSW (XML Signature Wrapping) = include an
	 * assertion in the signed assertion
	 * 
	 * @throws Exception
	 */
	@Test(expected = SamlProcessingException.class)
	public void testAuthnResponseAttacked3() throws Exception {
		this.testAuthnResponseProcessingScenario1(this.responseAttacked3);
	}

	/**
	 * Test Attack 4 of AuthnResponse with all bindings. Attack 4 : Add an unsigned assertion in a signed response
	 * 
	 * @throws Exception
	 */
	@Test(expected = SamlProcessingException.class)
	public void testAuthnResponseAttacked4() throws Exception {
		this.testAuthnResponseProcessingScenario1(this.responseAttacked4);
	}

	/**
	 * Test a valid AuthnResponse without original AuthnRequest.
	 * 
	 * @throws Exception
	 */
	@Test(expected = SamlProcessingException.class)
	public void testNoOriginalAuthnRequestProcessing() throws Exception {
		this.spProcessor.getSaml20Storage().clear();
		this.testAuthnResponseProcessingScenario1(this.responseAssertSigned);
	}

	/**
	 * Test Scenario 1 with all bindings.
	 * 
	 * @param resourceMessage
	 * @throws Exception
	 */
	protected void testAuthnResponseProcessingScenario1(final Resource resourceMessage) throws Exception {
		// POST binding
		this.testAuthnResponseProcessingScenario1(SamlBindingEnum.SAML_20_HTTP_POST, "/cas/Shibboleth.sso/SAML2/POST",
				resourceMessage);
		// Redirect binding
		this.testAuthnResponseProcessingScenario1(SamlBindingEnum.SAML_20_HTTP_REDIRECT,
				"/cas/Shibboleth.sso/SAML2/Redirect", resourceMessage);
	}

	/**
	 * Test the processinf of an AuthnResponse with Scenario 1. Scenario 1 : The authn response must provide 1
	 * Authentication with 1 Attribute Scenario 1
	 * 
	 * @param binding
	 * 
	 * @throws Exception
	 */
	protected void testAuthnResponseProcessingScenario1(final SamlBindingEnum binding, final String endpointUri,
			final Resource resourceMessage) throws Exception {

		final Response openSamlAuthnResponse = (Response) SamlTestResourcesHelper
				.buildOpenSamlXmlObjectFromResource(resourceMessage);
		final HttpServletRequest mockHttpRequest = this.managePostMessage(binding, endpointUri, resourceMessage);

		this.processor.initialize(this.factory, openSamlAuthnResponse, mockHttpRequest, this.spProcessor);

		final IIncomingSaml incomingSaml = this.processor.processIncomingSamlMessage();

		Assert.assertNotNull("Incoming SAML is null !", incomingSaml);

		final IQuery samlQuery = incomingSaml.getSamlQuery();
		Assert.assertNotNull("SAML query !", samlQuery);
		Assert.assertEquals("Wrong type for SAML query !", QueryAuthnResponse.class, samlQuery.getClass());

		final QueryAuthnResponse authnQuery = (QueryAuthnResponse) samlQuery;

		final List<IAuthentication> samlAuthns = authnQuery.getSamlAuthentications();
		Assert.assertNotNull("List of Authentications is null !", samlAuthns);
		Assert.assertEquals("Number of authentications in response is bad !", 1, samlAuthns.size());

		final List<String> samlAttributeValues = samlAuthns.iterator().next()
				.getAttribute(AuthnResponseQueryProcessorTest.SAML_ATTRIBUTE_KEY_SCENARIO_1);
		Assert.assertEquals("SAML attributes list size is incorrect !", 1, samlAttributeValues.size());
		Assert.assertEquals("SAML attribute value is incorrect !",
				AuthnResponseQueryProcessorTest.SAML_ATTRIBUTE_VALUE_SCENARIO_1, samlAttributeValues.iterator().next());
	}

	protected MockHttpServletRequest managePostMessage(final SamlBindingEnum binding, final String endpointUri,
			final Resource resourceMessage) throws IOException, UnsupportedSamlOperation, SamlProcessingException,
			SamlSecurityException {
		final String samlMessage = SamlTestResourcesHelper.readFile(resourceMessage);
		final String encodedMessage = SamlHelper.httpPostEncode(samlMessage);

		return this.manageMessage(binding, endpointUri, encodedMessage);
	}

	protected MockHttpServletRequest manageRedirectMessage(final SamlBindingEnum binding, final String endpointUri,
			final Resource resourceMessage) throws IOException, UnsupportedSamlOperation, SamlProcessingException,
			SamlSecurityException {
		final String samlMessage = SamlTestResourcesHelper.readFile(resourceMessage);
		String encodedMessage = SamlHelper.httpRedirectEncode(samlMessage);
		encodedMessage = URLDecoder.decode(encodedMessage, "UTF-8");
		return this.manageMessage(binding, endpointUri, encodedMessage);
	}

	protected MockHttpServletRequest manageMessage(final SamlBindingEnum binding, final String endpointUri,
			final String encodedMessage) throws IOException, UnsupportedSamlOperation, SamlProcessingException,
			SamlSecurityException {
		final MockHttpServletRequest mockHttpRequest = SamlTestResourcesHelper.BuildSamlMockResponse(encodedMessage,
				binding.getHttpMethod());
		mockHttpRequest.setRequestURI(endpointUri);

		return mockHttpRequest;
	}

}