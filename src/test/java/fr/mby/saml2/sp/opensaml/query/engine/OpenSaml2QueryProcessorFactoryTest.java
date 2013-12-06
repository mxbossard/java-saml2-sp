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

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import fr.mby.saml2.sp.api.core.ISaml20SpProcessor;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.SamlSecurityException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.api.query.engine.IQueryProcessor;
import fr.mby.saml2.sp.impl.helper.SamlHelper;
import fr.mby.saml2.sp.impl.helper.SamlTestResourcesHelper;
import fr.mby.saml2.sp.opensaml.query.engine.AuthnResponseQueryProcessor;
import fr.mby.saml2.sp.opensaml.query.engine.OpenSaml2QueryProcessorFactory;
import fr.mby.saml2.sp.opensaml.query.engine.SloResponseQueryProcessor;

/**
 * Integration Test of Query Processor Factory with opensaml2 library.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
@RunWith(value=SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:openSaml2QueryProcessorFactoryContext.xml")
public class OpenSaml2QueryProcessorFactoryTest {

	@Mock
	private ISaml20SpProcessor spProcessor;

	@Autowired
	private OpenSaml2QueryProcessorFactory factory;

	@javax.annotation.Resource(name="responseSimpleSigned")
	private ClassPathResource responseSimpleSigned;

	@javax.annotation.Resource(name="sloResponse")
	private ClassPathResource sloResponse;

	@javax.annotation.Resource(name="authnRequest")
	private ClassPathResource authnRequest;

	@javax.annotation.Resource(name="responseAttacked1")
	private ClassPathResource responseAttacked1;

	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	/**
	 * Valid case : Authn Response with POST binding.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testPostAuthnResponse() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_POST;
		IQueryProcessor queryProcessor = this.managePostMessage(binding, "/cas/Shibboleth.sso/SAML2/POST", this.responseSimpleSigned);

		Assert.assertEquals("Wrong type of query processor built !", AuthnResponseQueryProcessor.class, queryProcessor.getClass());

	}

	/**
	 * Valid case : Authn Response with Redirect binding.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testRedirectAuthnResponse() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_REDIRECT;
		IQueryProcessor queryProcessor = this.manageRedirectMessage(binding, "/cas/Shibboleth.sso/SAML2/Redirect", this.responseSimpleSigned);

		Assert.assertEquals("Wrong type of query processor built !", AuthnResponseQueryProcessor.class, queryProcessor.getClass());
	}

	/**
	 * Valid case : SLO response with POST binding.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testPostSloResponse() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_POST;
		IQueryProcessor queryProcessor = this.managePostMessage(binding, "/cas/Shibboleth.sso/SAML2/POST", this.sloResponse);

		Assert.assertEquals("Wrong type of query processor built !", SloResponseQueryProcessor.class, queryProcessor.getClass());
	}

	/**
	 * Valid case : SLO response with Redirect binding.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testRedirectSloResponse() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_REDIRECT;
		IQueryProcessor queryProcessor = this.manageRedirectMessage(binding, "/cas/Shibboleth.sso/SAML2/Redirect", this.sloResponse);

		Assert.assertEquals("Wrong type of query processor built !", SloResponseQueryProcessor.class, queryProcessor.getClass());
	}

	/**
	 * Error case : Authn Response with Post binding but bad endpoint.
	 * 
	 * @throws Exception
	 */
	@Test(expected=SamlProcessingException.class)
	public void testPostAuthnResponseBadEndpoint1() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_POST;
		IQueryProcessor queryProcessor = this.managePostMessage(binding, "/cas/Shibboleth.sso/SLO/POST", this.responseSimpleSigned);

		// Should not be processed !
		queryProcessor.processIncomingSamlMessage();
	}

	/**
	 * Error case : Authn Response with Post binding but bad endpoint.
	 * 
	 * @throws Exception
	 */
	@Test(expected=SamlProcessingException.class)
	public void testPostAuthnResponseBadEndpoint2() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_POST;
		IQueryProcessor queryProcessor = this.managePostMessage(binding, "/cas/Shibboleth.sso/Truc/POST", this.responseSimpleSigned);

		// Should not be processed !
		queryProcessor.processIncomingSamlMessage();
	}

	/**
	 * Error case : Authn Response with Post binding but bad encoding.
	 * 
	 * @throws Exception
	 */
	@Test(expected=SamlProcessingException.class)
	public void testPostAuthnResponseBadEncoding() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_POST;
		this.managePostMessage(binding, "/cas/Shibboleth.sso/SAML2/Redirect", this.responseSimpleSigned);
	}

	/**
	 * Error case : Authn Response with Post binding but not supported encoding
	 * 
	 * @throws Exception
	 */
	@Test(expected=UnsupportedSamlOperation.class)
	public void testPostAuthnResponseNotExistingEncoding1() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_POST;
		this.managePostMessage(binding, "/cas/Shibboleth.sso/SAML2/Truc", this.responseSimpleSigned);
	}

	/**
	 * Error case : Authn Response with Post binding but not supported encoding
	 * 
	 * @throws Exception
	 */
	@Test(expected=UnsupportedSamlOperation.class)
	public void testPostAuthnResponseNotExistingEncoding2() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_POST;
		this.managePostMessage(binding, "/cas/Shibboleth.sso/SAML2", this.responseSimpleSigned);
	}

	/**
	 * Error case : Authn Request currently not processed with this config.
	 * 
	 * @throws Exception
	 */
	@Test(expected=UnsupportedSamlOperation.class)
	public void testPostAuthnRequest() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_POST;
		this.managePostMessage(binding, "/cas/Shibboleth.sso/SAML2/POST", this.authnRequest);
	}

	/**
	 * Test Attack 1 of AuthnResponse.
	 * Attack 1 : Corruption of XML tree = invalid XML
	 * 
	 * @throws Exception
	 */
	@Test(expected=SamlProcessingException.class)
	public void testAuthnResponseAttacked1() throws Exception {
		SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_POST;
		this.managePostMessage(binding, "/cas/Shibboleth.sso/SAML2/POST", this.responseAttacked1);
	}

	protected IQueryProcessor managePostMessage(final SamlBindingEnum binding, final String endpointUri, final Resource resourceMessage) throws IOException, UnsupportedSamlOperation,
	SamlProcessingException, SamlSecurityException {
		String samlMessage = SamlTestResourcesHelper.readFile(resourceMessage);
		String encodedMessage = SamlHelper.httpPostEncode(samlMessage);

		return this.manageMessage(binding, endpointUri, encodedMessage);
	}

	protected IQueryProcessor manageRedirectMessage(final SamlBindingEnum binding, final String endpointUri, final Resource resourceMessage) throws IOException, UnsupportedSamlOperation,
	SamlProcessingException, SamlSecurityException {
		String samlMessage = SamlTestResourcesHelper.readFile(resourceMessage);
		String encodedMessage = SamlHelper.httpRedirectEncode(samlMessage);

		return this.manageMessage(binding, endpointUri, encodedMessage);
	}

	protected IQueryProcessor manageMessage(final SamlBindingEnum binding, final String endpointUri, final String encodedMessage) throws IOException, UnsupportedSamlOperation,
	SamlProcessingException, SamlSecurityException {
		MockHttpServletRequest mockHttpRequest = SamlTestResourcesHelper.BuildSamlMockResponse(encodedMessage, binding.getHttpMethod());
		mockHttpRequest.setRequestURI(endpointUri);

		IQueryProcessor queryProcessor = this.factory.buildQueryProcessor(this.spProcessor, mockHttpRequest);

		Assert.assertNotNull("Query processor not built !", queryProcessor);
		return queryProcessor;
	}

}