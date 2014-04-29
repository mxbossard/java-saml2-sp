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

package fr.mby.saml2.sp.opensaml.core;

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.signature.Signature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import fr.mby.saml2.sp.api.core.ISaml20Storage;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.api.om.IOutgoingSaml;
import fr.mby.saml2.sp.api.om.IRequestWaitingForResponse;
import fr.mby.saml2.sp.impl.query.QuerySloRequest;

/**
 * Integration Test for opensaml2 implementations.
 * 
 * @author Maxime Bossard - 2013
 * 
 */
@RunWith(value = SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:openSaml20IntegrationContext.xml")
public class OpenSaml20IntegrationTest {

	@SuppressWarnings("unused")
	private static final String SP_ENTITY_ID = "http://www.recia.fr/service";

	private static final String REQUEST_ID = "SOME_REQUEST_ID_12487";

	private static final String IDP_ENTITY_ID = "http://www.recia.fr/idp";

	private static final String RESPONSE_ID = "SOME_RESPONSE_ID_56093";

	@javax.annotation.Resource(name = "responseAssertSigned")
	private ClassPathResource responseAssertSigned;

	@javax.annotation.Resource(name = "responseSimpleSigned")
	private ClassPathResource responseSimpleSigned;

	@javax.annotation.Resource(name = "responseFullSigned")
	private ClassPathResource responseFullSigned;

	@Autowired
	private OpenSaml20IdpConnector idpConnector;

	@Autowired
	private OpenSaml20SpProcessor spProcessor;
	
	private final LogoutRequestBuilder logoutRequestBuilder = new LogoutRequestBuilder();
	
	private final LogoutResponseBuilder logoutResponseBuilder = new LogoutResponseBuilder();
	
	private final IssuerBuilder issuerBuilder = new IssuerBuilder();
	
	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	@Test
	public void testFindSaml20IdpConnectorToUseToProcessRequests() throws Exception {
		// The SP receive à LogoutRequest from the IdP. Which IdP to choose ?
		LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();
		Issuer issuer = issuerBuilder.buildObject();
		
		// Issuer
		issuer.setValue(IDP_ENTITY_ID);
		
		// Request
		logoutRequest.setIssuer(issuer);
		logoutRequest.setID(REQUEST_ID);
		
		this.spProcessor.findSaml20IdpConnectorToUse(logoutRequest);
	}
	
	@Test
	public void testFindSaml20IdpConnectorToUseToProcessResponses() throws Exception {
		// TODO implement this test
		
		IRequestWaitingForResponse logoutRequest = new QuerySloRequest();
		
		ISaml20Storage samlStorage = Mockito.mock(ISaml20Storage.class);
		Mockito.when(samlStorage.findRequestWaitingForResponse(REQUEST_ID)).thenReturn(logoutRequest);
		this.spProcessor.setSaml20Storage(samlStorage);
		
		LogoutResponse logoutResponse = logoutResponseBuilder.buildObject();
		Issuer issuer = issuerBuilder.buildObject();
		
		// Issuer
		issuer.setValue(IDP_ENTITY_ID);
		
		// Request
		logoutResponse.setIssuer(issuer);
		logoutResponse.setID(RESPONSE_ID);
		logoutResponse.setInResponseTo(REQUEST_ID);
		
		this.spProcessor.findSaml20IdpConnectorToUse(logoutResponse);

	}

	@Test
	public void testBuildSaml20AuthnRequest() throws Exception {
		// TODO implement this test
		// Loop on all bindings available
		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
			final Map<String, String[]> parametersMap = new HashMap<String, String[]>();

			final IOutgoingSaml outgoingSaml = this.idpConnector.buildSaml20AuthnRequest(parametersMap, binding);
			Assert.assertNotNull("AuthnRequest's IOutgoingSaml cannot be null !", outgoingSaml);

		}
	}

	@Test
	public void testBuildSaml20SingleLogoutRequest() throws Exception {
		// TODO implement this test
		// Loop on all bindings available
		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
			final String sessionIndex = "sessionIndex_789654_sessionIndex_123654";

			final IOutgoingSaml outgoingSaml = this.idpConnector.buildSaml20SingleLogoutRequest(sessionIndex, binding);
			Assert.assertNotNull("SloRequest's IOutgoingSaml cannot be null !", outgoingSaml);

		}
	}

	@Test
	public void testBuildSaml20SingleLogoutResponse() throws Exception {
		// TODO implement this test
		// Loop on all bindings available
		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
			final String originRequestId = "originRequestId_258741_originRequestId_963258";
			final String relayState = "relayState852789";

			final IOutgoingSaml outgoingSaml = this.idpConnector.buildSaml20SingleLogoutResponse(binding,
					originRequestId, relayState);
			Assert.assertNotNull("SloResponse's IOutgoingSaml cannot be null !", outgoingSaml);

		}
	}

	@Test
	public void testProcessSaml20IncomingRequestWithAuthnResponse() throws Exception {
		// TODO implement this test
		final MockHttpServletRequest request = new MockHttpServletRequest();

		final IIncomingSaml incomingSaml = this.spProcessor.processSaml20IncomingRequest(request);

		Assert.assertNotNull("AuthnResponse's IIncomingSaml cannot be null !", incomingSaml);
	}

	@Test
	public void testProcessSaml20IncomingRequestWithSloRequest() throws Exception {
		// TODO implement this test
		final MockHttpServletRequest request = new MockHttpServletRequest();

		final IIncomingSaml incomingSaml = this.spProcessor.processSaml20IncomingRequest(request);

		Assert.assertNotNull("SloRequest's IIncomingSaml cannot be null !", incomingSaml);
	}

	@Test
	public void testProcessSaml20IncomingRequestWithSloResponse() throws Exception {
		// TODO implement this test
		final MockHttpServletRequest request = new MockHttpServletRequest();

		final IIncomingSaml incomingSaml = this.spProcessor.processSaml20IncomingRequest(request);

		Assert.assertNotNull("SloResponse's IIncomingSaml cannot be null !", incomingSaml);
	}

	@Test
	public void testSignSamlObject() throws Exception {
		// TODO implement this test
		final SignableSAMLObject signable = null;
		final Signature signature = this.spProcessor.signSamlObject(signable);

		Assert.assertNotNull("Signature cannot be null !", signature);
	}

	@Test
	public void testLogout() throws Exception {
		// TODO implement this test
		final String sessionIndex = "index_de_folie";
		this.spProcessor.logout(sessionIndex);
	}
}
