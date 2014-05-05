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

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.signature.Signature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import fr.mby.saml2.sp.api.core.ISaml20IdpConnector;
import fr.mby.saml2.sp.api.core.ISaml20Storage;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.api.om.IOutgoingSaml;
import fr.mby.saml2.sp.api.om.IRequestWaitingForResponse;
import fr.mby.saml2.sp.impl.helper.SamlTestResourcesHelper;
import fr.mby.saml2.sp.impl.om.BasicSamlAuthentication;
import fr.mby.saml2.sp.impl.query.QueryAuthnRequest;
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

	private static final String IDP1_ENTITY_ID = "http://www.recia.fr/idp";
	
	private static final String IDP2_ENTITY_ID = "http://www.recia.fr/idp2";

	private static final String RESPONSE_ID = "SOME_RESPONSE_ID_56093";

	private static final String AUTH_SUBJECT_ID = "AUTH_SUBJECT_ID_03476";

	private static final String SESSION_INDEX_1 = "SESSION_INDEX_1_23785";

	private static final String SP_AUTHN_SERVER_NAME_ENDPOINT = "www.recia.fr";
	
	private static final String SP_AUTHN_POST_URI_ENDPOINT = "/cas/Shibboleth.sso/SAML2/POST";
	
	private static final String SP_AUTHN_REDIRECT_URI_ENDPOINT = "/cas/Shibboleth.sso/SAML2/Redirect";

	@javax.annotation.Resource(name = "authnRequest")
	private ClassPathResource authnRequest;
	
	@javax.annotation.Resource(name = "responseFullSignedRedirectEncoded")
	private ClassPathResource responseFullSignedRedirectEncoded;
	
	@javax.annotation.Resource(name = "responseFullSignedPostEncoded")
	private ClassPathResource responseFullSignedPostEncoded;
	
	@Autowired
	@Qualifier("idpConnector")
	private OpenSaml20IdpConnector idpConnector1;

	@Autowired
	@Qualifier("idpConnector2")
	private OpenSaml20IdpConnector idpConnector2;
	
	@Autowired
	private ISaml20Storage samlStorage;
	
	@Autowired
	private OpenSaml20SpProcessor spProcessor;
	
	private final LogoutRequestBuilder logoutRequestBuilder = new LogoutRequestBuilder();
	
	private final LogoutResponseBuilder logoutResponseBuilder = new LogoutResponseBuilder();
	
	private final IssuerBuilder issuerBuilder = new IssuerBuilder();
	
	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	/**
	 * Initialize the Storage by adding the original requests in the storage.
	 * 
	 * @throws Exception
	 */
	@Before
	public void addAuthnRequestInMockedStorage() throws Exception {
		// Store AuthnRequest in mocked storage
		final AuthnRequest openSamlAuthnRequest = (AuthnRequest) SamlTestResourcesHelper
				.buildOpenSamlXmlObjectFromResource(this.authnRequest);
		final String authnRequestId = openSamlAuthnRequest.getID();
		
		final Map<String, String[]> parametersMap = new HashMap<String, String[]>();
		final IRequestWaitingForResponse authnRequestData = new QueryAuthnRequest(authnRequestId, this.idpConnector1, parametersMap);
		Mockito.when(this.samlStorage.findRequestWaitingForResponse(authnRequestId)).thenReturn(authnRequestData);
	}
	
	/**
	 * The SP receive à LogoutRequest from the IdP. Which IdPConnector to choose ?
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindSaml20IdpConnectorToUseToProcessRequests() throws Exception {
		final LogoutRequest logoutRequest = this.logoutRequestBuilder.buildObject();
		final Issuer issuer = issuerBuilder.buildObject();
		
		// Issuer
		issuer.setValue(IDP2_ENTITY_ID);
		
		// Request
		logoutRequest.setIssuer(issuer);
		logoutRequest.setID(REQUEST_ID);
		
		final ISaml20IdpConnector connectorToUse = this.spProcessor.findSaml20IdpConnectorToUse(logoutRequest);
		Assert.assertNotNull("No IdPConnector to use found !", connectorToUse);
		Assert.assertEquals("Wrong IdPConnector used !", this.idpConnector2, connectorToUse);
	}
	
	/**
	 * The SP receive à LogoutResponse from the IdP. Which IdPConnector to choose ?
	 * @throws Exception
	 */
	@Test
	public void testFindSaml20IdpConnectorToUseToProcessResponses() throws Exception {
		// Mock the Original Request the response is responding to.
		Mockito.when(this.samlStorage.findAuthentication(SESSION_INDEX_1)).thenReturn(this.buildBasicSamlAuthentication());
		// Build the original request with IdpConnector1
		final IOutgoingSaml logoutRequest = this.idpConnector1.buildSaml20SingleLogoutRequest(SESSION_INDEX_1, SamlBindingEnum.SAML_20_HTTP_POST);
		Mockito.when(this.samlStorage.findRequestWaitingForResponse(REQUEST_ID)).thenReturn((IRequestWaitingForResponse) logoutRequest.getSamlQuery());
		
		
		final LogoutResponse logoutResponse = this.logoutResponseBuilder.buildObject();
		final Issuer issuer = issuerBuilder.buildObject();
		
		// Issuer
		issuer.setValue(IDP1_ENTITY_ID);
		
		// Request
		logoutResponse.setIssuer(issuer);
		logoutResponse.setID(RESPONSE_ID);
		logoutResponse.setInResponseTo(REQUEST_ID);
		
		final ISaml20IdpConnector connectorToUse = this.spProcessor.findSaml20IdpConnectorToUse(logoutResponse);
		Assert.assertNotNull("No IdPConnector to use found !", connectorToUse);
		Assert.assertEquals("Wrong IdPConnector used !", this.idpConnector1, connectorToUse);
	}

	protected BasicSamlAuthentication buildBasicSamlAuthentication() {
		final BasicSamlAuthentication auth = new BasicSamlAuthentication();
		auth.setSubjectId(AUTH_SUBJECT_ID);
		return auth;
	}

	@Test
	public void testBuildSaml20AuthnRequest() throws Exception {
		// Loop on all bindings available
		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
			final Map<String, String[]> parametersMap = new HashMap<String, String[]>();

			final IOutgoingSaml outgoingSaml = this.idpConnector1.buildSaml20AuthnRequest(parametersMap, binding);
			Assert.assertNotNull("AuthnRequest's IOutgoingSaml cannot be null !", outgoingSaml);

			// TODO implement checks
		}
	}

	@Test
	public void testBuildSaml20SingleLogoutRequest() throws Exception {
		final String sessionIndex = "sessionIndex_789654_sessionIndex_123654";
		
		// Put the original Auth in the mocked storage.
		Mockito.when(this.samlStorage.findAuthentication(sessionIndex)).thenReturn(this.buildBasicSamlAuthentication());
		
		// Loop on all bindings available
		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
			// Try to build the SloRequest
			final IOutgoingSaml outgoingSaml = this.idpConnector1.buildSaml20SingleLogoutRequest(sessionIndex, binding);
			Assert.assertNotNull("SloRequest's IOutgoingSaml cannot be null !", outgoingSaml);
			
			// TODO implement checks
		}
	}

	@Test
	public void testBuildSaml20SingleLogoutResponse() throws Exception {
		// Loop on all bindings available
		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
			final String originRequestId = "originRequestId_258741_originRequestId_963258";
			final String relayState = "relayState852789";

			final IOutgoingSaml outgoingSaml = this.idpConnector1.buildSaml20SingleLogoutResponse(binding,
					originRequestId, relayState);
			Assert.assertNotNull("SloResponse's IOutgoingSaml cannot be null !", outgoingSaml);
			
			// TODO implement checks
		}
	}

	@Test
	public void testProcessSaml20IncomingRequestWithPostAuthnResponse() throws Exception {
		final String relayState = "rs_18743";
		 
		// Store AuthnRequest in mocked storage
		final AuthnRequest openSamlAuthnRequest = (AuthnRequest) SamlTestResourcesHelper
				.buildOpenSamlXmlObjectFromResource(this.authnRequest);
		final String authnRequestId = openSamlAuthnRequest.getID();
		
		final Map<String, String[]> parametersMap = new HashMap<String, String[]>();
		final IRequestWaitingForResponse authnRequestData = new QueryAuthnRequest(authnRequestId, this.idpConnector1, parametersMap);
		Mockito.when(this.samlStorage.findRequestWaitingForResponse(authnRequestId)).thenReturn(authnRequestData);
		
		final MockHttpServletRequest request = new MockHttpServletRequest("POST", SP_AUTHN_POST_URI_ENDPOINT);
		final String encodedRequest = SamlTestResourcesHelper.readFile(this.responseFullSignedPostEncoded);
		request.setServerName(SP_AUTHN_SERVER_NAME_ENDPOINT);
		request.setParameter("SAMLResponse", encodedRequest);
		request.setParameter("RelayState", relayState);

		final IIncomingSaml incomingSaml = this.spProcessor.processSaml20IncomingRequest(request);

		Assert.assertNotNull("AuthnResponse's IIncomingSaml cannot be null !", incomingSaml);
		
		// TODO implement checks
	}

	@Test
	public void testProcessSaml20IncomingRequestWithRedirectAuthnResponse() throws Exception {
		// TODO implement this test
		final String relayState = "rs_28435";
		
		final String encodedRequest = SamlTestResourcesHelper.readFile(this.responseFullSignedRedirectEncoded);
		final MockHttpServletRequest request = new MockHttpServletRequest("GET", SP_AUTHN_REDIRECT_URI_ENDPOINT);
		request.setServerName(SP_AUTHN_SERVER_NAME_ENDPOINT);
		request.setQueryString("?SAMLResponse=" + encodedRequest + "&RelayState=" + relayState);
		request.setParameter("SAMLResponse", URLDecoder.decode(encodedRequest, "UTF-8"));
		request.setParameter("RelayState", relayState);
		
		final IIncomingSaml incomingSaml = this.spProcessor.processSaml20IncomingRequest(request);

		Assert.assertNotNull("AuthnResponse's IIncomingSaml cannot be null !", incomingSaml);
		
		// TODO implement checks
	}
	
	@Test
	public void testProcessSaml20IncomingRequestWithGetSloRequest() throws Exception {
		// TODO implement this test
		final String relayState = "rs_69437";
		
		final MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("GET");
		request.setAttribute("SAMLRequest", null);
		request.setAttribute("RelayState", relayState);
		
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
