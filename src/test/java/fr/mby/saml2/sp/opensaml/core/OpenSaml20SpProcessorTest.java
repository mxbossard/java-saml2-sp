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

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
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
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import fr.mby.saml2.sp.api.core.ISaml20Storage;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.api.om.IRequestWaitingForResponse;
import fr.mby.saml2.sp.impl.query.QuerySloRequest;

/**
 * Unit Test for opensaml2 implementation of ISaml20SpProcessor.
 * 
 * @author Maxime Bossard - 2013
 * 
 */
@RunWith(value = SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:idpSideConfigContext.xml")
public class OpenSaml20SpProcessorTest {

	private static final String REQUEST_ISSUER = "http://www.recia.fr/service";

	private static final String REQUEST_ID = "SOME_REQUEST_ID_12487";

	private static final String RESPONSE_ISSUER = "http://www.recia.fr/idp";

	private static final String RESPONSE_ID = "SOME_RESPONSE_ID_56093";

	@javax.annotation.Resource(name = "responseAssertSigned")
	private ClassPathResource responseAssertSigned;

	@javax.annotation.Resource(name = "responseSimpleSigned")
	private ClassPathResource responseSimpleSigned;

	@javax.annotation.Resource(name = "responseFullSigned")
	private ClassPathResource responseFullSigned;

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
	public void testSignSamlObject() throws Exception {
		final Signature signature1 = this.spProcessor.buildSignature(false);
		Assert.assertNotNull("Signature cannot be null !", signature1);
		Assert.assertNotNull("Signature KeyInfo cannot be null !", signature1.getKeyInfo());

		final Signature signature2 = this.spProcessor.buildSignature(true);
		Assert.assertNotNull("Signature cannot be null !", signature2);
		Assert.assertNull("Signature KeyInfo must be null !", signature2.getKeyInfo());
	}

	@Test
	public void testFindSaml20IdpConnectorToUseToProcessRequests() throws Exception {
		// TODO implement this test
		LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();
		Issuer issuer = issuerBuilder.buildObject();
		
		// Issuer
		issuer.setValue(REQUEST_ISSUER);
		
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
		issuer.setValue(RESPONSE_ISSUER);
		
		// Request
		logoutResponse.setIssuer(issuer);
		logoutResponse.setID(RESPONSE_ID);
		logoutResponse.setInResponseTo(REQUEST_ID);
		
		this.spProcessor.findSaml20IdpConnectorToUse(logoutResponse);

	}

	@Test
	public void testTryAuthenticationPropagation() throws Exception {
		// TODO implement this test
		final IIncomingSaml incomingSaml = null;
		this.spProcessor.tryAuthenticationPropagation(incomingSaml);

	}

}
