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

package fr.mby.saml2.sp.opensaml;

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.signature.Signature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.api.om.IOutgoingSaml;
import fr.mby.saml2.sp.opensaml.core.OpenSaml20IdpConnector;
import fr.mby.saml2.sp.opensaml.core.OpenSaml20SpProcessor;

/**
 * Integration Test for opensaml2 implementations.
 * 
 * @author Maxime Bossard - 2013
 * 
 */
@RunWith(value = SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:openSaml20IdpConnectorContext.xml")
public class OpenSaml20IntegrationTest {

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

	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
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
