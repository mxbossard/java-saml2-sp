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

import java.io.IOException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.signature.Signature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import fr.mby.saml2.sp.impl.helper.SamlTestResourcesHelper;
import fr.mby.saml2.sp.opensaml.helper.OpenSamlHelper;

/**
 * Tests d'intégration de la library opensaml2 dans le SP Processor.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
@RunWith(value = SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:idpSideConfigContext.xml")
public class OpenSaml20ProcessingTest {

	@javax.annotation.Resource(name = "responseAssertSigned")
	private ClassPathResource responseAssertSigned;

	@javax.annotation.Resource(name = "responseSimpleSigned")
	private ClassPathResource responseSimpleSigned;

	@javax.annotation.Resource(name = "responseFullSigned")
	private ClassPathResource responseFullSigned;

	@Autowired
	private OpenSaml20SpProcessor spProcessor;

	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	@Test
	public void signMessage() throws Exception {
		final Response response = (Response) SamlTestResourcesHelper
				.buildOpenSamlXmlObjectFromResource(this.responseSimpleSigned);

		this.signResponse(response);
	}

	/**
	 * Temp method to sign a message.
	 * 
	 * @param samlResponse
	 * @throws IOException
	 */
	private void signResponse(final Response samlResponse) throws IOException {
		// final Assertion assertion = samlResponse.getAssertions().iterator().next();
		// Signature signature1 = this.spProcessor.buildSignature(false);
		final Signature signature2 = this.spProcessor.buildSignature(false);
		// assertion.setSignature(signature1);
		samlResponse.setSignature(signature2);
		// OpenSamlHelper.httpPostEncode(assertion);
		OpenSamlHelper.httpPostEncode(samlResponse);
	}

}
