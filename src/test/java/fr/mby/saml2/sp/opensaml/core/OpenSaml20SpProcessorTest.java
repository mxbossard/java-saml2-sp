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

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import fr.mby.saml2.sp.impl.helper.SamlTestResourcesHelper;

/**
 * Unit Test for opensaml2 implementation of ISaml20SpProcessor.
 * 
 * @author Maxime Bossard - 2013
 * 
 */
@RunWith(value = SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:idpSideConfigContext.xml")
public class OpenSaml20SpProcessorTest {

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
	public void testSignSamlObject() throws Exception {
		final Response response = (Response) SamlTestResourcesHelper
				.buildOpenSamlXmlObjectFromResource(this.responseSimpleSigned);

		this.spProcessor.signSamlObject(response);

	}

}
