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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.signature.Signature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import fr.mby.saml2.sp.api.handler.IAuthenticationHandler;
import fr.mby.saml2.sp.api.om.IAuthentication;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.impl.helper.SamlTestResourcesHelper;
import fr.mby.saml2.sp.impl.om.BasicSamlAuthentication;
import fr.mby.saml2.sp.impl.query.QueryAuthnResponse;

/**
 * Unit Test for opensaml2 implementation of ISaml20SpProcessor.
 * 
 * @author Maxime Bossard - 2013
 * 
 */
@RunWith(value = SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:idpSideConfigContext.xml")
public class OpenSaml20SpProcessorTest {

	private static final String AUTH_ATTR_KEY = "AUTH_ATTR_KEY";
	
	private static final String AUTH_ATTR_VALUE_1 = "AUTH_ATTR_VALUE_1";
	
	private static final String AUTH_ATTR_VALUE_2 = "AUTH_ATTR_VALUE_2";
	
	private static final List<String> AUTH_ATTR_VALUES = new ArrayList<String>();
	static {
		AUTH_ATTR_VALUES.add(AUTH_ATTR_VALUE_1);
		AUTH_ATTR_VALUES.add(AUTH_ATTR_VALUE_2);
	}

	@Autowired
	private OpenSaml20SpProcessor spProcessor;

	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	@Test
	public void testBuildSignature() throws Exception {
		final Signature signature1 = this.spProcessor.buildSignature(false);
		Assert.assertNotNull("Signature cannot be null !", signature1);
		Assert.assertNotNull("Signature KeyInfo cannot be null !", signature1.getKeyInfo());

		final Signature signature2 = this.spProcessor.buildSignature(true);
		Assert.assertNotNull("Signature cannot be null !", signature2);
		Assert.assertNull("Signature KeyInfo must be null !", signature2.getKeyInfo());
	}

	@Test
	public void testTryAuthenticationPropagation() throws Exception {

		final IIncomingSaml incomingSaml = Mockito.mock(IIncomingSaml.class);
		final QueryAuthnResponse queryAuthnResponse = Mockito.mock(QueryAuthnResponse.class);
		final List<IAuthentication> authns = new ArrayList<IAuthentication>();
		final BasicSamlAuthentication basicAuth = new BasicSamlAuthentication();
		basicAuth.addAttribute(AUTH_ATTR_KEY, AUTH_ATTR_VALUES);
		authns.add(basicAuth);
		
		Mockito.when(incomingSaml.getSamlQuery()).thenReturn(queryAuthnResponse);
		Mockito.when(queryAuthnResponse.getSamlAuthentications()).thenReturn(authns);
		
		final AtomicBoolean authPropagated = new AtomicBoolean(false);
		
		this.spProcessor.setAuthenticationHandler(new IAuthenticationHandler() {
			
			@Override
			public void propagateAuthentications(List<IAuthentication> authentications) {
				Assert.assertNotNull("No authentications propagated !", authentications);
				Assert.assertEquals("Bad authentications list size !", authns.size(), authentications.size());
				
				final IAuthentication authn = authentications.iterator().next();
				Assert.assertNotNull("Null authentication attributes list !", authn.getAttributes());
				Assert.assertEquals("Bad authentication attributes list size !", basicAuth.getAttributes().size(), authn.getAttributes().size());

				final List<String> values = authn.getAttribute(AUTH_ATTR_KEY);
				Assert.assertNotNull("No attribute values found in propagated authentications !", values);
				Assert.assertEquals("Bad values list size !", AUTH_ATTR_VALUES.size(), values.size());
				
				final Iterator<String> valuesIt = values.iterator();
				Assert.assertEquals("Bad first propagated authentication attibutes !", AUTH_ATTR_VALUE_1, valuesIt.next());
				Assert.assertEquals("Bad second propagated authentication attribute value !", AUTH_ATTR_VALUE_2, valuesIt.next());
				
				authPropagated.set(true);
			}
		});
		
		this.spProcessor.tryAuthenticationPropagation(incomingSaml);

		Assert.assertTrue("Authentication wasn't propagated !", authPropagated.get());
	}

}
