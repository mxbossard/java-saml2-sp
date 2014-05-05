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

import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.xml.ConfigurationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.SerializationUtils;

import fr.mby.saml2.sp.api.core.ISaml20Storage;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.om.IRequestWaitingForResponse;
import fr.mby.saml2.sp.impl.helper.SamlTestResourcesHelper;
import fr.mby.saml2.sp.impl.om.BasicSamlAuthentication;
import fr.mby.saml2.sp.impl.query.QueryAuthnRequest;
import fr.mby.saml2.sp.impl.query.QuerySloRequest;
import fr.mby.saml2.sp.impl.query.QuerySloResponse;

/**
 * Unit Test for opensaml2 implementation of ISaml20IdpConnector.
 * 
 * @author Maxime Bossard - 2013
 * 
 */
@RunWith(value = SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:openSaml20IdpConnectorContext.xml")
public class OpenSaml20IdpConnectorTest {

	@Autowired
	private OpenSaml20IdpConnector idpConnector;

	@Autowired
	private ISaml20Storage samlStorage;
	
	@javax.annotation.Resource(name = "authnRequest")
	private ClassPathResource authnRequest;
	
	private String authnRequestId;
	
	@javax.annotation.Resource(name = "sloRequest")
	private ClassPathResource sloRequest;
	
	private String sloRequestId;
	
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
	public void initStorageWithRequest() throws Exception {

		final AuthnRequest openSamlAuthnRequest = (AuthnRequest) SamlTestResourcesHelper
				.buildOpenSamlXmlObjectFromResource(this.authnRequest);
		this.authnRequestId = openSamlAuthnRequest.getID();
		
		final Map<String, String[]> parametersMap = new HashMap<String, String[]>();
		final IRequestWaitingForResponse authnRequestData = new QueryAuthnRequest(this.authnRequestId, this.idpConnector, parametersMap);
		Mockito.when(this.samlStorage.findRequestWaitingForResponse(this.authnRequestId)).thenReturn(authnRequestData);
		
		final LogoutRequest openSamlLogoutRequest = (LogoutRequest) SamlTestResourcesHelper
				.buildOpenSamlXmlObjectFromResource(this.sloRequest);
		this.sloRequestId = openSamlLogoutRequest.getID();
		
		final IRequestWaitingForResponse sloRequestData = new QuerySloRequest(this.sloRequestId, this.idpConnector);
		Mockito.when(this.samlStorage.findRequestWaitingForResponse(this.sloRequestId)).thenReturn(sloRequestData);
	}

	@Test
	public void testGenerateUniqueQueryId() throws Exception {
		final String uniqueId = this.idpConnector.generateUniqueQueryId();

		Assert.assertNotNull("Generated Id cannot be null !", uniqueId);
		Assert.assertTrue("Weak generated Id !", uniqueId.length() > 16);
	}

	@Test
	public void testBuildQueryAuthnRequest() throws Exception {
		final Map<String, String[]> parametersMap = new HashMap<String, String[]>();
		final String[] paramMapValue = new String[]{"value42"};
		parametersMap.put("key42", paramMapValue);

		final QueryAuthnRequest query = this.idpConnector.buildQueryAuthnRequest(parametersMap);

		Assert.assertNotNull("Query cannot be null !", query);
		Assert.assertNotNull("QueryAuthnRequest's parameters map cannot be null !", query.getParametersMap());
		Assert.assertArrayEquals("Bad param values in QueryAuthnRequest !", paramMapValue, query.getParametersMap()
				.get("key42"));

		Assert.assertNotNull("QueryAuthnRequest's Id cannot be null !", query.getId());
		Assert.assertNotNull("QueryAuthnRequest's IdPConnectorBuilder cannot be null !", query.getIdpConnectorBuilder());
		
		// Test Serialization
		final byte[] serialized = SerializationUtils.serialize(query);
		final QueryAuthnRequest deserializedQuery = (QueryAuthnRequest) SerializationUtils.deserialize(serialized);

		Assert.assertEquals("Serialization / Deserialization problem !", query.getId(), deserializedQuery.getId());
		Assert.assertNotNull("Serialization / Deserialization problem !", deserializedQuery.getIdpConnectorBuilder());
		Assert.assertEquals("Serialization / Deserialization problem !", query.getIdpConnectorBuilder(),
				deserializedQuery.getIdpConnectorBuilder());
		Assert.assertArrayEquals("Serialization / Deserialization problem !", paramMapValue, deserializedQuery
				.getParametersMap().get("key42"));
	}

	@Test
	public void testBuildQuerySloResponse() throws Exception {
		final QuerySloResponse query = this.idpConnector.buildQuerySloResponse(this.sloRequestId);

		Assert.assertNotNull("Query cannot be null !", query);
		Assert.assertNotNull("QuerySloResponse's Id !", query.getId());
		Assert.assertEquals("QuerySloResponse's InResponseTo Id !", this.sloRequestId, query.getInResponseToId());

		// Test Serialization
		final byte[] serialized = SerializationUtils.serialize(query);
		final QuerySloResponse deserializedQuery = (QuerySloResponse) SerializationUtils.deserialize(serialized);

		Assert.assertEquals("Serialization / Deserialization problem !", query.getId(), deserializedQuery.getId());
		Assert.assertEquals("Serialization / Deserialization problem !", query.getInResponseToId(),
				deserializedQuery.getInResponseToId());
	}

	@Test
	public void testBuildQuerySloRequest() throws Exception {
		final QuerySloRequest query = this.idpConnector.buildQuerySloRequest();

		Assert.assertNotNull("Query cannot be null !", query);
		Assert.assertNotNull("QuerySloResponse's Id !", query.getId());
		Assert.assertNotNull("QueryAuthnRequest's IdPConnectorBuilder cannot be null !", query.getIdpConnectorBuilder());

		// Test Serialization
		final byte[] serialized = SerializationUtils.serialize(query);
		final QuerySloRequest deserializedQuery = (QuerySloRequest) SerializationUtils.deserialize(serialized);

		Assert.assertEquals("Serialization / Deserialization problem !", query.getId(), deserializedQuery.getId());
		Assert.assertNotNull("Serialization / Deserialization problem !", deserializedQuery.getIdpConnectorBuilder());
		Assert.assertEquals("Serialization / Deserialization problem !", query.getIdpConnectorBuilder(),
				deserializedQuery.getIdpConnectorBuilder());
	}

	@Test
	public void testBuildAuthnRequest() throws Exception {
		// Loop on all bindings available
		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {

			final AuthnRequest request = this.idpConnector.buildAuthnRequest(binding);

			Assert.assertNotNull("Request cannot be null !", request);
		}
	}

	@Test
	public void testBuildLogoutRequest() throws Exception {
		// Loop on all bindings available
		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
			final BasicSamlAuthentication auth = new BasicSamlAuthentication();
			auth.setAuthenticationInstant(new DateTime());
			auth.setSessionIndex("sessionIndex");
			auth.setSubjectId("subjectId_4126985");

			final LogoutRequest request = this.idpConnector.buildLogoutRequest(binding, auth);

			Assert.assertNotNull("Request cannot be null !", request);
		}
	}

	@Test
	public void testBuildLogoutResponse() throws Exception {
		// Loop on all bindings available
		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {

			final LogoutResponse request = this.idpConnector.buildLogoutResponse(binding);

			Assert.assertNotNull("Request cannot be null !", request);
		}
	}

	@Test
	public void testBuildIssuer() throws Exception {
		final Issuer issuer = this.idpConnector.buildIssuer();

		Assert.assertNotNull("Issuer cannot be null !", issuer);
	}

	@Test
	public void testBuildNotBeforeTime() throws Exception {
		final DateTime issueInstant = new DateTime();
		final DateTime beforeTime = this.idpConnector.buildNotBeforeTime(issueInstant);

		Assert.assertNotNull("NotBeforeTime cannot be null !", beforeTime);
		final long windowValidity = this.idpConnector.getIdpConfig().getTimeValidityWindow();
		final DateTime expected = issueInstant.minus(windowValidity);
		Assert.assertEquals("Bad NotBeforeTime !", expected, beforeTime);
	}

	@Test
	public void testBuildNotOnOrAFterTime() throws Exception {
		final DateTime issueInstant = new DateTime();
		final DateTime afterTime = this.idpConnector.buildNotOnOrAfterTime(issueInstant);

		Assert.assertNotNull("NotOnOrAfterTime cannot be null !", afterTime);
		final long windowValidity = this.idpConnector.getIdpConfig().getTimeValidityWindow();
		final DateTime expected = issueInstant.plus(windowValidity);
		Assert.assertEquals("Bad NotOnOrAfterTime !", expected, afterTime);
	}

}
