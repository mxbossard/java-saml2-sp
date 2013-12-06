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
package fr.mby.saml2.sp.impl.helper;

import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityException;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This class is not a test but a helper for the test !
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public abstract class SamlTestResourcesHelper {

	/** Ressource base path for mocked request. */
	private static final String RESOURCE_BASE_PATH = "test";

	/**
	 * Read a Ressource File.
	 * 
	 * @param resourceFile
	 * @return the string representation of the file
	 * @throws IOException
	 * @throws SecurityException
	 * @throws MessageDecodingException
	 */
	public static XMLObject buildOpenSamlXmlObjectFromResource(final Resource resourceFile)
			throws Exception {
		// Parse XML file
		BasicParserPool ppMgr = new BasicParserPool();
		ppMgr.setNamespaceAware(true);
		Document inCommonMDDoc = ppMgr.parse(resourceFile.getInputStream());
		Element rootElement = inCommonMDDoc.getDocumentElement();

		// Get apropriate unmarshaller
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(rootElement);

		// Unmarshall using the document root element, an EntitiesDescriptor in this case
		XMLObject xmlObject = unmarshaller.unmarshall(rootElement);

		Assert.assertNotNull("Unable to read test SAML XML file !", xmlObject);

		return xmlObject;
	}

	/**
	 * Read a Ressource File.
	 * 
	 * @param resourceFile
	 * @return the string representation of the file
	 * @throws IOException
	 */
	public static String readFile(final Resource resourceFile) throws IOException {
		return FileUtils.readFileToString(resourceFile.getFile());
	}

	/**
	 * Build a Mock Request representing a SAML Request.
	 * 
	 * @param encodedMessage
	 * @return the mock request
	 */
	public static MockHttpServletRequest BuildSamlMockRequest(final String encodedMessage, final String binding) {
		MockHttpServletRequest request = new MockHttpServletRequest(
				new MockServletContext(SamlTestResourcesHelper.RESOURCE_BASE_PATH));
		request.setMethod(binding);
		request.setParameter("SAMLRequest", encodedMessage);
		return request;
	}

	/**
	 * Build a Mock Request representing a SAML Response.
	 * 
	 * @param encodedMessage
	 * @return the mock request
	 */
	public static MockHttpServletRequest BuildSamlMockResponse(final String encodedMessage, final String binding) {
		MockHttpServletRequest request = new MockHttpServletRequest(
				new MockServletContext(SamlTestResourcesHelper.RESOURCE_BASE_PATH));
		request.setMethod(binding);
		request.setParameter("SAMLResponse", encodedMessage);
		return request;
	}

}
