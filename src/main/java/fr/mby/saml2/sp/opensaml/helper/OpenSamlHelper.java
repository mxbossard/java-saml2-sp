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
package fr.mby.saml2.sp.opensaml.helper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Timer;
import java.util.zip.DeflaterOutputStream;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.impl.helper.SamlHelper;
import fr.mby.saml2.sp.opensaml.wrapper.SpringResourceWrapper;

import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public abstract class OpenSamlHelper {

	/** Logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(OpenSamlHelper.class);

	private static IdentifierGenerator idGenerator;

	static {
		try {
			OpenSamlHelper.idGenerator = new SecureRandomIdentifierGenerator();
		} catch (NoSuchAlgorithmException e) {
			OpenSamlHelper.LOGGER.error("Unable to generate random hex string !", e);
		}
	}

	/**
	 * Marshall an opensaml SignableSAMLObject.
	 * 
	 * @param signableSamlObject the SignableSAMLObject
	 * @return the marshalled XML.
	 * @throws MarshallingException
	 * 
	 * @throws SignatureException 
	 */
	public static String marshallSignableSamlObject(final SignableSAMLObject signableSamlObject)
			throws MarshallingException, SignatureException {
		String xmlMessage = null;
		try {
			Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(signableSamlObject);
			Element element = marshaller.marshall(signableSamlObject);

			// Sign the saml object
			Signature signature = signableSamlObject.getSignature();
			Assert.notNull(signature, "The request is not signed !");
			Signer.signObject(signature);

			StringWriter rspWrt = new StringWriter();
			XMLHelper.writeNode(element, rspWrt);
			xmlMessage = rspWrt.toString();

			// Logging XML Authn Response
			OpenSamlHelper.LOGGER.debug("Marshalled SAML Object: {}", xmlMessage);
		} catch (MarshallingException e) {
			OpenSamlHelper.LOGGER.warn("Error while marshalling SAML 2.0 Object !", e);
			throw e;
		}

		return xmlMessage;
	}

	/**
	 * Marshall an opensaml XMLObject.
	 * 
	 * @param xmlObject the XMLObject
	 * @return the marshalled XML.
	 * @throws MarshallingException
	 */
	public static String marshallXmlObject(final XMLObject xmlObject) throws MarshallingException {
		String xmlMessage = null;
		try {
			Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(xmlObject);
			Element element = marshaller.marshall(xmlObject);
			StringWriter rspWrt = new StringWriter();
			XMLHelper.writeNode(element, rspWrt);
			xmlMessage = rspWrt.toString();

			// Logging XML Authn Response
			OpenSamlHelper.LOGGER.debug("Marshalled SAML Object: {}", xmlMessage);
		} catch (MarshallingException e) {
			OpenSamlHelper.LOGGER.warn("Error while marshalling SAML 2.0 Object !", e);
			throw e;
		}

		return xmlMessage;
	}

	/**
	 * Unmarshall an opensaml XMLObject.
	 * @param xmlObjectQName
	 * @param xmlType
	 * 
	 * @param xmlObject the XMLObject
	 * @return the marshalled XML.
	 * @throws MarshallingException
	 */
	public static XMLObject unmarshallXmlObject(final QName xmlObjectQName, final String messageXML) throws UnmarshallingException {
		XMLObject xmlObject = null;
		try {
			DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputStream in = new ByteArrayInputStream(messageXML.getBytes());
			Document document = docBuilder.parse(in);

			Element element = XMLHelper.constructElement(document, xmlObjectQName);

			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(xmlObjectQName);
			xmlObject = unmarshaller.unmarshall(element);
		} catch (UnmarshallingException e) {
			throw e;
		} catch (Exception e) {
			OpenSamlHelper.LOGGER.error("Error while parsing xml message !", e);
		}

		return xmlObject;
	}

	/**
	 * Generate the relay state token.
	 * It embbed the IdP config Id and the SAML binding used.
	 * 
	 * @param idpConfigId the IdP config Id
	 * @param binding the binding
	 * @return the relay state
	 */
	public static String generateRelayState(final String idpConfigId, final SamlBindingEnum binding) {
		StringBuilder relayState = new StringBuilder(128);
		// Random chain
		relayState.append(OpenSamlHelper.generateRandomHexString(16));
		// Plus time (ns)
		relayState.append(String.valueOf(System.nanoTime()).substring(5));
		relayState.append(SamlHelper.RELAY_STATE_SEPARATOR);
		// Supported binding
		relayState.append(binding.ordinal());

		return SamlHelper.base64Encode(relayState.toString());
	}

	/**
	 * @param i
	 * @return
	 */
	public static String generateRandomHexString(final int size) {
		String id = OpenSamlHelper.idGenerator.generateIdentifier(size);

		return id;
	}

	public static String encodeSamlObject(final SamlBindingEnum binding, final SignableSAMLObject samlObject) {
		String encodedAuthnRequest = null;
		try {
			switch (binding) {
			case SAML_20_HTTP_POST:
				encodedAuthnRequest = OpenSamlHelper.httpPostEncode(samlObject);
				break;
			case SAML_20_HTTP_REDIRECT:
				encodedAuthnRequest = OpenSamlHelper.httpRedirectEncode(samlObject);
				break;
			}
		} catch (UnsupportedEncodingException e) {
			OpenSamlHelper.LOGGER.error("Error while encoding SAML 2.0 AuthnRequest !", e);
		} catch (IOException e) {
			OpenSamlHelper.LOGGER.error("Error while encoding SAML 2.0 AuthnRequest !", e);
		}
		Assert.notNull(encodedAuthnRequest, "Error while encoding authn request !");
		return encodedAuthnRequest;
	}

	/**
	 * Encode a SAML2 request for the HTTP-POST binding.
	 * 
	 * @param signable the request
	 * @return the encoded request
	 * @throws IOException
	 */
	public static String httpPostEncode(final SignableSAMLObject signable) throws IOException {
		String base64EncodedRequest = null;

		if (signable != null) {

			// TODO MBD: Use OpenSaml encoders
			//			VelocityEngine engine = new VelocityEngine();
			//			String templateId = "classpath:/templates/saml2-post-binding.vm";
			//			HTTPPostEncoder postEncoder = new HTTPPostEncoder(engine , templateId);
			//
			//			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			//			messageContext.setP;
			//			postEncoder.encode(messageContext);

			try {
				// Now we must build our representation to put into the html form to
				// be submitted to the idp
				Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(signable);
				org.w3c.dom.Element authDOM = marshaller.marshall(signable);

				//Signing the request
				Signature signature = signable.getSignature();
				Assert.notNull(signature, "The request is not signed !");
				Signer.signObject(signature);

				StringWriter rspWrt = new StringWriter();
				XMLHelper.writeNode(authDOM, rspWrt);
				String messageXML = rspWrt.toString();

				// Encode XML message
				base64EncodedRequest = SamlHelper.httpPostEncode(messageXML);

			} catch (MarshallingException e) {
				OpenSamlHelper.LOGGER.error("Error while marshalling SAML 2.0 Request !", e);
			} catch (SignatureException e) {
				OpenSamlHelper.LOGGER.error("Error while signing SAML 2.0 Request !", e);
			}
		}

		return base64EncodedRequest;
	}

	/**
	 * Encode a SAML2 request for the HTTP-redirect binding.
	 * 
	 * @param request the request
	 * @return the encoded request
	 * @throws IOException
	 */
	public static String httpRedirectEncode(final SignableSAMLObject request) throws IOException {
		String urlEncodedRequest = null;
		ByteArrayOutputStream byteArrayOutputStream = null;
		DeflaterOutputStream deflaterOutputStream = null;

		if (request != null) {
			try {
				// Now we must build our representation to put into the html form to
				// be submitted to the idp
				Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(request);
				org.w3c.dom.Element authDOM = marshaller.marshall(request);

				//Signing the request
				Signature signature = request.getSignature();
				Assert.notNull(signature, "The request is not signed !");
				Signer.signObject(signature);

				StringWriter rspWrt = new StringWriter();
				XMLHelper.writeNode(authDOM, rspWrt);
				String messageXML = rspWrt.toString();

				// Encode XML message
				urlEncodedRequest = SamlHelper.httpRedirectEncode(messageXML);

			} catch (MarshallingException e) {
				OpenSamlHelper.LOGGER.error("Error while marshalling SAML 2.0 Request !", e);
			} catch (SignatureException e) {
				OpenSamlHelper.LOGGER.error("Error while signing SAML 2.0 Request !", e);
			} finally {
				if (byteArrayOutputStream != null) {
					byteArrayOutputStream.close();
				}
				if (deflaterOutputStream != null) {
					deflaterOutputStream.close();
				}
			}
		}

		return urlEncodedRequest;
	}

	/**
	 * Build a metadata provider if a metadata resource was provided.
	 * 
	 * @param metadata the metadata resource
	 * @return the metadata provider
	 * @throws MetadataProviderException
	 * @throws XMLParserException
	 */
	public static MetadataProvider buildMetadataProvider(final Resource metadata) throws MetadataProviderException, XMLParserException {
		ResourceBackedMetadataProvider metatdataProvider = null;

		if ((metadata != null) && metadata.exists()) {
			org.opensaml.util.resource.Resource resource = new SpringResourceWrapper(metadata);

			metatdataProvider = new ResourceBackedMetadataProvider(new Timer(), resource);
			StaticBasicParserPool parserPool = new StaticBasicParserPool();
			parserPool.initialize();
			metatdataProvider.setParserPool(parserPool);
			metatdataProvider.initialize();
		}

		return metatdataProvider;
	}

}
