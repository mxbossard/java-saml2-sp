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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import fr.mby.saml2.sp.api.config.IWayfConfig;
import fr.mby.saml2.sp.api.core.ISaml20IdpConnector;
import fr.mby.saml2.sp.api.core.ISaml20SpProcessor;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public abstract class SamlHelper {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(SamlHelper.class);

	/** Name of the security logger. */
	public static final String SECURITY_LOGGER_NAME = "Saml-Security";

	/** Security logger. */
	private static final Logger SECURITY_LOGGER = LoggerFactory.getLogger(SamlHelper.SECURITY_LOGGER_NAME);

	/** SAML Response HTTP Param name. */
	public static final String SAML_RESPONSE_PARAM_KEY = "SAMLResponse";

	/** SAML Request HTTP Param name. */
	public static final String SAML_REQUEST_PARAM_KEY = "SAMLRequest";

	/** SAML Relay State HTTP Param name. */
	public static final String RELAY_STATE_PARAM_KEY = "RelayState";

	/** HTTP Request servlet path part for the Single Logout Service endpoint. */
	public static final String SAML2_SERVPATH_ROUTER = "/Shibboleth.sso/";

	/** HTTP Request servlet path part for the Single Logout Service endpoint. */
	public static final String SLO_SERVPATH_ROUTER = "SLO";

	/** HTTP Request servlet path part for the Assertion Consuming Service endpoint. */
	public static final String ACS_SERVPATH_ROUTER = "SAML2";

	/** HTTP Request servlet path part for a HTTP-POST binding. */
	public static final String HTTP_POST_BINDING_SERVPATH_ROUTER = "POST";

	/** HTTP Request servlet path part for a HTTP-Redirect binding. */
	public static final String HTTP_REDIRECT_BINDING_SERVPATH_ROUTER = "Redirect";

	/** Char separator for relay state. */
	public static final String RELAY_STATE_SEPARATOR = "$";

	/** Saml HTTP-Redirect binding encoding. */
	public static final String CHAR_ENCODING = "UTF-8";

	/** The SP processor for CAS. */
	private static Collection<ISaml20SpProcessor> spProcessors = new ArrayList<ISaml20SpProcessor>(8);

	/** The wayf config for CAS. */
	private static IWayfConfig wayfConfig;

	/**
	 * Log a Security Problem in Security Logger and rethrow the Exception.
	 * 
	 * @param e
	 * @param samlMessage
	 * @throws SamlProcessingException
	 */
	public static void logSecurityProblem(final Throwable e, final String samlMessage) throws SamlProcessingException {
		final String securityMessage;
		// Log in security logger the SAML message cause of the security exception
		if (StringUtils.hasText(samlMessage)) {
			securityMessage = String.format("Plugin SAML security problem for incoming SAML message: [%1$s] !",
					samlMessage);
		} else {
			securityMessage = "Plugin SAML security problem before decoding incoming SAML message !";
		}

		SamlHelper.SECURITY_LOGGER.warn(securityMessage, e);

		throw new SamlProcessingException(samlMessage, e);
	}

	/**
	 * Retrieve the SP processor for CAS corresponding to the endpoint URL.
	 * 
	 * @return the SP processor
	 * @throws SamlProcessingException
	 *             if no SP Processor found to use
	 */
	public static ISaml20SpProcessor findSpProcessorToUse(final String endpointUrl) throws SamlProcessingException {
		for (final ISaml20SpProcessor spProcessor : SamlHelper.spProcessors) {
			for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
				final String spEnpointUrl = spProcessor.getSpConfig().getEndpointUrl(binding);
				if ((spEnpointUrl != null) && spEnpointUrl.equals(endpointUrl)) {
					if (SamlHelper.LOGGER.isDebugEnabled()) {
						SamlHelper.LOGGER.debug(String.format("EndpointUrl [%1$s] corrsponding to SPProcessor [%2$s]",
								endpointUrl, spProcessor.getSpConfig().getId()));
					}
					return spProcessor;
				}
			}
		}

		throw new SamlProcessingException(String.format(
				"Endpoint URL: [%1$s] isn't matching any registered SP processor !", endpointUrl));
	}

	/**
	 * Retrieve the IdP Connector corresponding to the entity ID.
	 * 
	 * @return the SP processor
	 */
	public static ISaml20IdpConnector findIdpConnectorToUse(final String idpEntityId) throws SamlProcessingException {
		for (final ISaml20SpProcessor spProcessor : SamlHelper.spProcessors) {
			final ISaml20IdpConnector idpConnector = spProcessor.findSaml20IdpConnectorToUse(idpEntityId);
			if (idpConnector != null) {
				return idpConnector;
			}
		}

		throw new SamlProcessingException(String.format(
				"IdP entityID: [%1$s] isn't matching any registered IdP Connector !", idpEntityId));
	}

	/**
	 * Register the SP processor for CAS.
	 * 
	 * @param spProc
	 *            the SP processor
	 */
	public static void registerSpProcessor(final ISaml20SpProcessor spProc) {
		SamlHelper.spProcessors.add(spProc);
	}

	/**
	 * Retrieve the wayf config for CAS.
	 * 
	 * @return the wayf config
	 */
	public static IWayfConfig getWayfConfig() {
		return SamlHelper.wayfConfig;
	}

	/**
	 * Register the wayf config for CAS.
	 * 
	 * @param wayfConf
	 *            the wayf config
	 */
	public static void registerWayfConfig(final IWayfConfig wayfConf) {
		SamlHelper.wayfConfig = wayfConf;
	}

	/**
	 * Test if the http request contain a SAML request.
	 * 
	 * @param request
	 *            the http request
	 * @return true if the request contain a SAML Request
	 */
	public static boolean isSamlRequest(final HttpServletRequest request) {
		final String samlRequest = SamlHelper.getSamlRequest(request);

		return StringUtils.hasText(samlRequest);
	}

	/**
	 * Retrieve a SAML request from http request.
	 * 
	 * @param request
	 *            the http request
	 * @return the SAML request.
	 */
	public static String getSamlRequest(final HttpServletRequest request) {
		return request.getParameter(SamlHelper.SAML_REQUEST_PARAM_KEY);
	}

	/**
	 * Test if the http request contain a SAML response.
	 * 
	 * @param request
	 *            the http request
	 * @return true if the request contain a SAML Response
	 */
	public static boolean isSamlResponse(final HttpServletRequest request) {
		final String samlResponse = SamlHelper.getSamlResponse(request);

		return StringUtils.hasText(samlResponse);
	}

	/**
	 * Retrieve a SAML response from http request.
	 * 
	 * @param request
	 *            the http request
	 * @return the SAML response.
	 */
	public static String getSamlResponse(final HttpServletRequest request) {
		return request.getParameter(SamlHelper.SAML_RESPONSE_PARAM_KEY);
	}

	/**
	 * Retrieve a SAML message from http request.
	 * 
	 * @param request
	 *            the http request
	 * @return the SAML message (can be null).
	 */
	public static String getEncodedSamlMesage(final HttpServletRequest request) {
		String samlMessage = null;

		if (SamlHelper.isSamlRequest(request)) {
			samlMessage = SamlHelper.getSamlRequest(request);
		} else if (SamlHelper.isSamlResponse(request)) {
			samlMessage = SamlHelper.getSamlResponse(request);
		}

		return samlMessage;
	}

	/**
	 * Retrieve relay state from http request.
	 * 
	 * @param request
	 *            the http request
	 * @return the relay state.
	 */
	public static String getRelayState(final HttpServletRequest request) {
		String relayState = null;
		if (request != null) {
			relayState = request.getParameter(SamlHelper.RELAY_STATE_PARAM_KEY);
		}
		return relayState;
	}

	public static String base64Encode(final String text) {
		final String encodedText = Base64.encodeBytes(text.getBytes(), Base64.DONT_BREAK_LINES);

		return encodedText;
	}

	public static String base64Decode(final String text) {
		final byte[] decodedText = Base64.decode(text);

		return new String(decodedText);
	}

	public static String cleanupUrl(final String url) {
		if (url == null) {
			return null;
		}

		final int jsessionPosition = url.indexOf(";jsession");

		if (jsessionPosition == -1) {
			return url;
		}

		final int questionMarkPosition = url.indexOf("?");

		if (questionMarkPosition < jsessionPosition) {
			return url.substring(0, url.indexOf(";jsession"));
		}

		return url.substring(0, jsessionPosition) + url.substring(questionMarkPosition);
	}

	/**
	 * Encode a SAML2 request for the HTTP-POST binding.
	 * 
	 * @param signable
	 *            the request
	 * @return the encoded request
	 * @throws IOException
	 */
	public static String httpPostEncode(final String samlMessage) throws IOException {
		ByteArrayOutputStream byteArrayOutputStream = null;
		String base64EncodedRequest = null;

		try {
			byteArrayOutputStream = new ByteArrayOutputStream();

			// Base 64 Encoded Only for HTTP POST binding
			byteArrayOutputStream.write(samlMessage.getBytes());
			byteArrayOutputStream.flush();
			base64EncodedRequest = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);

			if (SamlHelper.LOGGER.isDebugEnabled()) {
				SamlHelper.LOGGER.debug(String.format("SAML 2.0 Request: %s", samlMessage));
				SamlHelper.LOGGER.debug(String.format("Encoded HTTP-POST Request: %s", base64EncodedRequest));
			}
		} finally {
			if (byteArrayOutputStream != null) {
				byteArrayOutputStream.close();
			}
		}

		return base64EncodedRequest;
	}

	/**
	 * Encode a SAML2 request for the HTTP-redirect binding. The encoded message is not URL encoded !
	 * 
	 * @param request
	 *            the request
	 * @return the encoded request
	 * @throws IOException
	 */
	public static String httpRedirectEncode(final String samlMessage) throws IOException {
		String deflatedRequest = null;
		ByteArrayOutputStream byteArrayOutputStream = null;
		DeflaterOutputStream deflaterOutputStream = null;

		try {
			final Deflater deflater = new Deflater(Deflater.DEFLATED, true);
			byteArrayOutputStream = new ByteArrayOutputStream();
			deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);

			// Deflated then Base 64 encoded then Url Encoded for HTTP REDIRECT Binding
			deflaterOutputStream.write(samlMessage.getBytes());
			deflaterOutputStream.finish();
			deflater.finish();

			deflatedRequest = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);

			if (SamlHelper.LOGGER.isDebugEnabled()) {
				SamlHelper.LOGGER.debug(String.format("SAML 2.0 Request: %s", samlMessage));
				SamlHelper.LOGGER.debug(String.format("Encoded HTTP-Redirect Request: %s", deflatedRequest));
			}
		} finally {
			if (byteArrayOutputStream != null) {
				byteArrayOutputStream.close();
			}
			if (deflaterOutputStream != null) {
				deflaterOutputStream.close();
			}
		}

		return deflatedRequest;
	}

	/**
	 * Decode a SAML2 anthentication request for the HTTP-redirect binding.
	 * 
	 * @param authnRequest
	 *            the authn request
	 * @return the encoded request
	 * @throws IOException
	 */
	public static String httpRedirectDecode(final String encodedRequest) throws IOException {
		String inflatedRequest = null;

		ByteArrayInputStream bytesIn = null;
		InflaterInputStream inflater = null;

		final byte[] decodedBytes = Base64.decode(encodedRequest);

		try {
			bytesIn = new ByteArrayInputStream(decodedBytes);
			inflater = new InflaterInputStream(bytesIn, new Inflater(true));
			final Writer writer = new StringWriter();
			final char[] buffer = new char[1024];

			final Reader reader = new BufferedReader(new InputStreamReader(inflater, "UTF-8"));
			int n;
			while ((n = reader.read(buffer)) != -1) {
				writer.write(buffer, 0, n);
			}

			inflatedRequest = writer.toString();
		} finally {
			if (bytesIn != null) {
				bytesIn.close();
			}
			if (inflater != null) {
				inflater.close();
			}
		}

		return inflatedRequest;
	}

}
