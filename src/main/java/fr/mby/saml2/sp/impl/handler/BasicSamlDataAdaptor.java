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
package fr.mby.saml2.sp.impl.handler;

import java.net.URLEncoder;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import fr.mby.saml2.sp.api.handler.ISamlDataAdaptor;
import fr.mby.saml2.sp.api.om.IOutgoingSaml;
import fr.mby.saml2.sp.api.om.IResponse;
import fr.mby.saml2.sp.api.query.IQuery;
import fr.mby.saml2.sp.impl.helper.SamlHelper;

/**
 * Basic SAML data adaptor.
 * The SAML request is embedded in HTTP request with following parameters :
 * <ul>
 * <li>SAMLRequest</li>
 * <li>RelayState</li>
 * </ul>
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class BasicSamlDataAdaptor implements ISamlDataAdaptor {

	/** Logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(BasicSamlDataAdaptor.class);

	/**
	 * Retrieve the HTTP param name which will represent the SAML message.
	 * 
	 * @param outgoingData
	 * @return the HTTP param name
	 */
	public static String getSamlMessageParamName(final IOutgoingSaml outgoingData) {
		String paramName = null;

		if (outgoingData != null) {
			IQuery query = outgoingData.getSamlQuery();

			if (IResponse.class.isAssignableFrom(query.getClass())) {
				// The message is a Response
				paramName = SamlHelper.SAML_RESPONSE_PARAM_KEY;
			} else {
				paramName = SamlHelper.SAML_REQUEST_PARAM_KEY;
			}
		}

		return paramName;
	}

	@Override
	public String buildHttpRedirectBindingUrl(final IOutgoingSaml outgoingData) {
		final String samlMessage = outgoingData.getSamlMessage();
		final String relayState = outgoingData.getRelayState();

		// Encoding
		final String httpEncodedMessage;
		final String urlEncodedMessage;
		final String urlEncodedRelayState;
		try {
			Assert.hasText(samlMessage, "SAML message cannot be empty !");
			// HTTP-Redirect encoding
			httpEncodedMessage = SamlHelper.httpRedirectEncode(samlMessage);

			// URL encoding
			urlEncodedMessage = URLEncoder.encode(httpEncodedMessage, "UTF-8");
			if (StringUtils.hasText(relayState)) {
				urlEncodedRelayState = URLEncoder.encode(relayState, "UTF-8");
			} else {
				urlEncodedRelayState = null;
			}
		} catch (Exception e) {
			final String message = "Error while HTTP-Redirect encoding SAML message !";
			BasicSamlDataAdaptor.LOGGER.error(message, e);
			throw new IllegalStateException(message, e);
		}

		StringBuffer redirectUrl = new StringBuffer(2048);
		redirectUrl.append(outgoingData.getEndpointUrl());
		if (StringUtils.hasText(urlEncodedMessage) && StringUtils.hasText(urlEncodedRelayState)) {
			redirectUrl.append("?");
			if (StringUtils.hasText(urlEncodedRelayState)) {
				redirectUrl.append(SamlHelper.RELAY_STATE_PARAM_KEY);
				redirectUrl.append("=");
				redirectUrl.append(urlEncodedRelayState);
				redirectUrl.append("&");
			}
			redirectUrl.append(BasicSamlDataAdaptor.getSamlMessageParamName(outgoingData));
			redirectUrl.append("=");
			redirectUrl.append(urlEncodedMessage);
		}

		final String urlRequest = redirectUrl.toString();

		BasicSamlDataAdaptor.LOGGER.debug(
				"Basic HTTP-Redirect URL built: [{}]", urlRequest);

		return urlRequest;
	}

	@Override
	public Collection<Entry<String, String>> buildHttpPostBindingParams(final IOutgoingSaml outgoingData) {
		Collection<Entry<String, String>> samlDataParams =
				new ArrayList<Entry<String, String>>();

		String relayState = outgoingData.getRelayState();
		if (StringUtils.hasText(relayState)) {
			Entry<String, String> entry = new SimpleEntry<String, String>(
					SamlHelper.RELAY_STATE_PARAM_KEY, relayState);
			samlDataParams.add(entry);
		}

		String samlMessage = outgoingData.getSamlMessage();

		// Encoding
		final String encodedMessage;
		try {
			encodedMessage = SamlHelper.httpPostEncode(samlMessage);
		} catch (Exception e) {
			BasicSamlDataAdaptor.LOGGER.error(
					"Error while Redirect encoding SAML message !", e);
			throw new IllegalStateException("Error while Redirect encoding SAML message !", e);
		}

		if (StringUtils.hasText(encodedMessage)) {
			Entry<String, String> entry = new SimpleEntry<String, String>(
					BasicSamlDataAdaptor.getSamlMessageParamName(outgoingData), encodedMessage);
			samlDataParams.add(entry);
		}

		BasicSamlDataAdaptor.LOGGER.debug(String.format(
				"Basic HTTP-POST params built: [%s]", samlDataParams.toString()));

		return samlDataParams;
	}

}
