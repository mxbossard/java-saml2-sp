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
package fr.mby.saml2.sp.opensaml.query.engine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.SessionIndex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import fr.mby.saml2.sp.api.core.ISaml20IdpConnector;
import fr.mby.saml2.sp.api.core.ISaml20SpProcessor;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.exception.NotSignedException;
import fr.mby.saml2.sp.api.exception.SamlBuildingException;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.SamlSecurityException;
import fr.mby.saml2.sp.api.exception.SamlValidationException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.api.om.IOutgoingSaml;
import fr.mby.saml2.sp.impl.helper.SamlHelper;
import fr.mby.saml2.sp.impl.helper.SamlValidationHelper;
import fr.mby.saml2.sp.impl.query.QuerySloRequest;

/**
 * OpenSaml 2 implementation of QueryProcessor for incoming SLO Response.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public class SloRequestQueryProcessor extends BaseOpenSaml2QueryProcessor<QuerySloRequest, LogoutRequest> {

	/** Logger. */
	private final Logger logger = LoggerFactory.getLogger(SloRequestQueryProcessor.class);

	@Override
	protected void checkSecurity() throws SamlSecurityException {
		final LogoutRequest sloRequest = this.getOpenSamlObject();
		final Issuer issuer = sloRequest.getIssuer();
		final ISaml20IdpConnector idpConnector = this.findIdpConnector(issuer);

		try {
			this.validateSignatureTrust(sloRequest, issuer, idpConnector);
		} catch (NotSignedException e) {
			throw new SamlSecurityException(
					"The SLO Request cannot be trusted, signature is missing !");
		}
	}

	@Override
	protected void validateConditions() throws SamlValidationException {
		final LogoutRequest sloRequest = this.getOpenSamlObject();

		int clockSkew = this.getFactory().getClockSkewSeconds();
		DateTime notOnOrAfter = sloRequest.getNotOnOrAfter();
		SamlValidationHelper.validateTimes(clockSkew, null, notOnOrAfter);
	}

	@Override
	protected void process() throws SamlProcessingException, SamlSecurityException, UnsupportedSamlOperation {
		final LogoutRequest sloRequest = this.getOpenSamlObject();
		final ISaml20SpProcessor spProcessor = this.getSpProcessor();

		// Logout from SP
		List<SessionIndex> sessionIndexes = sloRequest.getSessionIndexes();
		if (!CollectionUtils.isEmpty(sessionIndexes)) {
			for (SessionIndex sessionIndex : sessionIndexes) {
				spProcessor.logout(sessionIndex.getSessionIndex());
			}
		}

		// Send SLO Response
		try {
			final SamlBindingEnum binding = SamlBindingEnum.SAML_20_HTTP_POST;
			ISaml20IdpConnector idpConnector = this.findIdpConnector(sloRequest.getIssuer());
			IOutgoingSaml sloResponseRequest = this.buildOutgoingSloResponse(sloRequest, binding , idpConnector);
			this.sendSloResponse(binding, sloResponseRequest);
		} catch (SamlBuildingException e) {
			throw new SamlProcessingException("Unable to build SLO Response to send back to the IdP !", e);
		}
	}

	@Override
	protected QuerySloRequest buildSamlQuery() throws SamlProcessingException, SamlSecurityException {
		final LogoutRequest sloRequest = this.getOpenSamlObject();

		// Incoming Request : No IdP connector builder, build by the IdP !
		final QuerySloRequest query = new QuerySloRequest(sloRequest.getID(), null);

		return query;
	}

	/**
	 * Build a SLO Response to send, based on a SLO request.
	 * 
	 * @param request the HTTP request
	 * @param binding the SLO Request binding
	 * @return the SLO Response to return to the IdP
	 * @throws SamlBuildingException
	 */
	protected IOutgoingSaml buildOutgoingSloResponse(final LogoutRequest logoutRequest,
			final SamlBindingEnum binding, final ISaml20IdpConnector idpConnector)
					throws SamlBuildingException {
		Assert.notNull(logoutRequest, "SLO Request must be supplied !");

		final String relayState = SamlHelper.getRelayState(this.getHttpRequest());
		final String originRequestId = logoutRequest.getID();
		IOutgoingSaml sloResponseRequest = idpConnector.buildSaml20SingleLogoutResponse(
				binding, originRequestId, relayState);

		this.logger.debug("SAML 2.0 Logout Response processing ended.");
		return sloResponseRequest;
	}


	/**
	 * Send the SLO Response via the URL Api.
	 * 
	 * @param binding the binding to use
	 * @param sloResponseRequest the SLO Response request
	 */
	protected void sendSloResponse(final SamlBindingEnum binding, final IOutgoingSaml sloResponseRequest) {
		URL sloUrl = null;
		HttpURLConnection sloConnexion = null;

		try {
			switch(binding) {
			case SAML_20_HTTP_REDIRECT:
				String redirectUrl = sloResponseRequest.getHttpRedirectBindingUrl();

				sloUrl = new URL(redirectUrl);
				sloConnexion = (HttpURLConnection) sloUrl.openConnection();
				sloConnexion.setReadTimeout(10000);
				sloConnexion.connect();
				break;

			case SAML_20_HTTP_POST:
				String sloEndpointUrl = sloResponseRequest.getEndpointUrl();
				Collection<Entry<String, String>> sloPostParams = sloResponseRequest.getHttpPostBindingParams();
				StringBuffer samlDatas = new StringBuffer(1024);
				Iterator<Entry<String, String>> itParams = sloPostParams.iterator();
				Entry<String, String> firstParam = itParams.next();
				samlDatas.append(firstParam.getKey());
				samlDatas.append("=");
				samlDatas.append(firstParam.getValue());
				while (itParams.hasNext()) {
					Entry<String, String> param = itParams.next();
					samlDatas.append("&");
					samlDatas.append(param.getKey());
					samlDatas.append("=");
					samlDatas.append(param.getValue());
				}

				sloUrl = new URL(sloEndpointUrl);
				sloConnexion = (HttpURLConnection) sloUrl.openConnection();
				sloConnexion.setDoInput(true);

				OutputStreamWriter writer = new OutputStreamWriter(sloConnexion.getOutputStream());
				writer.write(samlDatas.toString());
				writer.flush();
				writer.close();

				sloConnexion.setReadTimeout(10000);
				sloConnexion.connect();
				break;

			default:
				break;
			}

			if (sloConnexion != null) {
				InputStream responseStream = sloConnexion.getInputStream();

				StringWriter writer = new StringWriter();
				IOUtils.copy(responseStream, writer, "UTF-8");
				String response = writer.toString();

				this.logger.debug(String.format("HTTP response to SLO Request sent: [%s] ", response));

				int responseCode = sloConnexion.getResponseCode();

				String samlMessage = sloResponseRequest.getSamlMessage();
				String endpointUrl = sloResponseRequest.getEndpointUrl();
				if (responseCode < 0) {
					this.logger.error("Unable to send SAML 2.0 Single Logout Response [{}] to endpoint URL [{}] !",
							samlMessage, endpointUrl);
				} else if (responseCode == 200) {
					this.logger.info("SAML 2.0 Single Logout Request correctly sent to [{}] !",
							endpointUrl);
				} else {
					this.logger.error(
							"HTTP response code: [{}] ! Error while sending SAML 2.0 Single Logout Request [{}] to endpoint URL [{}] !",
							new Object[]{responseCode, samlMessage, endpointUrl});
				}
			}

		} catch (MalformedURLException e) {
			this.logger.error(String.format("Malformed SAML SLO request URL: [%s] !",
					sloUrl.toExternalForm()), e);
		} catch (IOException e) {
			this.logger.error(String.format("Unable to send SAML SLO request URL: [%s] !",
					sloUrl.toExternalForm()), e);
		} finally {
			sloConnexion.disconnect();
		}
	}


}
