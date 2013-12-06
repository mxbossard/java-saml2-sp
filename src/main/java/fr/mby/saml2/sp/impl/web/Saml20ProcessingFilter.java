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

package fr.mby.saml2.sp.impl.web;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import fr.mby.saml2.sp.api.core.ISaml20SpProcessor;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.api.query.IQuery;
import fr.mby.saml2.sp.impl.helper.SamlHelper;
import fr.mby.saml2.sp.impl.query.QueryAuthnRequest;
import fr.mby.saml2.sp.impl.query.QueryAuthnResponse;

/**
 * Filter which process SAML Incoming requests.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public class Saml20ProcessingFilter implements Filter {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(Saml20ProcessingFilter.class);

	@Override
	public void init(final FilterConfig filterConfig) throws ServletException {
		// Nothing to do.
	}

	@Override
	public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
			throws IOException, ServletException {
		ServletRequest chainingRequest = request;

		if (HttpServletRequest.class.isAssignableFrom(request.getClass())) {
			final HttpServletRequest httpRequest = (HttpServletRequest) request;
			if (SamlHelper.isSamlResponse(httpRequest) || SamlHelper.isSamlRequest(httpRequest)) {
				// If it's a SAML 2.0 Response
				Saml20ProcessingFilter.LOGGER.debug("Start processing SAML 2.0 incoming request ...");
				try {

					// Process SAML response
					final IIncomingSaml samlIncomingMsg = this.processSaml2Request(httpRequest);

					if (samlIncomingMsg != null) {
						final IQuery samlQuery = samlIncomingMsg.getSamlQuery();
						Assert.notNull(samlQuery, "No SAML query found in IncomingSaml message !");

						if (QueryAuthnResponse.class.isAssignableFrom(samlQuery.getClass())) {
							// The incoming message is a SAML Authn Response
							final QueryAuthnResponse authnResp = (QueryAuthnResponse) samlQuery;
							final QueryAuthnRequest authnReq = authnResp.getOriginalRequest();
							Assert.notNull(authnReq,
									"No initial Authn Req request corresponding to SAML response found !");

							// Retrieve initial params
							final Map<String, String[]> initialParams = authnReq.getParametersMap();
							Assert.notNull(initialParams, "No initial params bound to the initial request !");

							// Replace the request with the SAML 2.0 Response one.
							chainingRequest = new Saml20RequestWrapper(httpRequest, initialParams);
						}

					}

					// Forward
					final RequestDispatcher requestDispatcher = chainingRequest.getRequestDispatcher("/login");
					requestDispatcher.forward(chainingRequest, response);
					return;
				} catch (final Throwable e) {
					Saml20ProcessingFilter.LOGGER.error("Error while processing SAML 2.0 incoming request !", e);
				}
			}
		}

		chain.doFilter(chainingRequest, response);
	}

	@Override
	public void destroy() {
		// Nothing to do.
	}

	protected IIncomingSaml processSaml2Request(final HttpServletRequest samlRequest) throws SamlProcessingException,
			UnsupportedSamlOperation {
		IIncomingSaml incomingSaml = null;

		final String endpointUrl = samlRequest.getRequestURL().toString();
		final ISaml20SpProcessor spProcessor = SamlHelper.findSpProcessorToUse(endpointUrl);

		incomingSaml = spProcessor.processSaml20IncomingRequest(samlRequest);

		if (incomingSaml == null) {
			String incomingRequest = null;
			if (SamlHelper.isSamlRequest(samlRequest)) {
				incomingRequest = SamlHelper.getSamlRequest(samlRequest);
			} else if (SamlHelper.isSamlResponse(samlRequest)) {
				incomingRequest = SamlHelper.getSamlResponse(samlRequest);
			}
			Saml20ProcessingFilter.LOGGER.error(String.format("Unable to process SAML incoming request: [%s] !",
					incomingRequest));
		}

		return incomingSaml;
	}

}
