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

import fr.mby.saml2.sp.impl.helper.SamlHelper;

/**
 * Filter which process SAML
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
	public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException,
	ServletException {
		ServletRequest chainingRequest = request;

		if (HttpServletRequest.class.isAssignableFrom(request.getClass())) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			if(SamlHelper.isSamlResponse(httpRequest) || SamlHelper.isSamlRequest(httpRequest)) {
				// If it's a SAML 2.0 Response
				Saml20ProcessingFilter.LOGGER.debug("Start processing SAML 2.0 incoming request ...");
				try {
					// Replace the request with the SAML 2.0 Response one.
					chainingRequest = new Saml20ResponseCasRequest(httpRequest);

					// Forward
					RequestDispatcher requestDispatcher=chainingRequest.getRequestDispatcher("/login");
					requestDispatcher.forward(chainingRequest, response);
					return;
				} catch (Throwable e) {
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

}
