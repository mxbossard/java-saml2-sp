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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.CollectionUtils;

import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.impl.helper.SamlHelper;

/**
 * HTTP Servlet Request Wrapper which process a SAML 2.0 response and retrieve parameters of initial CAS Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public class Saml20RequestWrapper extends HttpServletRequestWrapper {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(Saml20RequestWrapper.class);

	/** Extended parameters. */
	private final Map<String, String[]> parameters;

	@SuppressWarnings("unchecked")
	protected Saml20RequestWrapper(final HttpServletRequest request, final Map<String, String[]> initialParams)
			throws SamlProcessingException, UnsupportedSamlOperation {
		super(request);

		Saml20RequestWrapper.LOGGER.debug("Wrapping SAML 2.0 request...");

		// Unlock the map
		final Map<String, String[]> parameters = new HashMap<String, String[]>(super.getParameterMap());

		final String idpIdParamKey = SamlHelper.getWayfConfig().getIdpIdParamKey();
		parameters.remove(idpIdParamKey);
		parameters.remove(SamlHelper.SAML_RESPONSE_PARAM_KEY);

		if (!CollectionUtils.isEmpty(initialParams)) {
			parameters.putAll(initialParams);
		}

		// Lock the map.
		this.parameters = MapUtils.unmodifiableMap(parameters);
	}

	/**
	 * Extended parametters whose includes initial CAS request parameters. {@inheritDoc}
	 */
	@Override
	public String getParameter(final String paramName) {
		String result = null;

		final String[] values = this.getParameterValues(paramName);
		if (!ArrayUtils.isEmpty(values)) {
			result = values[0];
		}

		return result;
	}

	/**
	 * Extended parametters whose includes initial CAS request parameters. {@inheritDoc}
	 */
	@Override
	public String[] getParameterValues(final String paramName) {
		return this.parameters.get(paramName);
	}

	/**
	 * Extended parametters whose includes initial CAS request parameters. {@inheritDoc}
	 */
	@Override
	public Map<?, ?> getParameterMap() {
		return this.parameters;
	}

}
