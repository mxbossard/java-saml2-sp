/**
 * Copyright 2013 Maxime Bossard
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.mby.saml2.sp.impl;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import fr.mby.saml2.sp.api.ISaml20SpFacade;
import fr.mby.saml2.sp.api.config.IIdpConfig;
import fr.mby.saml2.sp.api.config.ISpConfig;
import fr.mby.saml2.sp.api.config.IWayfConfig;
import fr.mby.saml2.sp.api.core.ISaml20SpProcessor;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.exception.SamlBuildingException;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.api.handler.ISessionIndexProvider;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.api.om.IOutgoingSaml;
import fr.mby.saml2.sp.api.query.engine.IQueryProcessorFactory;
import fr.mby.saml2.sp.impl.helper.SamlHelper;

/**
 * @author Maxime Bossard - 2013
 * 
 */
public class BasicSaml20SpFacade implements ISaml20SpFacade, InitializingBean {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(BasicSaml20SpFacade.class);

	@Autowired
	private IWayfConfig wayfConfig;

	@Autowired
	/** Session Index provider. */
	private ISessionIndexProvider sessionIndexProvider;

	@Autowired
	private IQueryProcessorFactory queryProcessorFactory;

	@Override
	public List<ISpConfig> getSpConfigList() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<IIdpConfig> getIdpConfigList(final String spConfigId) {
		return this.wayfConfig.getIdpsConfig();
	}

	@Override
	public IOutgoingSaml getSamlAuthnRequest(final Map<String, String[]> parametersMap, final SamlBindingEnum binding,
			final String idpConfigId) throws SamlBuildingException {
		IOutgoingSaml samlRequest = null;

		if (StringUtils.hasText(idpConfigId)) {
			final IIdpConfig idpConfig = this.wayfConfig.findIdpConfigById(idpConfigId);
			if (idpConfig != null) {
				samlRequest = idpConfig.getSaml20IdpConnector().buildSaml20AuthnRequest(parametersMap, binding);
			}
		}

		Assert.notNull(samlRequest, "SAML 2.0 Authn Request wasn't generated !");

		return samlRequest;
	}

	@Override
	public IOutgoingSaml getSamlSingleLogoutRequest(final HttpServletRequest request, final SamlBindingEnum binding,
			final String idpConfigId) throws SamlBuildingException {
		IOutgoingSaml samlRequest = null;

		if (StringUtils.hasText(idpConfigId)) {
			final IIdpConfig idpConfig = this.wayfConfig.findIdpConfigById(idpConfigId);
			if (idpConfig != null) {
				final String sessionIndex = this.sessionIndexProvider.retrieveSessionIndexFromRequest(request);
				Assert.hasText(sessionIndex, "Session Index is needed to build a SLO request !");
				samlRequest = idpConfig.getSaml20IdpConnector().buildSaml20SingleLogoutRequest(sessionIndex, binding);
			}
		}

		Assert.notNull(samlRequest, "SAML 2.0 Authn Request wasn't generated !");

		return samlRequest;
	}

	@Override
	public IIncomingSaml processSaml20IncomingRequest(final HttpServletRequest request) throws SamlProcessingException,
			UnsupportedSamlOperation {

		return this.processSaml20IncomingRequestInternal(request);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.wayfConfig, "No WayfConfig injected !");
		Assert.notNull(this.sessionIndexProvider, "The Session Index provider wasn't injected !");
	}

	protected IIncomingSaml processSaml20IncomingRequestInternal(final HttpServletRequest request)
			throws SamlProcessingException, UnsupportedSamlOperation {
		IIncomingSaml incomingSaml = null;

		final String endpointUrl = request.getRequestURL().toString();
		final ISaml20SpProcessor spProcessor = SamlHelper.findSpProcessorToUse(endpointUrl);

		incomingSaml = spProcessor.processSaml20IncomingRequest(request);

		if (incomingSaml == null) {
			String incomingRequest = null;
			if (SamlHelper.isSamlRequest(request)) {
				incomingRequest = SamlHelper.getSamlRequest(request);
			} else if (SamlHelper.isSamlResponse(request)) {
				incomingRequest = SamlHelper.getSamlResponse(request);
			}
			BasicSaml20SpFacade.LOGGER.error(String.format("Unable to process SAML incoming request: [%s] !",
					incomingRequest));
		}

		return incomingSaml;
	}

}
