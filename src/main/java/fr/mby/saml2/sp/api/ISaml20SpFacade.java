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

package fr.mby.saml2.sp.api;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import fr.mby.saml2.sp.api.config.IIdpConfig;
import fr.mby.saml2.sp.api.config.ISpConfig;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.api.exception.SamlBuildingException;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.api.om.IOutgoingSaml;

/**
 * @author Maxime Bossard - 2013
 * 
 */
public interface ISaml20SpFacade {

	List<ISpConfig> getSpConfigList();

	List<IIdpConfig> getIdpConfigList(String spConfigId);

	/**
	 * Build a SAML AuthnRequest for this IdP.
	 * 
	 * @param parametersMap
	 *            Map of HTTP parameters to store in request context cache
	 * @param binding
	 *            the SAML binding used for this request
	 * @param idpConfigId
	 *            id of the IdP to use
	 * @return the SAML 2.0 AuthnRequest
	 * @throws SamlBuildingException
	 */
	IOutgoingSaml getSamlAuthnRequest(Map<String, String[]> parametersMap, SamlBindingEnum binding, String idpConfigId)
			throws SamlBuildingException;

	/**
	 * Build a SAML Logout Request for this IdP.
	 * 
	 * @param request
	 *            the HttpServletRequest containing the SAML 2.0 request
	 * @param binding
	 *            the SAML binding used for this request
	 * @param idpConfigId
	 *            id of the IdP to use
	 * @return the SAML 2.0 Logout Request
	 * @throws SamlBuildingException
	 */
	IOutgoingSaml getSamlSingleLogoutRequest(HttpServletRequest request, SamlBindingEnum binding, String idpConfigId)
			throws SamlBuildingException;

	/**
	 * Process an incoming SAML 2.0 HTTP request.
	 * 
	 * @param request
	 *            the HttpServletRequest containing the SAML 2.0 request
	 * @return the SAML 2.0 response datas
	 * @throws SamlProcessingException
	 *             in case of problem during processing.
	 */
	IIncomingSaml processSaml20IncomingRequest(HttpServletRequest request) throws SamlProcessingException,
			UnsupportedSamlOperation;

}
