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

package fr.mby.saml2.sp.api.core;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.signature.Signature;

import fr.mby.saml2.sp.api.config.ISpConfig;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.api.om.IIncomingSaml;
import fr.mby.saml2.sp.api.om.IRequestWaitingForResponse;

/**
 * SAML 2.0 IdP connector to ensure dialog with the IdP.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public interface ISaml20SpProcessor {

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

	/**
	 * Find the SAML 2.0 IdP Connector corresponding to an entity Id.
	 * 
	 * @param idpEntityId
	 *            the EntityId of the connector
	 * @return the SAML 2.0 IdP connector attached
	 */
	ISaml20IdpConnector findSaml20IdpConnectorToUse(String idpEntityId);

	/**
	 * Store a SAML request, which was built on this SP for a later use, in the cache.
	 * 
	 * @param requestData
	 *            the request to store
	 */
	void storeRequestWaitingForResponseInCache(IRequestWaitingForResponse samlRequest);

	/**
	 * Retrieve a SAML request waiting for a response, stored in the cache.
	 * 
	 * @param inResponseToId
	 *            the id of the request
	 * @return the request waiting for a response
	 */
	IRequestWaitingForResponse retrieveRequestWaitingForResponse(String inResponseToId);

	/**
	 * Retrieve the SAML 2.0 Facade.
	 * 
	 * @return the SAML 2.0 facade
	 */
	ISaml20Storage getSaml20Storage();

	/**
	 * Retrieve the SP config attached to this connector.
	 * 
	 * @return the SP configuration
	 */
	ISpConfig getSpConfig();

	/**
	 * Retrieve the Decrypter attached to this connector.
	 * 
	 * @return the decrypter
	 */
	Decrypter getDecrypter();

	/**
	 * Sign a SAML Object as builded by this SP.
	 * 
	 * @param signable
	 *            a Signable SAML object
	 * @return the signature witch signed the object
	 */
	Signature signSamlObject(SignableSAMLObject signable);

	/**
	 * Logout a previous authentication.
	 * 
	 * @param sessionIndex
	 *            the IdP session index
	 * @return true if the session was logout
	 */
	boolean logout(String sessionIndex);
}
