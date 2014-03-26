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

import fr.mby.saml2.sp.api.om.IAuthentication;
import fr.mby.saml2.sp.api.om.IRequestWaitingForResponse;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public interface ISaml20Storage {

	/**
	 * Store SAML 2.0 Credentials for a session index.
	 * 
	 * @param sessionIndex
	 *            the user's session index
	 * @param authentication
	 *            the user authentication
	 */
	void storeAuthentication(String sessionIndex, IAuthentication authentication);

	/**
	 * Retrieve SAML 2.0 credentials of a session index.
	 * 
	 * @param sessionIndex
	 *            the user's session index
	 * @return the user authentication
	 */
	IAuthentication findAuthentication(String sessionIndex);

	/**
	 * Remove SAML 2.0 Credentials of a session index.
	 * 
	 * @param sessionIndex
	 *            the user's session index
	 * @return the user authentication
	 */
	IAuthentication removeAuthentication(String sessionIndex);

	/**
	 * Find the CAS TGT Id corresponding to the SAML 2.0 Name ID.
	 * 
	 * @param nameId
	 *            the user's SAML Name ID
	 * @return the CAS TGT Id
	 */
	String findSessionIndexBySamlNameId(String nameId);

	/**
	 * Store a Request waiting for a response.
	 * 
	 * @param request the waiting request
	 */
	void storeRequestWaitingForResponse(IRequestWaitingForResponse request);
	
	/**
	 * Find a Request waiting for a response previously stored.
	 * 
	 * @param requestId
	 * @return
	 */
	IRequestWaitingForResponse findRequestWaitingForResponse(String requestId);
	
	/**
	 * Remove a Request waiting for a response previously stored.
	 * 
	 * @param requestId
	 * @return
	 */
	IRequestWaitingForResponse removeRequestWaitingForResponse(String requestId);
	
	/** Clear storage. Use it for test purpose only ! */
	void clear();
}
