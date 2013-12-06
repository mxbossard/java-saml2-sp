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

package fr.mby.saml2.sp.api.handler;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Maxime Bossard - 2013
 * 
 */
public interface ISessionIndexProvider {

	/**
	 * Retrieve the user Session Index from the HTTP request.
	 * 
	 * @param request
	 *            the HTTP request
	 * @return the not null Session index
	 */
	String retrieveSessionIndexFromRequest(HttpServletRequest request);

}