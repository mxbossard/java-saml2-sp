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

package fr.mby.saml2.sp.api.om;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import org.joda.time.DateTime;

/**
 * Base interface representing an authentication from an IdP.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public interface IAuthentication extends Serializable {

	/**
	 * Get the authentication instant.
	 * 
	 * @return The authentication instant.
	 */
	DateTime getAuthenticationInstant();

	/**
	 * Get the Entity Id of the IdP choosed by the user to perform the authentication.
	 * 
	 * @return the IdP Entity Id.
	 */
	String getIdpEntityId();

	/**
	 * Get the authenticated subject ID.
	 * 
	 * @return the authenticated subject ID
	 */
	String getSubjectId();

	/**
	 * Get the authenticated subject session ID on the IdP.
	 * 
	 * @return the session ID on the IdP
	 */
	String getSessionIndex();

	/**
	 * Get on attribute values.
	 * 
	 * @param name
	 *            the name of the attribute
	 * @return the values of the attribute
	 */
	List<String> getAttribute(String name);

	/**
	 * Get the map containing all attributes and their values.
	 * 
	 * @return the attributes map
	 */
	Map<String, List<String>> getAttributes();

}
