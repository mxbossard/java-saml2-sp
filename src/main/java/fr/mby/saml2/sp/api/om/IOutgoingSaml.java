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

import java.util.Collection;
import java.util.Map.Entry;

/**
 * Interface representing datas which the SP want to send
 * outside (to an IdP).
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IOutgoingSaml extends ISamlData {

	/**
	 * Get the full SAML message encapsulated in HTTP-Redirect binding URL.
	 * 
	 * @return the HTTP-Redirect URL
	 */
	String getHttpRedirectBindingUrl();

	/**
	 * Get the HTTP-POST binding request parameters.
	 * 
	 * @return the HTTP request params
	 */
	Collection<Entry<String, String>> getHttpPostBindingParams();

}
