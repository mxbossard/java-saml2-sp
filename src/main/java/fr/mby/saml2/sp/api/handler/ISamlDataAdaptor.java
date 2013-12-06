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
package fr.mby.saml2.sp.api.handler;

import java.util.Collection;
import java.util.Map.Entry;

import fr.mby.saml2.sp.api.om.IOutgoingSaml;

/**
 * Adaptor which allow to configure the shape of SAML datas in HTTP requests.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface ISamlDataAdaptor {

	/**
	 * Build the HTTP-Redirect binding Request to send with GET method.
	 * 
	 * @return the HTTP-Redirect URL request
	 */
	String buildHttpRedirectBindingUrl(IOutgoingSaml outgoingData);

	/**
	 * Build the HTTP-POST binding params to send with POST method.
	 * 
	 * @return the HTTP-Post params request
	 */
	Collection<Entry<String, String>> buildHttpPostBindingParams(IOutgoingSaml outgoingData);
}
