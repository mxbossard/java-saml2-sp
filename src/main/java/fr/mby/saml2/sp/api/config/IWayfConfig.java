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
package fr.mby.saml2.sp.api.config;

import java.io.Serializable;
import java.util.List;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IWayfConfig extends Serializable {

	/**
	 * Retrieve all IdPs config ordered.
	 * 
	 * @return an ordered list of IdPs config.
	 */
	List<IIdpConfig> getIdpsConfig();

	/**
	 * Find an IdP config from its Id.
	 * 
	 * @param id the IdP config Id
	 * @return the corresponding IdP config
	 */
	IIdpConfig findIdpConfigById(String id);

	/**
	 * IdP id parameter key in HTTP request.
	 * @return IdP id parameter key in HTTP request.
	 */
	String getIdpIdParamKey();
}
