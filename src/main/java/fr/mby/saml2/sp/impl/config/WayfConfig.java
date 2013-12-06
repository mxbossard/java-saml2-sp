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
package fr.mby.saml2.sp.impl.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import fr.mby.saml2.sp.api.config.IIdpConfig;
import fr.mby.saml2.sp.api.config.IWayfConfig;
import fr.mby.saml2.sp.impl.helper.SamlHelper;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class WayfConfig implements IWayfConfig, InitializingBean {

	/** SVUID. */
	private static final long serialVersionUID = -8041965026650236495L;

	/** IdPs configuration map. */
	private Map <String, IIdpConfig> idpConfigs;

	/** IdPs configuration ordered list. */
	private List <IIdpConfig> idpConfigsList;

	/** IdP id parameter key in HTTP request. */
	private String idpIdParamKey;

	@Override
	public IIdpConfig findIdpConfigById(final String id) {
		return this.idpConfigs.get(id);
	}

	@Override
	public List<IIdpConfig> getIdpsConfig() {
		return this.idpConfigsList;
	}

	/**
	 * IdPs configuration ordered list.
	 * 
	 * @param idpConfigs IdPs configuration ordered list
	 */
	public void setConfig(final List<IIdpConfig> idpConfigs) {
		Assert.notEmpty(idpConfigs, "IdP config ordered list is empty !");
		this.idpConfigsList = idpConfigs;
		this.idpConfigs = new HashMap<String, IIdpConfig>();
		for (IIdpConfig config : idpConfigs) {
			IIdpConfig previous = this.idpConfigs.put(config.getId(), config);
			Assert.isNull(previous, String.format(
					"Two IdP configs owned the same unique Id: [%s] !", previous));
			config.registerWayfConfig(this);
		}
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notEmpty(this.idpConfigs, "No IdP Config supplied !");
		Assert.notNull(this.idpIdParamKey, "No IdP id parameter key configured !");

		// Register this config in the Helper
		SamlHelper.registerWayfConfig(this);
	}

	/**
	 * IdP id parameter key in HTTP request.
	 * 
	 * @return IdP id parameter key in HTTP request.
	 */
	@Override
	public String getIdpIdParamKey() {
		return this.idpIdParamKey;
	}

	/**
	 * IdP id parameter key in HTTP request.
	 * 
	 * @param idpIdParamKey
	 */
	public void setIdpIdParamKey(final String idpIdParamKey) {
		this.idpIdParamKey = idpIdParamKey;
	}

}
