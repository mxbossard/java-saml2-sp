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

package fr.mby.saml2.sp.api.config;

import java.io.Serializable;

import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.core.io.Resource;

import fr.mby.saml2.sp.api.core.ISaml20IdpConnector;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;

/**
 * IdP configuration for display.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public interface IIdpConfig extends Serializable {

	/** Id of the IdP config. */
	String getId();

	/** Description of the IdP. */
	String getDescription();

	/** Picture of the IdP. */
	String getPictureUrl();

	/** SAML 2.0 Connector for the IdP. */
	ISaml20IdpConnector getSaml20IdpConnector();

	/** Register a SAML 2.0 Connector for the IdP. */
	void registerSaml20IdpConnector(ISaml20IdpConnector saml20IdpConnector);

	/**
	 * Access to the global wayf configuration.
	 * 
	 * @return the global wayf configuration
	 */
	IWayfConfig getWayfConfig();

	/**
	 * Register the global wayf configuration.
	 * 
	 * @param wayfConfig
	 *            the global wayf configuration
	 */
	void registerWayfConfig(IWayfConfig wayfConfig);

	/**
	 * Retrieve the IdP Entity Id.
	 * 
	 * @return the IdP Entity Id
	 */
	String getIdpEntityId();

	/**
	 * Time window in ms durint which the request are valids (by default 300000ms means requests are valid +-300000ms).
	 * 
	 * @return the time validity window
	 */
	public long getTimeValidityWindow();

	/**
	 * Retrieve the binding which must be used to send SAML requests.
	 * 
	 * @return the binding used to send SAML requests
	 */
	SamlBindingEnum getRequestBinding();

	boolean isForceAuthentication();

	Resource getIdpMetadata();

	SamlBindingEnum getResponseBinding();

	Integer getAttributeConsumingServiceIndex();

	SignatureTrustEngine getSignatureTrustEngine();

	String getIdpSsoEndpointUrl(SamlBindingEnum binding);

	String getIdpSloEndpointUrl(SamlBindingEnum binding);
}
