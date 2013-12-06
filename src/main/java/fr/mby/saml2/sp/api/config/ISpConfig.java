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
import java.security.PrivateKey;

import org.opensaml.xml.security.x509.BasicX509Credential;

import fr.mby.saml2.sp.api.core.SamlBindingEnum;


/**
 * SP configuration.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface ISpConfig extends Serializable {

	/** Service Provider Id. */
	String getId();

	/** Service Provider SAML entity ID. */
	String getEntityId();

	/** Service Provider description. */
	String getDescription();

	/** Service Provider representative picture. */
	String getPictureUrl();

	/**
	 * Service Provider endpoint URL for this binding.
	 * 
	 * @param binding the binding
	 * @return the endpoint URL
	 */
	String getEndpointUrl(SamlBindingEnum binding);

	/** Used to decrypt assertions. */
	PrivateKey getDecryptionKey();

	/** Used to sign requests. */
	PrivateKey getSigningKey();

	/** Used to encrypt assertions. */
	BasicX509Credential getDecryptionCredential();

	/** Used for something ?. */
	BasicX509Credential getSigningCredential();

}
