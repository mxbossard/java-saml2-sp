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
package fr.mby.saml2.sp.impl.om;


import fr.mby.saml2.sp.api.om.ISamlData;
import fr.mby.saml2.sp.api.query.IQuery;

/**
 * Saml message.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public abstract class SamlMessage implements ISamlData {

	/** Svuid. */
	private static final long serialVersionUID = 7583934230467679286L;

	/** SAML message representing the request to send. */
	private String samlMessage;

	/** Relay State to send. */
	private String relayState;

	/** Endpoint URL where to send the Request. */
	private String endpointUrl;

	/** Query representation of the message. */
	private IQuery samlQuery;

	@Override
	public String getSamlMessage() {
		return this.samlMessage;
	}

	@Override
	public String getRelayState() {
		return this.relayState;
	}

	@Override
	public String getEndpointUrl() {
		return this.endpointUrl;
	}

	@Override
	public IQuery getSamlQuery() {
		return this.samlQuery;
	}

	public void setSamlQuery(final IQuery samlQuery) {
		this.samlQuery = samlQuery;
	}

	public void setSamlMessage(final String samlMessage) {
		this.samlMessage = samlMessage;
	}

	public void setRelayState(final String relayState) {
		this.relayState = relayState;
	}

	public void setEndpointUrl(final String endpointUrl) {
		this.endpointUrl = endpointUrl;
	}


}
