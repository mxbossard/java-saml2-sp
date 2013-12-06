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

import java.util.Collection;
import java.util.Map.Entry;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import fr.mby.saml2.sp.api.handler.ISamlDataAdaptor;
import fr.mby.saml2.sp.api.om.IOutgoingSaml;

/**
 * Saml Message to send from the SP to an IdP.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlOutgoingMessage extends SamlMessage implements IOutgoingSaml {

	/** Svuid. */
	private static final long serialVersionUID = 8857292232752789760L;

	/** URL to send the request with Redirect binding. */
	private String httpRedirectBindingUrl;

	/** SAML HTTP params to send the request. */
	private Collection<Entry<String, String>> httpPostBindingParams;

	/** SAML data adaptor configuring the request shape. */
	private transient ISamlDataAdaptor samlDataAdaptor;

	/**
	 * Unique constructor.
	 * 
	 * @param idpConnectorBuilder
	 */
	public SamlOutgoingMessage(final ISamlDataAdaptor pSamlDataAdaptor) {
		super();

		Assert.notNull(pSamlDataAdaptor, "No SAML data adaptor provided !");
		this.samlDataAdaptor = pSamlDataAdaptor;
	}

	@Override
	public String getHttpRedirectBindingUrl() {
		if (!StringUtils.hasText(this.httpRedirectBindingUrl)) {
			this.httpRedirectBindingUrl = this.buildHttpRedirectBindingUrl();
		}

		return this.httpRedirectBindingUrl;
	}

	@Override
	public Collection<Entry<String, String>> getHttpPostBindingParams() {
		if (this.httpPostBindingParams == null) {
			this.httpPostBindingParams = this.buildHttpPostBindingParams();
		}

		return this.httpPostBindingParams;
	}

	/**
	 * Build the SAML HTTP-Redirect request URL.
	 * 
	 * @return the HTTP-Redirect request URL
	 */
	protected String buildHttpRedirectBindingUrl() {
		final String redirectUrl = this.samlDataAdaptor.buildHttpRedirectBindingUrl(this);
		Assert.notNull(redirectUrl, "HTTP Redirect URL wasn't built !");

		return redirectUrl;
	}

	/**
	 * Build the SAML HTTP-POST request parameters.
	 * 
	 * @return the HTTP-POST request params
	 */
	public Collection<Entry<String, String>> buildHttpPostBindingParams() {
		final Collection<Entry<String, String>> params =
				this.samlDataAdaptor.buildHttpPostBindingParams(this);
		Assert.notEmpty(params, "HTTP POST params weren't built !");

		return params;
	}

}
