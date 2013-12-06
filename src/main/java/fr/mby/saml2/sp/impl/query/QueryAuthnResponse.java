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
package fr.mby.saml2.sp.impl.query;

import java.util.List;

import fr.mby.saml2.sp.api.om.IAuthentication;
import fr.mby.saml2.sp.api.om.IResponse;

/**
 * SAML Authn Response to a SAML Authn Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class QueryAuthnResponse extends SamlQuery implements IResponse {

	/** Svuid. */
	private static final long serialVersionUID = 381464903804175698L;

	/** Authentications embeded in the response. */
	private List<IAuthentication> samlAuthentications;

	private String inResponseToId;

	private QueryAuthnRequest originalRequest;

	public QueryAuthnResponse(final String id) {
		super(id);
	}

	@Override
	public String getInResponseToId() {
		return this.inResponseToId;
	}

	@Override
	public QueryAuthnRequest getOriginalRequest() {
		return this.originalRequest;
	}

	public List<IAuthentication> getSamlAuthentications() {
		return this.samlAuthentications;
	}

	public void setOriginalRequest(final QueryAuthnRequest originalRequest) {
		this.originalRequest = originalRequest;
	}

	public void setInResponseToId(final String inResponseToId) {
		this.inResponseToId = inResponseToId;
	}

	public void setSamlAuthentications(final List<IAuthentication> authns) {
		this.samlAuthentications = authns;
	}

}
