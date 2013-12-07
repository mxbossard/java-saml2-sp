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

import fr.mby.saml2.sp.api.om.IResponse;

/**
 * SAML SLO Response to a SAML SLO Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public class QuerySloResponse extends SamlQuery implements IResponse {

	/** Svuid. */
	private static final long serialVersionUID = 99264549059131337L;

	private String inResponseToId;

	private QuerySloRequest originalRequest;

	/** Default constructor for serialization. */
	public QuerySloResponse() {
		super();
	}

	public QuerySloResponse(final String id) {
		super(id);
	}

	@Override
	public String getInResponseToId() {
		return this.inResponseToId;
	}

	@Override
	public QuerySloRequest getOriginalRequest() {
		return this.originalRequest;
	}

	public void setOriginalRequest(final QuerySloRequest originalRequest) {
		this.originalRequest = originalRequest;
	}

	public void setInResponseToId(final String inResponseToId) {
		this.inResponseToId = inResponseToId;
	}

}
