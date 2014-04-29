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

import java.io.IOException;

import org.springframework.util.Assert;

import fr.mby.saml2.sp.api.config.IIdpConfig;
import fr.mby.saml2.sp.api.core.ISaml20IdpConnector;
import fr.mby.saml2.sp.api.om.IRequestWaitingForResponse;
import fr.mby.saml2.sp.impl.helper.SamlHelper;

/**
 * SAML SLO Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public class QuerySloRequest extends SamlQuery implements IRequestWaitingForResponse {

	/** Svuid. */
	private static final long serialVersionUID = 1081464086973460157L;

	/** IdPConnector Id wich we can serialize. */
	private String idpConnectorId;

	private transient ISaml20IdpConnector idpConnectorBuilder;

	/** Default constructor for serialization. */
	public QuerySloRequest() {
		super();
	}

	public QuerySloRequest(final String id, final ISaml20IdpConnector idpConnectorBuilder) {
		super(id);
		
		Assert.notNull(idpConnectorBuilder, "No IdpConnector builder supplied !");
		this.idpConnectorBuilder = idpConnectorBuilder;
		this.idpConnectorId = idpConnectorBuilder.getIdpConfig().getId();
	}

	@Override
	public ISaml20IdpConnector getIdpConnectorBuilder() {
		return this.idpConnectorBuilder;
	}


	private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
		in.defaultReadObject();
		this.loadIdpConnector(this.idpConnectorId);
	}
	
	private void writeObject(java.io.ObjectOutputStream out) throws IOException {
		out.defaultWriteObject();
	}

	protected void loadIdpConnector(final String idpConnectorId) {
		final IIdpConfig idpConfig = SamlHelper.getWayfConfig().findIdpConfigById(idpConnectorId);
		Assert.notNull(idpConfig, "No compatible IdP config found !");

		this.idpConnectorBuilder = idpConfig.getSaml20IdpConnector();
	}

}
