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
package fr.mby.saml2.sp.opensaml.query.engine;

import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutResponse;

import fr.mby.saml2.sp.api.core.ISaml20IdpConnector;
import fr.mby.saml2.sp.api.exception.NotSignedException;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.SamlSecurityException;
import fr.mby.saml2.sp.api.exception.SamlValidationException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;
import fr.mby.saml2.sp.impl.query.QuerySloRequest;
import fr.mby.saml2.sp.impl.query.QuerySloResponse;

/**
 * OpenSaml 2 implementation of QueryProcessor for incoming SLO Response.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public class SloResponseQueryProcessor extends BaseOpenSaml2QueryProcessor<QuerySloResponse, LogoutResponse> {

	@Override
	protected void checkSecurity() throws SamlSecurityException {
		final LogoutResponse sloResponse = this.getOpenSamlObject();
		final Issuer issuer = sloResponse.getIssuer();
		final ISaml20IdpConnector idpConnector = this.findIdpConnector(issuer);

		try {
			this.validateSignatureTrust(sloResponse, issuer, idpConnector);
		} catch (NotSignedException e) {
			throw new SamlSecurityException(
					"The SLO Response cannot be trusted, signature is missing !");
		}
	}

	@Override
	protected void validateConditions() throws SamlValidationException {
		// Nothing to validate
	}

	@Override
	protected void process() throws SamlProcessingException, SamlSecurityException, UnsupportedSamlOperation {
		// Nothing to process
	}

	@Override
	protected QuerySloResponse buildSamlQuery() throws SamlProcessingException, SamlSecurityException {
		final LogoutResponse sloResponse = this.getOpenSamlObject();

		final String inResponseToId = sloResponse.getInResponseTo();
		final QuerySloRequest originalRequest =
				this.checkResponseLegitimacy(inResponseToId, QuerySloRequest.class);

		QuerySloResponse query = new QuerySloResponse(sloResponse.getID());
		query.setInResponseToId(inResponseToId);
		query.setOriginalRequest(originalRequest);

		return query;
	}

}
