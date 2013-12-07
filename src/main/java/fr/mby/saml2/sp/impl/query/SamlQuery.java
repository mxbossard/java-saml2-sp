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

import fr.mby.saml2.sp.api.query.IQuery;

/**
 * Base ISamlQuery implementation.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 * 
 */
public abstract class SamlQuery implements IQuery {

	/** Svuid. */
	private static final long serialVersionUID = 8644852271120115445L;

	private String id;

	/** Default constructor for serialization. */
	public SamlQuery() {
		super();
	}

	@Override
	public String getId() {
		return this.id;
	}

	public SamlQuery(final String id) {
		super();
		this.id = id;
	}

}
