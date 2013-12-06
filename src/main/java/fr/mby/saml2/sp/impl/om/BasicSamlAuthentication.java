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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.joda.time.DateTime;

import fr.mby.saml2.sp.api.exception.SamlSecurityException;
import fr.mby.saml2.sp.api.om.IInternalAuthentication;

/**
 * Basic implementation of a ISamlAuthentication. This object is immutable after a call on locked() method.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public class BasicSamlAuthentication implements IInternalAuthentication {

	/** Svuid. */
	private static final long serialVersionUID = 4483119001430907777L;

	/** Is this object locked (immutable) ?. */
	private boolean locked = false;

	/** IdP Authentication instant. */
	private DateTime authenticationInstant;

	/** IdP Entity Id. */
	private String idpEntityId;

	/** IdP subject ID. */
	private String subjectId;

	/** IdP session id. */
	private String sessionIndex;

	/** Subject attributes. */
	private final Map<String, List<String>> attributes = new HashMap<String, List<String>>(2);

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder(256);
		sb.append("BasicSamlAuthentication [authInstant=");
		sb.append(this.authenticationInstant);
		sb.append(", idpEntityId=");
		sb.append(this.idpEntityId);
		sb.append(", subjectId=");
		sb.append(this.subjectId);
		sb.append(", sessionIndex=");
		sb.append(this.sessionIndex);
		sb.append(", attributes=");
		sb.append(this.attributes.toString());
		sb.append("]");

		return sb.toString();
	}

	@Override
	public DateTime getAuthenticationInstant() {
		return this.authenticationInstant;
	}

	@Override
	public String getIdpEntityId() {
		return this.idpEntityId;
	}

	@Override
	public String getSubjectId() {
		return this.subjectId;
	}

	@Override
	public String getSessionIndex() {
		return this.sessionIndex;
	}

	@Override
	public void addAttribute(final String name, final List<String> values) throws SamlSecurityException {
		if (this.locked) {
			throw new IllegalAccessError("The BasicSamlAuthentication is locked ! It cannot be modified !");
		}

		final List<String> alreadyKnown = this.attributes.get(name);
		if (alreadyKnown != null) {
			throw new SamlSecurityException(String.format(
					"Assertion contained multiple attributes with same name: [%1$s] !", name));
		}

		this.attributes.put(name, values);
	}

	/** Turn the BasicSamlAuthentication immutable. */
	public void lock() {
		this.locked = true;
	}

	@Override
	public List<String> getAttribute(final String name) {
		return this.attributes.get(name);
	}

	@Override
	public Map<String, List<String>> getAttributes() {
		return this.attributes;
	}

	public void setAuthenticationInstant(final DateTime authenticationInstant) {
		if (this.locked) {
			throw new IllegalAccessError("The BasicSamlAuthentication is locked ! It cannot be modified !");
		}

		this.authenticationInstant = authenticationInstant;
	}

	public void setSubjectId(final String subjectId) {
		if (this.locked) {
			throw new IllegalAccessError("The BasicSamlAuthentication is locked ! It cannot be modified !");
		}

		this.subjectId = subjectId;
	}

	public void setSessionIndex(final String sessionIndex) {
		if (this.locked) {
			throw new IllegalAccessError("The BasicSamlAuthentication is locked ! It cannot be modified !");
		}

		this.sessionIndex = sessionIndex;
	}

	/**
	 * Setter of idpEntityId.
	 * 
	 * @param idpEntityId
	 *            the idpEntityId to set
	 */
	public void setIdpEntityId(final String idpEntityId) {
		this.idpEntityId = idpEntityId;
	}

}
