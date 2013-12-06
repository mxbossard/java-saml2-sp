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
package fr.mby.saml2.sp.api.exception;


/**
 * A SAML security problem. This problem should be considered as a potential attack !
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlSecurityException extends Exception {

	/** Svuid. */
	private static final long serialVersionUID = 8895835344122467592L;

	public SamlSecurityException(final String message) {
		super(message);
	}

	public SamlSecurityException(final String message, final Throwable cause) {
		super(message, cause);
	}

}
