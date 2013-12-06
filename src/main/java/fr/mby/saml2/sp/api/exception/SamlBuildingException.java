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
 * A SAML building problem.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlBuildingException extends Exception {

	/** SVUID. */
	private static final long serialVersionUID = 3445043904522046709L;

	public SamlBuildingException() {
		super();
	}

	public SamlBuildingException(final String message, final Throwable cause) {
		super(message, cause);
	}

	public SamlBuildingException(final String message) {
		super(message);
	}

	public SamlBuildingException(final Throwable cause) {
		super(cause);
	}

}
